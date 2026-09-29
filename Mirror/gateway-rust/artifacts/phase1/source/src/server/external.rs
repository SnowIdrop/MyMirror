// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/external.rs
// Created : 2026-09-28
// Summary : 注入脚本改写出去的 `/external/<scheme>/<host>/<path>` 外链代理。
//           目标由客户端给出，因此每个请求都要重新做公网校验，并把解析结果
//           钉扎到这一次连接；转发不带任何账号、浏览器或 CF 凭据，重定向与
//           HTML 正文一律拒绝。
// -----------------------------------------------------------------------------

//! 外链代理（缺口 2 残项）：打开 `/external/*`，但只对公网目标开放。
//!
//! 逆向材料里原版用 `is_allowed_external_proxy_host` + `is_public_external_ip`
//! 两道检查（报告 07 §5.1），白名单内容未还原；本实现保留同一形状的收口：
//! 只允许 http/https、主机必须是公网地址、解析结果先校验再使用（防 DNS 重绑定），
//! 转发不携带任何凭据，重定向与 `text/html` 正文按上游故障处理。

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 允许的转发方法：页面用到的第三方调用（读取、注册、上报、同步）都在这里。
/// 不含 CONNECT/TRACE 这类隧道或反射方法。
const EXTERNAL_ALLOW: &str = "GET, HEAD, POST, PUT, PATCH, DELETE";

/// 已解析并校验的外链目标。
struct Target {
    url: url::Url,
    /// 校验通过的解析结果：请求时钉扎到这些地址，避免校验后重新解析被换成内网。
    /// 离线合成回环（`Config::public_prefix_base`）不为 None 的结果钉扎。
    pinned: Option<(String, Vec<SocketAddr>)>,
}

/// 目标被拒绝的原因：文案要能指导调用方，状态码要区分「请求不合法」与「目标不允许」。
enum Rejection {
    Malformed,
    Scheme,
    BlockedHost,
    BlockedAddress,
    Unresolvable,
}

impl Rejection {
    fn into_response(self) -> Response {
        match self {
            Self::Malformed => error(StatusCode::BAD_REQUEST, "外链目标路径不合法").into_response(),
            Self::Scheme => {
                error(StatusCode::BAD_REQUEST, "外链代理仅支持 http/https 上游").into_response()
            }
            Self::BlockedHost => error(
                StatusCode::FORBIDDEN,
                "外链代理拒绝内网、localhost 或非公网主机",
            )
            .into_response(),
            Self::BlockedAddress => error(
                StatusCode::FORBIDDEN,
                "外链代理目标解析到非公网地址",
            )
            .into_response(),
            Self::Unresolvable => {
                error(StatusCode::BAD_GATEWAY, "外链代理目标无法解析").into_response()
            }
        }
    }
}

/// `/external/<scheme>/<host>/<path>` 入口。目标校验失败按原因返回，不接触上游。
pub(super) async fn answer(app: &App, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let target = match resolve(&app.config, &path, query.as_deref()).await {
        Ok(target) => target,
        Err(rejection) => return rejection.into_response(),
    };
    let method = request.method().clone();
    if !matches!(
        method,
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return proxy::method_not_allowed(EXTERNAL_ALLOW);
    }
    forward(app, request, target, method).await
}

/// 解析目标并校验公网可达性；`Config::public_prefix_base` 由测试构造（生产
/// `Config::from_env` 恒为 None），命中时把目标指到本机桩并跳过公网校验，
/// 其余转发语义完全一致。
async fn resolve(config: &Config, path: &str, query: Option<&str>) -> Result<Target, Rejection> {
    let rest = path
        .strip_prefix("/external/")
        .filter(|rest| !rest.is_empty())
        .ok_or(Rejection::Malformed)?;
    let (scheme, tail) = rest.split_once('/').ok_or(Rejection::Malformed)?;
    if !matches!(scheme, "http" | "https") {
        return Err(Rejection::Scheme);
    }
    let mut target = url::Url::parse(&format!("{scheme}://{tail}")).map_err(|_| Rejection::Malformed)?;
    target.set_query(query);
    // URL 里的凭据、非默认端口之外的畸形形态都不接受：代理只转发页面自己的调用。
    if !target.username().is_empty() || target.password().is_some() {
        return Err(Rejection::Malformed);
    }
    let host = target
        .host_str()
        .ok_or(Rejection::Malformed)?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if let Some(base) = &config.public_prefix_base {
        let mut fixture = base.clone();
        fixture.set_path(target.path());
        fixture.set_query(target.query());
        return Ok(Target {
            url: fixture,
            pinned: None,
        });
    }
    if is_blocked_host_name(&host) {
        return Err(Rejection::BlockedHost);
    }
    let port = target.port_or_known_default().ok_or(Rejection::Malformed)?;
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| Rejection::Unresolvable)?
        .collect();
    if addresses.is_empty() {
        return Err(Rejection::Unresolvable);
    }
    if !addresses.iter().all(|address| is_public_ip(address.ip())) {
        return Err(Rejection::BlockedAddress);
    }
    Ok(Target {
        url: target,
        pinned: Some((host, addresses)),
    })
}

/// 主机名层面的拒绝：IP 字面量留给地址校验，这里只挡单标签名与内网后缀。
fn is_blocked_host_name(host: &str) -> bool {
    if host.is_empty() {
        return true;
    }
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    !host.contains('.')
        || [".local", ".internal", ".localhost", ".lan", ".home"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
}

/// 公网地址判定：回环、私网、链路本地、CGNAT、组播、保留与文档段一律不算公网。
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_v4(address),
        // IPv4-mapped（`::ffff:a.b.c.d`）按内层地址判定，否则 127.0.0.1 会被当成公网。
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => is_public_v4(mapped),
            None => is_public_v6(address),
        },
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast()
        // 240.0.0.0/4 保留段、0.0.0.0/8 与 100.64.0.0/10（CGNAT）都不是私网段，
        // 标准库的 `is_reserved` 尚未稳定，因此按首字节判断。
        || first >= 240
        || first == 0
        || (first == 100 && (64..128).contains(&second))
        // 198.18.0.0/15 是基准测试段（标准库的 `is_benchmarking` 同样未稳定）。
        || (first == 198 && (18..20).contains(&second))
        // 192.0.0.0/24 是 IETF 协议专用段。
        || (first == 192 && second == 0 && address.octets()[2] == 0))
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        // fe80::/10 链路本地、fc00::/7 唯一本地地址。
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xfe00) == 0xfc00
        // 2001:db8::/32 文档段。
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

/// 转发：只复制值类请求头 + 低熵身份组（第三方源没下发过 `Accept-CH`，
/// 高熵提示不发），不携带任何账号、浏览器或 CF 凭据。
async fn forward(app: &App, request: Request, target: Target, method: Method) -> Response {
    let (parts, body) = request.into_parts();
    let mut headers = HeaderMap::new();
    // Public third-party calls never receive browser, gateway, account or CF credentials.
    for name in [
        "accept",
        "accept-encoding",
        "accept-language",
        "content-type",
        "if-none-match",
        "if-modified-since",
        "range",
        "if-range",
        "x-ms-blob-type",
    ] {
        if let Some(value) = parts.headers.get(name) {
            headers.insert(name, value.clone());
        }
    }
    identity::apply_low_entropy_identity(&mut headers);
    if !matches!(method, Method::GET | Method::HEAD) {
        // 浏览器对第三方写请求会带 chatgpt.com 的 origin/referer；镜像源自证一致。
        headers.insert("origin", HeaderValue::from_static("https://chatgpt.com"));
        headers.insert("referer", HeaderValue::from_static("https://chatgpt.com/"));
    }
    let mut builder = identity::client_builder().timeout(app.config.timeout);
    if let Some((host, addresses)) = &target.pinned {
        // 校验过的地址直接钉扎给本次请求：解析与连接之间没有第二次解析。
        builder = builder.resolve_to_addrs(host.clone(), addresses.clone());
    }
    let upstream = builder
        .build()
        .expect("外链客户端构造不依赖运行期配置")
        .request(method.clone(), target.url.as_str())
        .headers(headers);
    let upstream = match method {
        // 读取类请求无正文；其余方法按流透传，避免把第三方上传整个读进内存。
        Method::GET | Method::HEAD => upstream.send().await,
        _ => upstream
            .body(wreq::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await,
    };
    let upstream = match upstream {
        Ok(value) => value,
        Err(cause) => {
            tracing::warn!(module = "gateway", error = %cause, "外链代理请求失败");
            return error(StatusCode::BAD_GATEWAY, "外链目标不可达").into_response();
        }
    };
    let status = upstream.status();
    if status.is_redirection() {
        return error(StatusCode::BAD_GATEWAY, "外链目标返回重定向，未跟随").into_response();
    }
    let content_type = upstream
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if content_type.eq_ignore_ascii_case("text/html") {
        return error(StatusCode::BAD_GATEWAY, "外链目标返回 HTML，未转发").into_response();
    }
    static_assets::stream_public_response(upstream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 公网判定：内网、回环、CGNAT、链路本地、组播、保留与文档段全拒。
    #[test]
    fn only_public_addresses_are_proxied() {
        for blocked in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.168.1.1",
            "192.0.2.10",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(!is_public_ip(ip), "{blocked} 不该被当作公网地址");
        }
        for allowed in [
            "1.1.1.1",
            "8.8.8.8",
            "100.128.0.1",
            "192.0.1.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            let ip: IpAddr = allowed.parse().unwrap();
            assert!(is_public_ip(ip), "{allowed} 应当被当作公网地址");
        }
    }

    /// 主机名拒绝：单标签名与内网后缀；IP 字面量交给地址校验。
    #[test]
    fn blocked_host_names_cover_local_and_single_label_hosts() {
        for blocked in ["localhost", "router.local", "gateway.internal", "printer.lan"] {
            assert!(is_blocked_host_name(blocked), "{blocked} 不该被转发");
        }
        for allowed in ["example.com", "cdn.oaistatic.com", "8.8.8.8", "2001:4860::8888"] {
            assert!(!is_blocked_host_name(allowed), "{allowed} 应当通过主机名检查");
        }
    }

    /// 路径解析：协议与形态不合法的目标在接触上游之前被拒绝。
    #[tokio::test]
    async fn target_parsing_rejects_bad_schemes_and_shapes() {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: "fixture.db".into(),
            secret: "external-fixture-secret".into(),
            key: "external-fixture-key-000000000001".into(),
            django: url::Url::parse("http://127.0.0.1:1/").unwrap(),
            upstream: url::Url::parse("http://127.0.0.1:1/").unwrap(),
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            cfbypass: None,
            timeout: std::time::Duration::from_secs(1),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
            admin_public_url: None,
        };
        for path in ["/external/", "/external/https", "/external/ftp/example.com/x"] {
            assert!(
                resolve(&config, path, None).await.is_err(),
                "{path} 不该被解析成目标"
            );
        }
        assert!(matches!(
            resolve(&config, "/external/https/localhost/x", None).await,
            Err(Rejection::BlockedHost)
        ));
        assert!(matches!(
            resolve(&config, "/external/http/127.0.0.1:8080/x", None).await,
            Err(Rejection::BlockedAddress)
        ));
    }
}

// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/public_prefixes.rs
// Created : 2026-09-23
// Summary : 注入脚本改写目标的服务端策略表（缺口 2）。可代理的前缀按固定主机
//           反代，有意不代理的前缀返回按类别区分的可行动文案；两类都不带凭据。
//           契约测试直接从 src/assets/gateway-client.html 抽取改写目标，
//           脚本新增前缀而不更新本表会让测试失败。
// -----------------------------------------------------------------------------

//! 缺口 2：让脚本已经改写出去的每个前缀都有对应的服务端处理或明确的失败语义，
//! 不再出现「改写成功但服务端 503」的静默断裂。目标主机是编译期常量，客户端
//! 不能借这些前缀选择任意上游。

use super::*;
use axum::http::Method;

/// 代理条目：本地前缀 → (上游主机, 上游路径前缀)。
struct Prefix {
    local: &'static str,
    host: &'static str,
    upstream: &'static str,
}

/// 可代理的静态/媒体前缀。全部只允许 GET/HEAD，一律不携带账号或 CF 凭据。
const PROXY: &[Prefix] = &[
    Prefix {
        local: "/common/",
        host: "cdn.openai.com",
        upstream: "/common/",
    },
    Prefix {
        local: "/static-rsc-1/",
        host: "images.openai.com",
        upstream: "/static-rsc-1/",
    },
    Prefix {
        local: "/static-rsc-4/",
        host: "images.openai.com",
        upstream: "/static-rsc-4/",
    },
    Prefix {
        local: "/images-openai/",
        host: "images.openai.com",
        upstream: "/",
    },
    Prefix {
        local: "/images-app/",
        host: "persistent.oaistatic.com",
        upstream: "/images-app/",
    },
    Prefix {
        local: "/persistent-deep-research/",
        host: "persistent.oaistatic.com",
        upstream: "/deep-research/",
    },
    Prefix {
        local: "/files/",
        host: "sdmntprwestus3.oaiusercontent.com",
        upstream: "/files/",
    },
    Prefix {
        local: "/files-southcentral/",
        host: "sdmntprsouthcentralus.oaiusercontent.com",
        upstream: "/files/",
    },
    Prefix {
        local: "/files-north/",
        host: "sdmntprnznorth.oaiusercontent.com",
        upstream: "/files/",
    },
    Prefix {
        local: "/openai-files/",
        host: "files.openai.com",
        upstream: "/",
    },
    Prefix {
        local: "/connector-assets/",
        host: "connector-openai-deep-research.web-sandbox.oaiusercontent.com",
        upstream: "/assets/",
    },
    Prefix {
        local: "/mapbox/styles/v1/oai-data/",
        host: "api.mapbox.com",
        upstream: "/styles/v1/oai-data/",
    },
    Prefix {
        local: "/mapbox/",
        host: "api.mapbox.com",
        upstream: "/",
    },
    Prefix {
        local: "/google-s2/",
        host: "www.google.com",
        upstream: "/s2/",
    },
    Prefix {
        local: "/google-avatar/a/",
        host: "lh3.googleusercontent.com",
        upstream: "/a/",
    },
    Prefix {
        local: "/gstatic-t0/",
        host: "t0.gstatic.com",
        upstream: "/",
    },
    Prefix {
        local: "/gstatic-t1/",
        host: "t1.gstatic.com",
        upstream: "/",
    },
    Prefix {
        local: "/gstatic-t2/",
        host: "t2.gstatic.com",
        upstream: "/",
    },
    Prefix {
        local: "/gstatic-t3/",
        host: "t3.gstatic.com",
        upstream: "/",
    },
];

/// 有意不代理的前缀与文案。保持 503 状态码，但按类别给出可行动信息，
/// 而不是把「未开放」和「上游故障」混成同一句话。
const REFUSED: &[(&str, &str)] = &[
    (
        "/external/",
        "外链代理尚未开放：原版按上游主机白名单转发，白名单内容未还原",
    ),
    ("/v1/", "OpenAI 兼容接口（/v1/chat/completions）尚未开放"),
    ("/vendor-script/", "第三方脚本代理不在本候选范围"),
    ("/vendor-static", "第三方脚本代理不在本候选范围"),
    ("/cloudflare-insights/", "第三方脚本代理不在本候选范围"),
    ("/vendor-batch/collect", "第三方遥测上报不在本候选范围"),
    ("/ga/collect", "第三方遥测上报不在本候选范围"),
    ("/mapbox-events/events/", "地图遥测上报不在本候选范围"),
    ("/connector-deep-research/", "沙箱页面尚未开放"),
    ("/connector-deep-research", "沙箱页面尚未开放"),
];

/// 前缀命中结果。
pub(super) enum Route {
    /// 反代到固定上游：无账号凭据、拒绝重定向与非 2xx、拒绝 `text/html` 正文。
    Proxy(url::Url),
    /// 有意不代理：返回固定文案的 503，不接触上游。
    Refused(&'static str),
}

/// 命中策略表则返回处置方式；未命中返回 None，由其它分支（页面、匿名通道、
/// 已登录业务面、内部媒体代理）决定。
pub(super) fn resolve(config: &Config, path: &str, query: Option<&str>) -> Option<Route> {
    // `/ab/*` 的上游来自配置（原版 CHATGPT_AB_BASE_URL），未配置时给出可行动文案。
    if let Some(rest) = strip_local(path, "/ab/") {
        return Some(match (ab_base(config), safe_remainder(rest)) {
            (Some(mut base), Some(rest)) => {
                base.set_path(&format!("/{rest}"));
                base.set_query(query);
                Route::Proxy(base)
            }
            (Some(_), None) => Route::Refused("资源路径不合法"),
            (None, _) => Route::Refused("CHATGPT_AB_BASE_URL 未配置：/ab/ 统计请求未代理"),
        });
    }
    if let Some(entry) = longest_prefix(path) {
        let (entry, rest) = entry;
        return Some(match safe_remainder(rest) {
            Some(rest) => {
                let mut target = table_base(config, entry.host);
                target.set_path(&format!("{}{}", entry.upstream, rest));
                target.set_query(query);
                Route::Proxy(target)
            }
            None => Route::Refused("资源路径不合法"),
        });
    }
    REFUSED
        .iter()
        .find(|(local, _)| strip_local(path, local).is_some())
        .map(|(_, message)| Route::Refused(message))
}

/// `/ab/` 基址：只在 `CHATGPT_AB_BASE_URL` 已配置时成立；离线回归用
/// [`Config::public_prefix_base`] 把该基址指到本机桩，配置语义不变。
fn ab_base(config: &Config) -> Option<url::Url> {
    let configured = config.ab_upstream.as_ref()?;
    Some(
        config
            .public_prefix_base
            .clone()
            .unwrap_or_else(|| configured.clone()),
    )
}

/// 策略表条目基址：生产装载是表内的固定主机；离线合成回环回归用
/// [`Config::public_prefix_base`] 把同一组路径指到本机桩，路径映射逻辑不变。
fn table_base(config: &Config, host: &str) -> url::Url {
    config.public_prefix_base.clone().unwrap_or_else(|| {
        url::Url::parse(&format!("https://{host}/")).expect("策略表基址必须是合法 URL")
    })
}

/// 反代一个已解析的策略表目标：只允许 GET/HEAD，复用公共资源转发（不复制凭据，
/// 拒绝重定向与 `text/html` 正文）。有意不代理的条目由调用方直接返回文案。
pub(super) async fn answer(app: &App, request: Request, target: url::Url) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return proxy::method_not_allowed("GET, HEAD");
    }
    // 同源公共资源：一律不带账号/CF 凭据，正文不得是可执行页面。
    static_assets::forward_public(app, request, target, |content_type| {
        !content_type.eq_ignore_ascii_case("text/html")
    })
    .await
}

/// 最长前缀匹配：`/mapbox/styles/v1/oai-data/` 优先于 `/mapbox/`，
/// 结果与表内书写顺序无关。
fn longest_prefix(path: &str) -> Option<(&'static Prefix, &str)> {
    PROXY
        .iter()
        .filter_map(|entry| Some((entry, strip_local(path, entry.local)?)))
        .max_by_key(|(entry, _)| entry.local.len())
}

/// 前缀匹配：以 `/` 结尾的条目按前缀命中，其余条目要求整段相等
/// （避免 `/vendor-static` 命中 `/vendor-static-x`）。
fn strip_local<'a>(path: &'a str, local: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(local)?;
    (local.ends_with('/') || rest.is_empty()).then_some(rest)
}

/// 路径余段校验：拒绝空段、`.`/`..`、反斜杠、非可打印 ASCII，以及编码后的
/// 分隔符（上游解码后会变回跨段/跨路径语义），因此客户端不能借前缀选择任意目标。
fn safe_remainder(rest: &str) -> Option<&str> {
    let trimmed = rest.strip_suffix('/').unwrap_or(rest);
    if !trimmed.is_empty()
        && trimmed
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
    {
        return None;
    }
    let lowered = rest.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c"]
        .iter()
        .any(|encoded| lowered.contains(encoded))
    {
        return None;
    }
    rest.bytes()
        .all(|byte| byte.is_ascii_graphic() && !b"\\\"<>".contains(&byte))
        .then_some(rest)
}

/// 改写目标前缀的服务端处置，供契约测试与文档共用。
#[cfg(test)]
pub(super) enum Disposition {
    /// 由本表或其它已注册路由处理
    Handled,
    /// 有意不代理，返回固定文案
    Refused,
}

/// 其它模块已注册的服务端路由面（与 server.rs / proxy.rs / static_assets.rs 对应）。
#[cfg(test)]
const ELSEWHERE: &[&str] = &[
    "/assets/",
    "/cdn/",
    "/ces/",
    "/public-api/",
    "/backend-anon/",
    "/backend-api/",
    "/realtime/",
    "/internal-upstream/",
    "/ws-chatgpt",
];

#[cfg(test)]
pub(super) fn disposition(prefix: &str) -> Option<Disposition> {
    // `/` 是页面路由本体，也是改写表的兜底目标。
    if prefix == "/" {
        return Some(Disposition::Handled);
    }
    // `/api/*` 由本机 next-auth 兼容面处理，未实现的子路径是显式 404。
    if prefix.starts_with("/api/") {
        return Some(Disposition::Handled);
    }
    if strip_local(prefix, "/ab/").is_some()
        || ELSEWHERE
            .iter()
            .any(|local| strip_local(prefix, local).is_some())
        || PROXY
            .iter()
            .any(|entry| strip_local(prefix, entry.local).is_some())
    {
        return Some(Disposition::Handled);
    }
    REFUSED
        .iter()
        .any(|(local, _)| strip_local(prefix, local).is_some())
        .then_some(Disposition::Refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture_config() -> Config {
        let loopback = url::Url::parse("http://127.0.0.1:18090/").expect("fixture URL 无效");
        Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: "fixture.db".into(),
            secret: "prefix-fixture-admin-secret".into(),
            key: "prefix-fixture-encryption-key-000001".into(),
            django: loopback.clone(),
            upstream: loopback.clone(),
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").expect("fixture WS 基址无效"),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            cfbypass: None,
            timeout: Duration::from_secs(1),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
        }
    }

    /// 注入脚本的每一条改写目标都必须在本表或其它已注册路由上有确定语义。
    #[test]
    fn every_rewritten_prefix_has_a_server_side_answer() {
        let html = include_str!("../assets/gateway-client.html");
        let mut targets: Vec<String> = Vec::new();
        for line in html.lines() {
            let trimmed = line.trim();
            // 绝对→相对 pairs 表条目与 CSS 改写链的第二段字面量都是目标前缀。
            if trimmed.starts_with("['") || trimmed.starts_with(".replaceAll('") {
                if let Some(target) = second_literal(trimmed) {
                    targets.push(target);
                }
            }
        }
        // 脚本运行时拼出的两个前缀：外链代理与内置主机媒体代理。
        targets.push("/external/".into());
        targets.push("/internal-upstream/".into());
        targets.sort();
        targets.dedup();
        // 2026-09-23 实测：脚本改写表共 63 条 pair、39 个互不相同的同源目标前缀
        // （见 NEXT_WORK.md 缺口 2）；加上运行时拼出的两个前缀共 41 个。
        assert_eq!(targets.len(), 41, "改写表解析失败：{targets:?}");
        for target in &targets {
            assert!(
                disposition(target).is_some(),
                "{target} 已被脚本改写，但服务端没有对应语义"
            );
        }
        for target in [
            "/", "/api/", "/ces/", "/public-api/", "/realtime/", "/backend-api/",
            "/backend-api/estuary/", "/backend-anon/", "/assets/", "/cdn/", "/cdn/assets/",
            "/internal-upstream/",
        ] {
            assert!(
                matches!(disposition(target), Some(Disposition::Handled)),
                "{target} 必须由已注册路由处理"
            );
        }
        for target in [
            "/vendor-static",
            "/vendor-script/",
            "/mapbox-events/events/",
            "/v1/",
            "/external/",
            "/cloudflare-insights/",
            "/vendor-batch/collect",
            "/connector-deep-research",
            "/connector-deep-research/",
        ] {
            assert!(
                matches!(disposition(target), Some(Disposition::Refused)),
                "{target} 必须按“有意不代理”登记"
            );
        }
    }

    /// 表内每个代理条目都产生固定主机 + 固定路径的地址。
    #[test]
    fn proxy_entries_map_to_fixed_hosts_and_paths() {
        let config = fixture_config();
        for (path, host, upstream_path) in [
            ("/common/fonts/a.woff2", "cdn.openai.com", "/common/fonts/a.woff2"),
            ("/static-rsc-1/a.png", "images.openai.com", "/static-rsc-1/a.png"),
            ("/static-rsc-4/a.png", "images.openai.com", "/static-rsc-4/a.png"),
            ("/images-openai/a.png", "images.openai.com", "/a.png"),
            ("/images-app/a.png", "persistent.oaistatic.com", "/images-app/a.png"),
            (
                "/persistent-deep-research/a.png",
                "persistent.oaistatic.com",
                "/deep-research/a.png",
            ),
            (
                "/files/v1/f.png",
                "sdmntprwestus3.oaiusercontent.com",
                "/files/v1/f.png",
            ),
            (
                "/files-southcentral/v1/f.png",
                "sdmntprsouthcentralus.oaiusercontent.com",
                "/files/v1/f.png",
            ),
            (
                "/files-north/v1/f.png",
                "sdmntprnznorth.oaiusercontent.com",
                "/files/v1/f.png",
            ),
            ("/openai-files/a.png", "files.openai.com", "/a.png"),
            (
                "/connector-assets/a.js",
                "connector-openai-deep-research.web-sandbox.oaiusercontent.com",
                "/assets/a.js",
            ),
            (
                "/mapbox/styles/v1/oai-data/style.json",
                "api.mapbox.com",
                "/styles/v1/oai-data/style.json",
            ),
            ("/mapbox/tiles/1.pbf", "api.mapbox.com", "/tiles/1.pbf"),
            ("/google-s2/a.png", "www.google.com", "/s2/a.png"),
            ("/google-avatar/a/abc", "lh3.googleusercontent.com", "/a/abc"),
            ("/gstatic-t0/a.woff2", "t0.gstatic.com", "/a.woff2"),
            ("/gstatic-t3/a.woff2", "t3.gstatic.com", "/a.woff2"),
        ] {
            let Some(Route::Proxy(target)) = resolve(&config, path, Some("v=1")) else {
                panic!("{path} 必须命中代理条目");
            };
            assert_eq!(target.scheme(), "https", "{path}");
            assert_eq!(target.host_str(), Some(host), "{path}");
            assert_eq!(target.path(), upstream_path, "{path}");
            assert_eq!(target.query(), Some("v=1"), "{path}");
        }
        // `/mapbox/styles/...` 比 `/mapbox/` 更长：必须按最长前缀改写。
        let Some(Route::Proxy(target)) = resolve(&config, "/mapbox/styles/v1/oai-data/x", None)
        else {
            panic!("mapbox styles 必须命中代理条目");
        };
        assert_eq!(target.path(), "/styles/v1/oai-data/x");
    }

    /// 路径余段不允许变成任意目标；`/ab/` 未配置时给出可行动文案。
    #[test]
    fn path_escapes_and_unconfigured_prefixes_are_refused() {
        let config = fixture_config();
        for path in [
            "/common/../secret",
            "/common/%2e%2e/secret",
            "/common/%2Fsecret",
            "/common//a.png",
            "/files/a\\b.png",
            "/mapbox/a b.png",
        ] {
            assert!(
                matches!(resolve(&config, path, None), Some(Route::Refused(_))),
                "{path}"
            );
        }
        let Some(Route::Refused(message)) = resolve(&config, "/ab/x", None) else {
            panic!("未配置 CHATGPT_AB_BASE_URL 时必须给出可行动文案");
        };
        assert!(message.contains("CHATGPT_AB_BASE_URL"), "{message}");
        // 未命中任何条目的路径交给其它分支（例如 /backend-api/*），不在这里拒绝。
        assert!(resolve(&config, "/backend-api/models", None).is_none());
        assert!(resolve(&config, "/nothing/here", None).is_none());
    }

    fn second_literal(line: &str) -> Option<String> {
        // 形如 `['from', 'to'],` 与 `.replaceAll('from', 'to')`：第 4 段就是目标字面量。
        let value = line.split('\'').nth(3)?;
        value.starts_with('/').then(|| value.to_owned())
    }
}

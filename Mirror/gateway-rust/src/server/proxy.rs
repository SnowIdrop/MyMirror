// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/proxy.rs
// Created : 2026-09-22
// Summary : 聊天/管理代理会话子模块：/0x/*（django 透传）与 /backend-api/me、
//           /backend-api/conversations（会话列表归属隔离）三项差异实现。
// 证据来源：QEMU 无网隔离 guest 的原版运行时观测
//           evidence/proxy-v3-original-007（含 001-006 的早期轮次，
//           001-002 为空态/范围探针、003-007 为请求构造探针）。
//           基线差异见 evidence/response-diff-final.json 的三个 session 用例。
// -----------------------------------------------------------------------------

//! 代理子模块（挂载于 `server`，父模块需要 `mod proxy;` 与路由接线）。
//!
//! 接线需求（主代理执行，本模块不修改父文件）：
//! - `/0x/*path`、`/admin`、`/admin/*path` 的 handler 换成 [`django_proxy`]；
//!   [`django_proxy`] 用 `Option<ConnectInfo<SocketAddr>>` 读取 TCP 对端 IP 写入上游
//!   `x-chatgpt-mirror-client-ip`（观测：X-Forwarded-For / 伪造头都会被覆盖）。
//!   要复现该头，`main.rs` 的 `axum::serve(listener, router)` 必须改为
//!   `axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())`；
//!   未接线时该头缺失、其余行为不变（不 500）。
//! - `fallback` 的 handler 使用 [`chat_proxy`]。
//!
//! 观测契约要点（原版，见 evidence/proxy-v3-original-007/results.json）：
//! - 上游请求头：客户端端到端头保留；`user-agent` 恒被替换为默认浏览器 UA；
//!   `accept` 缺省补 `*/*`；`accept-encoding` 保留客户端值；`authorization` 只使用
//!   会话关联的 access_token（mirror token 与客户端 Authorization 都不转发）；
//!   `x-real-ip`/`x-forwarded-for` 客户端值一律丢弃（原版观测 p1-cfg-client-ip-headers：
//!   上游只见 TCP 对端 IP 写入的 `x-chatgpt-mirror-client-ip`）；
//!   `cookie` 只用 会话 extra_cookies + CF 缓存中名为 `cf_clearance` 的条目
//!   （客户端 cookie 丢弃）；chat 路径额外固定 origin/referer（scheme://host 去端口）。
//! - `/0x/*`：任意方法透传，流式响应（无 content-length，由 HTTP 栈分块）。
//! - `/backend-api/me`：状态码、端到端响应头与原始字节透传（非重序列化），
//!   上游 4xx/5xx 与畸形正文也原样回传。
//! - `/backend-api/conversations`：仅 GET；offset/limit 等查询原样转发；成功 2xx 时
//!   解析上游 JSON，从 `items[].id` 过滤出 (chatgpt_username, user_name) 归属当前
//!   会话的条目（重复条目不去重、未知归属不认领），`total` 换成该账号 + 用户的
//!   conversation_owners 计数，其余键原样保留（serde_json 默认按键排序输出）；
//!   非 2xx 或正文不可解析时返回 `{"items":[],"total":0}`（状态码保留上游值）。
//! - 重启恢复：归属行持久化在 conversation_owners；conversation_statistics 的
//!   存量回填由 storage 的 schema.sql 在启动时执行（证据：p3-after-restart-list）。
//!
//! CSP 与安全响应头由统一中间件负责；text/html 客户端资源从原版离线响应重建，
//! 静态资源来源/哈希记录在 evidence/client-template-v3.json，未执行浏览器验收。
//! 响应头语义：本模块只在代理响应上写入 [`ProxiedResponse`] 标记，`vary` 合并
//! （Cookie/Authorization + accept-encoding）、私有 cache 与固定 CSP 全部由父模块
//! 中间件（`private_headers` + `compression::compress`）负责，本模块不再自行
//! 追加或模拟压缩层的 vary。

use super::*;
use anyhow::Context;
use axum::extract::ConnectInfo;
use axum::http::Method;
use bytes::Bytes;
use futures_util::TryStreamExt;
use rusqlite::params;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};

/// 请求体上限（与父 `forward` 一致）。
const MAX_BODY: usize = 16 * 1024 * 1024;

/// 上游默认 User-Agent（原版对 django 与 chat 上游一致强制覆盖，见 p1-me-client-headers、
/// p1-cfg-client-cookie-ua：客户端 UA 均被替换）。
pub(super) const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

/// 已取得原版成功观测、允许放行的 chat 读取路径。
const ME_PATH: &str = "/backend-api/me";
const CONVERSATIONS_PATH: &str = "/backend-api/conversations";

/// 请求方向需要过滤的逐跳头与凭据头（`connection` 命名头另行按值移除）。
/// cookie/x-mirror-token 丢弃；Django 必须保留 Authorization，chat 路径另行替换为上游凭据。
const REQUEST_HOP_BY_HOP: [&str; 12] = [
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "cookie",
    "x-mirror-token",
];

/// 客户端可伪造的代理链 IP 头：原版不转发客户端提供的这两个头（观测
/// p1-cfg-client-ip-headers：上游只有 TCP 对端 IP 写入的 `x-chatgpt-mirror-client-ip`，
/// 客户端的 X-Real-IP/X-Forwarded-For 均未出现；见 evidence/proxy-v3-audit.json 第 2 项）。
/// 非逐跳头，单独成列，不并入 [`REQUEST_HOP_BY_HOP`]。
const CLIENT_PROXY_IP_HEADERS: [&str; 2] = ["x-real-ip", "x-forwarded-for"];

/// 响应方向需要过滤的逐跳头；`content-length` 由本层按实际正文重算（流式响应不设，
/// 由 HTTP 栈用分块传输），`transfer-encoding` 一律不复制（任务硬要求）。
const RESPONSE_HOP_BY_HOP: [&str; 9] = [
    "connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
];

/// `/0x/*`、`/admin*` 的 django 透传入口（父路由 handler 替换点）。
pub(super) async fn django_proxy(
    State(app): State<Shared>,
    peer: Option<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let client_ip = peer.map(|ConnectInfo(address)| address.ip());
    match django_forward(&app, request, client_ip).await {
        Ok(response) => response,
        Err(failure) => error(StatusCode::BAD_GATEWAY, &failure.to_string()).into_response(),
    }
}

/// chat 代理入口（父 `fallback` handler 替换点）：仅放行已观测的读取路由，
/// 未确证路径继续以 503 门禁失败，不做整体直通。
pub(super) async fn chat_proxy(State(app): State<Shared>, request: Request) -> Response {
    // 缺失能力必须保持失败，不能用旧二进制回退或伪造成功响应。
    if request.uri().path().starts_with("/api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(token) = token_from(request.headers()) else {
        return error(StatusCode::UNAUTHORIZED, "未登录").into_response();
    };
    // 复用父 session()：mirror profile 下仍执行 Django 签名授权校验与撤销判定。
    let session = match session(&app, &token).await {
        Ok(Some(value)) => value,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "未登录").into_response(),
        Err(failure) => {
            return error(StatusCode::BAD_GATEWAY, &failure.to_string()).into_response()
        }
    };
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let result = if method == Method::GET && path == ME_PATH {
        me_passthrough(&app, request, &session).await
    } else if method == Method::GET && path == CONVERSATIONS_PATH {
        conversations_response(&app, request, &session).await
    } else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "聊天代理兼容门禁尚未通过，候选制品未启用此路径",
        )
        .into_response();
    };
    match result {
        Ok(response) => response,
        Err(failure) => error(StatusCode::BAD_GATEWAY, &failure.to_string()).into_response(),
    }
}

/// `/0x/*` 透传：附加 TCP 对端 IP 头；不转发任何客户端凭据头（观测无 authorization）。
async fn django_forward(
    app: &App,
    request: Request,
    client_ip: Option<IpAddr>,
) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let mut base = app.config.django.clone();
    base.set_path(parts.uri.path());
    base.set_query(parts.uri.query());
    let data = to_bytes(body, MAX_BODY).await.context("请求体读取失败")?;
    let mut headers = strip_request_hop_by_hop(&parts.headers)?;
    if let Some(ip) = client_ip {
        headers.insert(
            "x-chatgpt-mirror-client-ip",
            HeaderValue::from_str(&ip.to_string()).context("客户端 IP 头无效")?,
        );
    }
    let upstream =
        send_upstream_with_headers(app, parts.method, headers, base, data, None, &[]).await?;
    stream_response(upstream).await
}

/// `/backend-api/me`：会话解析后按原始字节回传，不做 JSON 重序列化。
async fn me_passthrough(app: &App, request: Request, session: &Session) -> Result<Response> {
    let credentials = load_credentials(app, session).await?;
    let (parts, body) = request.into_parts();
    let mut base = app.config.upstream.clone();
    base.set_path(parts.uri.path());
    base.set_query(parts.uri.query());
    let data = to_bytes(body, MAX_BODY).await.context("请求体读取失败")?;
    let upstream =
        send_upstream(app, parts.method, parts.headers, base, data, &credentials).await?;
    buffered_response(app, session, upstream).await
}

/// `/backend-api/conversations`：归属过滤 + 分页/总数语义（观测见模块注释）。
async fn conversations_response(
    app: &App,
    request: Request,
    session: &Session,
) -> Result<Response> {
    let credentials = load_credentials(app, session).await?;
    let (parts, body) = request.into_parts();
    let mut base = app.config.upstream.clone();
    base.set_path(parts.uri.path());
    base.set_query(parts.uri.query());
    let data = to_bytes(body, MAX_BODY).await.context("请求体读取失败")?;
    let upstream =
        send_upstream(app, parts.method, parts.headers, base, data, &credentials).await?;
    let (status, headers, body) = upstream_parts(upstream);
    let raw = to_bytes(body, usize::MAX)
        .await
        .context("上游响应读取失败")?;
    let payload = if status.is_success() {
        match serde_json::from_slice::<Value>(&raw) {
            Ok(value) => {
                let db = app.db.lock().await;
                let total: i64 = db.conn.query_row(
                    "SELECT count(*) FROM conversation_owners WHERE chatgpt_username=?1 AND user_name=?2",
                    params![session.account, session.user],
                    |row| row.get(0),
                )?;
                let rebuilt = rebuild_conversations(
                    value,
                    &mut |conversation_id| {
                        let found: i64 = db.conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM conversation_owners WHERE chatgpt_username=?1 AND conversation_id=?2 AND user_name=?3)",
                        params![session.account, conversation_id, session.user],
                        |row| row.get(0),
                    )?;
                        Ok(found != 0)
                    },
                    total,
                )?;
                drop(db);
                rebuilt
            }
            // 上游 2xx 但正文不是 JSON：原版同样回落为空列表信封（状态码保留）。
            Err(_) => json!({"items": [], "total": 0}),
        }
    } else {
        json!({"items": [], "total": 0})
    };
    let body = serde_json::to_vec(&payload).context("会话列表序列化失败")?;
    let body = inject_client_resource(app, session, &headers, body).await?;
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = strip_response_hop_by_hop(&headers);
    mark_proxied(&mut response);
    Ok(response)
}

/// 会话凭据：已校验会话（mirror_token → (user, account)）对应的上游 access_token
/// 与 extra_cookies；镜像 token 本身绝不转发上游。
struct SessionCredentials {
    access_token: String,
    cookies: Vec<(String, String)>,
}

async fn load_credentials(app: &App, session: &Session) -> Result<SessionCredentials> {
    let db = app.db.lock().await;
    let (access_token, extra_cookies): (String, String) = db.conn.query_row(
        "SELECT access_token, extra_cookies FROM gateway_sessions WHERE user_name=?1 AND chatgpt_username=?2",
        params![session.user, session.account],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let access_token = db.decrypt(&access_token)?;
    let extra_cookies = db.decrypt(&extra_cookies)?;
    Ok(SessionCredentials {
        access_token,
        cookies: parse_extra_cookies(&extra_cookies),
    })
}

/// 会话行 extra_cookies 解析：仅取 name/value 均为非空字符串的条目
/// （原版以序列结构存储；损坏条目跳过，避免带出无效 Cookie 头）。
fn parse_extra_cookies(raw: &str) -> Vec<(String, String)> {
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?.trim();
            let value = entry.get("value")?.as_str()?;
            (!name.is_empty() && !value.is_empty()).then(|| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

/// 进程内 CF 缓存中名为 `cf_clearance` 的条目；
/// 观测：旁站返回多个 cookie 时原版只取 cf_clearance（proxy-v3-original-006）。
fn cf_clearance_from(cache: &Value) -> Option<String> {
    let entries = cache.get("cookies")?.as_array()?;
    let mut pairs = Vec::new();
    for entry in entries {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = entry.get("value").and_then(Value::as_str) else {
            continue;
        };
        if name == "cf_clearance" && !value.is_empty() {
            pairs.push(format!("{name}={value}"));
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.join("; "))
    }
}

/// 上游 Cookie：会话 extra_cookies 在前、CF clearance 在后（观测顺序
/// `probe_extra=EV; cf_clearance=SYNTHETIC`）。
fn cookie_header(cookies: &[(String, String)], cf_clearance: Option<&str>) -> Option<String> {
    let mut pairs: Vec<String> = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    if let Some(cf_clearance) = cf_clearance {
        pairs.push(cf_clearance.to_owned());
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.join("; "))
    }
}

/// chat 上游的 origin 固定为 `scheme://host`（去端口；观测 http://127.0.0.1），
/// referer 为其加 `/`；客户端自带的同名字段一律覆盖。
fn chat_origin(base: &url::Url) -> Result<String> {
    let host = base.host_str().context("上游地址缺少主机名")?;
    Ok(format!("{}://{}", base.scheme(), host))
}

/// 请求头预处理：逐跳头 + `connection` 命名头 + 凭据头 + 客户端代理链 IP 头移除，
/// UA/accept 按观测补齐。
fn strip_request_hop_by_hop(headers: &HeaderMap) -> Result<HeaderMap> {
    let connection_tokens: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_lowercase())
        .collect();
    let mut headers = headers.clone();
    for name in REQUEST_HOP_BY_HOP {
        headers.remove(name);
    }
    for name in CLIENT_PROXY_IP_HEADERS {
        headers.remove(name);
    }
    for token in connection_tokens {
        headers.remove(token.as_str());
    }
    headers.insert("user-agent", HeaderValue::from_static(DEFAULT_USER_AGENT));
    if !headers.contains_key("accept") {
        headers.insert("accept", HeaderValue::from_static("*/*"));
    }
    Ok(headers)
}

/// 响应头预处理：逐跳头 + `connection` 命名头移除（content-length/transfer-encoding
/// 一律不复制，由本层或 HTTP 栈生成）。
fn strip_response_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let connection_tokens: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_lowercase())
        .collect();
    let mut headers = headers.clone();
    for token in connection_tokens {
        headers.remove(token.as_str());
    }
    for name in RESPONSE_HOP_BY_HOP {
        headers.remove(name);
    }
    headers
}

/// 标记代理响应：父中间件据此合并 `Cookie, Authorization`、补固定 CSP 与私有缓存
/// （标记同时把代理响应纳入 private 分支，覆盖 text/html/image 等非 JSON 正文）。
fn mark_proxied(response: &mut Response) {
    response.extensions_mut().insert(ProxiedResponse);
}

/// 发送上游请求：头处理 + 凭据/CF cookie 注入 + 固定 chat 头。
/// chat 路径覆盖 origin/referer，django 路径使用独立入口。
/// 客户端 IP 头由 django 路径在调用前自行写入（chat 路径观测无此头）。
async fn send_upstream(
    app: &App,
    method: Method,
    client_headers: HeaderMap,
    base: url::Url,
    body: Bytes,
    credentials: &SessionCredentials,
) -> Result<reqwest::Response> {
    let mut headers = strip_request_hop_by_hop(&client_headers)?;
    headers.remove("authorization");
    let origin = chat_origin(&base)?;
    headers.insert(
        "origin",
        HeaderValue::from_str(&origin).context("origin 头无效")?,
    );
    headers.insert(
        "referer",
        HeaderValue::from_str(&format!("{origin}/")).context("referer 头无效")?,
    );
    send_upstream_with_headers(
        app,
        method,
        headers,
        base,
        body,
        Some(&credentials.access_token),
        &credentials.cookies,
    )
    .await
}

/// 头处理完成后的发送步骤：附加 CF cookie / 会话 cookie 与 bearer 凭据。
async fn send_upstream_with_headers(
    app: &App,
    method: Method,
    mut headers: HeaderMap,
    base: url::Url,
    body: Bytes,
    bearer: Option<&str>,
    session_cookies: &[(String, String)],
) -> Result<reqwest::Response> {
    let cached = app.cf_cache.lock().await.clone();
    let cf_clearance = cached.as_ref().and_then(cf_clearance_from);
    if let Some(cookie) = cookie_header(session_cookies, cf_clearance.as_deref()) {
        headers.insert(
            "cookie",
            HeaderValue::from_str(&cookie).context("Cookie 头无效")?,
        );
    }
    if let Some(token) = bearer {
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).context("上游凭据头无效")?,
        );
    }
    app.client
        .request(method, base)
        .headers(headers)
        .body(body)
        .send()
        .await
        .context("上游请求失败")
}

/// 流式回传（django 路径）：不复制 content-length，由 HTTP 栈分块。
async fn stream_response(upstream: reqwest::Response) -> Result<Response> {
    let (status, headers, body) = upstream_parts(upstream);
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = strip_response_hop_by_hop(&headers);
    mark_proxied(&mut response);
    Ok(response)
}

/// 缓冲回传（chat 路径）：状态码与端到端头保留，正文按原始字节返回，
/// content-length 由实际字节数重算。
async fn buffered_response(
    app: &App,
    session: &Session,
    upstream: reqwest::Response,
) -> Result<Response> {
    let (status, headers, body) = upstream_parts(upstream);
    let data = to_bytes(body, usize::MAX)
        .await
        .context("上游响应读取失败")?;
    let data = inject_client_resource(app, session, &headers, data.to_vec()).await?;
    let mut response = Response::new(Body::from(data));
    *response.status_mut() = status;
    *response.headers_mut() = strip_response_hop_by_hop(&headers);
    mark_proxied(&mut response);
    Ok(response)
}

async fn inject_client_resource(
    app: &App,
    session: &Session,
    headers: &HeaderMap,
    mut body: Vec<u8>,
) -> Result<Vec<u8>> {
    if !headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"))
    {
        return Ok(body);
    }
    let force: bool = app.db.lock().await.conn.query_row(
        "SELECT force_chat_mode FROM gateway_sessions WHERE user_name=?1 AND chatgpt_username=?2",
        params![session.user, session.account],
        |row| row.get(0),
    )?;
    let blocked = blocked_value(app).await?;
    let mut hosts: std::collections::BTreeSet<String> =
        serde_json::from_str(include_str!("../assets/gateway-client-hosts.json"))
            .expect("内置主机表必须是合法 JSON");
    hosts.insert(
        app.config
            .upstream
            .host_str()
            .context("上游缺少主机名")?
            .to_owned(),
    );
    let blocked = serde_json::to_string(&blocked["paths"])?;
    let hosts = serde_json::to_string(&hosts)?;
    // 管理员配置字符串不能结束 script 元素；数值/布尔不经字符串拼接构造脚本。
    let resource = include_str!("../assets/gateway-client.html")
        .replacen("@@FORCE_CHAT@@", if force { "true" } else { "false" }, 1)
        .replacen("@@INTERNAL_HOSTS@@", &hosts.replace('<', "\\u003c"), 1)
        .replacen("@@BLOCKED_PATHS@@", &blocked.replace('<', "\\u003c"), 1);
    body.extend_from_slice(resource.as_bytes());
    Ok(body)
}

fn upstream_parts(upstream: reqwest::Response) -> (StatusCode, HeaderMap, Body) {
    let status = upstream.status();
    let mut headers = strip_response_hop_by_hop(upstream.headers());
    let body = Body::from_stream(upstream.bytes_stream().map_err(std::io::Error::other));
    let body = compression::decode_upstream(body, &mut headers);
    (status, headers, body)
}

/// 会话列表重建：`items` 为数组时按归属过滤并替换 `total`（其余键保留）；
/// 其它形态回落为空信封（观测：无 items 键的 200 响应与不可解析正文同为此形）。
fn rebuild_conversations(
    payload: Value,
    is_owned: &mut dyn FnMut(&str) -> Result<bool>,
    total: i64,
) -> Result<Value> {
    match payload {
        Value::Object(mut object) if object.get("items").map(Value::is_array).unwrap_or(false) => {
            let items = object
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut kept = Vec::with_capacity(items.len());
            for item in items {
                // 无字符串 id 的条目无法映射归属（原版同样不出现在结果中）。
                let Some(conversation_id) =
                    item.get("id").and_then(Value::as_str).map(str::to_owned)
                else {
                    continue;
                };
                if is_owned(&conversation_id)? {
                    // 重复条目不去重（观测 p2-dup-alice）。
                    kept.push(item);
                }
            }
            object.insert("items".into(), Value::Array(kept));
            object.insert("total".into(), json!(total));
            Ok(Value::Object(object))
        }
        _ => Ok(json!({"items": [], "total": 0})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_set(ids: &[&str]) -> std::collections::HashSet<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    #[test]
    fn conversations_filter_keeps_scope_and_extra_keys() {
        let payload = json!({
            "items": [
                {"id": "conv-1", "title": "one"},
                {"id": "conv-2", "title": "two"},
                {"id": "conv-2", "title": "two-dup"},
                {"title": "no-id"}
            ],
            "total": 5,
            "limit": 20,
            "offset": 0,
            "cursor": "abc"
        });
        let owned = owned_set(&["conv-2"]);
        let mut lookup = |id: &str| -> Result<bool> { Ok(owned.contains(id)) };
        let result = rebuild_conversations(payload, &mut lookup, 2).expect("重建失败");
        assert_eq!(
            result,
            json!({"cursor": "abc", "items": [
                {"id": "conv-2", "title": "two"},
                {"id": "conv-2", "title": "two-dup"}
            ], "limit": 20, "offset": 0, "total": 2})
        );
    }

    #[test]
    fn conversations_without_items_fall_back_to_empty_envelope() {
        let payload = json!({"stub": true, "path": "/backend-api/conversations"});
        let mut lookup = |_: &str| -> Result<bool> { Ok(true) };
        let result = rebuild_conversations(payload, &mut lookup, 9).expect("重建失败");
        assert_eq!(result, json!({"items": [], "total": 0}));
        let array_root = json!([1, 2, 3]);
        let result = rebuild_conversations(array_root, &mut lookup, 9).expect("重建失败");
        assert_eq!(result, json!({"items": [], "total": 0}));
        let items_not_array = json!({"items": 5, "total": 9});
        let result = rebuild_conversations(items_not_array, &mut lookup, 9).expect("重建失败");
        assert_eq!(result, json!({"items": [], "total": 0}));
    }

    #[test]
    fn cf_clearance_prefers_named_cookie_and_joins() {
        let cache = json!({"cookies": [
            {"name": "cf_probe", "value": "EXTRA1", "domain": "127.0.0.1"},
            {"name": "cf_clearance", "value": "SYNTHETIC", "domain": "127.0.0.1"}
        ]});
        assert_eq!(
            cf_clearance_from(&cache).as_deref(),
            Some("cf_clearance=SYNTHETIC")
        );
        let empty = json!({"cookies": [{"name": "cf_clearance", "value": ""}]});
        assert_eq!(cf_clearance_from(&empty), None);
        assert_eq!(cf_clearance_from(&json!({})), None);
    }

    #[test]
    fn cookie_header_order_and_extra_cookie_parsing() {
        let session = vec![("probe_extra".to_owned(), "EV".to_owned())];
        assert_eq!(
            cookie_header(&session, Some("cf_clearance=SYNTHETIC")).as_deref(),
            Some("probe_extra=EV; cf_clearance=SYNTHETIC")
        );
        assert_eq!(cookie_header(&[], None), None);
        let parsed = parse_extra_cookies(
            r#"[{"name":"a","value":"1"},{"name":"","value":"2"},{"name":"b","value":""},{"x":1}]"#,
        );
        assert_eq!(parsed, vec![("a".to_owned(), "1".to_owned())]);
        assert!(parse_extra_cookies("not-json").is_empty());
    }

    #[test]
    fn chat_origin_drops_port_and_referer_appends_slash() {
        let base = url::Url::parse("http://127.0.0.1:18090/").expect("URL 无效");
        let origin = chat_origin(&base).expect("origin 失败");
        assert_eq!(origin, "http://127.0.0.1");
        assert_eq!(format!("{origin}/"), "http://127.0.0.1/");
    }

    #[test]
    fn request_headers_drop_credentials_and_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("x-conn-token"));
        headers.append("connection", HeaderValue::from_static("x-second-hop"));
        headers.insert("x-second-hop", HeaderValue::from_static("drop-too"));
        headers.insert("x-conn-token", HeaderValue::from_static("drop-me"));
        headers.insert("cookie", HeaderValue::from_static("mirror_token=secret"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer mirrortoken"),
        );
        headers.insert("x-mirror-token", HeaderValue::from_static("secret"));
        headers.insert("accept-language", HeaderValue::from_static("zh-CN"));
        let filtered = strip_request_hop_by_hop(&headers).expect("过滤失败");
        assert!(!filtered.contains_key("x-conn-token"));
        assert!(!filtered.contains_key("cookie"));
        assert_eq!(filtered["authorization"], "Bearer mirrortoken");
        assert!(!filtered.contains_key("x-second-hop"));
        assert!(!filtered.contains_key("x-mirror-token"));
        assert_eq!(
            filtered.get("accept-language").map(|v| v.to_str().unwrap()),
            Some("zh-CN")
        );
        assert_eq!(
            filtered.get("user-agent").map(|v| v.to_str().unwrap()),
            Some(DEFAULT_USER_AGENT)
        );
        assert_eq!(
            filtered.get("accept").map(|v| v.to_str().unwrap()),
            Some("*/*")
        );
    }

    #[test]
    fn request_headers_drop_client_proxy_ip_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        headers.insert("x-e2e-keep", HeaderValue::from_static("keep-me"));
        let filtered = strip_request_hop_by_hop(&headers).expect("过滤失败");
        assert!(!filtered.contains_key("x-real-ip"));
        assert!(!filtered.contains_key("x-forwarded-for"));
        assert_eq!(
            filtered.get("x-e2e-keep").map(|v| v.to_str().unwrap()),
            Some("keep-me")
        );
    }

    #[test]
    fn response_headers_drop_transfer_encoding_and_mark_proxied() {
        let mut headers = HeaderMap::new();
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-length", HeaderValue::from_static("65"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let mut response = Response::new(Body::empty());
        *response.headers_mut() = strip_response_hop_by_hop(&headers);
        mark_proxied(&mut response);
        assert!(!response.headers().contains_key("transfer-encoding"));
        assert!(!response.headers().contains_key("content-length"));
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap()),
            Some("application/json")
        );
        assert!(!response.headers().contains_key("vary"));
        assert!(response.extensions().get::<ProxiedResponse>().is_some());
    }
}

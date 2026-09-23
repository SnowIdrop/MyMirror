// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/proxy.rs
// Created : 2026-09-22
// Summary : 聊天/管理代理会话子模块：/0x/*（django 透传）、已登录业务面
//           `/backend-api/*`（读写，含 me 与 conversations 的既有语义）、
//           公共前缀策略（server/public_prefixes.rs）、会话归属
//           （server/owners.rs）与 WebSocket 桥接（server/chat_ws.rs）。
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
//!   `cookie` 只用 会话 extra_cookies + CF 状态里的白名单 cookies（客户端 cookie 丢弃）；
//!   相比原版“只补 cf_clearance”，替代网关补整组白名单并支持挑战后重放一次，
//!   见 server/cloudflare.rs 的模块注释；chat 路径额外固定 origin/referer
//!   （scheme://host 去端口）。
//! - `/0x/*`：任意方法透传，流式响应（无 content-length，由 HTTP 栈分块）。
//! - `/backend-api/*`：放行读写与 SSE，方法语义交给上游；会话作用域路径与
//!   `POST …/conversation` 的续聊载荷在转发前做归属判定（server/owners.rs），
//!   创建响应在把含会话 id 的块交给客户端前登记归属。
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

/// 匿名通道与公共接口前缀（原版路由表：`/backend-anon/*` 为匿名通道，
/// `/public-api/`、`/ces/`、`/sentinel/`、`/cdn-cgi/` 为公共/遥测/挑战路径）。
/// 未登录页面只用这些前缀，因此本阶段放行它们；其余业务路径继续关闭。
const CHAT_OPEN_PREFIXES: [&str; 5] = [
    "/backend-anon/",
    "/public-api/",
    "/ces/",
    "/cdn-cgi/",
    "/sentinel/",
];

/// 匿名访客会话自身的路由：实测未登录站点在首页输入后跳转到 `/uc/<uuid>`
/// （聊天记录页）并从 `/unauth-mweb/assets/*` 取会话前端资源。
/// 两者都由上游源站提供，因此与页面路由一起放行。
const GUEST_OPEN_PREFIXES: [&str; 2] = ["/uc/", "/unauth-mweb/"];

/// 已知内部上游主机的同源媒体代理前缀：注入脚本把白名单主机改写为
/// `/internal-upstream/<scheme>/<host>/<path>`（见 assets/gateway-client.html）。
const INTERNAL_UPSTREAM_PREFIX: &str = "/internal-upstream/";

/// 会按分片轮换主机名的上游族：签名上传地址实测从 `files.oaiusercontent.com`
/// 变为 `files09.oaiusercontent.com`，精确主机表无法覆盖。地址本身带签名
/// （查询串中的 `sig`），且转发不带任何凭据，因此按域名后缀放行该族。
/// 同一份常量会注入客户端脚本（`@@INTERNAL_HOST_SUFFIXES@@`）。
const INTERNAL_UPSTREAM_SUFFIXES: [&str; 1] = [".oaiusercontent.com"];

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

/// chat 代理入口（父 `fallback` handler 替换点）：放行页面 `/`、`/c/*`，
/// 公共前缀策略（server/public_prefixes.rs）、匿名/公共接口前缀、白名单主机
/// 媒体代理、已登录业务面读写与实时通道，以及既有两条只读会话端点；
/// 其余路径继续以 503 门禁失败，不做整体直通。
pub(super) async fn chat_proxy(State(app): State<Shared>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    if path.starts_with("/assets/") || path.starts_with("/cdn/") {
        return super::static_assets::serve(&app, request).await;
    }
    // 注入脚本改写出去的公共静态/媒体前缀：与 `/assets/`、`/cdn/` 同属同源公共
    // 资源，不需要镜像会话，也一律不带账号凭据。
    let route = public_prefixes::resolve(&app.config, &path, request.uri().query());
    if let Some(route @ public_prefixes::Route::Proxy(_)) = route {
        return public_prefixes::answer(&app, request, route).await;
    }
    // 有意不代理的前缀保留既有门禁顺序：未登录仍先 401，已登录才给 503 文案。
    let refusal = match route {
        Some(public_prefixes::Route::Refused(message)) => Some(message),
        _ => None,
    };
    // 缺失能力必须保持失败，不能用旧二进制回退或伪造成功响应。
    if path.starts_with("/api/") {
        return error(StatusCode::NOT_FOUND, "本地未实现的 /api 路径").into_response();
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
    if let Some(message) = refusal {
        return error(StatusCode::SERVICE_UNAVAILABLE, message).into_response();
    }
    // 实时通道的 WebSocket 升级尚未实现：显式拒绝，而不是把升级请求当普通 GET 转发。
    let upgrades = request
        .headers()
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if upgrades && (path == "/realtime" || path.starts_with("/realtime/")) {
        return error(StatusCode::SERVICE_UNAVAILABLE, "实时通道升级未开放").into_response();
    }
    let method = request.method().clone();
    let result = if method == Method::GET && path == ME_PATH {
        me_passthrough(&app, request, &session).await
    } else if method == Method::GET && path == CONVERSATIONS_PATH {
        conversations_response(&app, request, &session).await
    } else if let Some(target) = internal_upstream_target(&path, request.uri().query()) {
        // 媒体代理只放行白名单主机，且从不携带账号凭据。
        if media_method_allowed(&method) {
            Ok(super::static_assets::media(&app, request, target).await)
        } else {
            Ok(method_not_allowed(super::static_assets::MEDIA_ALLOW))
        }
    } else if open_path(&path, &method) {
        chat_forward(app.clone(), request, &session).await
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

/// 本阶段放行判定：页面与匿名/公共接口前缀转发上游；媒体代理与既有两条只读
/// 会话端点在上面的分支里单独判定；其余路径继续 503 门禁。
fn open_path(path: &str, method: &Method) -> bool {
    if path == "/" || path.starts_with("/c/") {
        return matches!(*method, Method::GET | Method::HEAD);
    }
    // 已登录业务面与实时通道：方法语义交给上游，会话作用域的归属判定由
    // server/owners.rs 在转发前完成。
    if path.starts_with("/backend-api/") || path == "/realtime" || path.starts_with("/realtime/") {
        return true;
    }
    if GUEST_OPEN_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return true;
    }
    CHAT_OPEN_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// `/internal-upstream/<scheme>/<host>/<path>` → 上游绝对地址。
/// 只接受 https，且主机必须命中内置主机表（assets/gateway-client-hosts.json）
/// 或 [`INTERNAL_UPSTREAM_SUFFIXES`] 中的域名族，因此客户端不能借它选择任意目标。
fn internal_upstream_target(path: &str, query: Option<&str>) -> Option<url::Url> {
    let rest = path.strip_prefix(INTERNAL_UPSTREAM_PREFIX)?;
    let (scheme, rest) = rest.split_once('/')?;
    if scheme != "https" {
        return None;
    }
    // 注入脚本总是带上 `url.pathname`（至少为 `/`），因此这里要求显式分隔符，
    // 不接受“主机名后直接结束”的形态。
    let (host, tail) = rest.split_once('/')?;
    let hosts: std::collections::BTreeSet<String> =
        serde_json::from_str(include_str!("../assets/gateway-client-hosts.json")).ok()?;
    if !internal_upstream_host_allowed(host, &hosts) {
        return None;
    }
    let mut target = url::Url::parse(&format!("https://{host}/{tail}")).ok()?;
    target.set_query(query);
    Some(target)
}

fn internal_upstream_host_allowed(host: &str, hosts: &std::collections::BTreeSet<String>) -> bool {
    hosts.contains(host)
        || INTERNAL_UPSTREAM_SUFFIXES
            .iter()
            .any(|suffix| host.len() > suffix.len() && host.ends_with(suffix))
}

/// 方法门禁响应：带 `allow` 头的 405（静态与内部媒体前缀共用）。
pub(super) fn method_not_allowed(allow: &'static str) -> Response {
    let mut response = error(StatusCode::METHOD_NOT_ALLOWED, "该路径不支持此方法").into_response();
    response
        .headers_mut()
        .insert("allow", HeaderValue::from_static(allow));
    response
}

/// 内部上游媒体代理的方法门禁：GET/HEAD 读取，PUT 用于匿名上传的
/// Azure blob create-write 步骤（2026-09-23 实测 `POST /backend-anon/files` 返回
/// 带 `sp=cw` 的签名地址，对其 PUT 返回 201）。签名在查询串里自证，不依赖 Cookie。
fn media_method_allowed(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::PUT)
}

/// 页面与匿名/公共接口转发：带凭据会话用账号凭据，匿名会话用全局共享匿名身份；
/// HTML 响应缓冲后注入同源客户端资源，其余响应（含 SSE/媒体）流式回传。
/// 已登录业务面的会话作用域请求先做归属判定，创建响应在交给客户端前登记归属。
async fn chat_forward(app: Shared, request: Request, session: &Session) -> Result<Response> {
    let Some(auth) = chat_auth(&app, session).await? else {
        return Ok(error(StatusCode::UNAUTHORIZED, "会话或出口绑定已失效").into_response());
    };
    let (parts, body) = request.into_parts();
    let request_path = parts.uri.path().to_owned();
    let mut base = app.config.upstream.clone();
    base.set_path(&request_path);
    base.set_query(parts.uri.query());
    let data = to_bytes(body, MAX_BODY).await.context("请求体读取失败")?;
    // 共享账号下唯一的内容级边界：会话作用域与续聊写路径必须命中本用户的登记行，
    // 未知归属（含本批之前创建的会话）一律拒绝，且不接触上游。
    let ownership = owners::classify(&request_path, &parts.method, &data);
    if let owners::Ownership::Existing(conversation_id) = &ownership {
        if !owners::owned_by(&app, session, conversation_id).await? {
            return Ok(owners::refusal());
        }
    }
    // Cloudflare 挑战的刷新/重放与缓存失效统一在 [`send_chat`] 内处理；这里只分流响应形态。
    // 其它 4xx 是上游对具体请求的业务答复（实测 401 由客户端缺少 oai-* 头导致），
    // 重新获取身份并不能修复。
    let upstream = send_chat(&app, parts.method, parts.headers, base, data, &auth).await?;
    if is_html(&upstream) {
        buffered_response(&app, session, upstream).await
    } else if matches!(ownership, owners::Ownership::Creation) {
        let (status, headers, body) = upstream_parts(upstream);
        // 创建响应：先把正文里出现的会话 id 登记归属，再把该块交给客户端；
        // 非 2xx 没有新会话可登记，按原样回传。
        let body = if status.is_success() {
            owners::creation_body(app, session, request_path, body)
        } else {
            body
        };
        Ok(stream_body(status, headers, body))
    } else {
        stream_response(upstream).await
    }
}

fn is_html(upstream: &reqwest::Response) -> bool {
    upstream
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"))
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
        send_upstream_with_headers(app, parts.method, headers, base, data, None).await?;
    stream_response(upstream).await
}

/// `/backend-api/me`：会话解析后按原始字节回传，不做 JSON 重序列化。
async fn me_passthrough(app: &App, request: Request, session: &Session) -> Result<Response> {
    let Some(auth) = chat_auth(app, session).await? else {
        return Ok(error(StatusCode::UNAUTHORIZED, "会话或出口绑定已失效").into_response());
    };
    let (parts, body) = request.into_parts();
    let mut base = app.config.upstream.clone();
    base.set_path(parts.uri.path());
    base.set_query(parts.uri.query());
    let data = to_bytes(body, MAX_BODY).await.context("请求体读取失败")?;
    let upstream = send_chat(app, parts.method, parts.headers, base, data, &auth).await?;
    buffered_response(app, session, upstream).await
}

/// `/backend-api/conversations`：归属过滤 + 分页/总数语义（观测见模块注释）。
async fn conversations_response(
    app: &App,
    request: Request,
    session: &Session,
) -> Result<Response> {
    let Some(auth) = chat_auth(app, session).await? else {
        return Ok(error(StatusCode::UNAUTHORIZED, "会话或出口绑定已失效").into_response());
    };
    let (parts, body) = request.into_parts();
    let mut base = app.config.upstream.clone();
    base.set_path(parts.uri.path());
    base.set_query(parts.uri.query());
    let data = to_bytes(body, MAX_BODY).await.context("请求体读取失败")?;
    let upstream = send_chat(app, parts.method, parts.headers, base, data, &auth).await?;
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
    let (body, headers) = inject_client_resource(app, session, headers, body).await?;
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = strip_response_hop_by_hop(&headers);
    mark_proxied(&mut response);
    Ok(response)
}

/// 上游认证材料。带凭据会话用账号 access_token + extra_cookies；
/// 匿名会话用全局共享匿名身份（server/anonymous.rs）。
/// 镜像 token 本身绝不转发上游。
pub(super) struct ChatAuth {
    pub(super) access_token: Option<String>,
    pub(super) cookies: Vec<(String, String)>,
    pub(super) anonymous: bool,
    client: reqwest::Client,
}

/// 会话对应的上游认证材料：匿名会话取共享匿名身份，其余取账号凭据。
/// 匿名身份取不到时返回“无凭据匿名”材料，让上游给出真实答复而不是本地伪造。
pub(super) async fn chat_auth(app: &App, session: &Session) -> Result<Option<ChatAuth>> {
    if session.anonymous {
        // 匿名链路以 Cloudflare cookies 为唯一凭据：accessToken 只属于真实账号登录，
        // 实测匿名 `/api/auth/session` 返回 200 但不含该字段。
        let cookies = anonymous::ensure(app)
            .await
            .map(|identity| identity.cookies)
            .unwrap_or_default();
        return Ok(Some(ChatAuth {
            access_token: None,
            cookies,
            anonymous: true,
            client: session.outbound.client.clone(),
        }));
    }
    load_credentials(app, session).await
}

/// Observed auth/session refresh: accounts/check followed by me on every call.
/// Snapshot only this token's credentials; never hold SQLite across upstream IO.
pub(super) async fn refresh_auth_session(
    app: &App,
    session: &Session,
    token: &str,
) -> Result<Option<(String, String)>> {
    let (auth, mode) = {
        let db = app.db.lock().await;
        let row: Option<(String, String, String)> = db.conn.query_row(
            "SELECT access_token,extra_cookies,login_mode FROM gateway_sessions WHERE user_name=?1 AND chatgpt_username=?2 AND mirror_token=?3",
            params![session.user, session.account, sha256_hex(token)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let Some((access, cookies, mode)) = row else {
            return Ok(None);
        };
        let access_token = db.decrypt(&access)?;
        let raw_cookies = db.decrypt(&cookies)?;
        if sha256_hex(&json!([session.account,access_token,raw_cookies]).to_string()) != session.credential_binding {
            return Ok(None);
        }
        (ChatAuth {
            access_token: Some(access_token),
            cookies: parse_extra_cookies(&raw_cookies),
            anonymous: false,
            client: session.outbound.client.clone(),
        }, mode)
    };
    let accounts = send_chat(
        app, Method::GET, HeaderMap::new(),
        app.config.upstream.join("/backend-api/accounts/check/v4-2023-04-27")?,
        Bytes::new(), &auth,
    ).await?;
    // A failed plan lookup still refreshes me and displays free (observed fixture).
    let plan = if accounts.status().is_success() {
        let raw = to_bytes(upstream_parts(accounts).2, MAX_BODY).await?;
        let value: Value = serde_json::from_slice(&raw)?;
        value["accounts"]["default"]["account"]["plan_type"]
            .as_str().filter(|plan| !plan.is_empty()).unwrap_or("free").to_owned()
    } else {
        "free".to_owned()
    };
    let user = send_chat(
        app, Method::GET, HeaderMap::new(), app.config.upstream.join(ME_PATH)?,
        Bytes::new(), &auth,
    ).await?;
    let answer = cloudflare::read(user).await?;
    if !answer.status.is_success() {
        // 被 Cloudflare 拦截不等于会话已登出：按上游故障上抛，
        // 由 /api/auth/session 返回 502，避免前端把拦截当成登录失效。
        if answer.blocked() {
            return Err(cloudflare::blocked_error(
                "会话刷新失败",
                "backend-api/me",
                answer.status,
                None,
            )
            .into());
        }
        return Ok(None);
    }
    let user: Value = answer.json()?;
    // A refresh cannot rebind an existing resource/session to another account.
    if user["email"].as_str() != Some(session.account.as_str()) {
        return Ok(None);
    }
    Ok(Some((mode, plan)))
}

async fn load_credentials(app: &App, session: &Session) -> Result<Option<ChatAuth>> {
    let db = app.db.lock().await;
    let row: Option<(String, String, Option<i64>)> = db.conn.query_row(
        "SELECT access_token, extra_cookies, proxy_node_id FROM gateway_sessions WHERE user_name=?1 AND chatgpt_username=?2 AND mirror_token=?3",
        params![session.user, session.account, session.token_hash],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    let Some((access_token, extra_cookies, node)) = row else { return Ok(None); };
    if egress::binding(&db,&app.config,node)? != session.outbound.binding { return Ok(None); }
    let access_token = db.decrypt(&access_token)?;
    let extra_cookies = db.decrypt(&extra_cookies)?;
    if sha256_hex(&json!([session.account,access_token,extra_cookies]).to_string()) != session.credential_binding {
        return Ok(None);
    }
    Ok(Some(ChatAuth {
        access_token: Some(access_token),
        cookies: parse_extra_cookies(&extra_cookies),
        anonymous: false,
        client: session.outbound.client.clone(),
    }))
}

/// 会话行 extra_cookies 解析：仅取 name/value 均为非空字符串的条目
/// （原版以序列结构存储；损坏条目跳过，避免带出无效 Cookie 头）。
pub(super) fn parse_extra_cookies(raw: &str) -> Vec<(String, String)> {
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

/// chat 上游的 origin 固定为 `scheme://host`（去端口；观测 http://127.0.0.1），
/// referer 为其加 `/`；客户端自带的同名字段一律覆盖。
pub(super) fn chat_origin(base: &url::Url) -> Result<String> {
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

/// 发送上游请求（含 Cloudflare 挑战策略）：头处理 + 凭据/CF cookie 注入 +
/// 固定 chat 头 + Chrome146 身份补齐。chat 路径覆盖 origin/referer，django 路径
/// 使用独立入口；客户端 IP 头由 django 路径在调用前自行写入（chat 路径观测无此头）。
///
/// 命中实测 Cloudflare 挑战时：幂等 GET/HEAD 刷新一次 CF cookies 并重放一次；
/// 生成、SSE、上传等请求一律不重放（遵循“断线不得重发”），只失效缓存交给下一次请求。
async fn send_chat(
    app: &App,
    method: Method,
    client_headers: HeaderMap,
    base: url::Url,
    body: Bytes,
    auth: &ChatAuth,
) -> Result<reqwest::Response> {
    let generation = app.cloudflare.generation().await;
    let response =
        send_chat_once(app, &method, &client_headers, &base, &body, auth, &auth.cookies).await?;
    if !cloudflare::is_challenge(&response) {
        return Ok(response);
    }
    if !matches!(method, Method::GET | Method::HEAD) {
        // 本请求不重放：失效 CF 缓存（匿名会话同时失效持久化身份），
        // 由下一次请求重新走 cfbypass。
        app.cloudflare.invalidate().await;
        if auth.anonymous {
            anonymous::invalidate(app).await;
        }
        return Ok(response);
    }
    if !matches!(
        app.cloudflare.refresh_if_stale(app, generation).await,
        cloudflare::RefreshOutcome::Refreshed
    ) {
        return Ok(response);
    }
    // 匿名身份就是整组 Cloudflare cookies：刷新成功后用同一次结果重建身份再重放，
    // 不额外拉起第二次 cfbypass。
    let cookies = if auth.anonymous {
        // 并发的非 GET 挑战可能刚清空缓存，此时不做无凭据重放。
        let fresh = app.cloudflare.cookies().await;
        if fresh.is_empty() {
            return Ok(response);
        }
        anonymous::store(app, &fresh).await.cookies
    } else {
        auth.cookies.clone()
    };
    send_chat_once(app, &method, &client_headers, &base, &body, auth, &cookies).await
}

/// 单次上游发送；挑战重放与缓存失效策略见 [`send_chat`]。
async fn send_chat_once(
    app: &App,
    method: &Method,
    client_headers: &HeaderMap,
    base: &url::Url,
    body: &Bytes,
    auth: &ChatAuth,
    cookies: &[(String, String)],
) -> Result<reqwest::Response> {
    let mut headers = strip_request_hop_by_hop(client_headers)?;
    headers.remove("authorization");
    let origin = chat_origin(base)?;
    headers.insert(
        "origin",
        HeaderValue::from_str(&origin).context("origin 头无效")?,
    );
    headers.insert(
        "referer",
        HeaderValue::from_str(&format!("{origin}/")).context("referer 头无效")?,
    );
    apply_chrome_146_identity(&mut headers);
    // 匿名身份自带完整 Cloudflare cookie 组，不再叠加进程内 CF 缓存；
    // 带凭据会话按“会话 extra_cookies 在前、CF cookies 在后”合并。
    let cf = if auth.anonymous {
        Vec::new()
    } else {
        app.cloudflare.cookies().await
    };
    if let Some(cookie) = cloudflare::cookie_header(&[cookies, cf.as_slice()]) {
        headers.insert(
            "cookie",
            HeaderValue::from_str(&cookie).context("Cookie 头无效")?,
        );
    }
    if let Some(token) = auth.access_token.as_deref() {
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).context("上游凭据头无效")?,
        );
    }
    auth.client
        .request(method.clone(), base.clone())
        .headers(headers)
        .body(body.clone())
        .send()
        .await
        .context("上游请求失败")
}

/// 原版 Chrome146 网络身份（报告 08 §8.1 已确证字面量）：只补齐缺失的头，
/// 不覆盖客户端已发送的值（`apply_chrome_146_network_identity` 为 try_insert 链路）。
pub(super) fn apply_chrome_146_identity(headers: &mut HeaderMap) {
    for (name, value) in [
        ("sec-ch-ua", "\"Chromium\";v=\"146\", \"Not_A Brand\";v=\"99\""),
        ("sec-ch-ua-full-version", "\"146.0.7680.177\""),
        (
            "sec-ch-ua-full-version-list",
            "\"Chromium\";v=\"146.0.7680.177\", \"Not_A Brand\";v=\"99.0.0.0\"",
        ),
    ] {
        if !headers.contains_key(name) {
            headers.insert(
                name,
                HeaderValue::from_static(value),
            );
        }
    }
}

/// 头处理完成后的 Django 转发发送步骤：附加 CF cookie（无账号凭据）。
async fn send_upstream_with_headers(
    app: &App,
    method: Method,
    mut headers: HeaderMap,
    base: url::Url,
    body: Bytes,
    credentials: Option<&ChatAuth>,
) -> Result<reqwest::Response> {
    let cf = app.cloudflare.cookies().await;
    let session_cookies = credentials.map_or(&[][..], |value| value.cookies.as_slice());
    if let Some(cookie) = cloudflare::cookie_header(&[session_cookies, cf.as_slice()]) {
        headers.insert(
            "cookie",
            HeaderValue::from_str(&cookie).context("Cookie 头无效")?,
        );
    }
    if let Some(credentials) = credentials {
        if let Some(token) = credentials.access_token.as_deref() {
            headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {token}")).context("上游凭据头无效")?,
            );
        }
    }
    // Only the Django forwarding caller lacks account credentials. Chat always
    // uses the client captured with that exact token's egress binding.
    let client = credentials.map_or(&app.client, |value| &value.client);
    client
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
    Ok(stream_body(status, headers, body))
}

/// 流式响应组装：状态码与端到端头保留，正文由调用方提供（创建路径的归属包装）。
fn stream_body(status: StatusCode, headers: HeaderMap, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    mark_proxied(&mut response);
    response
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
    let (data, headers) = inject_client_resource(app, session, headers, data.to_vec()).await?;
    let mut response = Response::new(Body::from(data));
    *response.status_mut() = status;
    *response.headers_mut() = strip_response_hop_by_hop(&headers);
    mark_proxied(&mut response);
    Ok(response)
}

/// 注入点（证据：artifacts/phase1/page-original-001 的 authenticated-root：
/// 原版把客户端资源插在最后一个 head 元素之后、`</head>` 之前；fixture 正文为
/// `<html><head><script src=...></script><注入></script></head><body>`）。
/// 无 `</head>` 时追加到正文末尾（证据：evidence/proxy-v3-original-010 的
/// p1-me-html，fixture 为 `<html><body>probe-page</body></html>`，注入在 `</html>` 之后）。
fn insert_before_head_end(mut body: Vec<u8>, resource: &[u8]) -> Vec<u8> {
    const MARKER: &[u8] = b"</head>";
    let found = body
        .windows(MARKER.len())
        .position(|window| window.eq_ignore_ascii_case(MARKER));
    match found {
        Some(index) => {
            let tail = body.split_off(index);
            body.extend_from_slice(resource);
            body.extend_from_slice(&tail);
        }
        None => body.extend_from_slice(resource),
    }
    body
}

async fn inject_client_resource(
    app: &App,
    session: &Session,
    mut headers: HeaderMap,
    body: Vec<u8>,
) -> Result<(Vec<u8>, HeaderMap)> {
    if !headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"))
    {
        return Ok((body, headers));
    }
    // 注入必须基于明文：上游可能以 br/zstd/deflate/gzip 压缩 HTML。
    // 解码失败保持原字节与头部不变（不注入也不破坏正文），由下游按原编码回传。
    let body = match compression::decode_buffered(&headers, &body) {
        Ok(plain) => {
            headers.remove("content-encoding");
            headers.remove("content-length");
            plain
        }
        Err(cause) => {
            tracing::warn!(module = "gateway", error = %cause, "上游 HTML 解码失败，跳过客户端注入");
            return Ok((body, headers));
        }
    };
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
    let suffixes = serde_json::to_string(&INTERNAL_UPSTREAM_SUFFIXES)?;
    // 管理员配置字符串不能结束 script 元素；数值/布尔不经字符串拼接构造脚本。
    let resource = include_str!("../assets/gateway-client.html")
        .replacen("@@FORCE_CHAT@@", if force { "true" } else { "false" }, 1)
        .replacen("@@INTERNAL_HOSTS@@", &hosts.replace('<', "\\u003c"), 1)
        .replacen(
            "@@INTERNAL_HOST_SUFFIXES@@",
            &suffixes.replace('<', "\\u003c"),
            1,
        )
        .replacen("@@BLOCKED_PATHS@@", &blocked.replace('<', "\\u003c"), 1);
    Ok((insert_before_head_end(body, resource.as_bytes()), headers))
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

    /// 注入点必须命中第一个 `</head>`（大小写不敏感），缺失时退化为追加。
    #[test]
    fn injection_uses_head_end_and_falls_back_to_append() {
        let resource = b"<script id=\"gateway-user-logout-button\"></script>";
        assert_eq!(
            insert_before_head_end(
                b"<html><head><script src=\"/a.js\"></script></head><body>x</body></html>".to_vec(),
                resource
            ),
            b"<html><head><script src=\"/a.js\"></script><script id=\"gateway-user-logout-button\"></script></head><body>x</body></html>".to_vec()
        );
        assert_eq!(
            insert_before_head_end(b"<HTML><HEAD></HEAD></HTML>".to_vec(), resource),
            b"<HTML><HEAD><script id=\"gateway-user-logout-button\"></script></HEAD></HTML>".to_vec()
        );
        assert_eq!(
            insert_before_head_end(b"<html><body>probe-page</body></html>".to_vec(), resource),
            b"<html><body>probe-page</body></html><script id=\"gateway-user-logout-button\"></script>".to_vec()
        );
    }

    /// 媒体代理前缀只接受 https + 内置主机表；其它一律在接触上游前拒绝。
    #[test]
    fn internal_upstream_target_is_allowlisted() {
        let target = internal_upstream_target(
            "/internal-upstream/https/images.openai.com/static-rsc-2/a.png",
            Some("v=1"),
        )
        .expect("白名单主机必须可用");
        assert_eq!(
            target.as_str(),
            "https://images.openai.com/static-rsc-2/a.png?v=1"
        );
        assert_eq!(
            internal_upstream_target("/internal-upstream/https/cdn.oaistatic.com/", None)
                .expect("白名单主机必须可用")
                .as_str(),
            "https://cdn.oaistatic.com/"
        );
        // 签名上传地址的分片主机名会变化（实测 files → files09），按域后缀放行。
        for host in [
            "files09.oaiusercontent.com",
            "files0.oaiusercontent.com",
            "sdmntprwestus3.oaiusercontent.com",
        ] {
            assert_eq!(
                internal_upstream_target(
                    &format!("/internal-upstream/https/{host}/file-1?se=1&sp=cw"),
                    None
                )
                .expect("oaiusercontent 域名族必须可用")
                .host_str(),
                Some(host),
                "{host}"
            );
        }
        for path in [
            "/internal-upstream/http/images.openai.com/a.png",
            "/internal-upstream/https/evil.example/a.png",
            // 后缀族必须要求真实子域：裸域与伪装后缀都要拒绝。
            "/internal-upstream/https/oaiusercontent.com/a.png",
            "/internal-upstream/https/evil-oaiusercontent.com/a.png",
            "/internal-upstream/https/images.openai.com",
            "/internal-upstream",
            "/internal-upstream/https/",
            "/backend-api/me",
        ] {
            assert_eq!(internal_upstream_target(path, None), None, "{path}");
        }
    }

    /// 媒体方法门禁：读用 GET/HEAD，匿名上传签名地址用 PUT，其余方法拒绝。
    #[test]
    fn media_methods_are_limited_to_read_and_signed_put() {
        for method in [Method::GET, Method::HEAD, Method::PUT] {
            assert!(media_method_allowed(&method), "{method}");
        }
        for method in [Method::POST, Method::DELETE, Method::PATCH, Method::OPTIONS] {
            assert!(!media_method_allowed(&method), "{method}");
        }
    }

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

    /// CF 白名单过滤与同名去重由 server/cloudflare.rs 的单元测试覆盖；
    /// 这里只锁定代理层的拼接顺序与会话 cookies 解析。
    #[test]
    fn cookie_header_puts_session_before_cf_and_parses_submitted_cookies() {
        let session = vec![("probe_extra".to_owned(), "EV".to_owned())];
        let cf = vec![("cf_clearance".to_owned(), "SYNTHETIC".to_owned())];
        assert_eq!(
            cloudflare::cookie_header(&[&session, &cf]).as_deref(),
            Some("probe_extra=EV; cf_clearance=SYNTHETIC")
        );
        assert_eq!(
            cloudflare::cookie_header(&[&session]).as_deref(),
            Some("probe_extra=EV")
        );
        assert_eq!(cloudflare::cookie_header(&[&[], &[]]).as_deref(), None);
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

// Author: MingTea. Implemented contracts are listed in COMPATIBILITY.md; no original-binary fallback.
mod acl;
mod acl_admin;
mod anonymous;
mod chat_ws;
mod cloudflare;
mod compression;
mod egress;
mod management;
mod proxy;
mod public_prefixes;
mod static_assets;
use crate::{
    config::Config,
    crypto::sha256_hex,
    policy::{Policy, Revocation},
    resource_acl::{Identity, RequestIdentity},
    storage::Database,
};
use anyhow::{bail, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

pub struct App {
    config: Config,
    db: Mutex<Database>,
    client: reqwest::Client,
    cloudflare: cloudflare::Cloudflare,
    /// ACL 运行时：生成互斥租约与撤权中止（进程内状态，重启即清空）。
    acl: Arc<acl::Runtime>,
}
type Shared = Arc<App>;
type ApiResult = std::result::Result<Json<Value>, ApiError>;
/// API 错误：状态码、面向用户的消息与可选稳定错误码。
/// 只有明确的上游可用性问题才带 `code`（当前只有 Cloudflare 拦截），
/// 其余错误保持原有 `{"message":...}` 形状不变。
pub struct ApiError(StatusCode, String, Option<&'static str>);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({"message":self.1});
        if let Some(code) = self.2 {
            body["code"] = json!(code);
        }
        (self.0, Json(body)).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        // 凭据校验被 Cloudflare 拦截是上游可用性问题：既不是请求错误，
        // 也不能当成 token 失效，因此单独映射为 502 + upstream_blocked。
        if let Some(blocked) = e.downcast_ref::<cloudflare::UpstreamBlocked>() {
            return Self(
                StatusCode::BAD_GATEWAY,
                blocked.to_string(),
                Some("upstream_blocked"),
            );
        }
        tracing::error!(module="gateway", error=%e, "request failed");
        Self(StatusCode::BAD_REQUEST, e.to_string(), None)
    }
}
impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        Self::from(anyhow::Error::from(e))
    }
}
impl From<url::ParseError> for ApiError {
    fn from(e: url::ParseError) -> Self {
        Self::from(anyhow::Error::from(e))
    }
}
fn error(status: StatusCode, message: &str) -> ApiError {
    ApiError(status, message.into(), None)
}

/// 带稳定错误码的 API 错误：消费方（Django/管理端）按 `code` 分支，
/// 不依赖面向用户的文案。
fn error_code(status: StatusCode, message: &str, code: &'static str) -> ApiError {
    ApiError(status, message.into(), Some(code))
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

/// 登录/会话载荷里的 ACL 身份：`principal_kind` 决定该会话是否参与 ACL。
///
/// - `user`：必须是本候选契约的 Django 授权响应（三字段 + subject），否则拒绝；
/// - `visitor`：访客（Django `FREE_ACCOUNT`）没有可归属的镜像身份，资源路径一律
///   403 `acl_visitor_denied`，但页面与账号级路径保持既有可用性；
/// - 其它取值/缺失：说明 Django 响应不是本候选契约，直接拒绝而不构造降级身份。
fn identity_from_payload(payload: &Value) -> Result<Option<Identity>> {
    let subject = payload["user_name"]
        .as_str()
        .context("会话载荷缺少 user_name")?;
    match payload["principal_kind"].as_str() {
        Some("user") => Identity::from_authority(payload, subject, now())
            .map(Some)
            .map_err(anyhow::Error::from),
        Some("visitor") => Ok(None),
        _ => bail!("会话载荷 principal_kind 不是 user/visitor"),
    }
}

pub async fn router(config: Config) -> Result<Router> {
    let db = Database::open(&config.database, &config.key)?;
    db.conn.execute_batch("CREATE TABLE IF NOT EXISTS rust_authorizations(token_hash TEXT PRIMARY KEY, payload TEXT NOT NULL, expires_at INTEGER NOT NULL); PRAGMA user_version=1;")?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(config.timeout)
        .build()?;
    let app = Arc::new(App {
        config,
        db: Mutex::new(db),
        client,
        cloudflare: cloudflare::Cloudflare::new(),
        acl: Arc::new(acl::Runtime::default()),
    });
    if app.config.cfbypass.is_some() {
        match app.cloudflare.force(&app).await {
            Ok(_) => {}
            Err(cause) => tracing::warn!(module="gateway", error=%cause, "cfbypass prewarm failed"),
        }
    }
    // 旧归属一次性回填：只在 acl_resources 为空且无回填标记时调用映射端点。
    // 失败不阻塞启动（回填标记未写，下次启动重试），也不猜测无法唯一映射的行。
    if app.config.mirror_profile {
        if let Err(cause) = acl::backfill_legacy_ownership(&app).await {
            tracing::warn!(module = "gateway", error = %cause, "旧归属回填失败，保持未认领");
        }
    }
    let admin = Router::new()
        .route("/api/login", any(login))
        .route("/api/logout", any(logout))
        .route("/api/revoke-authorization", any(revoke))
        .route("/api/get-user-info", any(user_info))
        .route("/api/diagnose-chatgpt-auth", any(diagnose))
        .route("/api/backup/export", get(export_backup))
        .route("/api/backup/restore", any(restore_backup))
        .route("/api/blocked-paths", get(get_blocked).post(save_blocked))
        .route("/api/custom-scripts", get(get_scripts).post(save_scripts))
        .route("/api/mirror-proxy-config", get(get_proxy).post(save_proxy))
        .route("/api/test-mirror-proxy-config", any(test_proxy))
        .route("/api/user-work-mode", any(work_mode))
        .route("/api/get-user-quota-usage", any(quota_usage))
        .route("/api/operations-overview", any(overview))
        .route("/api/conversation-statistics", any(statistics))
        .route("/api/conversation-statistics/reset", any(reset_statistics))
        // ACL 管理 API 组（server/acl_admin.rs）：服务密钥由 require_admin 校验，
        // 管理员身份另由固定 Django 源 fresh 校验，二者不可互相替代。
        .route("/api/acl/resources", get(acl_admin::list_resources))
        .route("/api/acl/claim", post(acl_admin::claim))
        .route("/api/acl/share", post(acl_admin::share))
        .route("/api/acl/move", post(acl_admin::move_to_project))
        .route("/api/acl/audit", get(acl_admin::audit))
        // 管理端点（server/management.rs）：restore 仍留在父文件，另行原子校验。
        .route("/api/get-mirror-token", any(management::mirror_token))
        .route("/api/get-user-use-count", any(management::user_use_count))
        .route(
            "/api/get-chatgpt-use-count",
            any(management::chatgpt_use_count),
        )
        .route(
            "/api/close-chatgpt-memory",
            any(management::close_chatgpt_memory),
        )
        .route(
            "/api/political-moderation-config",
            get(management::political_moderation_config_get)
                .post(management::political_moderation_config_save),
        )
        .route(
            "/api/political-moderation-config/test",
            any(management::political_moderation_config_test),
        )
        .route_layer(middleware::from_fn_with_state(app.clone(), require_admin));
    Ok(Router::new()
        .merge(admin)
        .route("/api/not-login", get(handoff))
        .route("/api/auth/session", get(auth_session))
        // 未登录前端自带的 next-auth 客户端在进入对话前会访问这几个端点；
        // 实测形状见 evidence/anonymous-nextauth-001 与下方各 handler。
        .route("/api/auth/providers", get(auth_providers))
        .route("/api/auth/csrf", get(auth_csrf))
        .route("/api/auth/_log", post(auth_log))
        .route("/api/auth/error", get(auth_error))
        .route("/api/user-blocked-paths", get(user_blocked))
        .route("/api/refresh-cfbypass", any(refresh_cfbypass))
        // 注入脚本把浏览器 WebSocket 改写到本前缀；目标主机写死为
        // ws.chatgpt.com，会话与凭据判定在 chat_ws::route 内完成。
        .route("/ws-chatgpt", get(chat_ws::route))
        .route("/ws-chatgpt/*path", get(chat_ws::route))
        .route("/0x/*path", any(proxy::django_proxy))
        .route("/admin", any(proxy::django_proxy))
        .route("/admin/*path", any(proxy::django_proxy))
        .fallback(proxy::chat_proxy)
        // 顺序：private_headers 先写 `Cookie, Authorization`，压缩层随后追加
        // `accept-encoding`（后注册的 layer 在最外层，响应方向最后执行）。
        .layer(middleware::from_fn(private_headers))
        .layer(middleware::from_fn(compression::compress))
        .with_state(app))
}

/// 代理路径已由 server::proxy 的会话/透传处理器生成响应时写入的标记；
/// 统一中间件据此补齐固定 CSP 与私有缓存语义（401 门禁拒绝路径不带该标记，
/// 与原版观测一致：`p1-me-no-cookie`/`p2-conversations-no-cookie` 无 CSP）。
#[derive(Clone, Copy)]
pub(super) struct ProxiedResponse;

/// 原版 chat/django 代理固定 CSP（1270 字节，覆盖上游同名头；证据
/// evidence/proxy-v3-original-007 与 evidence/headers-v3-original-006 的全部代理成功用例）。
const PROXY_CSP: &str = "default-src 'self'; connect-src 'self' ws: wss: blob: https://static.cloudflareinsights.com https://chatgpt.com https://ab.chatgpt.com https://cdn.oaistatic.com https://cdn.openai.com https://images.openai.com https://*.oaiusercontent.com https://files.openai.com https://persistent.oaistatic.com https://www.google.com https://t0.gstatic.com https://t1.gstatic.com https://t2.gstatic.com https://t3.gstatic.com https://lh3.googleusercontent.com https://cdn.auth0.com; img-src 'self' data: blob: https://static.cloudflareinsights.com https://*.oaiusercontent.com https://files.openai.com https://persistent.oaistatic.com https://www.google.com https://t0.gstatic.com https://t1.gstatic.com https://t2.gstatic.com https://t3.gstatic.com https://lh3.googleusercontent.com https://cdn.auth0.com; font-src 'self' data: https://cdn.openai.com https://*.oaiusercontent.com https://persistent.oaistatic.com; style-src 'self' 'unsafe-inline' https://*.oaiusercontent.com https://persistent.oaistatic.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://chatgpt.com https://static.cloudflareinsights.com https://*.oaiusercontent.com; worker-src 'self' blob:; frame-src 'self' https://*.oaiusercontent.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self'";

/// 私有响应的缓存头值（原版对 JSON/重定向/代理响应一致）。
const PRIVATE_CACHE: &str = "private, no-store, no-cache, must-revalidate, max-age=0";

/// 代理响应的 `Cookie, Authorization` 合并：上游若已有 vary，则并入同一头的值
/// （观测：上游 `accept-encoding` → `accept-encoding, Cookie, Authorization`；
/// 上游已含 Cookie 值则不重复追加）。
fn merge_cookie_vary(headers: &mut HeaderMap) {
    let existing: Vec<String> = headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect();
    if existing
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("cookie"))
    {
        return;
    }
    let merged = if existing.is_empty() {
        HeaderValue::from_static("Cookie, Authorization")
    } else {
        // 上游 vary 值均来自已通过 `to_str` 的合法头值，拼接结果不可能非法。
        HeaderValue::from_str(&format!("{}, Cookie, Authorization", existing.join(", ")))
            .expect("vary 拼接结果必须是合法头值")
    };
    headers.remove("vary");
    headers.insert("vary", merged);
}

async fn private_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let proxied = response.extensions().get::<ProxiedResponse>().is_some();
    let private = proxied
        || response.status().is_redirection()
        || response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("application/json"))
            .unwrap_or(false);
    if private {
        for name in [
            "cache-control",
            "cdn-cache-control",
            "cloudflare-cdn-cache-control",
        ] {
            response
                .headers_mut()
                .insert(name, HeaderValue::from_static(PRIVATE_CACHE));
        }
        response
            .headers_mut()
            .insert("pragma", HeaderValue::from_static("no-cache"));
        response
            .headers_mut()
            .insert("expires", HeaderValue::from_static("0"));
        if proxied {
            merge_cookie_vary(response.headers_mut());
        } else {
            // 原版：所有私有 JSON/重定向响应都带 Cookie, Authorization；
            // require_admin 的 401 已自带 `accept-encoding`，此处保持单值不动。
            response
                .headers_mut()
                .entry("vary")
                .or_insert(HeaderValue::from_static("Cookie, Authorization"));
        }
    } else {
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-cache"));
        if response.status() != StatusCode::METHOD_NOT_ALLOWED {
            response
                .headers_mut()
                .entry("vary")
                .or_insert(HeaderValue::from_static("accept-encoding"));
        }
    }
    if proxied {
        response.headers_mut().insert(
            "content-security-policy",
            HeaderValue::from_static(PROXY_CSP),
        );
    }
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "same-origin"),
        ("x-frame-options", "SAMEORIGIN"),
        ("cross-origin-opener-policy", "same-origin"),
        ("permissions-policy", "camera=(), microphone=(), geolocation=()"),
        ("accept-ch", "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version"),
        ("strict-transport-security", "max-age=31536000; includeSubDomains; preload"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
async fn require_admin(State(app): State<Shared>, request: Request, next: Next) -> Response {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let direct = request
        .headers()
        .get("x-gateway-secret")
        .and_then(|h| h.to_str().ok());
    let valid = [bearer, direct]
        .iter()
        .flatten()
        .any(|s| bool::from(s.as_bytes().ct_eq(app.config.secret.as_bytes())));
    if !valid {
        let mut response =
            error(StatusCode::UNAUTHORIZED, "缺少或无效的网关认证信息").into_response();
        response
            .headers_mut()
            .insert("vary", HeaderValue::from_static("accept-encoding"));
        return response;
    }
    next.run(request).await
}

#[derive(Deserialize)]
struct Login {
    user_name: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    session_token: String,
    #[serde(default)]
    chatgpt_token: String,
    #[serde(flatten)]
    options: serde_json::Map<String, Value>,
}
async fn login(
    State(app): State<Shared>,
    Json(input): Json<Login>,
) -> std::result::Result<Response, ApiError> {
    // 匿名会话只是开发阶段的入口：上游凭据全部缺失且开关显式打开时才成立，
    // 默认仍按原版拒绝空凭据。
    let anonymous_login = input.access_token.is_empty()
        && input.session_token.is_empty()
        && input.chatgpt_token.is_empty();
    if anonymous_login && !app.config.allow_anonymous_session {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "chatgpt_token、access_token、session_token 至少提供一个",
        ));
    }
    let mut payload = Value::Object(input.options.clone());
    payload["user_name"] = json!(input.user_name);
    let expiry = authorize_login_payload(&app, &mut payload).await?;
    let node = match payload.get("proxy_node_id") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_i64().context("proxy_node_id 必须是整数或 null")?),
    };
    let outbound = {
        let db = app.db.lock().await;
        egress::load(&db, &app.config, node)?
    };
    payload["rust_egress_binding"] = json!(outbound.binding);
    // 提交的 extra_cookies 既用于入库，也注入凭据换取/校验请求
    // （原版换取 session_token 时只带会话 cookie，见模块注释）。
    let (extra_cookies, submitted) = submitted_cookies(payload.get("extra_cookies"));
    // 上游凭据必须经实际回环上游验证，不能以字符串非空代替验证。
    let (email, access) = if anonymous_login {
        // 匿名会话没有上游账号：上游身份由全局共享匿名身份提供
        // （server/anonymous.rs），本地归属键使用保留标签。
        (anonymous::ACCOUNT.to_owned(), String::new())
    } else {
        let access = if !input.access_token.is_empty() {
            input.access_token
        } else {
            exchange_session_with_client(
                &app, &outbound.client,
                if !input.session_token.is_empty() {
                    &input.session_token
                } else {
                    &input.chatgpt_token
                },
                &submitted,
            )
            .await?
        };
        let info = fetch_user_with_client(&app, &outbound.client, &access, &submitted).await?;
        let email = info["email"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("上游用户信息缺少 email")?
            .to_owned();
        (email, access)
    };
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let hash = sha256_hex(&token);
    let time = now();
    let mut db = app.db.lock().await;
    if egress::binding(&db, &app.config, node)? != outbound.binding {
        return Err(error(StatusCode::CONFLICT, "登录期间出口配置已变化，请重新登录"));
    }
    let encrypted_access = db.encrypt(&access)?;
    let session = if input.session_token.is_empty() {
        None
    } else {
        Some(db.encrypt(&input.session_token)?)
    };
    let extra = db.encrypt(&extra_cookies)?;
    // 稳定账号键：mirror profile 必须由 Django 载荷提供（缺失即拒绝登录，
    // 不能用用户名或客户端字段顶替）；original profile 与匿名会话没有上游账号，
    // 保持 NULL，ACL 路径随后按「无账号键」拒绝。
    let account_id = if app.config.mirror_profile && !anonymous_login {
        Some(
            payload["chatgpt_account_id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .context("登录载荷缺少 chatgpt_account_id")?
                .to_owned(),
        )
    } else {
        None
    };
    payload["rust_credential_binding"] = json!(sha256_hex(&json!([email, access, extra_cookies]).to_string()));
    let mode = if anonymous_login {
        anonymous::LOGIN_MODE
    } else {
        payload["login_mode"].as_str().unwrap_or("api")
    };
    let auth_payload = db.encrypt(&payload.to_string())?;
    let tx = db.conn.transaction()?;
    tx.execute("DELETE FROM rust_authorizations WHERE token_hash IN (SELECT mirror_token FROM gateway_sessions WHERE user_name=?1 AND chatgpt_username=?2)",params![input.user_name,email])?;
    tx.execute("INSERT INTO gateway_sessions(user_name,chatgpt_username,access_token,session_token,extra_cookies,login_mode,mirror_token,isolated_session,force_chat_mode,limits,proxy_node_id,daily_quota,monthly_quota,chatgpt_account_id,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15) ON CONFLICT(user_name,chatgpt_username) DO UPDATE SET access_token=excluded.access_token,session_token=excluded.session_token,extra_cookies=excluded.extra_cookies,mirror_token=excluded.mirror_token,login_mode=excluded.login_mode,isolated_session=excluded.isolated_session,force_chat_mode=excluded.force_chat_mode,limits=excluded.limits,proxy_node_id=excluded.proxy_node_id,daily_quota=excluded.daily_quota,monthly_quota=excluded.monthly_quota,chatgpt_account_id=excluded.chatgpt_account_id,updated_at=excluded.updated_at",
        params![input.user_name,email,encrypted_access,session,extra,mode,hash,payload["isolated_session"].as_bool().unwrap_or(true),payload["force_chat_mode"].as_bool().unwrap_or(true),payload.get("limits").cloned().unwrap_or(json!([])).to_string(),payload["proxy_node_id"].as_i64(),payload["daily_quota"].as_i64().unwrap_or(0),payload["monthly_quota"].as_i64().unwrap_or(0),account_id,time])?;
    tx.execute(
        "INSERT INTO rust_authorizations(token_hash,payload,expires_at) VALUES(?1,?2,?3)",
        params![hash, auth_payload, expiry],
    )?;
    tx.commit()?;
    let mut response=Json(
        json!({"chatgpt_username":email,"login_mode":mode,"login_url":format!("/api/not-login?user_gateway_token={token}"),"message":"登录成功"}),
    ).into_response();
    session_cookies(&mut response, &token, app.config.cookie_secure)?;
    Ok(response)
}

async fn authorize_login_payload(
    app: &App,
    payload: &mut Value,
) -> std::result::Result<i64, ApiError> {
    if !app.config.mirror_profile {
        return Ok(i64::MAX);
    }
    let policy = Policy::from_login(payload)?;
    let details = authority_details(app, &policy.authorization, &policy.user_name).await?;
    if details["active"] != true {
        return Err(error(StatusCode::UNAUTHORIZED, "Django 未确认有效授权"));
    }
    let expiry = details["expires_at"]
        .as_i64()
        .context("Django 缺少 expires_at")?;
    if expiry <= now() {
        return Err(error(StatusCode::UNAUTHORIZED, "Django 授权已过期"));
    }
    payload["version"] = json!(details["version"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("Django 缺少 version")?);
    payload["expires_at"] = json!(expiry);
    // ACL 可信身份：四个字段全部来自 Django 签名授权的响应，客户端载荷里的
    // 同名值在这里被覆盖，浏览器自报的身份不参与判权。
    // `active` 与 `expires_at`/`version` 一起写入：会话建立时固定的身份要能被
    // 后续每个请求原样复验（`Identity::from_authority` 同样要求这三项），
    // 否则登录成功但下一次请求就判身份无效。
    for key in ["active", "user_id", "is_admin", "subject", "principal_kind"] {
        payload[key] = details
            .get(key)
            .cloned()
            .with_context(|| format!("Django 授权响应缺少 {key}"))?;
    }
    Ok(expiry)
}

/// 固定的 Django 授权源：唯一可信身份来源。
///
/// `/api/login`、`/api/get-mirror-token` 与每个资源请求的复验都走这里；
/// 服务密钥只证明调用方是 Django，不构成管理员身份，管理员判定一律来自本响应。
pub(super) async fn authority_details(
    app: &App,
    authorization: &str,
    subject: &str,
) -> std::result::Result<Value, ApiError> {
    let response = app
        .client
        .post(app.config.django.join("/0x/user/gateway-authorization")?)
        .bearer_auth(&app.config.secret)
        .json(&json!({"authorization":authorization,"subject":subject}))
        .send()
        .await
        .context("Django 授权服务不可用")?;
    if !response.status().is_success() {
        return Err(error(StatusCode::UNAUTHORIZED, "登录已失效，请重新登录"));
    }
    response
        .json()
        .await
        .map_err(|cause| error(StatusCode::BAD_GATEWAY, &format!("Django 授权响应无效: {cause}")))
}

/// 管理 API 的请求方身份：服务密钥已由中间件校验，这里再要求请求自带
/// `authorization` + `subject` 并在固定 Django 源做一次 fresh 校验，最后要求
/// `is_admin`。缺任一步都不能构造管理员身份，服务密钥本身不代表管理员。
pub(super) async fn request_admin_identity(
    app: &App,
    headers: &HeaderMap,
) -> std::result::Result<Option<RequestIdentity>, ApiError> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
    };
    let (Some(authorization), Some(subject)) = (header("authorization"), header("subject")) else {
        return Ok(None);
    };
    let details = authority_details(app, authorization, subject).await?;
    // 身份三字段缺失/错型/访客/过期都由 `Identity::from_authority` 拒绝。
    let Ok(identity) = Identity::from_authority(&details, subject, now()) else {
        return Ok(None);
    };
    if !identity.is_admin() {
        return Ok(None);
    }
    Ok(Some(RequestIdentity::from_session(identity)))
}

fn session_cookies(response: &mut Response, token: &str, secure: bool) -> Result<()> {
    let secure = if secure { "; Secure" } else { "" };
    let cookie =
        format!("mirror_token={token}; Path=/; SameSite=Lax; Max-Age=604800{secure}; HttpOnly");
    response
        .headers_mut()
        .append("set-cookie", HeaderValue::from_str(&cookie)?);
    for name in ["access_token", "session_token", "next-auth.session-token"] {
        response.headers_mut().append(
            "set-cookie",
            HeaderValue::from_str(&format!(
                "{name}=; Path=/; SameSite=Lax; Max-Age=0{secure}; HttpOnly"
            ))?,
        );
    }
    Ok(())
}

/// 提交 cookies 的两种形态：数组按原版对象序列入库（观测 p1-login-carol →
/// p1-carol-extra-cookies 上游还原 `probe_extra=EV`），字符串形态沿用既有兼容路径；
/// 两者都只取 name/value 非空的条目，并注入凭据类上游请求。
fn submitted_cookies(value: Option<&Value>) -> (String, Vec<(String, String)>) {
    let stored = match value {
        Some(value) if value.is_array() => value.to_string(),
        Some(Value::String(text)) if !text.trim().is_empty() => text.clone(),
        _ => "[]".to_owned(),
    };
    let cookies = proxy::parse_extra_cookies(&stored);
    (stored, cookies)
}

async fn fetch_user(app: &App, access: &str, submitted: &[(String, String)]) -> Result<Value> {
    let outbound = { let db = app.db.lock().await; egress::load(&db, &app.config, None)? };
    fetch_user_with_client(app, &outbound.client, access, submitted).await
}
/// `access_token` 校验：提交 cookies 在前、CF cookies 在后；被 Cloudflare 拦截时
/// 刷新一次并重放一次，仍被拦截按 [`cloudflare::UpstreamBlocked`] 上报。
async fn fetch_user_with_client(
    app: &App,
    client: &reqwest::Client,
    access: &str,
    submitted: &[(String, String)],
) -> Result<Value> {
    let url = app.config.upstream.join("/backend-api/me")?;
    let (response, refresh) = cloudflare::get_with_challenge_retry(app, |cf| {
        let url = url.clone();
        let client = client.clone();
        let submitted = submitted.to_vec();
        let access = access.to_owned();
        async move {
            let mut request = client.get(url).bearer_auth(access);
            if let Some(cookie) = cloudflare::cookie_header(&[&submitted, &cf]) {
                request = request.header(
                    "cookie",
                    HeaderValue::from_str(&cookie).context("Cookie 头无效")?,
                );
            }
            request.send().await.context("上游请求失败")
        }
    })
    .await?;
    let answer = cloudflare::read(response).await?;
    if !answer.status.is_success() {
        if answer.blocked() {
            return Err(cloudflare::blocked_error(
                "access_token 校验失败",
                "backend-api/me",
                answer.status,
                refresh.as_ref(),
            )
            .into());
        }
        anyhow::bail!(
            "access_token 校验失败: backend-api/me 返回状态 {}",
            answer.status.as_u16()
        );
    }
    answer.json::<Value>()
}
async fn exchange_session(
    app: &App,
    session: &str,
    submitted: &[(String, String)],
) -> Result<String> {
    let outbound = { let db = app.db.lock().await; egress::load(&db, &app.config, None)? };
    exchange_session_with_client(app, &outbound.client, session, submitted).await
}
/// `session_token → access_token` 换取：会话 cookie 在前、提交 cookies 其次、
/// CF cookies 最后；被 Cloudflare 拦截时刷新一次并重放一次。
async fn exchange_session_with_client(
    app: &App,
    client: &reqwest::Client,
    session: &str,
    submitted: &[(String, String)],
) -> Result<String> {
    let url = app.config.upstream.join("/api/auth/session")?;
    let session_token = [(
        "__Secure-next-auth.session-token".to_owned(),
        session.to_owned(),
    )];
    let (response, refresh) = cloudflare::get_with_challenge_retry(app, |cf| {
        let url = url.clone();
        let client = client.clone();
        let submitted = submitted.to_vec();
        let session_token = session_token.clone();
        async move {
            let mut request = client.get(url);
            if let Some(cookie) =
                cloudflare::cookie_header(&[session_token.as_slice(), &submitted, &cf])
            {
                request = request.header(
                    "cookie",
                    HeaderValue::from_str(&cookie).context("Cookie 头无效")?,
                );
            }
            request.send().await.context("上游请求失败")
        }
    })
    .await?;
    let answer = cloudflare::read(response).await?;
    if !answer.status.is_success() {
        if answer.blocked() {
            return Err(cloudflare::blocked_error(
                "session_token 校验失败",
                "api/auth/session",
                answer.status,
                refresh.as_ref(),
            )
            .into());
        }
        anyhow::bail!(
            "session_token 校验失败: api/auth/session 返回状态 {}",
            answer.status.as_u16()
        );
    }
    answer.json::<Value>()?["accessToken"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .context("session_token 无法换取 access_token")
}
async fn user_info(State(app): State<Shared>, Json(input): Json<Value>) -> ApiResult {
    let token = input["chatgpt_token"].as_str().unwrap_or("");
    if token.is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "chatgpt_token 不能为空"));
    }
    let (_, submitted) = submitted_cookies(input.get("extra_cookies"));
    let access = if token.starts_with("eyJ") {
        token.into()
    } else {
        exchange_session(&app, token, &submitted).await?
    };
    Ok(Json(fetch_user(&app, &access, &submitted).await?))
}
async fn diagnose(State(app): State<Shared>, Json(input): Json<Value>) -> ApiResult {
    let access = input["access_token"].as_str().unwrap_or("");
    let session = input["session_token"].as_str().unwrap_or("");
    let (_, submitted) = submitted_cookies(input.get("extra_cookies"));
    let mut modes = Vec::new();
    let mut info = json!({"email":"","plan_type":"free"});
    let mut errors = Vec::new();
    // 上游被 Cloudflare 拦截时两种凭据都“无法验证”，消费方必须优先看该标志，
    // 不能把 false 当成凭据失效。
    let mut blocked = false;
    if !access.is_empty() {
        match fetch_user(&app, access, &submitted).await {
            Ok(v) => {
                info = v;
                modes.push("api");
            }
            Err(e) => {
                blocked |= e.downcast_ref::<cloudflare::UpstreamBlocked>().is_some();
                errors.push(e.to_string());
            }
        }
    }
    if !session.is_empty() {
        match exchange_session(&app, session, &submitted).await {
            Ok(_) => modes.push("web"),
            Err(e) => {
                blocked |= e.downcast_ref::<cloudflare::UpstreamBlocked>().is_some();
                errors.push(e.to_string());
            }
        }
    }
    if access.is_empty() && session.is_empty() {
        errors.push("未提供任何可诊断的 token".into());
    }
    Ok(Json(
        json!({"access_token_valid":modes.contains(&"api"),"session_token_valid":modes.contains(&"web"),"supported_login_modes":modes,"user_info":info,"last_check_at":now(),"last_error":errors.join("; "),"upstream_blocked":blocked}),
    ))
}
#[derive(Deserialize)]
struct UserName {
    user_name: String,
}
async fn logout(
    State(app): State<Shared>,
    Json(input): Json<UserName>,
) -> std::result::Result<Response, ApiError> {
    // 登出同样中止该用户在途流：会话行即将删除，剩余内容不能再下发。
    app.acl.abort_subject(&input.user_name);
    let mut db = app.db.lock().await;
    let tx = db.conn.transaction()?;
    tx.execute("DELETE FROM rust_authorizations WHERE token_hash IN (SELECT mirror_token FROM gateway_sessions WHERE user_name=?1)",[&input.user_name])?;
    tx.execute(
        "DELETE FROM gateway_sessions WHERE user_name=?1",
        [&input.user_name],
    )?;
    tx.commit()?;
    let mut response = Json(json!({"message":"退出成功"})).into_response();
    let secure = if app.config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    for (name, http_only) in [
        ("access_token", true),
        ("session_token", true),
        ("next-auth.session-token", true),
        ("__Secure-next-auth.session-token", true),
        ("chatgpt_username", false),
        ("gateway_user_name", false),
        ("login_mode", false),
        ("mirror_token", true),
        ("isolated_session", false),
        ("model_limits", false),
    ] {
        let suffix = if http_only { "; HttpOnly" } else { "" };
        response.headers_mut().append(
            "set-cookie",
            HeaderValue::from_str(&format!(
                "{name}=; Path=/; SameSite=Lax; Max-Age=0{secure}{suffix}"
            ))
            .context("退出 Cookie 无效")?,
        );
    }
    Ok(response)
}
async fn revoke(State(app): State<Shared>, Json(input): Json<Value>) -> ApiResult {
    let event = Revocation::from_json(&input)?;
    let mut db = app.db.lock().await;
    let records: Vec<(String, String)> = db
        .conn
        .prepare("SELECT token_hash,payload FROM rust_authorizations")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    let mut keys = Vec::new();
    // 撤权命中的会话，其镜像用户名（subject）用于中止在途流：撤权后不能再把
    // 剩余生成内容交给已失权用户。
    let mut subjects = Vec::new();
    for (key, value) in records {
        let payload: Value = serde_json::from_str(&db.decrypt(&value)?).context("会话策略损坏")?;
        let policy = Policy::from_login(&payload)?;
        if event.matches(&policy, now()) {
            subjects.push(policy.user_name.clone());
            keys.push(key);
        }
    }
    let tx = db.conn.transaction()?;
    for key in keys {
        tx.execute("DELETE FROM gateway_sessions WHERE mirror_token=?1", [&key])?;
        tx.execute(
            "DELETE FROM rust_authorizations WHERE token_hash=?1",
            [&key],
        )?;
    }
    tx.commit()?;
    drop(db);
    for subject in subjects {
        app.acl.abort_subject(&subject);
    }
    Ok(Json(json!({"revoked":true})))
}
async fn export_backup(State(app): State<Shared>) -> ApiResult {
    Ok(Json(app.db.lock().await.export_backup()?))
}
async fn restore_backup(State(app): State<Shared>, Json(input): Json<Value>) -> ApiResult {
    let mut db = app.db.lock().await;
    let result = db.restore_http_backup_validated(&input, |conn, crypto| {
        validate_restored_settings(conn, crypto)
            .map_err(|cause| anyhow::Error::new(ReloadError(cause)))?;
        let replaces_binding = input.get("gateway_sessions").is_some()
            || input["settings"].as_array().is_some_and(|settings| settings.iter()
                .any(|row| matches!(row["key"].as_str(),Some("mirror_proxy" | "rust_egress_epoch"))));
        if replaces_binding { egress::rotate_epoch(conn)?; }
        Ok(())
    });
    if let Err(cause) = result {
        if let Some(reload) = cause.downcast_ref::<ReloadError>() {
            let message = match validate_restored_settings(&db.conn, &db.crypto) {
                Ok(()) => format!("恢复后重载失败，Gateway 已回滚: {:#}", reload.0),
                Err(previous) => format!(
                    "恢复后重载失败: {:#}; 数据库已回滚，但运行时重载失败: {previous:#}",
                    reload.0
                ),
            };
            return Err(error(StatusCode::INTERNAL_SERVER_ERROR, &message));
        }
        return Err(cause.into());
    }
    Ok(Json(json!({"message":"网关备份已恢复"})))
}

#[derive(Debug)]
struct ReloadError(anyhow::Error);
impl std::fmt::Display for ReloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.0)
    }
}
impl std::error::Error for ReloadError {}

fn validate_restored_settings(
    conn: &rusqlite::Connection,
    crypto: &crate::crypto::Crypto,
) -> Result<()> {
    for (key, context) in [
        ("mirror_proxy", "读取代理配置失败"),
        ("custom_scripts", "读取脚本配置失败"),
        ("blocked_paths", "读取访问限制配置失败"),
        ("political_moderation", "读取审查配置失败"),
        ("anonymous_upstream", "读取匿名上游身份失败"),
    ] {
        let raw: Option<String> = conn
            .query_row(
                "SELECT value FROM gateway_settings WHERE key=?1",
                [key],
                |row| row.get(0),
            )
            .optional()?;
        let Some(raw) = raw else { continue };
        let text = if matches!(
            key,
            "mirror_proxy" | "political_moderation" | "anonymous_upstream"
        ) {
            crypto.decrypt(&raw).map_err(|cause| {
                let reason = if cause.to_string().contains("编码损坏") {
                    "敏感凭据编码损坏"
                } else {
                    "敏感凭据解密失败，请检查密钥"
                };
                anyhow::anyhow!("{context}: {reason}")
            })?
        } else {
            raw
        };
        if key == "custom_scripts" {
            serde_json::from_str::<Scripts>(&text).context(context)?;
        } else if key == "blocked_paths" {
            serde_json::from_str::<Blocked>(&text).context(context)?;
        } else {
            serde_json::from_str::<Value>(&text).context(context)?;
        }
    }
    Ok(())
}

fn default_blocked() -> Value {
    json!({"paths":["/#settings/Personalization","/#settings/Security","/#settings/Billing","/#settings/Account","/#settings/Safety","/#pricing"]})
}
async fn blocked_value(app: &App) -> Result<Value> {
    Ok(app
        .db
        .lock()
        .await
        .get_setting("blocked_paths")?
        .unwrap_or_else(default_blocked))
}
async fn get_blocked(State(app): State<Shared>) -> ApiResult {
    let v = blocked_value(&app).await?;
    Ok(Json(json!({"paths":v["paths"],"hash_paths":v["paths"]})))
}
#[derive(Deserialize)]
struct Blocked {
    #[serde(default)]
    paths: Vec<String>,
}
async fn save_blocked(State(app): State<Shared>, Json(input): Json<Blocked>) -> ApiResult {
    app.db
        .lock()
        .await
        .set_setting("blocked_paths", &json!({"paths":input.paths}))?;
    Ok(Json(
        json!({"paths":input.paths,"hash_paths":input.paths,"message":"访问限制配置已保存"}),
    ))
}
async fn get_scripts(State(app): State<Shared>) -> ApiResult {
    Ok(Json(
        app.db
            .lock()
            .await
            .get_setting("custom_scripts")?
            .unwrap_or(json!({"scripts":[],"trusted_cdn_sources":[]})),
    ))
}
#[derive(Deserialize)]
struct Scripts {
    #[serde(default)]
    scripts: Vec<CustomScriptItem>,
    #[serde(default)]
    trusted_cdn_sources: Vec<String>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename = "CustomScriptItem")]
struct CustomScriptItem {
    id: String,
    #[serde(flatten)]
    rest: serde_json::Map<String, Value>,
}
async fn save_scripts(State(app): State<Shared>, Json(input): Json<Scripts>) -> ApiResult {
    let v = json!({"scripts":input.scripts,"trusted_cdn_sources":input.trusted_cdn_sources});
    app.db.lock().await.set_setting("custom_scripts", &v)?;
    let mut out = v;
    out["message"] = json!("脚本配置已保存");
    Ok(Json(out))
}
fn default_proxy() -> Value {
    json!({"enabled":false,"nodes":[],"password":null,"proxy_url":null,"transport_mode":"reqwest","username":null})
}
fn sanitize_proxy(mut value: Value, message: Value) -> Value {
    value["has_password"] = json!(value["password"]
        .as_str()
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    value["password"] = Value::Null;
    value["message"] = message;
    value
}
async fn get_proxy(State(app): State<Shared>) -> ApiResult {
    let v = app
        .db
        .lock()
        .await
        .get_setting("mirror_proxy")?
        .unwrap_or_else(default_proxy);
    Ok(Json(sanitize_proxy(v, Value::Null)))
}
async fn save_proxy(State(app): State<Shared>, Json(input): Json<Value>) -> ApiResult {
    let mut v = default_proxy();
    let map = input.as_object().context("代理配置必须为对象")?;
    for (key, value) in map {
        if v.get(key).is_some() {
            v[key] = value.clone();
        }
    }
    if v["enabled"] == true {
        let url = v["proxy_url"].as_str().context("缺少代理地址")?;
        v["proxy_url"] = json!(crate::config::loopback_url(url)?.as_str());
    }
    if v["transport_mode"] != "reqwest" {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "指纹传输兼容尚未验证，不允许退化为普通 HTTP",
        ));
    }
    let mut db = app.db.lock().await;
    if v["password"].as_str().unwrap_or("").is_empty() {
        if let Some(old) = db.get_setting("mirror_proxy")? {
            v["password"] = old["password"].clone();
        }
    }
    let next_profile = egress::normalized(&app.config, &v, None)?;
    let old = db.get_setting("mirror_proxy")?.unwrap_or_else(default_proxy);
    let changed = egress::normalized(&app.config, &old, None).ok().as_ref() != Some(&next_profile);
    let encoded = db.encrypt(&v.to_string())?;
    let tx = db.conn.transaction()?;
    tx.execute("INSERT INTO gateway_settings(key,value,updated_at) VALUES('mirror_proxy',?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",params![encoded,now()])?;
    if changed {
        egress::rotate_epoch(&tx)?;
    }
    tx.commit()?;
    Ok(Json(sanitize_proxy(v, json!("代理配置已保存"))))
}
async fn test_proxy(State(app): State<Shared>, Json(input): Json<Value>) -> ApiResult {
    if input["enabled"] != true {
        return Err(error(StatusCode::BAD_REQUEST, "请先启用代理"));
    }
    let profile = egress::normalized(&app.config, &input, None)?;
    let client = egress::client(&app.config, &profile)?;
    let response = client
        .get(app.config.upstream.clone())
        .send()
        .await
        .context("代理端口连接失败")?;
    Ok(Json(
        json!({"message":format!("代理端口可连接，上游返回 HTTP {}",response.status().as_u16()),"upstream_status":response.status().as_u16()}),
    ))
}
#[derive(Deserialize)]
struct WorkMode {
    user_name: String,
    force_chat_mode: bool,
}
async fn work_mode(State(app): State<Shared>, Json(v): Json<WorkMode>) -> ApiResult {
    let affected = app.db.lock().await.conn.execute(
        "UPDATE gateway_sessions SET force_chat_mode=?1,updated_at=?2 WHERE user_name=?3",
        params![v.force_chat_mode, now(), v.user_name],
    )?;
    Ok(Json(json!({"affected":affected})))
}
#[derive(Deserialize)]
struct Period {
    day_start: i64,
    #[serde(rename = "month_start")]
    _month_start: i64,
}
async fn overview(State(app): State<Shared>, Json(v): Json<Period>) -> ApiResult {
    let db = app.db.lock().await;
    let active: i64 = db
        .conn
        .query_row("SELECT count(*) FROM gateway_sessions", [], |r| r.get(0))?;
    let today: i64 = db.conn.query_row(
        "SELECT count(*) FROM visit_logs WHERE created_at>=?1 AND log_type='proxy'",
        [v.day_start],
        |r| r.get(0),
    )?;
    Ok(Json(
        json!({"active_sessions":active,"today_requests":today}),
    ))
}
#[derive(Deserialize)]
struct Quota {
    user_name: String,
    day_start: i64,
    month_start: i64,
}
async fn quota_usage(State(app): State<Shared>, Json(v): Json<Quota>) -> ApiResult {
    let db = app.db.lock().await;
    let count = |start| {
        db.conn.query_row("SELECT count(*) FROM visit_logs WHERE username=?1 AND created_at>=?2 AND log_type='proxy'",params![v.user_name,start],|r|r.get::<_,i64>(0))
    };
    Ok(Json(
        json!({"daily_used":count(v.day_start)?,"monthly_used":count(v.month_start)?}),
    ))
}
#[derive(Deserialize)]
struct StatisticsRequest {
    #[serde(default)]
    user_name_list: Vec<String>,
    #[serde(default)]
    user_name: String,
}

async fn statistics(State(app): State<Shared>, Json(input): Json<StatisticsRequest>) -> ApiResult {
    let db = app.db.lock().await;
    let mut result = serde_json::Map::new();
    if !input.user_name.is_empty() {
        return Ok(Json(user_statistics(&db.conn, &input.user_name, true)?));
    }
    for user in input.user_name_list {
        result.insert(user.clone(), user_statistics(&db.conn, &user, false)?);
    }
    Ok(Json(Value::Object(result)))
}

fn user_statistics(conn: &rusqlite::Connection, user: &str, detailed: bool) -> Result<Value> {
    let (count, messages):(i64,i64) = conn.query_row(
        "SELECT COALESCE(SUM(CASE WHEN conversation_counted THEN 1 ELSE 0 END),0), COALESCE(SUM(message_count),0) FROM conversation_statistics WHERE user_name=?1",
        [user], |row|Ok((row.get(0)?,row.get(1)?)))?;
    let mut statement=conn.prepare("SELECT model_name,message_count FROM conversation_model_statistics WHERE user_name=?1 ORDER BY model_name")?;
    let rows = statement.query_map([user], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut models = serde_json::Map::new();
    for row in rows {
        let (model, count) = row?;
        models.insert(model, json!(count));
    }
    let mut value =
        json!({"conversation_count":count,"message_count":messages,"model_message_counts":models});
    if detailed {
        let mut statement=conn.prepare("SELECT conversation_id,title,message_count,updated_at FROM conversation_statistics WHERE user_name=?1 AND conversation_counted=1 ORDER BY updated_at DESC")?;
        let conversations=statement.query_map([user],|row|Ok(json!({"conversation_id":row.get::<_,String>(0)?,"title":row.get::<_,String>(1)?,"message_count":row.get::<_,i64>(2)?,"updated_at":row.get::<_,i64>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        value["conversations"] = json!(conversations);
    }
    Ok(value)
}
async fn reset_statistics(State(app): State<Shared>, Json(input): Json<Value>) -> ApiResult {
    let user = input["user_name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "缺少用户"))?;
    let mut db = app.db.lock().await;
    let tx = db.conn.transaction()?;
    tx.execute(
        "DELETE FROM conversation_statistics WHERE user_name=?1",
        [user],
    )?;
    tx.execute(
        "DELETE FROM conversation_model_statistics WHERE user_name=?1",
        [user],
    )?;
    tx.commit()?;
    Ok(Json(json!({"message":"统计已重置"})))
}

fn token_from(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = headers.get("x-mirror-token").and_then(|v| v.to_str().ok()) {
        return Some(token.into());
    }
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|p| p.trim().strip_prefix("mirror_token=").map(str::to_owned))
        })
}
struct Session {
    user: String,
    account: String,
    policy: Option<Policy>,
    token_hash: String,
    credential_binding: String,
    outbound: egress::Egress,
    /// 匿名会话（`login_mode = anonymous`）：上游凭据来自全局共享匿名身份。
    anonymous: bool,
    /// ACL 身份：mirror profile 为 Django 可信身份，original profile 为本地 user_name；
    /// 匿名会话与访客为 None（资源路径一律拒绝）。
    identity: Option<Identity>,
    /// 稳定上游账号键（Django `ChatgptAccount.pk`）；老会话/匿名会话为 None。
    account_id: Option<String>,
}
async fn session(app: &App, token: &str) -> Result<Option<Session>> {
    let hash = sha256_hex(token);
    let db = app.db.lock().await;
    let record:Option<(String,String,String,String,String,Option<String>)>=db.conn.query_row("SELECT user_name,chatgpt_username,access_token,extra_cookies,login_mode,chatgpt_account_id FROM gateway_sessions WHERE mirror_token=?1",[&hash],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
    let Some((user, account, encrypted, cookies, login_mode, account_id)) = record else {
        return Ok(None);
    };
    let authorization: Option<(String,i64)> = db.conn.query_row(
        "SELECT payload,expires_at FROM rust_authorizations WHERE token_hash=?1", [&hash],
        |row|Ok((row.get(0)?,row.get(1)?))).optional()?;
    let Some((authorization, expiry)) = authorization else { return Ok(None); };
    if expiry <= now() { return Ok(None); }
    let payload: Value = serde_json::from_str(&db.decrypt(&authorization)?)?;
    let credential_binding = sha256_hex(&json!([account,db.decrypt(&encrypted)?,db.decrypt(&cookies)?]).to_string());
    if payload["rust_credential_binding"].as_str()!=Some(credential_binding.as_str()) { return Ok(None); }
    let node: Option<i64> = db.conn.query_row("SELECT proxy_node_id FROM gateway_sessions WHERE mirror_token=?1",[&hash],|row|row.get(0))?;
    let outbound = egress::load(&db, &app.config, node)?;
    if payload["rust_egress_binding"].as_str()!=Some(outbound.binding.as_str()) { return Ok(None); }
    let policy = if app.config.mirror_profile {
        Some(Policy::from_login(&payload)?)
    } else {
        None
    };
    // ACL 身份：mirror profile 由 Django 每请求复验；original profile 信任本地
    // 镜像会话本身（与原始网关按 user_name 判定归属一致）。匿名/访客没有身份。
    let identity = if login_mode == anonymous::LOGIN_MODE {
        None
    } else if app.config.mirror_profile {
        identity_from_payload(&payload)?
    } else {
        Some(Identity::local(&user)?)
    };
    let value = Session {
        user,
        account,
        policy,
        token_hash: hash,
        credential_binding,
        outbound,
        anonymous: login_mode == anonymous::LOGIN_MODE,
        identity,
        account_id,
    };
    drop(db);
    // 访客与匿名会话没有可固定的 ACL 身份：mirror profile 下仍需每请求确认固定
    // Django 源继续判其为同一有效访客，避免撤权后旧会话继续使用账号级路径。
    let subject = value.policy.as_ref().map(|policy| policy.user_name.clone());
    if let (Some(policy), Some(subject)) = (&value.policy, subject) {
        let res = app
            .client
            .post(app.config.django.join("/0x/user/gateway-authorization")?)
            .bearer_auth(&app.config.secret)
            .json(&json!({"authorization":policy.authorization,"subject":policy.user_name}))
            .send()
            .await?;
        if !res.status().is_success() {
            return Ok(None);
        }
        let details: Value = res.json().await?;
        // 有身份的资源会话复验三字段 + subject；访客只确认仍是同一有效访客。
        // 两条路径都从固定 Django 源读取，任一变化都拒绝旧会话，不静默升权。
        let verified = match &value.identity {
            Some(identity) => {
                RequestIdentity::verify(identity, &details, &subject, now()).is_ok()
            }
            None => crate::resource_acl::verify_visitor(
                &details,
                &subject,
                &policy.version,
                now(),
            )
            .is_ok(),
        };
        if !verified {
            return Ok(None);
        }
    }
    if !session_binding_current(app, &value).await? { return Ok(None); }
    Ok(Some(value))
}

async fn session_binding_current(app: &App, session: &Session) -> Result<bool> {
    let db = app.db.lock().await;
    let node: Option<Option<i64>> = db.conn.query_row(
        "SELECT proxy_node_id FROM gateway_sessions WHERE mirror_token=?1 AND user_name=?2 AND chatgpt_username=?3",
        params![session.token_hash,session.user,session.account],|row|row.get(0)).optional()?;
    let Some(node) = node else { return Ok(false); };
    Ok(egress::binding(&db,&app.config,node)?==session.outbound.binding)
}
#[derive(Deserialize)]
struct Handoff {
    user_gateway_token: String,
}
async fn handoff(
    State(app): State<Shared>,
    Query(v): Query<Handoff>,
) -> std::result::Result<Response, ApiError> {
    if session(&app, &v.user_gateway_token).await?.is_none() {
        return Err(error(StatusCode::UNAUTHORIZED, "未登录"));
    }
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let old = sha256_hex(&v.user_gateway_token);
    let new = sha256_hex(&token);
    let mut db = app.db.lock().await;
    let tx = db.conn.transaction()?;
    let changed = tx.execute(
        "UPDATE gateway_sessions SET mirror_token=?1,updated_at=?2 WHERE mirror_token=?3",
        params![new, now(), old],
    )?;
    if changed != 1 {
        return Err(error(StatusCode::UNAUTHORIZED, "未登录"));
    }
    tx.execute(
        "UPDATE rust_authorizations SET token_hash=?1 WHERE token_hash=?2",
        params![new, old],
    )?;
    tx.commit()?;
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert("location", HeaderValue::from_static("/"));
    session_cookies(&mut response, &token, app.config.cookie_secure)?;
    Ok(response)
}
/// 上游 next-auth 命名空间的本地兼容面：未登录前端自带的 next-auth 客户端在进入
/// 对话前会访问这几个端点。2026-09-23 直连实测（evidence/anonymous-nextauth-001）：
/// `providers` 是四个 oauth 条目、`csrf` 是 64 位十六进制 token、`_log` 空正文 200、
/// `error` 是站点错误页 200。镜像只补齐形状：不创建登录态、不做访客会话引导、
/// 不下发上游 cookie；`signinUrl`/`callbackUrl` 改写为同源相对路径，避免跳出镜像。
const AUTH_PROVIDER_IDS: [&str; 4] = [
    "openai",
    "openai-dev",
    "openai-sidetron",
    "openai-sidetron-dev",
];

/// `/api/auth/_log` 请求体上限：该端点只上报客户端日志，读取后丢弃；
/// 设上限避免匿名请求用超大正文占用内存。
const AUTH_LOG_BODY_LIMIT: usize = 64 * 1024;

/// `/api/auth/error` 的本地最小错误页。上游返回的是整站页面，这里只保留同源提示，
/// 不引用任何上游资源，也不回显请求参数。
const AUTH_ERROR_PAGE: &str = "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>ChatGPT</title></head><body><p>此镜像未提供 ChatGPT 账号登录（NextAuth）流程，请返回 <a href=\"/\">首页</a>。</p></body></html>";

async fn auth_providers() -> Json<Value> {
    let mut providers = serde_json::Map::new();
    for id in AUTH_PROVIDER_IDS {
        providers.insert(
            id.to_owned(),
            json!({
                "id": id,
                "name": id,
                "type": "oauth",
                "signinUrl": format!("/api/auth/signin/{id}"),
                "callbackUrl": format!("/api/auth/callback/{id}"),
            }),
        );
    }
    Json(Value::Object(providers))
}

async fn auth_csrf() -> Json<Value> {
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
    Json(json!({"csrfToken": token}))
}

async fn auth_log(body: Body) -> Response {
    // 上游实测返回 200 空正文；日志体读取后丢弃。读取失败（超限或连接中断）同样
    // 返回 200：该端点是客户端的尽力上报，没有需要回传客户端的语义。
    let _ = to_bytes(body, AUTH_LOG_BODY_LIMIT).await;
    StatusCode::OK.into_response()
}

async fn auth_error() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        AUTH_ERROR_PAGE,
    )
        .into_response()
}

async fn auth_session(State(app): State<Shared>, headers: HeaderMap) -> ApiResult {
    let Some(token) = token_from(&headers) else {
        return Ok(Json(json!({})));
    };
    let Some(s) = session(&app, &token).await? else {
        return Ok(Json(json!({})));
    };
    // 匿名会话没有可刷新的上游账号；返回空会话对象，前端按未登录界面渲染。
    if s.anonymous {
        return Ok(Json(json!({})));
    }
    let refreshed = proxy::refresh_auth_session(&app, &s, &token).await.map_err(|cause| {
        tracing::warn!(error=%cause, "auth session upstream refresh failed");
        error(StatusCode::BAD_GATEWAY, "上游会话刷新失败")
    })?;
    let Some((mode, plan)) = refreshed else {
        return Ok(Json(json!({})));
    };
    // Revocation or re-login while awaiting upstream must invalidate this result.
    if session(&app, &token).await?.is_none() {
        return Ok(Json(json!({})));
    }
    let id = sha256_hex(&s.account)
        .trim_start_matches("sha256:")
        .to_owned();
    Ok(Json(
        json!({"authProvider":"openai","expires":"2099-12-31T23:59:59.000Z","loginMode":mode,"planType":plan,"user":{"email":s.account,"id":id,"name":s.account,"image":null,"picture":null}}),
    ))
}
async fn user_blocked(State(app): State<Shared>, headers: HeaderMap) -> ApiResult {
    let t = token_from(&headers).ok_or_else(|| error(StatusCode::UNAUTHORIZED, "未登录"))?;
    let s = session(&app, &t)
        .await?
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "未登录"))?;
    let forced: bool = app.db.lock().await.conn.query_row(
        "SELECT force_chat_mode FROM gateway_sessions WHERE user_name=?1 AND chatgpt_username=?2",
        params![s.user, s.account],
        |r| r.get(0),
    )?;
    let value = blocked_value(&app).await?;
    Ok(Json(
        json!({"force_chat_mode":forced,"paths":value["paths"]}),
    ))
}
async fn refresh_cfbypass(State(app): State<Shared>, headers: HeaderMap) -> ApiResult {
    let t = token_from(&headers).ok_or_else(|| error(StatusCode::UNAUTHORIZED, "未登录"))?;
    if session(&app, &t).await?.is_none() {
        return Err(error(StatusCode::UNAUTHORIZED, "未登录"));
    }
    app.cloudflare.force(&app).await?;
    Ok(Json(json!({"message":"cookies 已更新"})))
}

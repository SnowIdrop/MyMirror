// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/management.rs
// Created : 2026-09-22
// Summary : 六个管理端点的行为实现（get-mirror-token / get-user-use-count /
//           get-chatgpt-use-count / close-chatgpt-memory /
//           political-moderation-config[/test]）。
// 证据来源：QEMU 无网隔离 guest 的原版运行时观测
//           evidence/management-v3-original-005（含 001-004 的早期轮次）；
//           静态证据见 reverse/reports/03-gateway-static-analysis.md §7/§9/§12
//           与 08-reconstruction-notes.md §10.5/§10.6。
// -----------------------------------------------------------------------------

//! 管理端点子模块（挂载于 `server`，由父模块 `mod management;` + `any(...)` 接线）。
//!
//! 与父模块共享 `App`/`Shared`/`ApiError`/`error`/`now`：未观测到的公共 helper
//! 一律不新增到父文件，缺口以“接线需求”形式回报主代理。
//!
//! 响应 `vary` 说明：vary 与压缩由父模块的统一中间件负责（`private_headers`
//! 写 `Cookie, Authorization`，`compression::compress` 按阈值/内容类型追加
//! `accept-encoding` 并执行真正的 gzip 编码）；本模块不再自行模拟压缩层行为。

use super::*;
use anyhow::Context;
use rand::RngCore;
use rusqlite::{params, params_from_iter, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// `/api/not-login?user_gateway_token=` 前缀（原版 0xd87a?? 邻域字面量）。
const LOGIN_URL_PREFIX: &str = "/api/not-login?user_gateway_token=";

/// 统一 JSON 响应：vary 与压缩全部交给父模块中间件，这里只产出正文与 content-type。
fn json_response(value: Value) -> Response {
    Json(value).into_response()
}

/// 管理端 JSON 错误响应：状态码自定；vary 与压缩同样由父模块中间件统一处理。
fn json_message(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

/// 管理端点统一返回类型（父模块接线时直接用于 `any(...)`）。
type MgmtResult = std::result::Result<Response, ApiError>;

// ---------------------------------------------------------------------------
// /api/get-mirror-token
// ---------------------------------------------------------------------------

/// 观测：7 个字段；`user_name`/`chatgpt_list` 必填，其余带默认值
/// （isolated_session 默认 false、force_chat_mode 默认 true，实测写库值）。
#[derive(Deserialize, serde::Serialize)]
pub(super) struct MirrorTokenRequest {
    user_name: String,
    chatgpt_list: Vec<String>,
    #[serde(default)]
    isolated_session: bool,
    #[serde(default = "default_force_chat_mode")]
    force_chat_mode: bool,
    #[serde(default)]
    limits: Vec<Value>,
    #[serde(default)]
    daily_quota: u64,
    #[serde(default)]
    monthly_quota: u64,
    #[serde(flatten)]
    options: Map<String, Value>,
}

/// 观测：mirror-token 未传 force_chat_mode 时写库为 TRUE（login 默认同为 true）。
fn default_force_chat_mode() -> bool {
    true
}

/// 为指定 ChatGPT 账号签发/轮换网关登录态，返回 login_url 列表。
pub(super) async fn mirror_token(
    State(app): State<Shared>,
    Json(input): Json<MirrorTokenRequest>,
) -> MgmtResult {
    // 观测：user_name 用 trim 后是否为空做门槛，但写库保留原值（DB 出现 " alice "）。
    if input.user_name.trim().is_empty()
        || input.chatgpt_list.iter().all(|item| item.trim().is_empty())
    {
        return Ok(json_message(
            StatusCode::BAD_REQUEST,
            "user_name 和 chatgpt_list 不能为空",
        ));
    }
    let mut policies = std::collections::HashMap::new();
    if app.config.mirror_profile {
        for account in input
            .chatgpt_list
            .iter()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
        {
            let mut payload = serde_json::to_value(&input).context("序列化授权载荷失败")?;
            let model_policy = input
                .options
                .get("model_policies")
                .and_then(|policies| policies.get(account.to_lowercase()))
                .and_then(Value::as_object)
                .context("Django 缺少账号模型策略")?;
            for field in ["model_isolation", "model_allowed_ids", "model_rate_limits"] {
                payload[field] = model_policy
                    .get(field)
                    .with_context(|| format!("Django 缺少 {field}"))?
                    .clone();
            }
            let expiry = authorize_login_payload(&app, &mut payload).await?;
            policies.insert(account.to_owned(), (payload, expiry));
        }
    }
    let limits = serde_json::to_string(&input.limits).context("序列化 limits 失败")?;
    let time = now();
    let mut db = app.db.lock().await;
    let Database { conn, crypto } = &mut *db;
    let tx = conn.transaction()?;
    let mut issued = Vec::new();
    // 观测：按 chatgpt_list 顺序逐项处理（重复项重复签发、空白项跳过、大小写敏感）。
    for item in &input.chatgpt_list {
        let account = item.trim();
        if account.is_empty() {
            continue;
        }
        let credentials: Option<(String, Option<String>, String)> = tx
            .query_row(
                "SELECT access_token, session_token, COALESCE(extra_cookies, '[]') \
                 FROM chatgpt_accounts WHERE chatgpt_username = ?1 AND auth_status = TRUE LIMIT 1",
                [account],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        // 观测：账号未入库或 auth_status 非 TRUE 时不产出条目（不是报错）。
        let Some((access_raw, session_raw, cookies_raw)) = credentials else {
            continue;
        };
        // encrypt 对 enc:v1: 输入幂等、对存量明文行就地加密，与 login 写入同义。
        let access = crypto.encrypt(&access_raw)?;
        let session = match session_raw {
            Some(raw) => Some(crypto.encrypt(&raw)?),
            None => None,
        };
        let cookies = crypto.encrypt(&cookies_raw)?;
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let token: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let hash = sha256_hex(&token);
        // 观测：已存在 (user_name, chatgpt_username) 行时轮换 token 并更新
        // updated_at，created_at 保持不变。
        tx.execute("DELETE FROM rust_authorizations WHERE token_hash IN (SELECT mirror_token FROM gateway_sessions WHERE user_name=?1 AND chatgpt_username=?2)", params![input.user_name, account])?;
        tx.execute(
            "INSERT INTO gateway_sessions (user_name, chatgpt_username, access_token, \
             session_token, extra_cookies, login_mode, mirror_token, isolated_session, \
             force_chat_mode, limits, proxy_node_id, daily_quota, monthly_quota, created_at, \
             updated_at) VALUES (?1,?2,?3,?4,?5,'api',?6,?7,?8,?9,NULL,?10,?11,?12,?12) \
             ON CONFLICT(user_name, chatgpt_username) DO UPDATE SET \
             access_token=excluded.access_token, session_token=excluded.session_token, \
             extra_cookies=excluded.extra_cookies, login_mode=excluded.login_mode, \
             mirror_token=excluded.mirror_token, isolated_session=excluded.isolated_session, \
             force_chat_mode=excluded.force_chat_mode, limits=excluded.limits, \
             daily_quota=excluded.daily_quota, monthly_quota=excluded.monthly_quota, \
             updated_at=excluded.updated_at",
            params![
                &input.user_name,
                account,
                access,
                session,
                cookies,
                hash,
                input.isolated_session,
                input.force_chat_mode,
                limits,
                input.daily_quota,
                input.monthly_quota,
                time
            ],
        )?;
        if let Some((payload, expiry)) = policies.get(account) {
            tx.execute(
                "INSERT INTO rust_authorizations(token_hash,payload,expires_at) VALUES(?1,?2,?3)",
                params![hash, crypto.encrypt(&payload.to_string())?, expiry],
            )?;
        }
        // 观测：响应条目只有这三个键，login_mode 恒为刚写入的 'api'。
        issued.push(json!({
            "chatgpt_username": account,
            "login_mode": "api",
            "login_url": format!("{LOGIN_URL_PREFIX}{token}"),
        }));
    }
    tx.commit()?;
    Ok(json_response(Value::Array(issued)))
}

// ---------------------------------------------------------------------------
// /api/get-user-use-count、/api/get-chatgpt-use-count
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct UserUseCountRequest {
    username_list: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct ChatgptUseCountRequest {
    chatgpt_list: Vec<String>,
}

/// 观测：无论真实模型如何，响应内层键恒为 "gpt-4o"（空库、命中、未知用户均如此）。
const USE_COUNT_MODEL_LABEL: &str = "gpt-4o";

/// 观测：一次查询同时取 1/2/3/4 小时四个互斥窗口（SQL 见报告 §9 的 SUM(CASE) 语句）。
const USE_COUNT_SQL: &str = "SELECT \
     COALESCE(SUM(CASE WHEN created_at >= ?1 THEN 1 ELSE 0 END), 0), \
     COALESCE(SUM(CASE WHEN created_at >= ?2 AND created_at < ?1 THEN 1 ELSE 0 END), 0), \
     COALESCE(SUM(CASE WHEN created_at >= ?3 AND created_at < ?2 THEN 1 ELSE 0 END), 0), \
     COALESCE(SUM(CASE WHEN created_at >= ?4 AND created_at < ?3 THEN 1 ELSE 0 END), 0) \
     FROM visit_logs WHERE ";

/// 按 `username_list` 聚合访问日志（不区分 log_type，观测：chat 行同样计入）。
pub(super) async fn user_use_count(
    State(app): State<Shared>,
    Json(input): Json<UserUseCountRequest>,
) -> MgmtResult {
    let db = app.db.lock().await;
    let counts = aggregate_use_count(&db, "username", &input.username_list)?;
    Ok(json_response(counts))
}

/// 按 `chatgpt_list` 聚合访问日志（列 = visit_logs.chatgpt_username）。
pub(super) async fn chatgpt_use_count(
    State(app): State<Shared>,
    Json(input): Json<ChatgptUseCountRequest>,
) -> MgmtResult {
    let db = app.db.lock().await;
    let counts = aggregate_use_count(&db, "chatgpt_username", &input.chatgpt_list)?;
    Ok(json_response(counts))
}

/// 逐键聚合：空白键跳过（观测 {} 响应）、重复键合并、键序 = 字典序（BTreeMap）。
fn aggregate_use_count(db: &Database, column: &'static str, keys: &[String]) -> Result<Value> {
    // 列名由 &'static str 约束为调用点字面量，请求内容不会进入 SQL。
    let sql = format!("{USE_COUNT_SQL}{column} = ?5");
    let time = now();
    let mut result = Map::new();
    for key in keys {
        if key.trim().is_empty() {
            continue;
        }
        let windows: (i64, i64, i64, i64) = db.conn.query_row(
            &sql,
            params![time - 3600, time - 7200, time - 10800, time - 14400, key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        let mut models = Map::new();
        models.insert(
            USE_COUNT_MODEL_LABEL.to_string(),
            json!({
                "last_1h": windows.0,
                "last_2h": windows.1,
                "last_3h": windows.2,
                "last_4h": windows.3,
            }),
        );
        result.insert(key.clone(), Value::Object(models));
    }
    Ok(Value::Object(result))
}

// ---------------------------------------------------------------------------
// /api/close-chatgpt-memory
// ---------------------------------------------------------------------------

/// 观测：4 个字段全部可缺省；`user_name`/`chatgpt_name`/`chatgpt_username`/
/// `mirror_token` 四个键都真实存在（整数探针得到 422）。
#[derive(Deserialize)]
pub(super) struct CloseChatgptMemoryRequest {
    #[serde(default)]
    user_name: String,
    #[serde(default)]
    chatgpt_name: String,
    #[serde(default)]
    chatgpt_username: String,
    #[serde(default)]
    mirror_token: String,
}

/// 关闭（删除）匹配的网关登录态，返回删除行数。
pub(super) async fn close_chatgpt_memory(
    State(app): State<Shared>,
    Json(input): Json<CloseChatgptMemoryRequest>,
) -> MgmtResult {
    // 观测：trim 结果只用于判空；实际比较用原值（" alice " 不匹配 "alice"、
    // " <token> " 不匹配该 token），镜像原版 trim_matches 后仍绑原串的写法。
    let mut clauses = Vec::new();
    let mut binds: Vec<rusqlite::types::Value> = Vec::new();
    if !input.mirror_token.trim().is_empty() {
        clauses.push("mirror_token = ?");
        binds.push(rusqlite::types::Value::Text(sha256_hex(
            &input.mirror_token,
        )));
    }
    if !input.user_name.trim().is_empty() {
        clauses.push("user_name = ?");
        binds.push(rusqlite::types::Value::Text(input.user_name.clone()));
    }
    if !input.chatgpt_name.trim().is_empty() {
        clauses.push("chatgpt_username = ?");
        binds.push(rusqlite::types::Value::Text(input.chatgpt_name.clone()));
    }
    if !input.chatgpt_username.trim().is_empty() {
        clauses.push("chatgpt_username = ?");
        binds.push(rusqlite::types::Value::Text(input.chatgpt_username.clone()));
    }
    // 观测：全部字段为空时返回 0 且不动库（语句构造被跳过）。
    let affected = if clauses.is_empty() {
        0
    } else {
        let sql = format!(
            "DELETE FROM gateway_sessions WHERE {}",
            clauses.join(" OR ")
        );
        let mut db = app.db.lock().await;
        let tx = db.conn.transaction()?;
        tx.execute(&format!("DELETE FROM rust_authorizations WHERE token_hash IN (SELECT mirror_token FROM gateway_sessions WHERE {})", clauses.join(" OR ")), params_from_iter(binds.iter()))?;
        let affected = tx.execute(&sql, params_from_iter(binds.iter()))?;
        tx.commit()?;
        affected
    };
    Ok(json_response(
        json!({"affected": affected, "message": "ok"}),
    ))
}

// ---------------------------------------------------------------------------
// /api/political-moderation-config 与 /api/political-moderation-config/test
// ---------------------------------------------------------------------------

/// 观测：10 个字段；必填 protocol/model/base_url/mode，其余有默认值
/// （enabled=false、api_key=""、custom_terms=[]、限流 10/30/120）。
#[derive(Deserialize)]
pub(super) struct PoliticalModerationConfigRequest {
    #[serde(default)]
    enabled: bool,
    protocol: String,
    model: String,
    #[serde(default)]
    api_key: String,
    base_url: String,
    mode: String,
    #[serde(default)]
    custom_terms: Vec<String>,
    #[serde(default = "default_limit_per_minute")]
    limit_per_minute: u32,
    #[serde(default = "default_limit_per_five_minutes")]
    limit_per_five_minutes: u32,
    #[serde(default = "default_limit_per_hour")]
    limit_per_hour: u32,
}

fn default_limit_per_minute() -> u32 {
    10
}

fn default_limit_per_five_minutes() -> u32 {
    30
}

fn default_limit_per_hour() -> u32 {
    120
}

/// 落库/复用的配置快照（与存储 JSON 的 10 个键一一对应）。
#[derive(serde::Serialize, Deserialize)]
struct PoliticalModerationConfig {
    enabled: bool,
    protocol: String,
    model: String,
    api_key: String,
    base_url: String,
    mode: String,
    custom_terms: Vec<String>,
    limit_per_minute: u32,
    limit_per_five_minutes: u32,
    limit_per_hour: u32,
}

impl Default for PoliticalModerationConfig {
    /// 观测：空库 GET 的默认值（protocol/model/base_url/mode/limits/custom_terms）。
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: "openai_chat".into(),
            model: String::new(),
            api_key: String::new(),
            base_url: "https://api.openai.com/v1".into(),
            mode: "relaxed".into(),
            custom_terms: Vec::new(),
            limit_per_minute: default_limit_per_minute(),
            limit_per_five_minutes: default_limit_per_five_minutes(),
            limit_per_hour: default_limit_per_hour(),
        }
    }
}

impl PoliticalModerationConfig {
    fn from_request(
        input: PoliticalModerationConfigRequest,
        api_key: String,
        base_url: String,
    ) -> Self {
        Self {
            enabled: input.enabled,
            protocol: input.protocol,
            model: input.model,
            api_key,
            base_url,
            mode: input.mode,
            custom_terms: input.custom_terms,
            limit_per_minute: input.limit_per_minute,
            limit_per_five_minutes: input.limit_per_five_minutes,
            limit_per_hour: input.limit_per_hour,
        }
    }

    /// 观测：GET 与保存响应共用同一视图；`api_key` 只以 `api_key_configured`
    /// 暴露；`latency_ms` 在全部观测中均为 null。
    fn view(&self) -> Value {
        json!({
            "api_key_configured": !self.api_key.is_empty(),
            "base_url": self.base_url,
            "custom_terms": self.custom_terms,
            "enabled": self.enabled,
            "latency_ms": Value::Null,
            "limit_per_five_minutes": self.limit_per_five_minutes,
            "limit_per_hour": self.limit_per_hour,
            "limit_per_minute": self.limit_per_minute,
            "message": "政治敏感内容屏蔽配置已保存",
            "mode": self.mode,
            "model": self.model,
            "protocol": self.protocol,
        })
    }
}

/// 读取已存配置；未写入时返回 None（GET 用默认值）。
async fn stored_moderation_config(app: &App) -> Result<Option<PoliticalModerationConfig>> {
    let stored = app.db.lock().await.get_setting("political_moderation")?;
    let Some(value) = stored else {
        return Ok(None);
    };
    let stored = serde_json::from_value::<PoliticalModerationConfig>(value)
        .context("political_moderation 配置损坏")?;
    Ok(Some(stored))
}

/// 观测：GET 恒为 200 且带 `message`；method 路由为 get(...)+post(...)。
pub(super) async fn political_moderation_config_get(State(app): State<Shared>) -> MgmtResult {
    let config = stored_moderation_config(&app).await?.unwrap_or_default();
    Ok(json_response(config.view()))
}

/// 观测：合法协议名恰为这四个（`generate_content`/`gemini_generate_`/空串均被拒）。
fn is_supported_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        "openai_chat" | "openai_responses" | "anthropic_messages" | "gemini_generate_content"
    )
}

/// 观测：mode 只接受 relaxed/strict。
fn is_supported_mode(mode: &str) -> bool {
    matches!(mode, "relaxed" | "strict")
}

/// 观测的 Base URL 规则：语法必须可解析（否则“格式无效”）、必须是 https、且无
/// 账号、查询参数与片段；落库文本按原版只做 trim + 去尾部斜杠，同时返回解析
/// 结果供探测阶段复用（避免重复解析）。
fn normalize_base_url(raw: &str) -> std::result::Result<(String, url::Url), &'static str> {
    let trimmed = raw.trim();
    let url = url::Url::parse(trimmed).map_err(|_| "Base URL 格式无效")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Base URL 必须是无账号、查询参数和片段的 HTTPS 地址");
    }
    Ok((trimmed.trim_end_matches('/').to_string(), url))
}

/// 观测的校验顺序：protocol → mode → Base URL 语法/形状 →（enabled 时）密钥非空。
fn validate_moderation_request(
    input: &PoliticalModerationConfigRequest,
) -> std::result::Result<(String, url::Url), &'static str> {
    if !is_supported_protocol(&input.protocol) {
        return Err("不支持的审查 API 格式");
    }
    if !is_supported_mode(&input.mode) {
        return Err("审查模式只能是 relaxed 或 strict");
    }
    normalize_base_url(&input.base_url)
}

/// 保存配置；观测：enabled=true 必须先通过连通性/校准校验，失败不落库。
pub(super) async fn political_moderation_config_save(
    State(app): State<Shared>,
    Json(input): Json<PoliticalModerationConfigRequest>,
) -> MgmtResult {
    let (base_url, parsed_base) = match validate_moderation_request(&input) {
        Ok(validated) => validated,
        Err(reason) => return Ok(json_message(StatusCode::BAD_REQUEST, reason)),
    };
    if input.enabled {
        if input.api_key.trim().is_empty() {
            return Ok(json_message(StatusCode::BAD_REQUEST, "API 密钥不能为空"));
        }
        return Err(provider_gate(&parsed_base));
    }
    // 观测：空 api_key 仅在 Base URL 与原值完全一致时沿用已存密钥，
    // 换地址则丢弃（避免把 A 家密钥带给 B 家）。
    let stored = stored_moderation_config(&app).await?;
    let api_key = if input.api_key.trim().is_empty() {
        match stored {
            Some(previous) if previous.base_url == base_url => previous.api_key,
            _ => String::new(),
        }
    } else {
        input.api_key.clone()
    };
    let config = PoliticalModerationConfig::from_request(input, api_key, base_url);
    // 观测：整值以 enc:v1: 密文落在 gateway_settings（storage 已处理该键）。
    app.db.lock().await.set_setting(
        "political_moderation",
        &serde_json::to_value(&config).context("序列化审核配置失败")?,
    )?;
    Ok(json_response(config.view()))
}

/// 测试接口；观测：不校验密钥/模型非空，校验后立即发起连通性请求且不落库。
pub(super) async fn political_moderation_config_test(
    State(_app): State<Shared>,
    Json(input): Json<PoliticalModerationConfigRequest>,
) -> MgmtResult {
    let (_, parsed_base) = match validate_moderation_request(&input) {
        Ok(validated) => validated,
        Err(reason) => return Ok(json_message(StatusCode::BAD_REQUEST, reason)),
    };
    Err(provider_gate(&parsed_base))
}

/// 原版拒绝回环审核地址；本地 TLS 观测还在证书信任阶段被拒绝，未取得成功协议。
/// 公开保留未完成门禁，不把“未拨号”伪报为连接失败，也不保留猜测的 provider 载荷。
fn provider_gate(base: &url::Url) -> ApiError {
    let loopback = matches!(base.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(base.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    if loopback {
        error(
            StatusCode::BAD_REQUEST,
            "模型连通性验证失败: 审查模型地址必须解析到公网 IP",
        )
    } else {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "审核上游成功契约尚未验证；隔离传输不允许公网请求",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_rules_match_observed_messages() {
        assert_eq!(
            normalize_base_url("not-a-url").map(|value| value.0),
            Err("Base URL 格式无效")
        );
        assert!(normalize_base_url("").is_err());
        assert_eq!(
            normalize_base_url("http://93.184.216.34/v1").map(|value| value.0),
            Err("Base URL 必须是无账号、查询参数和片段的 HTTPS 地址")
        );
        assert!(normalize_base_url("https://user:pass@93.184.216.34/v1").is_err());
        assert!(normalize_base_url("https://93.184.216.34/v1?x=1").is_err());
        assert!(normalize_base_url("https://93.184.216.34/v1#frag").is_err());
        // 观测：空用户名信息、大小写 scheme、空格与尾部斜杠都被接受并归一化。
        assert_eq!(
            normalize_base_url("  https://93.184.216.34/v1//  ")
                .unwrap()
                .0,
            "https://93.184.216.34/v1"
        );
        assert_eq!(
            normalize_base_url("HTTPS://93.184.216.34/v1").unwrap().0,
            "HTTPS://93.184.216.34/v1"
        );
        assert_eq!(
            normalize_base_url("https://@93.184.216.34/v1").unwrap().0,
            "https://@93.184.216.34/v1"
        );
    }

    #[test]
    fn protocol_and_mode_whitelists_match_observed_rejections() {
        assert!(is_supported_protocol("openai_chat"));
        assert!(is_supported_protocol("openai_responses"));
        assert!(is_supported_protocol("anthropic_messages"));
        assert!(is_supported_protocol("gemini_generate_content"));
        assert!(!is_supported_protocol("generate_content"));
        assert!(!is_supported_protocol("gemini_generate_"));
        assert!(!is_supported_protocol(""));
        assert!(is_supported_mode("relaxed"));
        assert!(is_supported_mode("strict"));
        assert!(!is_supported_mode("lenient"));
    }
}

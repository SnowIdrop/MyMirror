// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/cloudflare.rs
// Created : 2026-09-23
// Summary : Cloudflare 边缘状态与凭据类上游调用的挑战重试策略。
//           原版在 session_token → access_token 换取路径上不刷新 cfbypass、也不重放，
//           CF 的 403 拦截页被当成 token 校验失败上报（报告 07 §3 粘连文案
//           `session_token 校验失败: api/auth/session 返回状态 `）。
//           本模块是替代网关的有意偏离：注入整组 CF cookies，命中实测挑战时刷新
//           一次并重放一次，仍被拦截则按“上游被拦截”返回，绝不回传上游正文。
// 证据来源：2026-09-23 本机真实上游实测（本地 cfbypass + chatgpt.com）
//           - 不带 Cloudflare cookies 直连返回 403 + `cf-mitigated: challenge`；
//           - cfbypass 只透出 cf_clearance/__cf_bm/__cflb/_cfuvid（报告 02 §1.3）。
// -----------------------------------------------------------------------------

//! 本地不变式：
//! - 只透出 cfbypass 白名单 cookie，旁站返回的其它名字一律丢弃；
//! - 冷却窗口只约束“因挑战自动触发”的刷新，启动预热、管理端点刷新与匿名身份获取不受限；
//! - 上游正文只用于本地判定，绝不写入响应、日志或错误消息。

use super::*;
use bytes::Bytes;
use serde::de::DeserializeOwned;
use std::time::{Duration, Instant};

/// cfbypass 白名单（报告 02 §1.3：只透出这四个 Cloudflare cookie）。
pub(super) const CLOUDFLARE_COOKIE_NAMES: [&str; 4] =
    ["cf_clearance", "__cf_bm", "__cflb", "_cfuvid"];

/// 挑战驱动刷新的冷却秒数：持续拦截时避免每次请求都拉起一次 cfbypass 浏览器。
const REFRESH_COOLDOWN_SECS: u64 = 30;

/// 连接类失败后、重放之前的等待毫秒数：让客户端连接池先淘汰那条已失败的连接。
const RETRY_SETTLE_MILLIS: u64 = 200;

/// 挑战驱动刷新的结论：既决定是否重放，也用于生成不含上游正文的错误说明。
#[derive(Debug)]
pub(super) enum RefreshOutcome {
    /// 已刷新（含复用并发刷新的结果）：调用方可以重放一次。
    Refreshed,
    /// 未配置 CF_BYPASS_URL。
    NotConfigured,
    /// 距上一次挑战驱动刷新不足冷却窗口。
    CoolingDown,
    /// 刷新失败；原因只来自本地或旁站，不含上游正文。
    Failed(String),
}

/// 凭据校验被 Cloudflare 拦截：独立类型，API 层据此返回 502 + `upstream_blocked`，
/// 而不是把它当成 token 失效。
#[derive(Debug)]
pub(super) struct UpstreamBlocked(String);

impl std::fmt::Display for UpstreamBlocked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UpstreamBlocked {}

/// 上游连接类失败（DNS/连接/TLS 停顿、连接被对端关闭）：与「凭据无效」和「客户端请求有误」
/// 都不是一回事，API 层据此返回 502 + `upstream_unavailable`。
/// 部署环境实测存在偶发失败（20 次探测中 4 次在 ~5 秒后失败），因此幂等 GET 会先自动重试一次。
#[derive(Debug)]
pub(super) struct UpstreamUnavailable(String);

impl std::fmt::Display for UpstreamUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UpstreamUnavailable {}

/// 进程内 CF 状态：白名单 cookies、刷新代次与最近一次挑战驱动刷新时间。
pub(super) struct Cloudflare {
    inner: Mutex<State>,
    refresh: Mutex<()>,
}

#[derive(Default)]
struct State {
    generation: u64,
    cookies: Vec<(String, String)>,
    last_attempt: Option<Instant>,
    /// 最近一次 cfbypass 返回的实测身份：`/api/refresh-cfbypass` 把它交给调用方，
    /// 便于运维核对「取 clearance 的那一跳」与自己是否声称同一个浏览器。
    identity: Option<Value>,
}

impl Cloudflare {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(State::default()),
            refresh: Mutex::new(()),
        }
    }

    /// 发送前读取代次：刷新完成后它能证明“并发期间已有人刷新过”，无需重复拉起浏览器。
    pub(super) async fn generation(&self) -> u64 {
        self.inner.lock().await.generation
    }

    /// 当前可用的 CF cookies（白名单过滤后的副本）。
    pub(super) async fn cookies(&self) -> Vec<(String, String)> {
        self.inner.lock().await.cookies.clone()
    }

    /// 最近一次 cfbypass 实测身份（旧版 cfbypass 不返回时为 `None`）。
    pub(super) async fn identity(&self) -> Option<Value> {
        self.inner.lock().await.identity.clone()
    }

    /// 失效当前 cookies：下一次请求必须重新走 cfbypass 才能通过。冷却计时保持不变。
    pub(super) async fn invalidate(&self) {
        self.inner.lock().await.cookies.clear();
    }

    /// 显式刷新（启动预热、`/api/refresh-cfbypass`、匿名身份获取）：不受冷却限制。
    pub(super) async fn force(&self, app: &App) -> Result<Vec<(String, String)>> {
        let _single_flight = self.refresh.lock().await;
        self.fetch_locked(app).await
    }

    /// 挑战驱动的刷新：并发调用共用一次在途请求，冷却窗口内不重复拉起 cfbypass。
    pub(super) async fn refresh_if_stale(&self, app: &App, observed: u64) -> RefreshOutcome {
        if app.config.cfbypass.is_none() {
            return RefreshOutcome::NotConfigured;
        }
        let _single_flight = self.refresh.lock().await;
        {
            let mut state = self.inner.lock().await;
            if state.generation != observed {
                // 并发调用已完成刷新：直接复用它的结果，不重复拉起浏览器。
                return RefreshOutcome::Refreshed;
            }
            if state
                .last_attempt
                .is_some_and(|started| started.elapsed() < Duration::from_secs(REFRESH_COOLDOWN_SECS))
            {
                return RefreshOutcome::CoolingDown;
            }
            // 失败与成功都算一次尝试，否则持续拦截会退化成每次请求都拉起浏览器。
            state.last_attempt = Some(Instant::now());
        }
        match self.fetch_locked(app).await {
            Ok(_) => RefreshOutcome::Refreshed,
            Err(cause) => RefreshOutcome::Failed(cause.to_string()),
        }
    }

    /// 取一次 cfbypass 并更新状态；调用方必须已持有 `refresh` 锁保证单飞。
    async fn fetch_locked(&self, app: &App) -> Result<Vec<(String, String)>> {
        let payload = fetch_payload(app).await?;
        let cookies = whitelist_cookies(&payload)?;
        let mut state = self.inner.lock().await;
        state.generation += 1;
        state.cookies = cookies.clone();
        state.identity = payload.get("identity").cloned();
        Ok(cookies)
    }
}

/// 调用旁站 cfbypass（原版 `/cloudflare5s/bypass-v1` + `GATEWAY_ADMIN_SECRET` Bearer）。
async fn fetch_payload(app: &App) -> Result<Value> {
    let base = app.config.cfbypass.as_ref().context("CF_BYPASS_URL 未配置")?;
    let result: Value = app
        .client
        .post(base.join("/cloudflare5s/bypass-v1")?.as_str())
        .bearer_auth(&app.config.secret)
        .json(&json!({"url":app.config.upstream.as_str(), "user_agent":identity::USER_AGENT}))
        .send()
        .await
        .context("cfbypass 请求失败")?
        .error_for_status()
        .context("cfbypass 拒绝请求")?
        .json()
        .await
        .context("cfbypass 响应无效")?;
    log_identity_mismatch(&result);
    Ok(result)
}

/// 取 clearance 的那一跳与网关必须声称同一个浏览器身份：`cf_clearance` 绑定
/// IP+UA+浏览器指纹，错配会让两次请求被关联。cfbypass 返回它实测到的身份，
/// 不一致时留痕（日志只记身份字段，不含 cookie 与令牌）。
fn log_identity_mismatch(payload: &Value) {
    let Some(identity) = payload.get("identity").filter(|value| value.is_object()) else {
        // 旧版 cfbypass 没有该字段：不能因此判定错配，但要让运维知道可比对性缺失。
        tracing::warn!(
            module = "gateway",
            "cfbypass 未返回 identity 字段，无法校验该跳的浏览器身份是否与网关一致"
        );
        return;
    };
    let unquoted = |name: &str| identity::hint(name).trim_matches('"').to_owned();
    // 字段路径与 cfbypass 的 `IdentityInfo`/`UserAgentDataInfo` 一一对应。
    // `platform_version` 也比对：Chrome 146 在 Linux 上默认启用
    // `ReduceUserAgentDataLinuxPlatformVersion`，该跳应当报空串；报出内核版本说明镜像里
    // 这个 feature 被关掉（或浏览器不是同一版），属于必须处理的错配。依据
    // `evidence/reference-chrome146-001/04-linux-platform-version.json`。
    for (field, want) in [
        ("user_agent", identity::USER_AGENT.to_owned()),
        ("user_agent_data.full_version", identity::full_version()),
        ("user_agent_data.platform", unquoted("sec-ch-ua-platform")),
        ("user_agent_data.architecture", unquoted("sec-ch-ua-arch")),
        ("user_agent_data.bitness", unquoted("sec-ch-ua-bitness")),
        (
            "user_agent_data.platform_version",
            unquoted("sec-ch-ua-platform-version"),
        ),
    ] {
        let actual = identity
            .pointer(&format!("/{}", field.replace('.', "/")))
            .and_then(Value::as_str);
        // 探测失败的字段是 null：那是 cfbypass 侧的可观测缺陷，不是身份错配。
        if let Some(actual) = actual {
            if actual != want {
                tracing::warn!(
                    module = "gateway",
                    field,
                    expected = %want,
                    actual = %actual,
                    "cfbypass 一跳的浏览器身份与网关声称值不一致"
                );
            }
        }
    }
}

/// 白名单过滤：非数组、缺少 name/value 与未列入白名单的条目一律丢弃。
fn whitelist_cookies(payload: &Value) -> Result<Vec<(String, String)>> {
    let entries = payload["cookies"]
        .as_array()
        .context("cfbypass 响应缺少 cookies 数组")?;
    let mut cookies = Vec::new();
    for entry in entries {
        let Some(name) = entry.get("name").and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        let Some(value) = entry.get("value").and_then(Value::as_str) else {
            continue;
        };
        if CLOUDFLARE_COOKIE_NAMES.contains(&name) && !value.is_empty() {
            cookies.push((name.to_owned(), value.to_owned()));
        }
    }
    anyhow::ensure!(!cookies.is_empty(), "cfbypass 未返回有效的 Cloudflare cookies");
    Ok(cookies)
}

/// 2026-09-23 实测的 Cloudflare 挑战：`403` + `cf-mitigated: challenge`。
pub(super) fn is_challenge(response: &wreq::Response) -> bool {
    response.status() == StatusCode::FORBIDDEN
        && response
            .headers()
            .get("cf-mitigated")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("challenge"))
}

/// 凭据类上游应答：正文已读取，只用于本地判定与错误说明，绝不回传客户端。
pub(super) struct Answer {
    pub(super) status: StatusCode,
    challenged: bool,
    body: Bytes,
    /// 上游可能按我们声明的 `accept-encoding` 压缩；`json()` 需要先解压。
    content_encoding: Option<HeaderValue>,
}

impl Answer {
    /// Cloudflare 边缘拦截：实测挑战，或 `403` 且正文不是 JSON（拦截页是 HTML）。
    pub(super) fn blocked(&self) -> bool {
        self.challenged
            || (self.status == StatusCode::FORBIDDEN
                && serde_json::from_slice::<Value>(&self.body).is_err())
    }

    pub(super) fn json<T: DeserializeOwned>(&self) -> Result<T> {
        let mut headers = HeaderMap::new();
        if let Some(encoding) = &self.content_encoding {
            headers.insert("content-encoding", encoding.clone());
        }
        let plain = crate::server::compression::decode_buffered(&headers, &self.body)
            .context("上游响应解压失败")?;
        serde_json::from_slice(&plain).context("上游响应不是有效 JSON")
    }
}

/// 读取应答正文；挑战标记必须在消费响应前采集。
/// 凭据类应答都是小体积 JSON 或拦截页，来源只有配置的上游，因此整体读入用于本地判定。
pub(super) async fn read(response: wreq::Response) -> Result<Answer> {
    let status = response.status();
    let challenged = is_challenge(&response);
    let content_encoding = response.headers().get("content-encoding").cloned();
    let body = response.bytes().await.context("上游正文读取失败")?;
    Ok(Answer {
        status,
        challenged,
        body,
        content_encoding,
    })
}

/// 幂等 GET 的上游处理：首轮连接失败自动重放一次（`label` 用于生成可行动文案），
/// 首轮命中实测挑战时刷新一次并重放一次。
/// `send` 每次都必须基于同一业务请求重新构造（请求与响应体都已被消费）。
pub(super) async fn get_with_challenge_retry<F, Fut>(
    app: &App,
    label: &str,
    send: F,
) -> Result<(wreq::Response, Option<RefreshOutcome>)>
where
    F: Fn(Vec<(String, String)>) -> Fut,
    Fut: std::future::Future<Output = Result<wreq::Response>>,
{
    let generation = app.cloudflare.generation().await;
    let first = match send(app.cloudflare.cookies().await).await {
        Ok(response) => response,
        Err(cause) => {
            // 出网偶发失败（DNS/连接/TLS 停顿、连接被对端关闭）在本项目的容器部署环境实测存在，
            // 而这些调用都是幂等 GET：重放一次没有副作用，仍失败才按上游不可用上报。
            tracing::warn!(
                module = "gateway",
                error = %format!("{cause:#}"),
                "上游连接失败，自动重试一次"
            );
            // 对端刚落连接时，失败的那条可能还留在客户端连接池里并被重放复用
            // （实测：不加等待时重试仍报同一条 `connection closed before message completed`，
            // 且没有建立新连接）。留一小段时间让池子先淘汰它，再重放。
            tokio::time::sleep(Duration::from_millis(RETRY_SETTLE_MILLIS)).await;
            match send(app.cloudflare.cookies().await).await {
                Ok(response) => response,
                Err(cause) => {
                    tracing::error!(
                        module = "gateway",
                        error = %format!("{cause:#}"),
                        "上游连接重试后仍失败"
                    );
                    return Err(anyhow::Error::new(UpstreamUnavailable(format!(
                        "{label}：上游连接失败，已自动重试一次仍失败，请稍后重试"
                    ))));
                }
            }
        }
    };
    if !is_challenge(&first) {
        return Ok((first, None));
    }
    let outcome = app.cloudflare.refresh_if_stale(app, generation).await;
    if !matches!(outcome, RefreshOutcome::Refreshed) {
        return Ok((first, Some(outcome)));
    }
    let retry = send(app.cloudflare.cookies().await).await?;
    Ok((retry, Some(outcome)))
}

/// 上游 Cookie 头：按传入顺序拼接多组 cookie，同名只保留最先出现的值。
/// 观测顺序要求会话/提交 cookie 在前、CF cookie 在后（proxy-v3-original-006）。
pub(super) fn cookie_header(groups: &[&[(String, String)]]) -> Option<String> {
    let mut names: Vec<&str> = Vec::new();
    let mut pairs = Vec::new();
    for group in groups {
        for (name, value) in group.iter() {
            if names.contains(&name.as_str()) {
                continue;
            }
            names.push(name.as_str());
            pairs.push(format!("{name}={value}"));
        }
    }
    (!pairs.is_empty()).then(|| pairs.join("; "))
}

/// “凭据校验被 Cloudflare 拦截”的说明：标签、端点、状态码与本地刷新结论。
/// 只包含这些信息与分支说明，绝不包含上游正文、Cookie 或 token 值。
pub(super) fn blocked_error(
    label: &str,
    endpoint: &str,
    status: StatusCode,
    refresh: Option<&RefreshOutcome>,
) -> UpstreamBlocked {
    let detail = match refresh {
        Some(RefreshOutcome::Refreshed) => {
            "Cloudflare 拦截，已刷新 CF cookies 并重试一次仍被拒绝".to_owned()
        }
        Some(RefreshOutcome::NotConfigured) => {
            "Cloudflare 拦截，CF_BYPASS_URL 未配置，无法取得 Cloudflare cookies".to_owned()
        }
        Some(RefreshOutcome::CoolingDown) => format!(
            "Cloudflare 拦截，距上次刷新不足 {REFRESH_COOLDOWN_SECS} 秒，未再次刷新 CF cookies"
        ),
        Some(RefreshOutcome::Failed(cause)) => {
            format!("Cloudflare 拦截，刷新 CF cookies 失败: {cause}")
        }
        None => "Cloudflare 拦截".to_owned(),
    };
    UpstreamBlocked(format!(
        "{label}: {endpoint} 返回状态 {}; {detail}",
        status.as_u16()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_drops_unknown_and_empty_cookies() {
        let payload = json!({"cookies": [
            {"name": "cf_clearance", "value": "CF"},
            {"name": "__cf_bm", "value": "BM"},
            {"name": "__cflb", "value": "LB"},
            {"name": "_cfuvid", "value": "UV"},
            {"name": "session", "value": "SECRET"},
            {"name": "cf_clearance", "value": ""},
            {"value": "no-name"}
        ]});
        assert_eq!(
            whitelist_cookies(&payload).expect("过滤失败"),
            vec![
                ("cf_clearance".to_owned(), "CF".to_owned()),
                ("__cf_bm".to_owned(), "BM".to_owned()),
                ("__cflb".to_owned(), "LB".to_owned()),
                ("_cfuvid".to_owned(), "UV".to_owned()),
            ]
        );
        assert!(whitelist_cookies(&json!({"cookies": [{"name": "session", "value": "x"}]})).is_err());
        assert!(whitelist_cookies(&json!({})).is_err());
    }

    #[test]
    fn cookie_header_keeps_first_occurrence_of_each_name() {
        let session = vec![("probe_extra".to_owned(), "EV".to_owned())];
        let cf = vec![
            ("probe_extra".to_owned(), "CF-WOULD-DUPLICATE".to_owned()),
            ("cf_clearance".to_owned(), "SYNTHETIC".to_owned()),
        ];
        assert_eq!(
            cookie_header(&[&session, &cf]).as_deref(),
            Some("probe_extra=EV; cf_clearance=SYNTHETIC")
        );
        assert_eq!(cookie_header(&[]).as_deref(), None);
        assert_eq!(cookie_header(&[&[], &[]]).as_deref(), None);
    }

    #[test]
    fn answer_classifies_edge_blocks_without_exposing_body() {
        let challenge = Answer {
            status: StatusCode::FORBIDDEN,
            challenged: true,
            body: Bytes::from_static(b"<html>Just a moment...</html>"),
            content_encoding: None,
        };
        assert!(challenge.blocked());
        let html403 = Answer {
            status: StatusCode::FORBIDDEN,
            challenged: false,
            body: Bytes::from_static(b"<html>blocked</html>"),
            content_encoding: None,
        };
        assert!(html403.blocked());
        let json403 = Answer {
            status: StatusCode::FORBIDDEN,
            challenged: false,
            body: Bytes::from_static(br#"{"detail":"account deactivated"}"#),
            content_encoding: None,
        };
        assert!(!json403.blocked());
        let unauthorized = Answer {
            status: StatusCode::UNAUTHORIZED,
            challenged: false,
            body: Bytes::from_static(b"<html>nope</html>"),
            content_encoding: None,
        };
        assert!(!unauthorized.blocked());
    }

    #[test]
    fn blocked_error_reports_endpoint_status_and_refresh_reason() {
        let refreshed = blocked_error(
            "session_token 校验失败",
            "api/auth/session",
            StatusCode::FORBIDDEN,
            Some(&RefreshOutcome::Refreshed),
        )
        .to_string();
        assert!(refreshed.contains("返回状态 403"), "{refreshed}");
        assert!(refreshed.contains("已刷新 CF cookies 并重试一次"), "{refreshed}");
        let missing = blocked_error(
            "session_token 校验失败",
            "api/auth/session",
            StatusCode::FORBIDDEN,
            Some(&RefreshOutcome::NotConfigured),
        )
        .to_string();
        assert!(missing.contains("CF_BYPASS_URL 未配置"), "{missing}");
        let cooling = blocked_error(
            "session_token 校验失败",
            "api/auth/session",
            StatusCode::FORBIDDEN,
            Some(&RefreshOutcome::CoolingDown),
        )
        .to_string();
        assert!(cooling.contains("未再次刷新"), "{cooling}");
        let failed = blocked_error(
            "access_token 校验失败",
            "backend-api/me",
            StatusCode::FORBIDDEN,
            Some(&RefreshOutcome::Failed("cfbypass 拒绝请求".to_owned())),
        )
        .to_string();
        assert!(failed.contains("cfbypass 拒绝请求"), "{failed}");
        for message in [refreshed, missing, cooling, failed] {
            assert!(!message.contains("<html"), "{message}");
        }
    }
}

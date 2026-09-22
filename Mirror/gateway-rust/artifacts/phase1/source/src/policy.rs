//! Mirror 网关 Rust 纯策略模块（无 I/O、无计时器）。
//!
//! 作者：MingTea
//!
//! 只读契约来源（Django 管理端，仅作为字段与语义依据，未复制其实现）：
//! - `backend/app/accounts/session_authority.py`：能力别名合并、普通模型允许清单与频率限制的构造方式
//! - `backend/app/chatgpt/views/chatgpt.py`：`/api/login` 实际下发的字段集合
//! - `backend/app/accounts/revocations.py`：`/api/revoke-authorization` 下发的撤销事件字段
//!
//! 显式声明的证据边界（不臆测未知协议）：
//! - `limits`：只读契约只能证明它是 `user.model_limit` 中字符串项的透传（历史字典结构已被
//!   `isinstance(item, str)` 过滤），前端没有写入控件、占位实现没有消费点，因此其现行语义
//!   无法证实；本模块只做类型校验与保存，不据此放行或拒绝模型。
//! - 请求侧 MCP/skills 的 ID 形态：只读契约只提供允许清单（id + 别名），未提供上游请求体
//!   字段或路径结构，`check_request` 不按猜测的字段名拦截，缺口已上报主代理。
//! - Work 模型豁免：管理端界面声明“Work 模型不参与隔离和频率限制”，但只读契约中不存在可
//!   判定 Work 模型的标识，调用方需自行决定对 Work 流量是否调用 `check_model`。

use anyhow::{anyhow, Result};
use serde_json::{Map, Value};

/// 登录策略：由 `/api/login` 载荷解析，`version` 与 `expires_at` 由主代理在完成 Django
/// 授权响应校验后写入，本模块不自行计算。
#[derive(Debug, Clone)]
pub struct Policy {
    pub user_name: String,
    pub authorization: String,
    pub version: String,
    pub expires_at: i64,
    pub isolated_session: bool,
    pub mcp_isolation: bool,
    pub skills_isolation: bool,
    pub model_isolation: bool,
    pub daily_quota: i64,
    pub monthly_quota: i64,
    pub model_allowed_ids: Vec<String>,
    pub model_rate_limits: Value,
    pub limits: Vec<String>,
    /// MCP 允许清单（能力 id 与别名）。`None` 表示载荷未包含该字段（能力策略未初始化），
    /// 隔离开启时按缺少初始化拒绝，不回退为 allow-all。
    pub mcp_allowed_ids: Option<Vec<String>>,
    /// Skills 允许清单，语义同 `mcp_allowed_ids`。
    pub skills_allowed_ids: Option<Vec<String>>,
}

impl Policy {
    /// 解析 `/api/login` 载荷。
    ///
    /// 除 `version`/`expires_at`（缺省为空值）与能力清单（缺失表示未初始化）外，其余字段必须
    /// 存在且类型正确；配置类型错误直接报错，避免静默退化（尤其不得把损坏的允许清单当成
    /// 空清单或 allow-all）。
    pub fn from_login(payload: &Value) -> Result<Self> {
        let map = payload
            .as_object()
            .ok_or_else(|| anyhow!("登录载荷必须是 JSON 对象"))?;

        // 身份字段来自 Django 管理端的签名载荷；空值或类型错误说明协议被破坏，
        // 直接拒绝而不是构造匿名会话。
        let user_name = required_string(map, "user_name")?;
        if user_name.trim().is_empty() {
            return Err(anyhow!("登录载荷 user_name 不能为空"));
        }
        let authorization = required_string(map, "authorization")?;
        if authorization.trim().is_empty() {
            return Err(anyhow!("登录载荷 authorization 不能为空"));
        }

        // version/expires_at 不在登录载荷中，由主代理校验 Django 响应后补写，缺省为空值。
        let version = optional_string(map, "version")?.unwrap_or_default();
        let expires_at = optional_i64(map, "expires_at")?.unwrap_or(0);

        let isolated_session = required_bool(map, "isolated_session")?;
        let mcp_isolation = required_bool(map, "mcp_isolation")?;
        let skills_isolation = required_bool(map, "skills_isolation")?;
        let model_isolation = required_bool(map, "model_isolation")?;

        let daily_quota = required_i64(map, "daily_quota")?;
        let monthly_quota = required_i64(map, "monthly_quota")?;
        if daily_quota < 0 || monthly_quota < 0 {
            return Err(anyhow!("登录载荷配额不能为负数"));
        }

        // 以下清单/限制都来自管理端配置；类型错误必须报错，把坏配置当成空清单会静默
        // 改变放行范围并掩盖真实故障。
        let model_allowed_ids = required_string_array(map, "model_allowed_ids")?;
        let limits = required_string_array(map, "limits")?;
        let model_rate_limits = required_object(map, "model_rate_limits")?;
        validate_model_rate_limits(&model_rate_limits)?;

        // 能力清单缺失表示能力策略未初始化（Django 侧 capability_policy_initialized=false），
        // 与“管理员明确授权 0 项”不同，因此保留 None 区分，交由 check_capability 拒绝。
        let mcp_allowed_ids = optional_string_array(map, "mcp_allowed_ids")?;
        let skills_allowed_ids = optional_string_array(map, "skills_allowed_ids")?;

        Ok(Self {
            user_name,
            authorization,
            version,
            expires_at,
            isolated_session,
            mcp_isolation,
            skills_isolation,
            model_isolation,
            daily_quota,
            monthly_quota,
            model_allowed_ids,
            model_rate_limits,
            limits,
            mcp_allowed_ids,
            skills_allowed_ids,
        })
    }

    /// 普通模型放行判定。
    ///
    /// 判定依据来自 Django 已解析的账号级策略：
    /// - `model_isolation == false`：该账号未配置普通模型策略或未启用隔离，放行；
    /// - `model_isolation == true`：仅放行 `model_allowed_ids` 内的模型（后端构造时已小写），
    ///   空清单是“未启用任何普通模型”的明确配置，拒绝而不是放行。
    ///
    /// `limits` 语义未被只读契约证实（见模块注释），不参与本判定；Work 模型豁免由调用方控制。
    pub fn check_model(&self, model: &str) -> Result<()> {
        let model = model.trim();
        // 空模型无法与任何清单比对，直接拒绝，避免被当成“无模型请求”放行。
        if model.is_empty() {
            return Err(anyhow!("请求模型为空，拒绝放行"));
        }
        if !self.model_isolation {
            return Ok(());
        }
        if self
            .model_allowed_ids
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(model))
        {
            return Ok(());
        }
        Err(anyhow!("模型 {} 不在普通模型允许清单内", model))
    }

    /// MCP / Skills 能力放行判定（同时覆盖能力 id 与别名，二者在 Django 侧合并为同一清单）。
    ///
    /// `kind` 仅接受 `mcp` 与 `skills`（忽略大小写），其他类型直接报错，避免未知能力类型被
    /// 当成已校验。隔离开启但清单缺失（未初始化）时同样报错拒绝，绝不回退为 allow-all。
    pub fn check_capability(&self, kind: &str, id: &str) -> Result<()> {
        let id = id.trim();
        // 空 ID 无法证明对应任何已授权项，直接拒绝。
        if id.is_empty() {
            return Err(anyhow!("能力 ID 为空，拒绝放行"));
        }
        let (isolation, allowlist, label) = match kind.trim() {
            value if value.eq_ignore_ascii_case("mcp") => {
                (self.mcp_isolation, self.mcp_allowed_ids.as_ref(), "MCP")
            }
            value if value.eq_ignore_ascii_case("skills") => (
                self.skills_isolation,
                self.skills_allowed_ids.as_ref(),
                "Skills",
            ),
            _ => {
                return Err(anyhow!("未知能力类型 {}，拒绝按未校验能力放行", kind));
            }
        };
        if !isolation {
            return Ok(());
        }
        let allowlist = allowlist.ok_or_else(|| {
            anyhow!(
                "{} 隔离已开启但缺少允许清单（能力策略未初始化），拒绝放行",
                label
            )
        })?;
        if allowlist.iter().any(|allowed| allowed.as_str() == id) {
            return Ok(());
        }
        Err(anyhow!("{} 能力 {} 不在允许清单内", label, id))
    }

    /// 请求级策略检查（仅覆盖有只读证据的部分）。
    ///
    /// 已覆盖：请求体顶层 `model` 为字符串时执行 [`Policy::check_model`]；字段存在但类型
    /// 错误时直接报错，避免悄悄跳过模型校验。
    ///
    /// 未覆盖并已上报主代理：请求侧 MCP/skills 的 ID 字段或路径结构在 Django 侧只读契约与
    /// 占位实现中都没有定义，本函数不按猜测的字段名拦截。
    pub fn check_request(&self, _path: &str, body: &Value) -> Result<()> {
        if let Some(model) = body.get("model") {
            let model = model
                .as_str()
                .ok_or_else(|| anyhow!("请求体 model 字段类型错误，拒绝按未校验模型放行"))?;
            self.check_model(model)?;
        }
        Ok(())
    }
}

/// 撤销事件：Django 在登出、踢下线和策略变更时下发，网关据此失效对应授权。
#[derive(Debug, Clone)]
pub struct Revocation {
    pub subject: String,
    pub version: String,
    pub include_visitors: bool,
    pub expires_at: i64,
}

impl Revocation {
    /// 解析 `/api/revoke-authorization` 事件体。
    ///
    /// 四个字段全部必填且类型严格；空 subject/version 视为协议错误拒绝，避免空串匹配到
    /// 任何会话造成误伤。
    pub fn from_json(value: &Value) -> Result<Self> {
        let map = value
            .as_object()
            .ok_or_else(|| anyhow!("撤销事件必须是 JSON 对象"))?;
        let subject = required_string(map, "subject")?;
        let version = required_string(map, "version")?;
        let include_visitors = required_bool(map, "include_visitors")?;
        let expires_at = required_i64(map, "expires_at")?;
        if subject.trim().is_empty() {
            return Err(anyhow!("撤销事件 subject 不能为空"));
        }
        if version.trim().is_empty() {
            return Err(anyhow!("撤销事件 version 不能为空"));
        }
        Ok(Self {
            subject,
            version,
            include_visitors,
            expires_at,
        })
    }

    /// 判定该撤销事件是否命中给定会话策略。
    ///
    /// 任一条不成立即不命中，保证旧事件不伤新会话：
    /// - 事件已过期（`expires_at <= now`）：旧授权届时也已自然失效；
    /// - version 不同或任一侧为空：重新登录、登出、策略变更都会更换版本；
    /// - subject 既非精确相等，也不是严格前缀 `<subject>:` 的访客会话。
    pub fn matches(&self, policy: &Policy, now: i64) -> bool {
        if self.expires_at <= now {
            return false;
        }
        if self.version.is_empty() || policy.version.is_empty() || self.version != policy.version {
            return false;
        }
        // subject 为空的事件（字段公开，可能被外部直接构造）不得命中任何会话。
        if self.subject.is_empty() || policy.user_name.is_empty() {
            return false;
        }
        if policy.user_name == self.subject {
            return true;
        }
        if self.include_visitors {
            // 访客 subject 形如 `free_account:<sid>`；前缀必须带冒号，
            // 防止 `free_account` 命中 `free_account2` 等其他主体。
            let prefix = format!("{}:", self.subject);
            return policy.user_name.starts_with(&prefix);
        }
        false
    }
}

fn required_string(map: &Map<String, Value>, key: &str) -> Result<String> {
    match map.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(anyhow!("字段 {} 类型错误，应为字符串", key)),
        None => Err(anyhow!("缺少字段 {}", key)),
    }
}

fn optional_string(map: &Map<String, Value>, key: &str) -> Result<Option<String>> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(anyhow!("字段 {} 类型错误，应为字符串", key)),
    }
}

fn required_bool(map: &Map<String, Value>, key: &str) -> Result<bool> {
    match map.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(anyhow!("字段 {} 类型错误，应为布尔值", key)),
        None => Err(anyhow!("缺少字段 {}", key)),
    }
}

fn required_i64(map: &Map<String, Value>, key: &str) -> Result<i64> {
    match map.get(key) {
        Some(Value::Number(value)) => value
            .as_i64()
            .ok_or_else(|| anyhow!("字段 {} 类型错误，应为整数", key)),
        Some(_) => Err(anyhow!("字段 {} 类型错误，应为整数", key)),
        None => Err(anyhow!("缺少字段 {}", key)),
    }
}

fn optional_i64(map: &Map<String, Value>, key: &str) -> Result<Option<i64>> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| anyhow!("字段 {} 类型错误，应为整数", key)),
        Some(_) => Err(anyhow!("字段 {} 类型错误，应为整数", key)),
    }
}

fn required_object(map: &Map<String, Value>, key: &str) -> Result<Value> {
    match map.get(key) {
        Some(value @ Value::Object(_)) => Ok(value.clone()),
        Some(_) => Err(anyhow!("字段 {} 类型错误，应为对象", key)),
        None => Err(anyhow!("缺少字段 {}", key)),
    }
}

fn required_string_array(map: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    match map.get(key) {
        Some(value) => string_array(key, value),
        None => Err(anyhow!("缺少字段 {}", key)),
    }
}

fn optional_string_array(map: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>> {
    match map.get(key) {
        None => Ok(None),
        Some(value) => Ok(Some(string_array(key, value)?)),
    }
}

/// 字符串数组解析：逐项去空白并丢弃空串（与 Django 侧对模型 id / 能力 id 与别名的处理一致）。
/// 任一元素不是字符串都视为配置类型错误并报错，绝不静默丢弃。
fn string_array(key: &str, value: &Value) -> Result<Vec<String>> {
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("字段 {} 类型错误，应为字符串数组", key))?;
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| anyhow!("字段 {} 含非字符串元素", key))?;
        let text = text.trim();
        if !text.is_empty() {
            result.push(text.to_owned());
        }
    }
    Ok(result)
}

/// 频率限制结构校验（形如 `model_id -> {hour_window_hours, hour_limit, week_limit, month_limit}`）。
/// 这些值可能来自早期数据库行或备份恢复等绕过序列化校验的写入路径，因此在实际消费前拒绝坏类型。
fn validate_model_rate_limits(value: &Value) -> Result<()> {
    let entries = value
        .as_object()
        .ok_or_else(|| anyhow!("model_rate_limits 必须是对象"))?;
    for (model_id, entry) in entries {
        if model_id.trim().is_empty() {
            return Err(anyhow!("model_rate_limits 含空模型 ID"));
        }
        let limit = entry
            .as_object()
            .ok_or_else(|| anyhow!("model_rate_limits.{} 必须是对象", model_id))?;
        for key in [
            "hour_window_hours",
            "hour_limit",
            "week_limit",
            "month_limit",
        ] {
            if let Some(raw) = limit.get(key) {
                let number = raw
                    .as_i64()
                    .ok_or_else(|| anyhow!("model_rate_limits.{}.{} 必须是整数", model_id, key))?;
                let minimum = if key == "hour_window_hours" { 1 } else { 0 };
                if number < minimum {
                    return Err(anyhow!(
                        "model_rate_limits.{}.{} 超出允许范围",
                        model_id,
                        key
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn base_payload() -> Value {
        json!({
            "user_name": "mirror-user",
            "authorization": "signed-grant",
            "isolated_session": true,
            "mcp_isolation": true,
            "skills_isolation": true,
            "model_isolation": true,
            "mcp_allowed_ids": ["connector-a", "connector-alias"],
            "skills_allowed_ids": ["skill-a", "skill-alias"],
            "limits": [],
            "daily_quota": 0,
            "monthly_quota": 0,
            "model_allowed_ids": ["gpt-4o"],
            "model_rate_limits": {
                "gpt-4o": {
                    "hour_window_hours": 1,
                    "hour_limit": 10,
                    "week_limit": 0,
                    "month_limit": 0
                }
            }
        })
    }

    fn policy_from(payload: Value) -> Policy {
        Policy::from_login(&payload).expect("合成登录载荷应可解析")
    }

    fn policy_with(user_name: &str, version: &str) -> Policy {
        let mut payload = base_payload();
        payload["user_name"] = json!(user_name);
        let mut policy = policy_from(payload);
        // 版本由主代理在 Django 校验后写入，这里直接覆盖以覆盖撤销匹配分支。
        policy.version = version.to_owned();
        policy
    }

    #[test]
    fn login_defaults_version_and_expiry_when_absent() {
        let policy = policy_from(base_payload());
        assert_eq!(policy.version, "");
        assert_eq!(policy.expires_at, 0);
    }

    #[test]
    fn model_allowlist_rejects_unlisted_and_normalizes_case() {
        let policy = policy_from(base_payload());
        assert!(policy.check_model("gpt-4o").is_ok());
        assert!(policy.check_model(" GPT-4O ").is_ok());
        assert!(policy.check_model("gpt-5").is_err());
    }

    #[test]
    fn disabled_model_isolation_allows_any_model() {
        let mut payload = base_payload();
        payload["model_isolation"] = Value::Bool(false);
        let policy = policy_from(payload);
        assert!(policy.check_model("gpt-5").is_ok());
    }

    #[test]
    fn empty_model_allowlist_denies_every_model() {
        let mut payload = base_payload();
        payload["model_allowed_ids"] = json!([]);
        let policy = policy_from(payload);
        assert!(policy.check_model("gpt-4o").is_err());
    }

    #[test]
    fn empty_model_or_capability_id_is_rejected() {
        let policy = policy_from(base_payload());
        assert!(policy.check_model("   ").is_err());
        assert!(policy.check_capability("mcp", " ").is_err());
    }

    #[test]
    fn capability_allowlist_matches_id_and_alias() {
        let policy = policy_from(base_payload());
        assert!(policy.check_capability("mcp", "connector-a").is_ok());
        assert!(policy.check_capability("MCP", "connector-alias").is_ok());
        assert!(policy.check_capability("skills", "skill-alias").is_ok());
        assert!(policy.check_capability("mcp", "connector-b").is_err());
        assert!(policy.check_capability("skills", "connector-a").is_err());
        assert!(policy.check_capability("plugins", "connector-a").is_err());
    }

    #[test]
    fn disabled_capability_isolation_allows_any_id() {
        let mut payload = base_payload();
        payload["mcp_isolation"] = Value::Bool(false);
        payload["skills_isolation"] = Value::Bool(false);
        let policy = policy_from(payload);
        assert!(policy.check_capability("mcp", "unknown-connector").is_ok());
        assert!(policy.check_capability("skills", "unknown-skill").is_ok());
    }

    #[test]
    fn explicitly_empty_allowlist_denies_capability() {
        let mut payload = base_payload();
        payload["mcp_allowed_ids"] = json!([]);
        let policy = policy_from(payload);
        assert!(policy.check_capability("mcp", "connector-a").is_err());
    }

    #[test]
    fn missing_capability_initialization_fails_closed() {
        let mut payload = base_payload();
        let map = payload.as_object_mut().expect("合成载荷应为对象");
        assert!(map.remove("mcp_allowed_ids").is_some());
        assert!(map.remove("skills_allowed_ids").is_some());
        let policy = policy_from(payload);
        assert!(policy.mcp_allowed_ids.is_none());
        assert!(policy.skills_allowed_ids.is_none());
        assert!(policy.check_capability("mcp", "connector-a").is_err());
        assert!(policy.check_capability("skills", "skill-a").is_err());
    }

    #[test]
    fn config_type_errors_are_rejected_instead_of_silent_fallback() {
        let mut payload = base_payload();
        payload["mcp_allowed_ids"] = json!("connector-a");
        assert!(Policy::from_login(&payload).is_err());

        let mut payload = base_payload();
        payload["skills_allowed_ids"] = json!(["ok", 7]);
        assert!(Policy::from_login(&payload).is_err());

        let mut payload = base_payload();
        payload["model_allowed_ids"] = json!([1, 2]);
        assert!(Policy::from_login(&payload).is_err());

        let mut payload = base_payload();
        payload["limits"] = json!(["gpt-4o", 5]);
        assert!(Policy::from_login(&payload).is_err());

        let mut payload = base_payload();
        payload["model_rate_limits"] = json!([]);
        assert!(Policy::from_login(&payload).is_err());

        let mut payload = base_payload();
        payload["model_rate_limits"] = json!({"gpt-4o": {"hour_limit": "fast"}});
        assert!(Policy::from_login(&payload).is_err());
    }

    #[test]
    fn login_requires_identity_and_non_negative_quota() {
        let mut payload = base_payload();
        let removed = payload
            .as_object_mut()
            .expect("合成载荷应为对象")
            .remove("user_name");
        assert!(removed.is_some());
        assert!(Policy::from_login(&payload).is_err());

        let mut payload = base_payload();
        payload["authorization"] = json!("   ");
        assert!(Policy::from_login(&payload).is_err());

        let mut payload = base_payload();
        payload["daily_quota"] = json!(-1);
        assert!(Policy::from_login(&payload).is_err());

        assert!(Policy::from_login(&json!("not-an-object")).is_err());
    }

    #[test]
    fn check_request_enforces_model_when_present() {
        let policy = policy_from(base_payload());
        assert!(policy
            .check_request("/backend-api/conversation", &json!({"model": "gpt-4o"}))
            .is_ok());
        assert!(policy
            .check_request("/backend-api/conversation", &json!({"model": "gpt-5"}))
            .is_err());
        assert!(policy.check_request("/backend-api/me", &json!({})).is_ok());
    }

    #[test]
    fn check_request_rejects_non_string_model() {
        let policy = policy_from(base_payload());
        assert!(policy
            .check_request("/backend-api/conversation", &json!({"model": 5}))
            .is_err());
    }

    #[test]
    fn revocation_matches_exact_subject_and_version() {
        let policy = policy_with("mirror-user", "v1");
        let event = Revocation {
            subject: "mirror-user".to_owned(),
            version: "v1".to_owned(),
            include_visitors: false,
            expires_at: 100,
        };
        assert!(event.matches(&policy, 50));
    }

    #[test]
    fn revocation_visitor_prefix_is_strict() {
        let event = Revocation {
            subject: "free_account".to_owned(),
            version: "v1".to_owned(),
            include_visitors: true,
            expires_at: 100,
        };
        assert!(event.matches(&policy_with("free_account", "v1"), 50));
        assert!(event.matches(&policy_with("free_account:abc123", "v1"), 50));
        assert!(!event.matches(&policy_with("free_account2", "v1"), 50));
        assert!(!event.matches(&policy_with("free_accountx:abc123", "v1"), 50));
        assert!(!event.matches(&policy_with("other:abc123", "v1"), 50));
    }

    #[test]
    fn revocation_without_visitors_does_not_hit_visitor_session() {
        let event = Revocation {
            subject: "free_account".to_owned(),
            version: "v1".to_owned(),
            include_visitors: false,
            expires_at: 100,
        };
        assert!(!event.matches(&policy_with("free_account:abc123", "v1"), 50));
    }

    #[test]
    fn delayed_revocation_does_not_hit_new_session() {
        let event = Revocation {
            subject: "mirror-user".to_owned(),
            version: "v1".to_owned(),
            include_visitors: false,
            expires_at: 100,
        };
        assert!(event.matches(&policy_with("mirror-user", "v1"), 50));
        // 重新登录后版本变化：延迟送达的旧事件不得命中新会话。
        assert!(!event.matches(&policy_with("mirror-user", "v2"), 60));
        // 版本尚未写入（Django 校验未完成）时不命中任何会话。
        assert!(!event.matches(&policy_with("mirror-user", ""), 60));

        // 访客删除事件按 sid 精确匹配：新访客 sid 不受旧事件影响。
        let visitor_event = Revocation {
            subject: "free_account:sid-old".to_owned(),
            version: "v1".to_owned(),
            include_visitors: false,
            expires_at: 100,
        };
        assert!(visitor_event.matches(&policy_with("free_account:sid-old", "v1"), 50));
        assert!(!visitor_event.matches(&policy_with("free_account:sid-new", "v1"), 60));
    }

    #[test]
    fn expired_revocation_matches_nothing() {
        let event = Revocation {
            subject: "mirror-user".to_owned(),
            version: "v1".to_owned(),
            include_visitors: false,
            expires_at: 100,
        };
        assert!(!event.matches(&policy_with("mirror-user", "v1"), 100));
        assert!(!event.matches(&policy_with("mirror-user", "v1"), 101));
    }

    #[test]
    fn revocation_from_json_parses_delivery_and_rejects_invalid() {
        let event = Revocation::from_json(&json!({
            "subject": "mirror-user",
            "version": "v1",
            "include_visitors": true,
            "expires_at": 123
        }))
        .expect("契约字段应可解析");
        assert_eq!(event.subject, "mirror-user");
        assert_eq!(event.version, "v1");
        assert!(event.include_visitors);
        assert_eq!(event.expires_at, 123);

        assert!(Revocation::from_json(&json!({
            "subject": "",
            "version": "v1",
            "include_visitors": false,
            "expires_at": 123
        }))
        .is_err());
        assert!(Revocation::from_json(&json!({
            "subject": "mirror-user",
            "version": "",
            "include_visitors": false,
            "expires_at": 123
        }))
        .is_err());
        assert!(Revocation::from_json(&json!({
            "subject": "mirror-user",
            "version": "v1",
            "expires_at": 123
        }))
        .is_err());
        assert!(Revocation::from_json(&json!({
            "subject": "mirror-user",
            "version": "v1",
            "include_visitors": false,
            "expires_at": 1.5
        }))
        .is_err());
    }
}

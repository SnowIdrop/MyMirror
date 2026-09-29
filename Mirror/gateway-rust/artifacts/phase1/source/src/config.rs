// Author: MingTea. Upstream origins are selected by server configuration only.
use anyhow::{bail, Context, Result};
use std::{env, path::PathBuf, time::Duration};
use url::Url;

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database: PathBuf,
    pub secret: String,
    pub key: String,
    pub django: Url,
    pub upstream: Url,
    /// WebSocket 上游基址。configured 模式固定为 `wss://ws.chatgpt.com/`（原版把
    /// 目标校验为该主机，见报告 08 §6.2）；offline 模式跟随 `CHATGPT_BASE_URL`
    /// 的回环主机，使合成回环回归能覆盖完整桥接路径。
    pub ws_upstream: Url,
    /// Public static origin; routes remain gated until their contract is verified.
    pub cdn_upstream: Option<Url>,
    /// A/B 统计基址（注入脚本改写目标 `/ab/*` 的上游）；未配置时该前缀按
    /// 可行动文案拒绝，不静默丢弃统计请求。
    pub ab_upstream: Option<Url>,
    /// 公共前缀（缺口 2 策略表）的固定上游基址覆盖：只用于离线合成回环回归，
    /// 生产装载（[`Config::from_env`]）保持 None，按策略表里的固定主机访问。
    pub public_prefix_base: Option<Url>,
    pub cfbypass: Option<Url>,
    pub timeout: Duration,
    pub mirror_profile: bool,
    pub cookie_secure: bool,
    /// 开发阶段匿名上游开关。默认关闭；仅显式 true 时允许无上游凭据的镜像会话
    /// 绑定全局共享匿名身份（见 server/anonymous.rs）。
    pub allow_anonymous_session: bool,
    /// 管理后台的**浏览器可达**基址（`ADMIN_PUBLIC_URL`）。原版是单端口同源部署，
    /// `/api/user-logout` 直接回相对路径 `/admin#/`；候选把管理界面拆到 nginx 侧车后
    /// 两者不同源（见 COMPATIBILITY「管理端与镜像面不同源」），此时必须配置本项，
    /// 否则用户点「返回后台 / 换号」会落在镜像端口上。未配置保持原版相对跳转。
    pub admin_public_url: Option<String>,
}

pub fn loopback_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    // 当前普通 HTTP 传输尚未完成原版指纹兼容验证，只允许隔离环境的数字回环地址。
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
            && !matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
    {
        bail!("当前候选制品只允许 http 数字回环上游；真实传输兼容门禁尚未通过");
    }
    Ok(url)
}

fn service_url(value: &str, offline: bool) -> Result<Url> {
    let url = if offline {
        loopback_url(value)?
    } else {
        Url::parse(value)?
    };
    // Callers replace the path or join absolute API paths. Reject a base path
    // rather than silently discarding a deployment's prefix or query settings.
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("上游必须是 HTTP(S) 服务源地址，不能含凭据、路径前缀、查询串或片段");
    }
    Ok(url)
}

/// 安全开关只接受字面量 true/false：拼写错误必须拒绝启动，
/// 不能因为宽容比较而意外放开匿名上游。
fn anonymous_session_flag(value: Option<&str>) -> Result<bool> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => bail!("GATEWAY_ALLOW_ANONYMOUS_SESSION 只能是 true 或 false"),
    }
}

/// 管理后台的浏览器可达基址。空值表示未配置（`/api/user-logout` 回原版的同源相对
/// 跳转 `/admin#/`）；非空必须是 http(s) 绝对地址，拒绝凭据与相对路径输入，
/// 避免把用户重定向到非预期来源。
fn admin_public_url(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let url = Url::parse(value).context("ADMIN_PUBLIC_URL 无效")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("ADMIN_PUBLIC_URL 必须是 http(s) 绝对地址，且不能含凭据");
    }
    // 存规范化后的字符串：非 ASCII 输入会被 Url 百分号编码，直接回写入响应头会失败。
    Ok(Some(url.to_string()))
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let secret = env::var("GATEWAY_ADMIN_SECRET")
            .unwrap_or_default()
            .trim()
            .to_owned();
        if secret.is_empty() {
            bail!("GATEWAY_ADMIN_SECRET 必须设置，不能使用内置默认值");
        }
        if secret.len() < 16 {
            bail!("GATEWAY_ADMIN_SECRET 长度至少需要 16 个字符");
        }
        let key =
            env::var("CREDENTIAL_ENCRYPTION_KEY").context("CREDENTIAL_ENCRYPTION_KEY 未配置")?;
        let profile = env::var("GATEWAY_COMPAT_PROFILE").unwrap_or_else(|_| "mirror".into());
        if !matches!(profile.as_str(), "mirror" | "original") {
            bail!("GATEWAY_COMPAT_PROFILE 必须是 mirror 或 original");
        }
        let offline = match env::var("GATEWAY_UPSTREAM_MODE").as_deref() {
            Ok("offline") | Err(env::VarError::NotPresent) => true,
            Ok("configured") => false,
            _ => bail!("GATEWAY_UPSTREAM_MODE 必须是 offline 或 configured"),
        };
        let django = service_url(
            &env::var("DJANGO_UPSTREAM").context("DJANGO_UPSTREAM 未配置")?,
            offline,
        )
        .context("DJANGO_UPSTREAM 无效")?;
        let upstream = service_url(
            &env::var("CHATGPT_BASE_URL").context("CHATGPT_BASE_URL 未配置")?,
            offline,
        )
        .context("CHATGPT_BASE_URL 无效")?;
        let cdn_upstream = match env::var("CHATGPT_CDN_BASE_URL") {
            Ok(value) => Some(service_url(&value, offline).context("CHATGPT_CDN_BASE_URL 无效")?),
            Err(env::VarError::NotPresent) if offline => None,
            Err(error) => return Err(error).context("CHATGPT_CDN_BASE_URL 未配置或无效"),
        };
        // WS 上游：configured 模式固定原版观测主机；offline 模式沿用回环基址，
        // 使合成回环回归能覆盖路由、鉴权与双向透传。
        let ws_upstream = if offline {
            let mut base = upstream.clone();
            base.set_scheme("ws")
                .map_err(|_| anyhow::anyhow!("WS 上游 scheme 无效"))?;
            base
        } else {
            Url::parse("wss://ws.chatgpt.com/")?
        };
        // `/ab/*` 是可选前缀：未配置时该前缀返回可行动文案，不影响其它路由启动。
        let ab_upstream = match env::var("CHATGPT_AB_BASE_URL") {
            Ok(value) => Some(service_url(&value, offline).context("CHATGPT_AB_BASE_URL 无效")?),
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("CHATGPT_AB_BASE_URL 无效"),
        };
        let cfbypass = match env::var("CF_BYPASS_URL") {
            Ok(value) => Some(service_url(&value, offline).context("CF_BYPASS_URL 无效")?),
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("CF_BYPASS_URL 无效"),
        };
        // 非 UTF-8 取值按“未设置”处理（保持关闭），与其它可选变量一致。
        let anonymous_env = env::var("GATEWAY_ALLOW_ANONYMOUS_SESSION").ok();
        let allow_anonymous_session = anonymous_session_flag(anonymous_env.as_deref())
            .context("GATEWAY_ALLOW_ANONYMOUS_SESSION 无效")?;
        let admin_public_url = admin_public_url(env::var("ADMIN_PUBLIC_URL").ok().as_deref())?;
        Ok(Self {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "40002".into())
                .parse()?,
            database: env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "data/gateway.db".into())
                .into(),
            secret,
            key,
            django,
            upstream,
            ws_upstream,
            cdn_upstream,
            ab_upstream,
            public_prefix_base: None,
            cfbypass,
            timeout: Duration::from_secs(
                env::var("REQUEST_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "180".into())
                    .parse()?,
            ),
            mirror_profile: profile == "mirror",
            cookie_secure: env::var("COOKIE_SECURE")
                .map(|v| v != "false")
                .unwrap_or(true),
            allow_anonymous_session,
            admin_public_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_services_accept_http_and_https_origins() {
        for value in [
            "http://django:8000",
            "https://chat.example.invalid",
            "https://static.example.invalid:8443/",
            "http://[::1]:18090",
            "https://127.0.0.1:18443",
        ] {
            assert!(service_url(value, false).is_ok(), "{value}");
        }
    }

    #[test]
    fn offline_services_still_require_numeric_http_loopback() {
        for value in ["http://127.0.0.1:18090", "http://[::1]:18090"] {
            assert!(service_url(value, true).is_ok(), "{value}");
        }
        for value in [
            "https://127.0.0.1",
            "http://localhost:8000",
            "http://django:8000",
            "https://chat.example.invalid",
            "http://192.0.2.1",
        ] {
            assert!(service_url(value, true).is_err(), "{value}");
        }
    }

    #[test]
    fn service_origins_reject_ambiguous_or_credential_bearing_bases() {
        for value in [
            "file:///tmp/upstream",
            "ftp://example.invalid",
            "ws://example.invalid",
            "//example.invalid",
            "https://user:password@example.invalid",
            "https://user@example.invalid",
            "http://127.0.0.1/prefix/",
            "http://127.0.0.1/?target=example.invalid",
            "http://127.0.0.1/#fragment",
            "http://127.0.0.1/?",
            "http://127.0.0.1/#",
            "",
        ] {
            assert!(service_url(value, false).is_err(), "{value}");
            assert!(service_url(value, true).is_err(), "{value}");
        }
    }

    #[test]
    fn anonymous_session_switch_requires_explicit_true() {
        assert!(!anonymous_session_flag(None).unwrap());
        assert!(!anonymous_session_flag(Some("false")).unwrap());
        assert!(anonymous_session_flag(Some("true")).unwrap());
        for value in ["True", "1", "yes", "enable", ""] {
            assert!(anonymous_session_flag(Some(value)).is_err(), "{value}");
        }
    }
}

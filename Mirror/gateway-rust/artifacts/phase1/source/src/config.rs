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
    /// Public static origin; routes remain gated until their contract is verified.
    pub cdn_upstream: Option<Url>,
    pub cfbypass: Option<Url>,
    pub timeout: Duration,
    pub mirror_profile: bool,
    pub cookie_secure: bool,
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
        let cfbypass = match env::var("CF_BYPASS_URL") {
            Ok(value) => Some(service_url(&value, offline).context("CF_BYPASS_URL 无效")?),
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("CF_BYPASS_URL 无效"),
        };
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
            cdn_upstream,
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
}

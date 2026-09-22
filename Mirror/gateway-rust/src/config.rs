// Author: MingTea. Unverified Internet transports are intentionally not enabled.
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
            django: loopback_url(&env::var("DJANGO_UPSTREAM").context("DJANGO_UPSTREAM 未配置")?)?,
            upstream: loopback_url(
                &env::var("CHATGPT_BASE_URL").context("CHATGPT_BASE_URL 未配置")?,
            )?,
            cfbypass: env::var("CF_BYPASS_URL")
                .ok()
                .map(|s| loopback_url(&s))
                .transpose()?,
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

// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/upstream_cookies.rs
// Created : 2026-09-24
// Summary : 上游 cookie jar：结构化 cookie 的捕获、作用域过滤、回注与账号级恢复。
//           逆向证据（MirrorNiXiang/reverse/extracted/chatgpt-mirror-gateway，
//           偏移均为文件字节偏移）：
//           `db::SupplementalCookie` 的 serde 字段名表 0xD914DD 起逐字为
//           domain/host_only/secure/http_only/expires/source/name/value/path；
//           行为方法 `is_mirror_local`(0x248780)、`is_current_at`(0x2488E0)、
//           `scope_identity`(0x248920)、`applies_to_url`(0x248E40)；
//           浏览器偏好排除表 `is_browser_preference_cookie_name`(0x1872F0)；
//           注入 `build_upstream_auth_cookie_header`(0x186100)；
//           双存储 `clear_stored_cloudflare_cookies`(0x24EEC0) 同时引用
//           chatgpt_accounts 与 gateway_sessions 的 extra_cookies；
//           设备 cookie 由 `server_oai_device_cookie`(0x187E40) 按
//           name == "oai-did" 与 source 字段（7 字节立即数 `browser`）筛选。
// -----------------------------------------------------------------------------

//! 上游 cookie jar：与原版同形的 9 字段 cookie，捕获后按域/路径/安全位/过期回注。
//! 会话凭据列 `extra_cookies` 是 `rust_credential_binding` 的绑定对象，绝不被本模块
//! 改写；jar 落在新增列 `gateway_sessions.upstream_cookies`，账号级一侧写号池行的
//! `chatgpt_accounts.extra_cookies`（同账号多镜像用户共享，与原版双存储一致）。

use super::{cloudflare::CLOUDFLARE_COOKIE_NAMES, App, Session};
use anyhow::{Context, Result};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::Database;

/// 设备 cookie 名（原版立即数还原，7 字节）。
pub(super) const DEVICE_COOKIE: &str = "oai-did";
/// 设备请求头名（原版字面量 0xD64C07/0xD64C88，13 字节）。
pub(super) const DEVICE_HEADER: &str = "oai-device-id";
/// 设备标识长度上限：浏览器实测值为 UUID（evidence/anonymous-nextauth-001/
/// mirror-run-007），放宽到 128 字节可见 ASCII，既容纳上游形态变化，又能安全
/// 拼进请求头与 Cookie。
const DEVICE_MAX_LEN: usize = 128;
/// 捕获来源标记（写入 `source` 字段，原版同名字段取值为 `browser` 等）。
const SOURCE_BROWSER: &str = "browser";
const SOURCE_SESSION: &str = "session";
const SOURCE_UPSTREAM: &str = "upstream";

/// 镜像自有 cookie（原版 `db::SupplementalCookie::is_mirror_local`，0x248780 引用的
/// 名字表 0xD8C8BA/0xD85FB0/0xD85FC0/0xD8BEB0/0xD54150）：属于镜像自身，绝不写进
/// 上游 jar，也绝不回注上游。
const MIRROR_LOCAL_NAMES: [&str; 10] = [
    "mirror_token",
    "mirror_api_session",
    "gateway_user_name",
    "login_mode",
    "model_limits",
    "isolated_session",
    "trusted_cdn_sources",
    "chatgpt_username",
    "next-auth.session-token",
    "__Secure-next-auth.session-token",
];

/// 浏览器偏好 cookie（原版 `is_browser_preference_cookie_name`，0x1872F0 引用的
/// 名字表 0xD548F0–0xD54990）：属于浏览器 UI 状态，不随共享账号搬迁。
const BROWSER_PREFERENCE_NAMES: [&str; 7] = [
    "oai-mweb-route-desktop",
    "oai-mweb-route-dl-config",
    "oai-default-mode_personalization",
    "oai_consent_personalization",
    "oai_consent_analytics",
    "oai_consent_marketing",
    "oai-last-model-config",
];

/// 上游 cookie（原版 `db::SupplementalCookie` 的 9 字段）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cookie {
    pub(super) name: String,
    pub(super) value: String,
    pub(super) domain: String,
    pub(super) host_only: bool,
    pub(super) path: String,
    pub(super) secure: bool,
    pub(super) http_only: bool,
    pub(super) expires: Option<i64>,
    pub(super) source: String,
}

impl Cookie {
    /// 序列化字段名与原版 serde 表逐字一致（含 `host_only`/`http_only` 下划线）。
    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "host_only": self.host_only,
            "path": self.path,
            "secure": self.secure,
            "http_only": self.http_only,
            "expires": self.expires,
            "source": self.source,
        })
    }

    /// 反序列化：缺字段按保守缺省补齐（历史行只有 name/value 两个字段）。
    fn from_json(value: &Value) -> Option<Self> {
        let name = value.get("name")?.as_str()?.trim();
        if name.is_empty() {
            return None;
        }
        Some(Self {
            name: name.to_owned(),
            value: value.get("value").and_then(Value::as_str)?.to_owned(),
            domain: value
                .get("domain")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim_start_matches('.')
                .to_ascii_lowercase(),
            host_only: value
                .get("host_only")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            path: value
                .get("path")
                .and_then(Value::as_str)
                .filter(|path| path.starts_with('/'))
                .unwrap_or("/")
                .to_owned(),
            secure: value
                .get("secure")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            http_only: value
                .get("http_only")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            expires: value.get("expires").and_then(Value::as_i64),
            source: value
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or(SOURCE_SESSION)
                .to_owned(),
        })
    }

    /// 是否属于镜像自有 cookie（原版 `is_mirror_local`）。
    fn is_mirror_local(&self) -> bool {
        MIRROR_LOCAL_NAMES
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&self.name))
    }

    /// 是否属于浏览器偏好 cookie（原版 `is_browser_preference_cookie_name`）。
    fn is_browser_preference(&self) -> bool {
        BROWSER_PREFERENCE_NAMES
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&self.name))
    }

    /// 可写入 jar 的条目：不在两张排除表内（名字非空由各构造点保证：
    /// `from_json` 拒空名、`from_session_pairs` 过滤空名、其余两处用固定名）。
    fn capturable(&self) -> bool {
        !self.is_mirror_local() && !self.is_browser_preference()
    }

    /// 是否来自上游实测（而不是 Django 下发的会话/号池原文）。只有这类条目回写
    /// 落库：会话凭据是 `rust_credential_binding` 绑定的原文，号池行的既有条目
    /// 由 Django 管理，二者都不该被本模块改写。
    fn is_captured(&self) -> bool {
        matches!(self.source.as_str(), SOURCE_BROWSER | SOURCE_UPSTREAM)
    }

    /// 是否仍有效（原版 `is_current_at`，0x2488E0）。
    fn is_current_at(&self, now: i64) -> bool {
        self.expires.is_none_or(|expires| expires > now)
    }

    /// 是否适用于该请求 URL（原版 `applies_to_url`，0x248E40）：域
    /// （host_only 精确 / 否则后缀）、安全位、路径前缀三条一起判定。
    pub(super) fn applies_to_url(&self, url: &url::Url, now: i64) -> bool {
        if !self.is_current_at(now) {
            return false;
        }
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return false;
        };
        let domain = self.domain.trim_start_matches('.').to_ascii_lowercase();
        // 空域只表示「不限定域」（Django 下发的历史 name/value 行），安全位与路径仍然生效。
        if !domain.is_empty() {
            let matched = if self.host_only {
                host == domain
            } else {
                host == domain || host.ends_with(&format!(".{domain}"))
            };
            if !matched {
                return false;
            }
        }
        if self.secure && url.scheme() != "https" {
            return false;
        }
        let request_path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        path_matches(&self.path, request_path)
    }
}

/// RFC6265 §5.1.4 路径匹配。
fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path == request_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

/// 请求 URL 派生的缺省路径（RFC6265 §5.1.4）：`/a/b` → `/a`，`/a` → `/`。
fn default_path(url: &url::Url) -> String {
    let path = url.path();
    if !path.starts_with('/') || path.matches('/').count() <= 1 {
        return "/".to_owned();
    }
    match path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(index) => path[..index].to_owned(),
    }
}

/// 时间戳（原版 `db::now_ts` 同义）。
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// 会话 `extra_cookies`（Django 下发的 name/value 结构）转 jar 条目：账号级凭据按
/// 上游主机 host-only 处理，排在最前以保持既有观测顺序。
pub(super) fn from_session_pairs(pairs: &[(String, String)], upstream_host: &str) -> Vec<Cookie> {
    pairs
        .iter()
        .filter(|(name, value)| !name.trim().is_empty() && !value.is_empty())
        .map(|(name, value)| Cookie {
            name: name.trim().to_owned(),
            value: value.clone(),
            domain: upstream_host.to_ascii_lowercase(),
            host_only: true,
            path: "/".to_owned(),
            secure: false,
            http_only: true,
            expires: None,
            source: SOURCE_SESSION.to_owned(),
        })
        .filter(Cookie::capturable)
        .collect()
}

/// 解析 JSON 数组形态的 jar（会话列/号池列共用）；非数组或坏条目按空/跳过处理。
pub(super) fn parse_json(raw: &str) -> Vec<Cookie> {
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    entries.iter().filter_map(Cookie::from_json).collect()
}

/// jar → JSON 数组（连同 `expires`/`source` 一起持久化）。
pub(super) fn to_json(jar: &[Cookie]) -> Result<String> {
    let entries: Vec<Value> = jar.iter().map(Cookie::to_json).collect();
    Ok(serde_json::to_string(&entries)?)
}

/// 合并：`extra` 的条目按 (name, domain, path) 覆盖 `into` 中的同名条目，其余按原
/// 顺序追加（保持会话凭据在前、捕获项在后的观测顺序）。
fn upsert(into: &mut Vec<Cookie>, extra: impl IntoIterator<Item = Cookie>) {
    for cookie in extra {
        if !cookie.capturable() {
            continue;
        }
        match into.iter_mut().find(|existing| {
            existing.name == cookie.name
                && existing.domain.eq_ignore_ascii_case(&cookie.domain)
                && existing.path == cookie.path
        }) {
            Some(existing) => *existing = cookie,
            None => into.push(cookie),
        }
    }
}

/// 取出适用于该 URL 的条目（原版 `cookies_to_header`/`build_upstream_auth_cookie_header`
/// 语义）：命中作用域且仍有效的条目按顺序返回，同名只保留最先出现的值。
pub(super) fn pairs_for(jar: &[Cookie], url: &url::Url) -> Vec<(String, String)> {
    let now = now();
    let mut names: Vec<&str> = Vec::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    for cookie in jar {
        if !cookie.applies_to_url(url, now) {
            continue;
        }
        if names.contains(&cookie.name.as_str()) {
            continue;
        }
        names.push(&cookie.name);
        pairs.push((cookie.name.clone(), cookie.value.clone()));
    }
    pairs
}

/// 设备标识：jar 里最后一个 `oai-did` 的值（原版 `server_oai_device_id`）。
pub(super) fn device_value(jar: &[Cookie]) -> Option<String> {
    jar.iter()
        .rfind(|cookie| cookie.name == DEVICE_COOKIE && !cookie.value.is_empty())
        .map(|cookie| cookie.value.clone())
}

/// 设备标识白名单：可见 ASCII，且不含 cookie 分隔符。
fn sanitize_device(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() || value.len() > DEVICE_MAX_LEN {
        return None;
    }
    let allowed = value
        .bytes()
        .all(|byte| (0x21..=0x7e).contains(&byte) && !matches!(byte, b';' | b',' | b'"'));
    if !allowed {
        return None;
    }
    Some(value.to_owned())
}

/// 写入设备标识（原版 `server_oai_device_cookie` 按 name + source 筛选的那一项）。
pub(super) fn set_device(jar: &mut Vec<Cookie>, value: &str, upstream_host: &str) {
    let Some(value) = sanitize_device(value) else {
        return;
    };
    upsert(
        jar,
        [Cookie {
            name: DEVICE_COOKIE.to_owned(),
            value,
            domain: upstream_host.to_ascii_lowercase(),
            host_only: true,
            path: "/".to_owned(),
            secure: false,
            http_only: false,
            expires: None,
            source: SOURCE_BROWSER.to_owned(),
        }],
    );
}

/// 浏览器本次请求携带的设备标识：优先 `oai-device-id` 头（原版
/// `browser_oai_device_id`，2026-09-23 实测浏览器确实发送该头），其次 Cookie 头里的
/// `oai-did` 兜底。
pub(super) fn device_from_request(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get(DEVICE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_device)
    {
        return Some(value);
    }
    let raw = headers.get("cookie")?.to_str().ok()?;
    for pair in raw.split(';') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key.trim() == DEVICE_COOKIE {
            return sanitize_device(value);
        }
    }
    None
}

/// 解析一个 `Set-Cookie` 头（原版捕获侧解析）：名字/值 + 属性。
fn parse_set_cookie(raw: &str, url: &url::Url, source: &str) -> Option<Cookie> {
    let (pair, attributes) = raw.split_once(';').unwrap_or((raw, ""));
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let mut cookie = Cookie {
        name: name.to_owned(),
        value: value.trim().to_owned(),
        domain: host,
        host_only: true,
        path: default_path(url),
        secure: false,
        http_only: false,
        expires: None,
        source: source.to_owned(),
    };
    let mut max_age: Option<i64> = None;
    for attribute in attributes.split(';') {
        let Some((key, raw_value)) = attribute.split_once('=') else {
            // 无值属性：Secure / HttpOnly。
            match attribute.trim().to_ascii_lowercase().as_str() {
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                _ => {}
            }
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let raw_value = raw_value.trim().trim_matches('"');
        match key.as_str() {
            "domain" => {
                let domain = raw_value.trim_start_matches('.').to_ascii_lowercase();
                if !domain.is_empty() {
                    cookie.host_only = false;
                    cookie.domain = domain;
                }
            }
            "path" if raw_value.starts_with('/') => cookie.path = raw_value.to_owned(),
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "max-age" => max_age = raw_value.parse::<i64>().ok(),
            "expires" => cookie.expires = parse_http_date(raw_value),
            _ => {}
        }
    }
    if let Some(seconds) = max_age {
        // Max-Age 优先于 Expires；非正值表示立即失效（删除指令）。
        cookie.expires = Some(now() + seconds);
    }
    Some(cookie)
}

/// `Expires` 的 HTTP 日期解析：只支持上游实际使用的 IMF-fixdate
/// （`Wed, 23 Sep 2026 04:34:44 GMT`，真实上游 `__cf_bm` 的观测形态），
/// 其它形态按「无过期时间」（会话 cookie）处理，不猜格式。
fn parse_http_date(raw: &str) -> Option<i64> {
    let mut parts = raw.split_whitespace();
    let _weekday = parts.next()?;
    let day: i64 = parts.next()?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next()?.parse().ok()?;
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// 公历日期 → 1970-01-01 起的天数（Howard Hinnant 的 days_from_civil）。
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// 捕获响应里的 `Set-Cookie`（原版 `capture_upstream_cookies`）。
/// 返回是否有条目变化，供调用方决定是否落库。
pub(super) fn capture(
    jar: &mut Vec<Cookie>,
    url: &url::Url,
    headers: &HeaderMap,
    source: &str,
) -> bool {
    let mut changed = false;
    for raw in headers.get_all("set-cookie").iter() {
        let Ok(raw) = raw.to_str() else { continue };
        let Some(cookie) = parse_set_cookie(raw, url, source) else {
            continue;
        };
        if !cookie.capturable() {
            continue;
        }
        // 已过期（含 `Max-Age=0` 的删除指令）视为删除，不再保留条目。
        let now = now();
        let expired = cookie.expires.is_some_and(|expires| expires <= now);
        let position = jar.iter().position(|existing| {
            existing.name == cookie.name
                && existing.domain.eq_ignore_ascii_case(&cookie.domain)
                && existing.path == cookie.path
        });
        match (position, expired) {
            // 删除指令（Max-Age<=0）：移除同键条目。
            (Some(index), true) => {
                jar.remove(index);
                changed = true;
            }
            (Some(index), false) => {
                if jar[index] != cookie {
                    jar[index] = cookie;
                    changed = true;
                }
            }
            (None, false) => {
                jar.push(cookie);
                changed = true;
            }
            (None, true) => {}
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// 持久化：会话列（gateway_sessions.upstream_cookies）与号池列（账号级）
// ---------------------------------------------------------------------------

/// 读取会话 jar（`upstream_cookies` 列，加密存储）。
pub(super) fn session_jar(db: &Database, user: &str, account: &str) -> Result<Vec<Cookie>> {
    let raw: Option<Option<String>> = db
        .conn
        .query_row(
            "SELECT upstream_cookies FROM gateway_sessions \
             WHERE user_name = ?1 AND chatgpt_username = ?2",
            params![user, account],
            |row| row.get(0),
        )
        .optional()?;
    let Some(encrypted) = raw.flatten() else {
        return Ok(Vec::new());
    };
    Ok(parse_json(&db.decrypt(&encrypted)?))
}

/// 写会话 jar；会话行不存在时 UPDATE 影响 0 行，不新建行。只落**实测捕获**条目：
/// Django 下发的会话凭据每次请求都会重新拼进 jar，重复落库只会在凭据撤换后留下副本。
fn store_session_jar(db: &Database, user: &str, account: &str, jar: &[Cookie]) -> Result<()> {
    let captured: Vec<Cookie> = jar
        .iter()
        .filter(|cookie| cookie.is_captured())
        .cloned()
        .collect();
    let encrypted = db.encrypt(&to_json(&captured)?)?;
    db.conn.execute(
        "UPDATE gateway_sessions SET upstream_cookies = ?1 \
         WHERE user_name = ?2 AND chatgpt_username = ?3",
        params![encrypted, user, account],
    )?;
    Ok(())
}

/// 读取号池账号行的 `extra_cookies`（账号级 jar，同账号多镜像用户共享）。
pub(super) fn pool_jar(db: &Database, account: &str) -> Result<Vec<Cookie>> {
    let raw: Option<String> = db
        .conn
        .query_row(
            "SELECT COALESCE(extra_cookies, '[]') FROM chatgpt_accounts \
             WHERE chatgpt_username = ?1",
            [account],
            |row| row.get(0),
        )
        .optional()?;
    let Some(encrypted) = raw else {
        return Ok(Vec::new());
    };
    Ok(parse_json(&db.decrypt(&encrypted)?))
}

/// 写号池行：逐条目就地更新，保留行内未知字段（Django 导入的行可能带附加键）；
/// 只写实测捕获条目，Django 管理的既有条目（含历史 name/value 行）原样保留；
/// 行不存在或列不是数组时跳过，不凭一次业务响应创建账号池记录。
fn store_pool_jar(db: &Database, account: &str, jar: &[Cookie]) -> Result<()> {
    let raw: Option<String> = db
        .conn
        .query_row(
            "SELECT COALESCE(extra_cookies, '[]') FROM chatgpt_accounts \
             WHERE chatgpt_username = ?1",
            [account],
            |row| row.get(0),
        )
        .optional()?;
    let Some(encrypted) = raw else {
        return Ok(());
    };
    let decrypted = db.decrypt(&encrypted)?;
    let Ok(Value::Array(mut entries)) = serde_json::from_str::<Value>(&decrypted) else {
        tracing::warn!(
            module = "gateway",
            account = %account,
            "号池账号 extra_cookies 不是 JSON 数组，跳过上游 Cookie 落库"
        );
        return Ok(());
    };
    for cookie in jar.iter().filter(|cookie| cookie.is_captured()) {
        let fields = cookie.to_json();
        let Some(fields) = fields.as_object() else {
            continue;
        };
        match entries
            .iter_mut()
            .find(|entry| entry.get("name").and_then(Value::as_str) == Some(cookie.name.as_str()))
        {
            // 只覆盖本候选负责的字段，保留行内其它未知键。
            Some(Value::Object(object)) => {
                for (key, field) in fields {
                    object.insert(key.clone(), field.clone());
                }
            }
            Some(_) => continue,
            None => entries.push(Value::Object(fields.clone())),
        }
    }
    let encrypted = db.encrypt(&serde_json::to_string(&entries)?)?;
    db.conn.execute(
        "UPDATE chatgpt_accounts SET extra_cookies = ?1 WHERE chatgpt_username = ?2",
        params![encrypted, account],
    )?;
    Ok(())
}

/// 组装会话 jar：会话凭据（Django 下发的 name/value）在前，其后是会话列已捕获条目，
/// 再从号池账号补齐缺失条目（原版 `restore_account_device_cookie_if_needed` 的账号级
/// 恢复，对全部 cookie 生效）。后两级只**补缺口**：同名条目以先到者为准，会话凭据
/// 永远压过落库副本，与原版 “if_needed” 语义一致。
pub(super) fn restore(
    db: &Database,
    user: &str,
    account: &str,
    session_pairs: &[(String, String)],
    upstream_host: &str,
) -> Result<Vec<Cookie>> {
    let mut jar = from_session_pairs(session_pairs, upstream_host);
    fill_gaps(&mut jar, session_jar(db, user, account)?);
    fill_gaps(&mut jar, pool_jar(db, account)?);
    Ok(jar)
}

/// 追加 jar 里还没有的名字（Cookie 头对同名也只发第一条，因此按名字判定即可）。
fn fill_gaps(jar: &mut Vec<Cookie>, extra: impl IntoIterator<Item = Cookie>) {
    for cookie in extra {
        if !cookie.capturable() || jar.iter().any(|existing| existing.name == cookie.name) {
            continue;
        }
        jar.push(cookie);
    }
}

/// 落库：会话列始终写，号池行存在时同步写账号级（原版双存储）。
pub(super) fn persist(db: &Database, user: &str, account: &str, jar: &[Cookie]) -> Result<()> {
    store_session_jar(db, user, account, jar)?;
    store_pool_jar(db, account, jar).context("保存上游 Cookie 失败")
}

/// 落库并记录失败：上游 cookie 是尽力而为的旁路状态，取不到只丢这一份副本，
/// 绝不判定凭据失效（原版「保存上游 Cookie 失败」日志同义）。
async fn save(app: &App, session: &Session, jar: &[Cookie]) {
    let db = app.db.lock().await;
    if let Err(cause) = persist(&db, &session.user, &session.account, jar) {
        tracing::error!(
            module = "gateway",
            error = %cause,
            account = %session.account,
            "保存上游 Cookie 失败"
        );
    }
}

/// 浏览器设备标识播种（原版 `browser_oai_device_id` 在请求侧生效）：jar 里已经有
/// `oai-did` 时不覆盖，由触发播种的第一个请求定型。
pub(super) async fn adopt_device_from_request(
    app: &App,
    session: &Session,
    jar: &mut Vec<Cookie>,
    headers: &HeaderMap,
) -> bool {
    if session.anonymous || device_value(jar).is_some() {
        return false;
    }
    let Some(value) = device_from_request(headers) else {
        return false;
    };
    set_device(jar, &value, &upstream_host(app));
    save(app, session, jar).await;
    true
}

/// 上游响应捕获（原版 `capture_upstream_cookies`）：真实上游是 cookie 的权威来源，
/// 取到即合并落库；捕获失败只记日志，不判定凭据失效。
pub(super) async fn capture_response(
    app: &App,
    session: &Session,
    jar: &mut Vec<Cookie>,
    url: &url::Url,
    response: &wreq::Response,
) {
    if session.anonymous {
        return;
    }
    if !capture(jar, url, response.headers(), SOURCE_UPSTREAM) {
        return;
    }
    save(app, session, jar).await;
}

/// CF 刷新后清掉 jar 里的旧 Cloudflare 条目（原版 `clear_stored_cloudflare_cookies`，
/// 0x24EEC0 同时清理会话与号池两处）：jar 在 Cookie 头里排在 CF 缓存之前，留着旧值会
/// 让刷新后的重放继续带失效的 `cf_clearance`，刷新形同无效。
pub(super) async fn forget_cloudflare(app: &App, session: &Session, jar: &mut Vec<Cookie>) {
    if session.anonymous {
        return;
    }
    let before = jar.len();
    jar.retain(|cookie| {
        !CLOUDFLARE_COOKIE_NAMES
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&cookie.name))
    });
    if jar.len() != before {
        save(app, session, jar).await;
    }
}

/// 上游主机名：jar 条目的 host-only 域从这里取。
pub(super) fn upstream_host(app: &App) -> String {
    app.config
        .upstream
        .host_str()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default()
}

/// 设备标识头（原版 `send_upstream_request` 与 WS 桥都显式写入该头）。
pub(super) fn device_header(value: &str) -> Option<(HeaderName, HeaderValue)> {
    HeaderValue::from_str(value)
        .ok()
        .map(|value| (HeaderName::from_static(DEVICE_HEADER), value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> url::Url {
        url::Url::parse(raw).unwrap()
    }

    fn cookie(name: &str, value: &str) -> Cookie {
        Cookie {
            name: name.to_owned(),
            value: value.to_owned(),
            domain: "chatgpt.com".to_owned(),
            host_only: true,
            path: "/".to_owned(),
            secure: false,
            http_only: false,
            expires: None,
            source: SOURCE_UPSTREAM.to_owned(),
        }
    }

    #[test]
    fn mirror_local_and_preference_names_are_never_captured() {
        for name in ["mirror_token", "mirror_api_session", "gateway_user_name"] {
            assert!(
                !cookie(name, "x").capturable(),
                "{name} 属于镜像自有 cookie"
            );
        }
        for name in [
            "next-auth.session-token",
            "__Secure-next-auth.session-token",
        ] {
            assert!(
                !cookie(name, "x").capturable(),
                "{name} 属于镜像自有 cookie"
            );
        }
        for name in [
            "oai_consent_analytics",
            "oai_consent_marketing",
            "oai-last-model-config",
            "oai-mweb-route-dl-config",
            "oai-default-mode_personalization",
        ] {
            assert!(!cookie(name, "x").capturable(), "{name} 属于浏览器偏好");
        }
        for name in [
            "oai-did", "oai-sc", "__oailb", "__cf_bm", "__cflb", "_cfuvid",
        ] {
            assert!(cookie(name, "x").capturable(), "{name} 必须可捕获");
        }
    }

    #[test]
    fn scope_uses_domain_path_secure_and_expiry() {
        let now = 1_000_000;
        let target = url("https://chatgpt.com/backend-api/me");
        assert!(cookie("a", "1").applies_to_url(&target, now));

        let mut host_only = cookie("a", "1");
        host_only.host_only = true;
        assert!(!host_only.applies_to_url(&url("https://ws.chatgpt.com/x"), now));

        let mut domain_suffix = cookie("a", "1");
        domain_suffix.host_only = false;
        assert!(domain_suffix.applies_to_url(&url("https://ws.chatgpt.com/x"), now));
        assert!(!domain_suffix.applies_to_url(&url("https://example.invalid/x"), now));

        let mut secure = cookie("a", "1");
        secure.secure = true;
        assert!(secure.applies_to_url(&target, now));
        assert!(!secure.applies_to_url(&url("http://chatgpt.com/backend-api/me"), now));

        let mut scoped = cookie("a", "1");
        scoped.path = "/backend-api".to_owned();
        assert!(scoped.applies_to_url(&target, now));
        assert!(!scoped.applies_to_url(&url("https://chatgpt.com/other"), now));

        let mut expired = cookie("a", "1");
        expired.expires = Some(now - 1);
        assert!(!expired.applies_to_url(&target, now));

        // 空域（Django 历史 name/value 行）只豁免域判定，路径与安全位照旧生效。
        let mut legacy = cookie("a", "1");
        legacy.domain = String::new();
        assert!(legacy.applies_to_url(&url("https://ws.chatgpt.com/x"), now));
        legacy.path = "/other".to_owned();
        assert!(!legacy.applies_to_url(&target, now));
    }

    #[test]
    fn set_cookie_attributes_are_parsed_with_rfc_defaults() {
        let target = url("https://chatgpt.com/backend-api/sentinel/frame.html");
        let parsed = parse_set_cookie(
            "oai-did=abc-123; Path=/; HttpOnly; Secure; SameSite=None",
            &target,
            SOURCE_UPSTREAM,
        )
        .unwrap();
        assert_eq!(parsed.name, "oai-did");
        assert_eq!(parsed.value, "abc-123");
        assert!(parsed.host_only, "无 Domain 属性时必须是 host-only");
        assert_eq!(parsed.domain, "chatgpt.com");
        assert_eq!(parsed.path, "/");
        assert!(parsed.secure && parsed.http_only);

        // 无 Path 属性时按 RFC6265 缺省路径取目录。
        let parsed = parse_set_cookie("a=1", &target, SOURCE_UPSTREAM).unwrap();
        assert_eq!(parsed.path, "/backend-api/sentinel");

        let parsed = parse_set_cookie(
            "a=1; Domain=.chatgpt.com; Path=/x",
            &target,
            SOURCE_UPSTREAM,
        )
        .unwrap();
        assert_eq!(parsed.domain, "chatgpt.com");
        assert!(!parsed.host_only);
        assert_eq!(parsed.path, "/x");

        assert_eq!(parse_set_cookie("novalue", &target, SOURCE_UPSTREAM), None);
    }

    #[test]
    fn capture_upserts_and_deletes_when_countered() {
        let target = url("https://chatgpt.com/backend-api/me");
        let mut jar = vec![cookie("__cf_bm", "old")];
        let mut headers = HeaderMap::new();
        headers.insert(
            "set-cookie",
            HeaderValue::from_static("__cf_bm=new; Path=/; Secure"),
        );
        assert!(capture(&mut jar, &target, &headers, SOURCE_UPSTREAM));
        assert_eq!(jar.len(), 1);
        assert_eq!(jar[0].value, "new");

        // 排除名单内的名字被忽略，且不产生变化。
        let mut headers = HeaderMap::new();
        headers.insert("set-cookie", HeaderValue::from_static("mirror_token=leak"));
        assert!(!capture(&mut jar, &target, &headers, SOURCE_UPSTREAM));
        assert_eq!(jar.len(), 1);

        // Max-Age=0 是删除指令。
        let mut headers = HeaderMap::new();
        headers.insert(
            "set-cookie",
            HeaderValue::from_static("__cf_bm=; Path=/; Max-Age=0"),
        );
        assert!(capture(&mut jar, &target, &headers, SOURCE_UPSTREAM));
        assert!(jar.is_empty());
    }

    #[test]
    fn header_keeps_first_occurrence_and_skips_out_of_scope_entries() {
        let mut jar = vec![cookie("a", "1"), cookie("a", "2")];
        let mut other = cookie("b", "3");
        other.domain = "example.invalid".to_owned();
        jar.push(other);
        let pairs = pairs_for(&jar, &url("https://chatgpt.com/x"));
        assert_eq!(
            pairs,
            vec![("a".to_owned(), "1".to_owned())],
            "同名只保留最先出现的值，作用域外条目不发"
        );
    }

    #[test]
    fn http_date_parsing_matches_known_timestamps() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        // 真实上游 __cf_bm 的 Expires 观测形态（evidence/anonymous-nextauth-001）。
        assert_eq!(
            parse_http_date("Wed, 23 Sep 2026 04:34:44 GMT"),
            Some(1_790_138_084)
        );
        assert_eq!(parse_http_date("not a date"), None);
    }

    #[test]
    fn device_helpers_accept_uuid_and_reject_malformed_values() {
        assert_eq!(
            sanitize_device("e9ed5d7b-54c4-459d-9dec-7440392daba3").as_deref(),
            Some("e9ed5d7b-54c4-459d-9dec-7440392daba3")
        );
        assert_eq!(sanitize_device(""), None);
        assert_eq!(sanitize_device(&"a".repeat(DEVICE_MAX_LEN + 1)), None);
        assert_eq!(sanitize_device("has;semicolon"), None);
        assert_eq!(sanitize_device("中文"), None);

        let mut headers = HeaderMap::new();
        headers.insert(DEVICE_HEADER, HeaderValue::from_static("from-header"));
        assert_eq!(
            device_from_request(&headers).as_deref(),
            Some("from-header")
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("a=1; oai-did=from-cookie"),
        );
        assert_eq!(
            device_from_request(&headers).as_deref(),
            Some("from-cookie")
        );
    }

    #[test]
    fn json_round_trip_keeps_all_nine_fields() {
        let mut jar = vec![cookie("oai-did", "value-1")];
        jar[0].expires = Some(1_788_957_284);
        jar[0].source = SOURCE_BROWSER.to_owned();
        let raw = to_json(&jar).unwrap();
        assert_eq!(parse_json(&raw), jar);
        // 历史行只有 name/value 时按 host-only 缺省补齐。
        let legacy = parse_json(r#"[{"name":"probe_extra","value":"EV"}]"#);
        assert_eq!(legacy.len(), 1);
        assert!(legacy[0].host_only);
        assert_eq!(legacy[0].path, "/");
    }
}

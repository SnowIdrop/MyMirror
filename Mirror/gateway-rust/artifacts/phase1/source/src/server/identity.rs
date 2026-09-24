// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/identity.rs
// Created : 2026-09-24
// Summary : 出网传输身份的唯一事实来源。传输画像（wreq/btls 的 Chrome146）与请求
//           头身份（UA + sec-ch-ua 全族）必须同源，任何一处单独改动都会让
//           「TLS 声称的版本」与「请求头声称的版本」对不上。
// 证据来源：
//           - 原版二进制：`proxy::apply_chrome_146_network_identity` 的字面量、
//             `LD_PRELOAD=libcurl-impersonate.so` + `CURL_IMPERSONATE=chrome146`
//             （reverse/reports/03 §5、08 §8.1）；
//           - 原版出站请求头实录（evidence/proxy-v3-original-007/results.json）
//             与真浏览器经候选网关的请求头清单（evidence/anonymous-nextauth-001）；
//           - 2026-09-24 真 Chromium 同源 XHR 服务端实录
//             （probe/evidence/browser-headers-*.json）：`sec-fetch-dest: empty`、
//             `sec-fetch-mode: cors`、`sec-fetch-site: same-origin`、无 `priority`、
//             XHR 不带 `upgrade-insecure-requests`，POST 才补 `origin`。
// -----------------------------------------------------------------------------

//! 不变式：所有出网客户端都由本模块构造；身份头只在这里定义一次。
//!
//! 覆盖语义是**强制整组覆盖**（不是原版的「缺失才补」）：浏览器带来的
//! `sec-ch-ua-platform` 等值一律被固定身份替换，否则 Windows 用户会让上游同时
//! 看到「UA 说 Linux」与「提示说 Windows」。

use super::*;
use axum::http::Method;
use axum::http::HeaderName;
use wreq::IntoEmulation;
use wreq::header::OrigHeaderMap;
use wreq_util::{Emulation, Platform, Profile};

/// 上游默认 User-Agent。与 `wreq_util` 的 Chrome146/Linux 画像给出的 UA 逐字相同
/// （`src/emulate/profile/chrome.rs` 的 v146 Linux 项），由库内单测交叉断言。
pub(super) const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

/// `navigator.platform` 在 Linux 桌面 Chrome 的真实取值。
const NAVIGATOR_PLATFORM: &str = "Linux x86_64";

/// 身份头整组。品牌列表采用 `wreq_util` 的 Chrome146 预设（Chromium + GREASE +
/// Google Chrome，与 UA 声称的 Chrome 品牌一致）；高熵项由本表显式给出，
/// 因为 `wreq_util` 只预设低熵三项。完整版本号沿用原版二进制字面量与镜像内
/// chromium 包版本（146.0.7680.177），UA 里的 `146.0.0.0` 是 Chrome 的 UA
/// 折叠写法，两者本来就不同。
const IDENTITY_HEADERS: [(&str, &str); 10] = [
    ("user-agent", USER_AGENT),
    (
        "sec-ch-ua",
        r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
    ),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""Linux""#),
    ("sec-ch-ua-platform-version", r#""""#),
    ("sec-ch-ua-arch", r#""x86""#),
    ("sec-ch-ua-bitness", r#""64""#),
    ("sec-ch-ua-model", r#""""#),
    ("sec-ch-ua-full-version", r#""146.0.7680.177""#),
    (
        "sec-ch-ua-full-version-list",
        r#""Chromium";v="146.0.7680.177", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.177""#,
    ),
];

/// 身份表是身份取值的唯一来源：调用方（含 cfbypass 交叉校验）按需读表，
/// 不再各自维护第二份字面量。值本身取自真 Chrome 的实测头。
pub(super) fn hint(name: &str) -> &'static str {
    IDENTITY_HEADERS
        .iter()
        .find(|(key, _)| *key == name)
        .unwrap_or_else(|| panic!("身份表缺少 {name}"))
        .1
}

/// 完整版本号（`sec-ch-ua-full-version` 去掉引号），与画像、cfbypass 镜像
/// chromium 包、原版二进制字面量同源。
pub(super) fn full_version() -> String {
    hint("sec-ch-ua-full-version").trim_matches('"').to_owned()
}

/// 真 Chrome 的 HTTP/1.1 请求头顺序（2026-09-24 服务端实录；同源 XHR 的
/// GET 高熵、GET 低熵与 POST 三次一致）。`host`/`connection`/`content-length`
/// 由传输层自己生成，不在表内；表外的头（cookie、authorization 等）按调用方
/// 插入顺序追加在后面。取值同样适用于 HTTP/2：HPACK 保持输入顺序。
const REQUEST_HEADER_ORDER: [&str; 19] = [
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-platform",
    "accept-language",
    "sec-ch-ua",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-mobile",
    "sec-ch-ua-arch",
    "sec-ch-ua-full-version",
    "user-agent",
    "content-type",
    "sec-ch-ua-platform-version",
    "accept",
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
];

/// TLS/HTTP2 画像：与 `IDENTITY_HEADERS` 同版本、同平台。
///
/// `headers(false)` 是刻意的：画像预设头是**导航**形状（`sec-fetch-dest: document`、
/// `sec-fetch-mode: navigate`、`accept: text/html,…`、`priority: u=0, i`），而
/// wreq 把它们作为「缺失才补」的默认头注入；候选网关转发的是 XHR/API 流量，
/// 2026-09-24 的真 Chromium 实录里这些请求没有 `priority`、`sec-fetch-*` 也是
/// `empty/cors/same-origin`。留着预设头等于在浏览器没给值时发出错误值，因此
/// 只取画像的 TLS/H2 指纹，请求头一律由本模块的表提供。
pub fn emulation() -> wreq::Emulation {
    // 只取画像的 TLS/H2 指纹：请求头一律由本模块的表提供（见 `client_builder`）。
    // H2 SETTINGS 逐项与真 Chrome146 对照过（`evidence/reference-chrome146-001`）：
    // `0001=65536 → 0002=0 → 0004=6291456 → 0006=262144`，**不含**
    // `MAX_CONCURRENT_STREAMS`——画像自带的行为与参照一致，不需要也不应该补，
    // 由 `tests/identity_fingerprint.rs` 对着参照证据锁定。
    Emulation::builder()
        .profile(Profile::Chrome146)
        .platform(Platform::Linux)
        .headers(false)
        .build()
        .into_emulation()
}

/// 出网客户端基线：画像 + 直连默认值 + 禁止重定向与协议重试。
/// 调用方按需追加 `proxy` 与 `timeout`。
pub fn client_builder() -> wreq::ClientBuilder {
    wreq::Client::builder()
        .emulation(emulation())
        .orig_headers(orig_headers())
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .retry(wreq::retry::Policy::never())
}

/// 强制整组身份头：先删除全部 `sec-ch-ua*`（含未来新增的未知高熵提示），
/// 再写入固定身份组。只覆盖表内十项是不够的——宿主浏览器新增的提示会与
/// Linux/Chrome146 的 UA 同时出现。
pub(super) fn apply_identity(headers: &mut HeaderMap) {
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_client_hint(name.as_str()))
        .cloned()
        .collect();
    for name in names {
        headers.remove(&name);
    }
    for (name, value) in IDENTITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
}

/// UA-CH 头名：`sec-ch-ua` 本身或 `sec-ch-ua-*` 家族。
fn is_client_hint(name: &str) -> bool {
    name.strip_prefix("sec-ch-ua")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
}

/// 真 Chrome 的请求头顺序，交给 wreq 在 HTTP/1.x 序列化与 HPACK 输出时套用。
pub(super) fn orig_headers() -> OrigHeaderMap {
    let mut map = OrigHeaderMap::with_capacity(REQUEST_HEADER_ORDER.len());
    for name in REQUEST_HEADER_ORDER {
        map.insert(name);
    }
    map
}

/// 注入脚本用的身份 JSON：每个值都从 [`IDENTITY_HEADERS`] 派生，JS 侧不再维护
/// 第二份字面量，网络层与页面 JS 因此不可能各自漂移。
pub(super) fn js_identity() -> Value {
    /// 头值是带引号的字符串形式（`"x86"`），而 `getHighEntropyValues` 返回的是
    /// 去掉引号的裸值（`x86`）。
    fn bare(name: &str) -> &'static str {
        hint(name).trim_matches('"')
    }
    let brands = |name: &str| -> Value {
        Value::Array(
            hint(name)
                .split(',')
                .filter_map(|item| {
                    let (brand, version) = item.trim().split_once(";v=")?;
                    Some(json!({
                        "brand": brand.trim().trim_matches('"'),
                        "version": version.trim().trim_matches('"'),
                    }))
                })
                .collect(),
        )
    };
    json!({
        "userAgent": USER_AGENT,
        // `navigator.appVersion` 是去掉 `Mozilla/` 前缀的 UA。
        "appVersion": USER_AGENT.strip_prefix("Mozilla/").unwrap_or(USER_AGENT),
        "platform": NAVIGATOR_PLATFORM,
        "brands": brands("sec-ch-ua"),
        "fullVersionList": brands("sec-ch-ua-full-version-list"),
        "mobile": hint("sec-ch-ua-mobile") == "?1",
        "platformName": bare("sec-ch-ua-platform"),
        "architecture": bare("sec-ch-ua-arch"),
        "bitness": bare("sec-ch-ua-bitness"),
        "model": bare("sec-ch-ua-model"),
        "platformVersion": bare("sec-ch-ua-platform-version"),
        "fullVersion": bare("sec-ch-ua-full-version"),
    })
}

/// API 型请求（网关自己发起的凭据换取、诊断、清单）的固定头集。
///
/// 取值来自真 Chromium 的同源 XHR 实录加上原版出站实录：
/// `accept`/`accept-language` 沿用原版自身的值（前端 axios 形状），
/// `sec-fetch-*` 取浏览器 XHR 的三元组，`origin` 只在非 GET 上出现。
/// 浏览器导航才有的 `upgrade-insecure-requests`/`sec-fetch-user` 与 XHR 上
/// 并未出现的 `priority` 一律不发：宁可不发，也不发一个真实浏览器不会发的头。
pub(super) fn api_baseline(base: &url::Url, method: &Method) -> Result<HeaderMap> {
    let origin = proxy::chat_origin(base)?;
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("accept", "application/json, text/plain, */*"),
        ("accept-language", "zh-CN,zh;q=0.9,en;q=0.8"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
        ("oai-language", "zh-CN"),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers.insert(
        "referer",
        HeaderValue::from_str(&format!("{origin}/")).context("referer 头无效")?,
    );
    if *method != Method::GET && *method != Method::HEAD {
        headers.insert(
            "origin",
            HeaderValue::from_str(&origin).context("origin 头无效")?,
        );
    }
    apply_identity(&mut headers);
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreq::IntoEmulation;

    #[test]
    fn identity_overwrites_foreign_and_removes_unknown_client_hints() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-ch-ua", HeaderValue::from_static("\"Chromium\";v=\"151\""));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
        headers.insert("sec-ch-ua-form-factors", HeaderValue::from_static("\"Desktop\""));
        headers.insert("sec-ch-ua-wow64", HeaderValue::from_static("?0"));
        headers.insert("user-agent", HeaderValue::from_static("foreign/1.0"));
        apply_identity(&mut headers);
        assert_eq!(headers["sec-ch-ua"], *hint_value("sec-ch-ua"));
        assert_eq!(headers["sec-ch-ua-platform"], "\"Linux\"");
        assert_eq!(headers["user-agent"], USER_AGENT);
        // 整组都要在，缺任何一项都会与 TLS 画像声称的版本对不上。
        for (name, value) in IDENTITY_HEADERS {
            assert_eq!(headers[name], *value, "{name}");
        }
        assert!(!headers.contains_key("sec-ch-ua-form-factors"));
        assert!(!headers.contains_key("sec-ch-ua-wow64"));
    }

    fn hint_value(name: &str) -> &'static str {
        IDENTITY_HEADERS
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap_or_else(|| panic!("身份表缺少 {name}"))
            .1
    }

    /// 注入脚本的身份 JSON 必须逐值来自身份表，否则网络层与页面 JS 会各自漂移。
    #[test]
    fn js_identity_derives_every_value_from_the_header_table() {
        let identity = js_identity();
        assert_eq!(identity["userAgent"], USER_AGENT);
        assert_eq!(
            identity["appVersion"],
            USER_AGENT.strip_prefix("Mozilla/").unwrap()
        );
        assert_eq!(identity["platform"], NAVIGATOR_PLATFORM);
        assert_eq!(identity["architecture"], "x86");
        assert_eq!(identity["bitness"], "64");
        assert_eq!(identity["platformName"], "Linux");
        assert_eq!(identity["platformVersion"], "");
        assert_eq!(identity["model"], "");
        assert_eq!(identity["fullVersion"], full_version());
        assert_eq!(identity["mobile"], json!(false));
        // 真实 Linux Chrome 不会返回 Windows 专有的 wow64，不合成。
        assert!(identity.get("wow64").is_none());
        let brands: Vec<(String, String)> = identity["brands"]
            .as_array()
            .expect("品牌表必须是数组")
            .iter()
            .map(|item| {
                (
                    item["brand"].as_str().expect("品牌名").to_owned(),
                    item["version"].as_str().expect("品牌版本").to_owned(),
                )
            })
            .collect();
        assert_eq!(
            brands,
            vec![
                ("Chromium".to_owned(), "146".to_owned()),
                ("Not-A.Brand".to_owned(), "24".to_owned()),
                ("Google Chrome".to_owned(), "146".to_owned()),
            ]
        );
        let full: Vec<(String, String)> = identity["fullVersionList"]
            .as_array()
            .expect("完整品牌表必须是数组")
            .iter()
            .map(|item| {
                (
                    item["brand"].as_str().expect("品牌名").to_owned(),
                    item["version"].as_str().expect("品牌版本").to_owned(),
                )
            })
            .collect();
        assert_eq!(full[0].1, full_version());
        assert_eq!(full[2], ("Google Chrome".to_owned(), full_version()));
        // 头里的品牌表与 JS 解析结果同源：改一处不改另一处时这里会红。
        assert!(hint_value("sec-ch-ua").contains(&format!("\"{}\";v=\"{}\"", brands[0].0, brands[0].1)));
        assert!(
            hint_value("sec-ch-ua-full-version-list")
                .contains(&format!("\"{}\";v=\"{}\"", full[0].0, full[0].1))
        );
    }

    /// `orig_headers` 必须按实测顺序注册：HTTP/1.x 序列化与 HPACK 都按它输出。
    #[test]
    fn orig_headers_lock_the_observed_chrome_order() {
        let ordered: Vec<String> = orig_headers()
            .iter()
            .map(|(name, _)| name.as_str().to_owned())
            .collect();
        assert_eq!(ordered, REQUEST_HEADER_ORDER.to_vec());
        // 身份组里的每一项都必须在顺序表里，否则它会被追加到末尾。
        for (name, _) in IDENTITY_HEADERS {
            assert!(REQUEST_HEADER_ORDER.contains(&name), "{name} 不在顺序表里");
        }
    }

    #[test]
    fn api_baseline_carries_xhr_fetch_metadata_and_origin_only_on_writes() {
        let base = url::Url::parse("https://chatgpt.com/").unwrap();
        let get = api_baseline(&base, &Method::GET).expect("基线构造失败");
        assert_eq!(get["sec-fetch-dest"], "empty");
        assert_eq!(get["sec-fetch-mode"], "cors");
        assert_eq!(get["sec-fetch-site"], "same-origin");
        assert_eq!(get["referer"], "https://chatgpt.com/");
        assert!(!get.contains_key("origin"), "GET 不带 origin");
        assert!(!get.contains_key("priority"), "XHR 上没有 priority");
        assert_eq!(get["user-agent"], USER_AGENT);
        let post = api_baseline(&base, &Method::POST).expect("基线构造失败");
        assert_eq!(post["origin"], "https://chatgpt.com");
    }

    /// 表与画像同源：UA 与低熵 client hints 必须与 `wreq_util` 的 Chrome146/Linux
    /// 预设逐字一致；高熵项的主版本号也必须跟着预设走。库升级换了画像版本而没人
    /// 改这张表时，这条会红。
    #[test]
    fn identity_headers_match_wreq_util_chrome146_linux_preset() {
        // 预设头默认开启，正是要拿它当对照基准。
        let preset = wreq_util::Emulation::builder()
            .profile(Profile::Chrome146)
            .platform(Platform::Linux)
            .build()
            .into_emulation()
            .headers;
        let ours = |name: &str| {
            IDENTITY_HEADERS
                .iter()
                .find(|(key, _)| *key == name)
                .unwrap_or_else(|| panic!("身份表缺少 {name}"))
                .1
        };
        for name in ["user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"] {
            assert_eq!(ours(name), preset[name], "{name} 与画像预设不一致");
        }
        let ua = preset["user-agent"].to_str().expect("预设 UA 必须是可见字符串");
        let major = ua
            .split("Chrome/")
            .nth(1)
            .and_then(|rest| rest.split('.').next())
            .expect("预设 UA 必须带 Chrome 主版本");
        assert!(ours("sec-ch-ua").contains(&format!("v=\"{major}\"")), "低熵品牌表主版本漂了");
        for name in ["sec-ch-ua-full-version", "sec-ch-ua-full-version-list"] {
            assert!(ours(name).contains(&format!("\"{major}.")), "{name} 主版本漂了");
        }
    }
}

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
use wreq_util::{Emulation, Platform, Profile};

/// 上游默认 User-Agent。与 `wreq_util` 的 Chrome146/Linux 画像给出的 UA 逐字相同
/// （`src/emulate/profile/chrome.rs` 的 v146 Linux 项），由库内单测交叉断言。
pub(super) const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

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

/// TLS/HTTP2 画像：与 `IDENTITY_HEADERS` 同版本、同平台。
///
/// `headers(false)` 是刻意的：画像预设头是**导航**形状（`sec-fetch-dest: document`、
/// `sec-fetch-mode: navigate`、`accept: text/html,…`、`priority: u=0, i`），而
/// wreq 把它们作为「缺失才补」的默认头注入；候选网关转发的是 XHR/API 流量，
/// 2026-09-24 的真 Chromium 实录里这些请求没有 `priority`、`sec-fetch-*` 也是
/// `empty/cors/same-origin`。留着预设头等于在浏览器没给值时发出错误值，因此
/// 只取画像的 TLS/H2 指纹，请求头一律由本模块的表提供。
pub fn emulation() -> Emulation {
    Emulation::builder()
        .profile(Profile::Chrome146)
        .platform(Platform::Linux)
        .headers(false)
        .build()
}

/// 出网客户端基线：画像 + 直连默认值 + 禁止重定向与协议重试。
/// 调用方按需追加 `proxy` 与 `timeout`。
pub fn client_builder() -> wreq::ClientBuilder {
    wreq::Client::builder()
        .emulation(emulation())
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .retry(wreq::retry::Policy::never())
}

/// 强制整组身份头：已有同名头一律被固定值覆盖。
pub(super) fn apply_identity(headers: &mut HeaderMap) {
    for (name, value) in IDENTITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
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
    fn identity_overwrites_foreign_client_hints() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-ch-ua", HeaderValue::from_static("\"Chromium\";v=\"151\""));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
        headers.insert("user-agent", HeaderValue::from_static("foreign/1.0"));
        apply_identity(&mut headers);
        assert_eq!(headers["sec-ch-ua"], *IDENTITY_HEADERS[1].1);
        assert_eq!(headers["sec-ch-ua-platform"], "\"Linux\"");
        assert_eq!(headers["user-agent"], USER_AGENT);
        // 整组都要在，缺任何一项都会与 TLS 画像声称的版本对不上。
        for (name, value) in IDENTITY_HEADERS {
            assert_eq!(headers[name], *value, "{name}");
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

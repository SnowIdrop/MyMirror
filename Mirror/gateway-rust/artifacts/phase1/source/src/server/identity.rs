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

/// 网关**自己发起**的请求所用的 `accept-language`：网关自发请求（凭据换取、清单、
/// 诊断）、WS 握手、cfbypass 一跳共用这一份。
///
/// 转发跳（chat / 公共 CDN / 外链）**不**用它覆盖客户端，见
/// [`fallback_accept_language`]。
///
/// 取值来自 2026-09-24 真 Chromium 同源 XHR 实录；注意那份实录的探针用的是
/// `new_context(locale="zh-CN")`，所以它记录的是「一台 zh-CN 浏览器」的值，
/// 不是 Chrome146 的固有属性。
pub(super) const ACCEPT_LANGUAGE: &str = "zh-CN,zh;q=0.9,en;q=0.8";

/// 应用层界面语言（`oai-language`）。**不属于浏览器指纹**：它取账号/应用语言，
/// 真 Chrome 会在一台 `navigator.language=en-US` 的机器上发出 `oai-language=zh-CN`
/// （2026-09-29 实测，见 `evidence/identity-acceptance-round3-001/`）。因此它与
/// [`ACCEPT_LANGUAGE`] 是两份独立事实，不再互相派生。
pub(super) const APP_LANGUAGE: &str = "zh-CN";

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

/// 低熵身份头：浏览器**无条件**发给任何源的那一组。高熵项（arch/bitness/model/
/// platform-version/full-version/full-version-list）只在目标源用 `Accept-CH` 授权过
/// 之后才发给该源——参照里同源 XHR 带全组，正是因为首个响应带了
/// `accept-ch`（`evidence/reference-chrome146-001/03-request-headers.json` 的
/// `accept_ch` 字段与 request 0 的低熵导航）。因此第三方 CDN/外链一律只发这一组：
/// 对一个从没发过 `Accept-CH` 的源送全套高熵提示，真 Chrome 不会这么做。
const LOW_ENTROPY_HINTS: [&str; 3] = ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"];

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

/// 真 Chrome 的**导航**请求头顺序。导航与 XHR 不是同一个形状：导航多出
/// `upgrade-insecure-requests` 与 `sec-fetch-user`、**没有** `origin`，而且
/// 提示块本身就是另一个顺序——不是把 [`REQUEST_HEADER_ORDER`] 插两个头就行。
///
/// 取自 `evidence/browser-header-order-002.json`（2026-09-29，镜像内
/// chromium 146.0.7680.177 实测，生成器 `probe/capture_header_order.py`）：
/// `*-second` 是高熵导航、`nav-from-link` 给出 `referer` 的槽位，两轮语言注入
/// 方式下逐位相同。低熵前缀（`sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
/// Upgrade-Insecure-Requests, User-Agent, Accept-Language, …`）与
/// `evidence/reference-chrome146-001` 的首次导航实录逐位一致，因此这份补采与
/// 原参照同源，不是另一个浏览器的形状。
///
/// 此前这里的高熵提示块沿用 XHR 顺序、`accept-language` 也放在第 3 位，
/// 与参照自己的导航实录（`accept-language` 紧跟 `user-agent`）相矛盾：
/// 同一个「浏览器」的导航与 XHR 报了两套头序，而真 Chrome 的两套都是固定的。
const NAVIGATION_HEADER_ORDER: [&str; 19] = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-full-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version-list",
    "upgrade-insecure-requests",
    "user-agent",
    "accept-language",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
];

/// 真 Chrome 的 **WebSocket 握手**头顺序（`evidence/browser-header-order-002.json`
/// 的 `ws` 项，两轮逐位相同）。握手既不带 `sec-ch-ua*` 也不带 `referer`，
/// 而且 `accept-language` 在 `accept-encoding` **之后**——与 XHR、导航都不同。
///
/// `host`/`connection`/`upgrade`/`sec-websocket-*` 由传输层生成，列在表里只是
/// 为了让这张表就是实录本身；不由本层提供的名字在顺序表里是空操作。
const WS_HANDSHAKE_HEADER_ORDER: [&str; 12] = [
    "host",
    "connection",
    "pragma",
    "cache-control",
    "user-agent",
    "upgrade",
    "origin",
    "sec-websocket-version",
    "accept-encoding",
    "accept-language",
    "sec-websocket-key",
    "sec-websocket-extensions",
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
    remove_client_hints(headers);
    for (name, value) in IDENTITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    fallback_accept_language(headers);
}

/// 第三方目标（公共 CDN、外链代理）的身份头：`user-agent` + **只有低熵**提示。
///
/// 与 [`apply_identity`] 一样先整组删除 `sec-ch-ua*`（含宿主浏览器带来的未知提示），
/// 再写回低熵三项。差别只在高熵项：那六项要等目标源用 `Accept-CH` 授权过才发，
/// 对一个从没授权过的第三方源送全套高熵提示，真 Chrome 不会这么做，反而是
/// 一条比「UA 说 Linux」更强的可指纹信号。见 [`LOW_ENTROPY_HINTS`]。
pub(super) fn apply_low_entropy_identity(headers: &mut HeaderMap) {
    remove_client_hints(headers);
    headers.insert(
        HeaderName::from_static("user-agent"),
        HeaderValue::from_static(USER_AGENT),
    );
    for name in LOW_ENTROPY_HINTS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(hint(name)),
        );
    }
    fallback_accept_language(headers);
}

/// 转发跳的 `accept-language`：客户端带了就用客户端的，没带才用身份常量兜底。
///
/// 界面语言 [`APP_LANGUAGE`] 不是浏览器指纹，`accept-language` **才是**——真
/// Chrome 的这一项由 `navigator.languages` 派生，与页面里 `navigator.language`、
/// `Intl` 的默认 locale 天然一致。在这一跳强行钉成固定值，上游就会看到
/// 「线网说 zh-CN、页面 JS 说 en-US」这种真浏览器不会产生的组合
/// （2026-09-29 真实上游验收实测到这一对，见
/// `evidence/identity-acceptance-round3-001/`）。
///
/// 兜底而不是「缺了就留空」：网关也会被非浏览器调用方（探针、脚本）访问，那些
/// 请求没有 `accept-language`，而上游看到的应当是「一条真 Chrome 的请求」。
fn fallback_accept_language(headers: &mut HeaderMap) {
    if !headers.contains_key("accept-language") {
        headers.insert(
            HeaderName::from_static("accept-language"),
            HeaderValue::from_static(ACCEPT_LANGUAGE),
        );
    }
}

fn remove_client_hints(headers: &mut HeaderMap) {
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_client_hint(name.as_str()))
        .cloned()
        .collect();
    for name in names {
        headers.remove(&name);
    }
}

/// UA-CH 头名：`sec-ch-ua` 本身或 `sec-ch-ua-*` 家族。
fn is_client_hint(name: &str) -> bool {
    name.strip_prefix("sec-ch-ua")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
}

/// 真 Chrome 的请求头顺序，交给 wreq 在 HTTP/1.x 序列化与 HPACK 输出时套用。
pub(super) fn orig_headers() -> OrigHeaderMap {
    ordered(&REQUEST_HEADER_ORDER)
}

/// 导航请求的顺序表，按请求覆盖客户端基线（`RequestBuilder::orig_headers`）。
/// 见 [`NAVIGATION_HEADER_ORDER`]。
pub(super) fn navigation_orig_headers() -> OrigHeaderMap {
    ordered(&NAVIGATION_HEADER_ORDER)
}

/// WS 握手的顺序表，按请求覆盖客户端基线（`WebSocketRequestBuilder::orig_headers`）。
/// 不覆盖就会套用 XHR 的顺序表（`accept-language` 第 3 位、提示块在最前），
/// 而真 Chrome 的握手顺序是另一套。见 [`WS_HANDSHAKE_HEADER_ORDER`]。
pub(super) fn ws_orig_headers() -> OrigHeaderMap {
    ordered(&WS_HANDSHAKE_HEADER_ORDER)
}

// `OrigHeaderMap::insert` 只收 `'static` 名字（顺序表要活到请求发出），因此这里
// 不能是普通借用。两个调用点传的都是 `const` 数组，静态提升后天然满足。
fn ordered(names: &'static [&'static str]) -> OrigHeaderMap {
    let mut map = OrigHeaderMap::with_capacity(names.len());
    for name in names {
        map.insert(*name);
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
        // 下面两项**没有对应的身份头**，只存在于 `getHighEntropyValues`：
        // chatgpt.com 的 `Accept-CH` 里没有它们（实录 `03-request-headers.json` 的
        // `accept_ch`），所以网络层不发；但 JS 侧真 Chromium146 一问就答，
        // 少答一项同样是漂移（2026-09-29 实测，见 probe/check_native_identity.py）。
        //
        // `wow64` 只在 32 位进程跑在 64 位 Windows 上才为真；本身份是 Linux，恒假。
        "wow64": false,
        // 桌面 Chrome 恒回 `["Desktop"]`；移动端才是 `["Mobile"]`。取自本表的
        // `sec-ch-ua-mobile`，不另立第二份事实。
        "formFactors": if hint("sec-ch-ua-mobile") == "?1" { ["Mobile"] } else { ["Desktop"] },
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
        ("accept-language", ACCEPT_LANGUAGE),
        // 与转发跳同值：见 [`proxy::GZIP_ONLY_ACCEPT_ENCODING`]。此前这里声明
        // `gzip, deflate, br, zstd` 而转发跳只声明 `gzip`，同一个源上同一个「用户」
        // 报了两套压缩能力。
        ("accept-encoding", proxy::GZIP_ONLY_ACCEPT_ENCODING),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
        // 应用层的界面语言，与 `accept-language` 是两份独立事实（见 [`APP_LANGUAGE`]）。
        ("oai-language", APP_LANGUAGE),
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
        // 2026-09-29 对真 Chromium146/Linux 实测（probe/check_native_identity.py）：
        // `getHighEntropyValues` 会回 `wow64: false` 与 `formFactors: ["Desktop"]`。
        // 这两项没有对应的身份头（chatgpt.com 的 `Accept-CH` 里没有它们），
        // 但 JS 一问就答——**少答一项**同样是漂移，所以身份 JSON 必须带上。
        assert_eq!(identity["wow64"], json!(false));
        assert_eq!(identity["formFactors"], json!(["Desktop"]));
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

    /// 导航顺序表与 XHR 顺序表是两个形状：导航多 `upgrade-insecure-requests`
    /// 与 `sec-fetch-user`、且不含 `origin`。写反了上游会看到一个「导航里带
    /// Origin」的浏览器。
    #[test]
    fn navigation_order_is_a_navigation_shape() {
        let ordered: Vec<String> = navigation_orig_headers()
            .iter()
            .map(|(name, _)| name.as_str().to_owned())
            .collect();
        assert_eq!(ordered, NAVIGATION_HEADER_ORDER.to_vec());
        for name in ["upgrade-insecure-requests", "sec-fetch-user"] {
            assert!(NAVIGATION_HEADER_ORDER.contains(&name), "导航必须带 {name}");
            assert!(!REQUEST_HEADER_ORDER.contains(&name), "XHR 不该带 {name}");
        }
        assert!(!NAVIGATION_HEADER_ORDER.contains(&"origin"), "导航不带 origin");
        // 身份组整组仍要在表里，否则会被追加到末尾。
        for (name, _) in IDENTITY_HEADERS {
            assert!(NAVIGATION_HEADER_ORDER.contains(&name), "{name} 不在导航顺序表里");
        }
    }

    /// 补采的真 Chromium146 头序实录（生成器 `probe/capture_header_order.py`）。
    const HEADER_ORDER_EVIDENCE: &str =
        include_str!("../../../../../evidence/browser-header-order-002.json");

    /// 实录里某个请求的头名序列（覆盖轮：`reference-chrome146-001` 与 cfbypass
    /// 都是 `Emulation.setUserAgentOverride` 形态，见证据的 `conclusions`）。
    fn recorded_order(tag: &str) -> Vec<String> {
        let evidence: Value = serde_json::from_str(HEADER_ORDER_EVIDENCE).expect("头序证据无效");
        evidence["language_via_cdp_override"]["requests"][tag]["header_names"]
            .as_array()
            .unwrap_or_else(|| panic!("证据缺少 {tag}"))
            .iter()
            .map(|value| value.as_str().expect("头名必须是字符串").to_owned())
            .collect()
    }

    /// 两张顺序表逐位对实录。此前导航表沿用了 XHR 的提示块顺序、`accept-language`
    /// 也放在第 3 位，与参照自己的导航实录相矛盾——同一个「浏览器」的导航与 XHR
    /// 报了两套头序。补采（高熵导航 + 点击导航）把两者都钉死在这里。
    #[test]
    fn order_tables_match_the_captured_chrome146_order() {
        // 逐跳头由传输层生成，不进顺序表。
        let strip = |names: Vec<String>| -> Vec<String> {
            names
                .into_iter()
                .filter(|name| name != "host" && name != "connection")
                .collect()
        };
        // 高熵导航（`Accept-CH` 生效后的第二次导航）+ 点击导航给出 referer 槽位。
        let mut nav = strip(recorded_order("nav-from-link"));
        assert_eq!(nav, NAVIGATION_HEADER_ORDER.to_vec());
        // 无 referer 的导航就是同一张表去掉 referer，不是另一个顺序。
        nav.retain(|name| name != "referer");
        assert_eq!(nav, strip(recorded_order("override-second")));
        // 子资源实录是 REQUEST_HEADER_ORDER 的独立交叉证据（实录没有 POST，
        // 因此 `content-type`/`origin` 两项只出现在参照里，这里按位剔除后比对）。
        let xhr: Vec<&str> = REQUEST_HEADER_ORDER
            .iter()
            .copied()
            .filter(|name| *name != "content-type" && *name != "origin")
            .collect();
        assert_eq!(strip(recorded_order("favicon.ico")), xhr);
        // WS 握手表包含传输层自有头：它就是实录本身。
        assert_eq!(recorded_order("ws"), WS_HANDSHAKE_HEADER_ORDER.to_vec());
        let ws_ordered: Vec<String> = ws_orig_headers()
            .iter()
            .map(|(name, _)| name.as_str().to_owned())
            .collect();
        assert_eq!(ws_ordered, WS_HANDSHAKE_HEADER_ORDER.to_vec());
        // 三张表互不相同：写错一张就等于在某类请求上换了个浏览器。
        assert_ne!(NAVIGATION_HEADER_ORDER.to_vec(), REQUEST_HEADER_ORDER.to_vec());
        assert!(
            WS_HANDSHAKE_HEADER_ORDER
                .iter()
                .all(|name| !name.starts_with("sec-ch-ua")),
            "握手顺序表里不该出现 sec-ch-ua*：真 Chrome 在握手上一个都不发"
        );
    }

    /// 第三方源只拿低熵三项：高熵提示要等 `Accept-CH` 授权，未授权就发是可指纹的。
    #[test]
    fn low_entropy_identity_drops_high_entropy_hints() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
        headers.insert("sec-ch-ua-arch", HeaderValue::from_static("\"arm\""));
        headers.insert("sec-ch-ua-form-factors", HeaderValue::from_static("\"Desktop\""));
        headers.insert("user-agent", HeaderValue::from_static("foreign/1.0"));
        apply_low_entropy_identity(&mut headers);
        assert_eq!(headers["user-agent"], USER_AGENT);
        for name in LOW_ENTROPY_HINTS {
            assert_eq!(headers[name], *hint_value(name), "{name}");
        }
        for (name, _) in IDENTITY_HEADERS {
            if name == "user-agent" || LOW_ENTROPY_HINTS.contains(&name) {
                continue;
            }
            assert!(!headers.contains_key(name), "{name} 属高熵项，不该发给第三方源");
        }
        assert!(!headers.contains_key("sec-ch-ua-form-factors"));
    }

    /// 转发跳的 `accept-language` 跟随客户端（真 Chrome 的该项由 `navigator.languages`
    /// 派生，与页面 JS 报的语言一致），只在该头缺失时兜底；界面语言与它无关。
    ///
    /// 此前这里把转发跳钉成身份常量，理由是「`oai-language` 说 zh-CN 而线上报
    /// de-DE」。该理由不成立：`oai-language` 是账号/应用语言，**不属于浏览器指纹**；
    /// 钉死的结果反而是上游看到「线网 zh-CN、页面 JS en-US」——真浏览器不会产生的
    /// 组合（2026-09-29 真实上游验收实测到这一对，见
    /// `evidence/identity-acceptance-round3-001/`）。
    #[test]
    fn accept_language_follows_the_browser_and_is_independent_of_oai_language() {
        // 客户端带了就原样转发，且只能有一个值。
        for apply in [
            apply_identity as fn(&mut HeaderMap),
            apply_low_entropy_identity as fn(&mut HeaderMap),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("accept-language", HeaderValue::from_static("en-US,en;q=0.9"));
            apply(&mut headers);
            assert_eq!(headers["accept-language"], "en-US,en;q=0.9");
            assert_eq!(
                headers.get_all("accept-language").iter().count(),
                1,
                "追加而不是保留单个值会同时暴露两套语言"
            );
            // 非浏览器调用方没带这一项：兜底成真 Chrome 会发的形状。
            let mut bare = HeaderMap::new();
            apply(&mut bare);
            assert_eq!(bare["accept-language"], ACCEPT_LANGUAGE);
        }
        // 网关自发的请求仍用固定值——它们是网关自己发的，没有对应的页面 JS。
        let base = url::Url::parse("https://chatgpt.com/").unwrap();
        let get = api_baseline(&base, &Method::GET).expect("基线构造失败");
        assert_eq!(get["accept-language"], ACCEPT_LANGUAGE);
        assert_eq!(get["oai-language"], APP_LANGUAGE);
        assert!(REQUEST_HEADER_ORDER.contains(&"accept-language"));
        assert!(NAVIGATION_HEADER_ORDER.contains(&"accept-language"));
    }

    /// 网关自发请求与转发跳必须对同一个源声明**同一套**压缩能力。
    #[test]
    fn every_upstream_hop_declares_the_same_accept_encoding() {
        let base = url::Url::parse("https://chatgpt.com/").unwrap();
        let get = api_baseline(&base, &Method::GET).expect("基线构造失败");
        assert_eq!(get["accept-encoding"], proxy::GZIP_ONLY_ACCEPT_ENCODING);
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

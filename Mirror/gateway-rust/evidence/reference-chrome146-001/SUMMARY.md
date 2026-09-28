# Chrome 146 版本匹配参照身份证据（reference-chrome146-001）

采集日期：2026-09-24（Asia/Shanghai）。三段全部只打本机回环，不接触任何上游；四条请求的
服务端记录里 `credential_headers_present` 全为空，证据不含任何 Cookie/令牌。

本目录另有一份**非运行时**补充：`04-linux-platform-version.json`（Chromium 源码核对，
回答「Linux 上 `sec-ch-ua-platform-version` 到底发什么」）。本机没有可运行的 Linux 浏览器，
该文件的结论全部来自源码，附 ref/commit/行号/文件 sha256，可独立复算。

- 参照浏览器：Chrome for Testing **146.0.7680.165** win64（`chrome.exe` 的 VersionInfo 与
  CDP `browser.version` 同值；`chrome_exe_sha256 = aa024f5f…`、`chrome_zip_sha256 = 65d1d4d9…`
  见 `00-run.json`）。
- 候选对照：`wreq-util Profile::Chrome146` + `Platform::Linux`，声称版本 146.0.7680.177
  （`artifacts/phase1/source/COMPATIBILITY.md`「传输身份统一」、
  `artifacts/phase1/source/src/server/identity.rs`、`evidence/tls-identity-reference.json`）。
- 探针：`artifacts/phase1/probe/probe_reference_identity.py`。

## 结论速览

| 项 | 实测值 |
|---|---|
| ClientHello 归一化 sha256（`https://127.0.0.1:<port>/`，无 SNI；**排序归一化**口径，见各采集的 `rust_normalized_sha256`） | `01425d3fe0c24e404839d678bca29b881e52bcd05b37efdc795aac02f703c3cb` |
| 候选在同一排序口径下的值 | **逐位相同**；候选运行时自锁的是**顺序敏感**口径（`identity_fingerprint.rs::EXPECTED_HELLO_SHA256 = 01e7ace0…`、`EXPECTED_HELLO_SNI_SHA256 = 15d917f3…`、`EXPECTED_H2_SHA256 = 7b3ac4b0…`），两边共同的比对口径是逐字段对照 |
| ClientHello 归一化 sha256（`https://localhost:<port>/`，有 SNI） | `502b55cca23185a72501e8a77f40741e54b0af48a2c08dd59c50c987e24e40ec` |
| `sec-ch-ua-platform-version`（Windows 真值） | `"15.0.0"` |
| `sec-ch-ua-platform-version`（Linux 真值，源码核对） | `""`（见 `04-linux-platform-version.json`） |
| H2 客户端 SETTINGS 顺序（id 与值） | `0001 HEADER_TABLE_SIZE=65536` → `0002 ENABLE_PUSH=0` → `0004 INITIAL_WINDOW_SIZE=6291456` → `0006 MAX_HEADER_LIST_SIZE=262144`（本次没有 GREASE 设置项） |
| H2 `WINDOW_UPDATE` | 流 0，increment `15663105` |
| H2 首条 HEADERS 伪头顺序 | `:method` → `:authority` → `:scheme` → `:path` |
| H2 首帧序列 | `SETTINGS` → `WINDOW_UPDATE` → `HEADERS`（preface 正确，TLS1.3 + ALPN h2） |
| 高熵同源 XHR 头顺序（GET） | `sec-ch-ua-full-version-list`, `sec-ch-ua-platform`, `accept-language`, `sec-ch-ua`, `sec-ch-ua-bitness`, `sec-ch-ua-model`, `sec-ch-ua-mobile`, `sec-ch-ua-arch`, `sec-ch-ua-full-version`, `user-agent`, `sec-ch-ua-platform-version`, `accept`, `sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-dest`, `referer`, `accept-encoding` |

`--version` 说明：Windows 版 `chrome.exe --version` **不回显版本**。本机实测两次：无其他 Chrome
会话时 stdout 为空、退出码 0；已有 Chrome 会话时 stdout 为「正在现有的浏览器会话中打开。」。
因此本批的版本证据取 VersionInfo + CDP，探针不再调用该命令（该命令在 Windows 上会转发到既有
会话，属于副作用）。复跑若要看该行为，请单独执行并自行清理进程。

## 采集命令

```powershell
# 1) 下载并解压 Chrome for Testing 146 到临时目录（二进制不入库、不进 evidence）
$tmp = "$env:TEMP\cft-146"
New-Item -ItemType Directory -Force -Path $tmp
curl.exe -L --fail --retry 3 -o "$tmp\chrome-win64.zip" `
  "https://storage.googleapis.com/chrome-for-testing-public/146.0.7680.165/win64/chrome-win64.zip"
Expand-Archive -LiteralPath "$tmp\chrome-win64.zip" -DestinationPath $tmp -Force

# 2) 三段采集（本机 python 是 Microsoft Store 占位程序，用解释器绝对路径）
cd D:\Project\ReMirror\MiRebuild\Mirror\gateway-rust\artifacts\phase1\probe
& "C:\Users\peropero\AppData\Local\Programs\Python\Python313\python.exe" probe_reference_identity.py `
  --chrome "$env:TEMP\cft-146\chrome-win64\chrome.exe" `
  --openssl "C:\Program Files\Git\usr\bin\openssl.exe" `
  --evidence "D:\Project\ReMirror\MiRebuild\Mirror\gateway-rust\evidence\reference-chrome146-001"
```

本次运行：`17:56:38` → `17:56:47`（+0800），退出码 0；证据为 `00-run.json`、
`01-clienthello.json`、`02-h2-first-frames.json`、`03-request-headers.json`。
自签证书由 openssl 现生成到 `%TEMP%\cft-146`，指纹
`57:4A:CD:8F:F9:CD:FB:F0:BC:E9:48:21:CD:E0:A6:FF:3D:50:AC:7E:99:55:A3:4E:AD:4A:E1:5C:5B:45:F3:7E`。

## 第一段：ClientHello（裸 TCP 监听，不完成握手）

| 项 | `127.0.0.1`（无 SNI） | `localhost`（有 SNI） |
|---|---|---|
| 握手字节数 | 1696 | 1810 |
| `legacy_version` / `session_id_bytes` | `0303` / 32 | `0303` / 32 |
| 密码套件（原始顺序，含 GREASE） | `6a6a,1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035` | `0a0a,1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035` |
| 扩展（原始顺序，含 GREASE） | `2a2a,0010,0012,0005,0017,001b,ff01,fe0d,000a,000d,0023,0033,000b,002d,002b,44cd,fafa` | `4a4a,000b,002b,0005,fe0d,001b,0017,000a,0012,0010,0023,0000,0033,000d,002d,ff01,44cd,3a3a` |
| GREASE 计数 | 套件 1 / 扩展 2 | 套件 1 / 扩展 2 |
| `compression_methods` | `00` | `00` |
| `alpn` | `h2, http/1.1` | `h2, http/1.1` |
| `supported_groups` | `11ec,001d,0017,0018` | `11ec,001d,0017,0018` |
| `key_share_groups` | `11ec,001d` | `11ec,001d` |
| `signature_algorithms` | `0403,0804,0401,0503,0805,0501,0806,0601`（8 项，无 ML-DSA） | 同左 |
| `supported_versions` | `0304,0303` | `0304,0303` |
| `has_*` | status_request/sct/certificate_compression/alps/encrypted_client_hello 全 true | 同左，另 `has_sni = true` |

关键结论：

- 归一化后（去 random、会话 id、GREASE 值与扩展顺序，规则与
  `source/tests/identity_fingerprint.rs` 逐字段一致）**IP 采集的 sha256 与候选画像锁定的常量
  完全相同**，即候选声称的 Chrome146 传输画像与真 Chrome 146 在本项目归一化口径下无差异。
- 上下文：与 Playwright 自带 Chromium 151 的对照里唯一的实质差异是 `signature_algorithms`
  的 ML-DSA 三项（`0904/0905/0906`）；Chrome 146 实测同样**不发** ML-DSA，8 项与候选逐项相同，
  因此那处差异确认是**版本差异**（151 vs 146），不是候选画像的问题。
- Chrome 146 每条连接都会换 GREASE 值与**扩展顺序**（两次采集顺序完全不同，套件顺序与集合
  稳定）。因此「保留原始顺序」是证据本身，但顺序不是可复用的身份不变量；跨连接可比较的是
  集合/计数与各字段取值，这正是 Rust 侧要排序归一的理由。
- SNI 只随输入出现：IP 字面量不发，`localhost` 采集时 `has_sni = true` 且 SNI 名字为
  `localhost`（`raw.sni_host`）。

## 第二段：HTTP/2 首帧（本地 TLS + ALPN h2，openssl 现生成自签证书）

连接结果：ALPN `h2`、TLS1.3、套件 `TLS_AES_256_GCM_SHA384`，客户端首批共 513 字节，
preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` 正确，收到帧序列为
`SETTINGS` → `WINDOW_UPDATE` → `HEADERS`（读到第一条 HEADERS 读完即主动关连接）。

| 帧 | 实测 |
|---|---|
| SETTINGS（id/值，按线上顺序） | `0001 HEADER_TABLE_SIZE=65536`、`0002 ENABLE_PUSH=0`、`0004 INITIAL_WINDOW_SIZE=6291456`、`0006 MAX_HEADER_LIST_SIZE=262144`；本次**没有** GREASE 设置项，原始 payload `000100010000000200000000000400600000000600040000` |
| WINDOW_UPDATE | 流 0，increment `15663105`（连接窗口） |
| 第一条 HEADERS | 流 1，flags `END_STREAM,END_HEADERS,PRIORITY`，伪头顺序 `:method` → `:authority` → `:scheme` → `:path` |
| 头部块解码结果 | 静态表能判定的名字：`:method`(GET)、`:authority`、`:scheme`(https)、`:path`(/)、`user-agent`、`accept-language`、`accept`、`accept-encoding`；其余 9 项是 `literal` 字面名（Chrome 首次请求用 Huffman 编码的字面名，例如 `sec-ch-ua*`、`sec-fetch-*`、`priority`），**按约定标注「未解码」并保留原始十六进制**，没有猜名字 |

## 第三段：请求头全量（本地 HTTP，导航响应带 `Accept-CH`）

页面：`http://localhost:<port>/` 导航 → 同源 `fetch` GET `/probe-get`、POST `/probe-post`
（POST 由页面显式设 `content-type: application/json`）。导航响应声明
`accept-ch: sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version,
sec-ch-ua-full-version-list, sec-ch-ua-model, sec-ch-ua-platform-version`。
http 段即拿到高熵 hints，未触发探针内置的 https 回退。页面结果为 `{"get": 200, "post": 200}`。
（https 回退分支另用探针的临时副本单独验过一次：https 段同样拿到全部高熵 hints，且头顺序与
http 段逐项相同；正式证据使用的是 http 段，未触发回退。）

导航请求（低熵，无 `Accept-CH` 补发）的顺序：
`Host, Connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests,
User-Agent, Accept-Language, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User,
Sec-Fetch-Dest, Accept-Encoding`。

高熵同源 XHR 的顺序（GET 与 POST 的差异已标注）：

| 位置 | GET `/probe-get` | POST `/probe-post` |
|---|---|---|
| 1-2 | `Host`, `Connection` | `Host`, `Connection`, `Content-Length` |
| 3-11 | `sec-ch-ua-full-version-list`, `sec-ch-ua-platform`, `Accept-Language`, `sec-ch-ua`, `sec-ch-ua-bitness`, `sec-ch-ua-model`, `sec-ch-ua-mobile`, `sec-ch-ua-arch`, `sec-ch-ua-full-version` | 同左 |
| 12-13 | `User-Agent` | `User-Agent`, `content-type` |
| 14 | `sec-ch-ua-platform-version` | `sec-ch-ua-platform-version` |
| 15-16 | `Accept`, `Sec-Fetch-Site` | `Accept`, `Origin` |
| 17-20 | `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Referer`, `Accept-Encoding` | `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Referer`, `Accept-Encoding` |

关键取值：

| 头 | 实测值 |
|---|---|
| `sec-ch-ua-platform-version` | `"15.0.0"`（Windows 真值，非空） |
| `sec-ch-ua-platform` | `"Windows"` |
| `sec-ch-ua` | `"Not-A.Brand";v="24", "Chromium";v="146"` |
| `sec-ch-ua-full-version-list` | `"Not-A.Brand";v="24.0.0.0", "Chromium";v="146.0.7680.165"` |
| `sec-ch-ua-full-version` | `"146.0.7680.165"` |
| `sec-ch-ua-arch` / `sec-ch-ua-bitness` / `sec-ch-ua-model` | `"x86"` / `"64"` / `""` |
| `sec-ch-ua-mobile` | `?0` |
| `user-agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/146.0.0.0 Safari/537.36` |
| `accept-encoding` | `gzip, deflate, br, zstd` |
| `accept`（fetch 默认） | `*/*` |
| `accept-language`（本次上下文） | `zh-CN` |
| `sec-fetch-*` 三元组（XHR） | `empty` / `cors` / `same-origin` |
| `referer` / `origin` | GET 只有 `referer`；POST 两者都有（`origin` 只在写请求上） |
| `cookie` / `authorization` | 四条请求都没有（`credential_headers_present` 均为空） |

上表是 Windows 真值。Linux 侧这条头不是「实测缺失」而是「源码可判定」：Chrome 146 的
`GetPlatformVersion()` 在 Linux 上被默认启用的 `ReduceUserAgentDataLinuxPlatformVersion`
短路成空串，再原样序列化成 `""`（见 `04-linux-platform-version.json` 与本文附录）。

## 与候选的逐字段差异清单

分类口径：**平台差异** = Windows 与 Linux 的平台取值不同；**版本或实现差异** = 版本号、
画像内部实现、序列化形状；**构建差异** = Chrome for Testing（Chromium 品牌构建）与品牌版
Chrome 的差别；**环境差异** = 本次夹具（headless、语言设置、调用方行为）造成，不是浏览器
版本或平台属性。

### A. TLS / ClientHello（对照 `evidence/tls-identity-reference.json` 的候选指纹）

| 字段 | 真 Chrome146 win64 实测 | 候选（声称 146/Linux） | 分类 | 结论 |
|---|---|---|---|---|
| `legacy_version` | `0303` | `0303` | — | 一致 |
| `session_id_bytes` | 32 | 32 | — | 一致 |
| `cipher_suites`（归一化后 15 项） | `002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9` | 同 | — | 逐项一致 |
| `grease_cipher_suites` / `grease_extensions` | 1 / 2 | 1 / 2 | — | 一致（GREASE 值本身每连接不同，不比较） |
| `compression_methods` | `00` | `00` | — | 一致 |
| `extension_types_sorted`（无 SNI） | `0005,000a,000b,000d,0010,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01` | 同 | — | 逐项一致 |
| `alpn` | `h2, http/1.1` | 同 | — | 一致 |
| `supported_groups` / `key_share_groups` | `11ec,001d,0017,0018` / `11ec,001d` | 同 | — | 一致 |
| `signature_algorithms` | `0403,0804,0401,0503,0805,0501,0806,0601`（8 项，无 ML-DSA） | 同 | — | 一致；此前与 Chromium 151 的 ML-DSA 差异确认是**版本差异** |
| `supported_versions` | `0304,0303` | 同 | — | 一致 |
| `has_sni` | IP 字面量 false；`localhost` true | IP 字面量 false | — | 与输入同形 |
| 其余 `has_*` | 全 true | 全 true | — | 一致 |
| 归一化 sha256（排序口径） | `01425d3f…0343cb` | `01425d3f…0343cb` | — | **逐位相同**；候选顺序敏感口径的自锁常量 `01e7ace0…` 与之口径不同、不直接比较 |

### B. HTTP 请求头

| 字段 | 真 Chrome146 win64 实测 | 候选（声称 146/Linux） | 分类 | 说明 |
|---|---|---|---|---|
| `sec-ch-ua-platform-version` | `"15.0.0"` | `""` | **平台差异（已闭合）** | Windows 真值实测；Linux 真值由源码核对判定为空串（`04-linux-platform-version.json`：Linux 上该 feature 默认启用 ⇒ `GetPlatformVersion()` 返回空串 ⇒ 头照发 `""`）。候选锁 `""` 在声称 Linux 时成立；同一张身份表用到 Windows 上就是错的 |
| `sec-ch-ua-platform` | `"Windows"` | `"Linux"` | 平台差异 | 预期差异 |
| `user-agent` | Windows + `HeadlessChrome/146.0.0.0` | Linux + `Chrome/146.0.0.0` | 平台差异 + 环境差异 | 平台部分预期不同；`HeadlessChrome` 是本次 headless 运行造成，非版本属性 |
| `sec-ch-ua` | `"Not-A.Brand";v="24", "Chromium";v="146"` | `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"` | **构建差异** | Chrome for Testing 是 Chromium 品牌构建，不报 `Google Chrome`，且 GREASE 品牌在前；要判候选的品牌列表是否与真 Chrome 一致，需要品牌版 Chrome 146（本机没有） |
| `sec-ch-ua-full-version-list` | `"Not-A.Brand";v="24.0.0.0", "Chromium";v="146.0.7680.165"` | `"Chromium";v="146.0.7680.177", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.177"` | 构建差异 + 版本差异 | 同上；另完整版本号 .165（CfT）与 .177（候选沿用镜像内 chromium 包）不同，属版本差异，主代理可决定是否对齐 |
| `sec-ch-ua-full-version` | `"146.0.7680.165"` | `"146.0.7680.177"` | 版本差异 | 同上 |
| `sec-ch-ua-arch` / `bitness` / `model` / `mobile` | `"x86"` / `"64"` / `""` / `?0` | 同 | — | 一致 |
| `accept-encoding` | `gzip, deflate, br, zstd` | `gzip, deflate, br, zstd` | — | 一致 |
| `accept`（fetch 原生） | `*/*` | `application/json, text/plain, */*`（axios 形状） | 环境差异 | 取决于调用方；不是版本属性 |
| `accept-language` | `zh-CN`（本次 locale） | `zh-CN,zh;q=0.9,en;q=0.8` | 环境差异 | 取决于浏览器语言配置/调用方 |
| `sec-fetch-dest/mode/site`（XHR） | `empty` / `cors` / `same-origin` | 同 | — | 一致 |
| `origin` 只在非 GET | GET 无、POST 有 | 同（`api_baseline` 只在非 GET 补） | — | 一致 |
| `priority`（XHR） | 本次未出现 | 未合成 | — | 一致 |
| 头顺序（XHR，去掉传输层生成的 `Host`/`Connection`/`Content-Length`） | 见上表 | `REQUEST_HEADER_ORDER`（19 项） | — | **逐项一致**（含 `content-type` 在 `sec-ch-ua-platform-version` 之前、`origin` 在 `sec-fetch-site` 之前、`referer` 在 `accept-encoding` 之前；GET 时缺位的 `content-type`/`origin` 与候选表的并集形状相符） |
| 头名大小写（HTTP/1.1） | 常见头名大写（`User-Agent`/`Accept`/`Referer`/`Origin`/`Content-Length`），`sec-ch-ua*` 与 fetch 侧 `content-type` 小写 | 候选顺序表统一小写 | 实现差异（低风险） | 候选出网走上游 h2，HPACK 一律小写，两者在该路径等价；只有当候选对 h1 上游发这些头时才可观测到差异 |

### C. HTTP/2 首帧（已闭合，2026-09-24 第二轮）

`tests/identity_fingerprint.rs` 现在会完成一次本地自签 TLS 握手并抓取候选的 h2 首帧，
逐项对照本文件 `capture`：

| 字段 | 真 Chrome146 win64 实测 | 候选实测 | 结论 |
|---|---|---|---|
| SETTINGS 顺序与值 | `0001=65536`、`0002=0`、`0004=6291456`、`0006=262144`（无 GREASE 项） | 同（并断言只有这四项） | 一致 |
| `WINDOW_UPDATE` | 流 0，`15663105` | 同 | 一致 |
| 伪头顺序 | `:method, :authority, :scheme, :path` | 同 | 一致 |
| 首帧序列 | `SETTINGS` → `WINDOW_UPDATE` → `HEADERS` | 同 | 一致 |

## 附录：Linux `sec-ch-ua-platform-version`（源码核对，2026-09-24）

本机没有可运行的 Linux 浏览器（WSL 无发行版、无 Docker），这条头改由源码判定，完整证据
（ref/commit/行号/sha256/引用原文）见 `04-linux-platform-version.json`。链条四步：

1. `third_party/blink/renderer/platform/runtime_enabled_features.json5`：tag
   `146.0.7680.165` 行 4379-4384、分支 `refs/branch-heads/7680` 行 4388-4392 同值——
   `name: "ReduceUserAgentDataLinuxPlatformVersion", status: {"Linux": "stable"}`。
2. 生成模板 `third_party/blink/renderer/build/scripts/templates/features_generated.cc.tmpl`：
   平台字典里的 `stable` 翻成 `base::FEATURE_ENABLED_BY_DEFAULT`，所以 Linux 构建默认启用。
3. `components/embedder_support/user_agent_utils.cc:581-588`：Linux 且开关启用时
   `GetPlatformVersion()` 直接 `return std::string()`；内核版本分支只在开关关闭时可达。
4. `content/browser/client_hints/client_hints.cc:746-749` 与 `:226-231`：该值经
   `SerializeHeaderString` 变成 `""` 后无条件 `SetHeader`，没有「空值就不发这个头」的分支。

结论：Linux 上 `sec-ch-ua-platform-version: ""`，与主机内核版本无关（换机器不变）；
`"15.0.0"`-这类非空值只出现在 Windows。JS 侧 `navigator.userAgentData.platformVersion`
取同一个 `UserAgentMetadata::platform_version`（`navigator_ua.cc:18-22` →
`navigator_ua_data.cc:64-67`），因此两个面同为 `""`。Windows 参照里
`sec-ch-ua-model: ""` 也走同一条「空值仍发头」的路径，可互为旁证。

## 未覆盖与限制

1. **Linux 列仍未实采**：UA、`sec-ch-ua-platform` 与 Linux 上的 brand 列表需要在 Linux
   （WSL）上用同一探针复采；本机只有 Windows，没有伪造。`sec-ch-ua-platform-version`
   已按上节用源码核对判定为 `""`；若要运行时复核，用有 Docker/发行版的机器跑 cfbypass
   容器内的 `probe_identity.py`（它回报 `platformVersion`）。
2. **品牌构建待验**：本次用的是 Chrome for Testing（Chromium 品牌），拿不到 `Google Chrome`
   品牌项与它的品牌顺序；`sec-ch-ua`/`full-version-list` 与候选的差异因此归为「构建差异」，
   不能据此判定候选错。
3. **H2 候选基线（已闭合）**：第二轮已用 `tests/identity_fingerprint.rs` 在本地自签 TLS 上抓取候选
   的 h2 首帧，SETTINGS/`WINDOW_UPDATE`/伪头顺序/首帧序列均与本参照逐项一致（见上 C 节）。
4. **headless 环境**：本次为 Playwright 新 headless（UA 带 `HeadlessChrome`）。UA-CH 取值与
   TLS/H2/头顺序不受影响；若需要非 headless 的 UA 字面量，需要一次带窗口的运行（本批未做，
   避免在宿主桌面弹窗）。
5. **H2 字面名未解码**：首条 HEADERS 里 9 个 Huffman 字面名按任务约定标注「未解码」，保留
   `name_raw_hex`；HTTP/1.1 段（第三段）给出了同一批头的真实名字，可互为旁证。
6. 探针在第一次运行中曾用 `chrome.exe --version` 探测版本，该命令在 Windows 会转发到既有
   Chrome 会话并留下进程；这些进程（全部来自 `%TEMP%\cft-146` 二进制）已终止，脚本也已去掉
   这次调用。当前探针运行不留残余进程（复跑后实测 0 个）。

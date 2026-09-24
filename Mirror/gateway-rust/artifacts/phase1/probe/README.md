# 真实上游探针（缺口 3 验收）

用真实的 ChatGPT **AccessToken** 跑一遍候选网关的已登录业务面，取得合成回环拿不到的证据：
真实上游对已分类读路径的状态码与字段形状、一次真实新建会话的归属登记、以及同账号第二个
镜像用户读该会话被拒。

## 先填凭据

打开 [access-token.txt](access-token.txt)，把这一行右侧的占位符替换成完整 AccessToken：

```text
access_token = PASTE_ACCESS_TOKEN_HERE
```

要点：

- 用 **AccessToken**（网页请求里的 `Bearer` 值），不要用 SessionToken。
- 该文件已在仓库 `.gitignore` 中，不会被提交；探针只读这一行，不打印、不写进证据、
  不放进命令行参数或环境变量。
- 没填完整时探针直接拒绝运行，不会发出任何请求。

## 运行

```powershell
cd D:\Project\ReMirror\MiRebuild\Mirror\gateway-rust\artifacts\phase1\source
cargo build --locked --offline

cd ..\probe
py -3 probe.py                      # 只读：7 条已分类读路径
py -3 probe.py --allow-real-write   # 再补：恰好一次真实新建会话 + 删除 + 第二用户读取
```

`--allow-real-write` 是刻意分开的一步：写请求在真实账号里不可撤销，先看只读结果再决定是否执行。
本机 PATH 上的 `python` 是 Microsoft Store 的占位程序，请用 `py -3`（或 Python 3.11+ 的绝对路径）。
探针只用标准库，不需要安装依赖。

## 探针做什么

1. 起一个本地 Django 授权桩（只回身份字段，不接触真实 Django），并以 `configured` 模式
   启动候选网关：`DATABASE_PATH=:memory:`、`GATEWAY_COMPAT_PROFILE=mirror`、无常驻改动。
2. 用 AccessToken 调 `/api/login` 换镜像会话。
3. 依次 GET：`/backend-api/me`、`accounts/check/v4-2023-04-27`、`conversations`、`projects`、
   `files/library/nodes`、`tasks`、`task_suggestions`。
4. 传 `--allow-real-write` 时：POST `/backend-api/f/conversation` 新建一次会话，出现会话 id
   即断开（不必等生成跑完），随后 DELETE `/backend-api/conversation/id/{id}`；再用第二个
   镜像用户 GET 同一会话，预期 404 `acl_not_found`。

## 探针不做什么

- 不写任何业务数据以外的内容：只有一次新建会话与它的一次删除，且新建在显式开关之后。
- 不重试：上游 4xx/5xx 按实际状态记录；生成类请求绝不重放。
- 不猜协议：新建会话的请求体形状没有实测证据，上游若拒绝就记录状态码后停止，
  不改用第二个端点、不改写请求体。

## 证据边界

证据写到 `evidence/probe-<时间戳>.json`（该目录已 gitignore），只包含：

状态码、内容类型、正文长度与 sha256、是否 HTML、是否被 Cloudflare 拦截、JSON 顶层字段名、
集合条目数与 `total`、本候选自己的错误码、耗时、网关日志行数、授权桩调用次数、令牌 sha256。

绝不包含：令牌、Cookie、镜像会话 token、上游响应正文、会话标题、会话 id 原文
（只存 sha256）。

拦截处理：命中 Cloudflare（`cf-mitigated: challenge`，或 403/502 加 HTML）时记录
`upstream_blocked` 并停止该次运行；未配置 `--cf-bypass-url` 时如实标注该路径没有真实证据，
不猜测上游协议。若本机有 cfbypass 服务，可用 `--cf-bypass-url http://127.0.0.1:<port>` 再跑一次，
网关会自行刷新一次并重放一次幂等 GET。

已知残留：若删除未返回 2xx，新建的会话可能仍留在账号里，请在网页端手动删除，且不要重复
运行本探针。

## 已观测结果（2026-09-24）

真实 AccessToken 下的第一轮结果与逐路径状态码见
[`../../evidence/gap3-real-probe-001/SUMMARY.md`](../../evidence/gap3-real-probe-001/SUMMARY.md)。
摘要：凭据换取、`/backend-api/me`、`accounts/check`、`conversations` 稳定 `200`；
`GET /projects` 恒为 `405`（上游该路径只有 `POST`）；`task_suggestions` 为 `404`；
`POST /f/conversation` 被上游以 JSON `403` 拒绝，未创建会话、未重试。
本机直连存在间歇性发送阶段失败（记为网关自身 `502`，非挑战形状），当时本地 cfbypass
（`127.0.0.1:18001`）未运行，因此建议先起 cfbypass 再带 `--cf-bypass-url` 复跑。

另注意：`conversations` 的 `items`/`total` 是 ACL 过滤后的视图，**不能**用来判断账号里
原本有多少会话。

## 设备 Cookie 真实探针（`probe_device_cookie.py`，2026-09-24）

验证「上游是否下发 `oai-did`」与「候选的捕获/播种是否对真实上游成立」。相对 `probe.py`：

```powershell
cd D:\Project\ReMirror\MiRebuild\Mirror\gateway-rust\artifacts\phase1\probe
py -3 probe_device_cookie.py --scan-only            # 只读：页面/SDK/sentinel 引导扫描
py -3 probe_device_cookie.py --scan-only --skip-seed # 只读：不播种，单独验证捕获
py -3 probe_device_cookie.py --capture-first --allow-real-write  # 生产顺序 + 一次真实写入
```

差异与要点：

- 用**文件**数据库，跑完以标准库 sqlite3 只读检查 `gateway_sessions.upstream_cookies` 的非空
  行数（不解密、不取值），因此能直接观测「捕获是否发生」；探针记录该列的存在性与非空行数，
  不改写数据库。
- 记录每一跳响应 `set-cookie` 的**名字**（值不落盘），用于判断上游是否下发 `oai-did`。
- 每个触及上游的请求之间随机停 8–12 秒，实际秒数记入证据的 `pauses`；
  `--no-pause` 只用于本地调试（需自行保证不触真实上游）。
- `--capture-first` 复现生产顺序：先让上游在页面/SDK 下发布设备 cookie，再发起写请求，
  不发送伪造的设备标识。其余写边界与 `probe.py` 相同（恰好一次新建 + 一次删除）。

结果见 [`../../evidence/device-cookie-real-001/SUMMARY.md`](../../evidence/device-cookie-real-001/SUMMARY.md)。

## 浏览器驱动验收（`probe_browser_create.py`，2026-09-24）

用真实 Chromium 经候选网关打开真实 chatgpt.com 页面，验证「页面能否进入登录态」与
「浏览器能否完成一次真实新建会话」。需要一个本机 Playwright（本机为系统 Python 3.13
的 Playwright 1.62 + `chromium-1234`；探针用 `channel="chromium"` 走完整 Chromium 的
new headless，而不是 headless shell）。

```powershell
cd D:\Project\ReMirror\MiRebuild\Mirror\gateway-rust\artifacts\phase1\probe
# 凭据草稿（本文件不入库）：access-token.txt 或 session-token.txt
py -3 probe_browser_create.py --use-session-token            # 只读：加载页面并逐跳记录
py -3 probe_browser_create.py --use-session-token --allow-real-write   # 真实新建一次并删除
```

差异与要点：

- 复用 `probe.py` 的授权桩、网关进程管理与登录流程；网关库为 `:memory:`，无常驻改动。
- 证据只落 method/路径/资源类型/头名/状态/content-type，以及 `content-type`、`accept`、
  `accept-language`、`sec-ch-ua*` 这类不含凭据的头值；Cookie、`Authorization`、令牌、
  响应正文与消息内容一律不落盘。会话 id 只落 sha256。
- 登录交接（`/api/not-login`）会**轮换** mirror_token：删除步骤用交接后从浏览器
  cookie 里取到的 token，用交接前的值会被判未登录（这正是首轮删除 401 的原因）。
- 页面加载不需要 cfbypass：真实浏览器自带 `sec-ch-ua*`，`GET /` 直接 200。
  `--session-token-as-extra-cookie` 可复现「管理面导入过会话 cookie」的账号形态。

## 端到端验收（`probe_browser_accept.py`，2026-09-24）

在浏览器驱动的基础上补齐「消息 → 流式回复 → 停止生成 → 重命名 → 重载后历史 → 跨用户隔离
→ 删除」，并在只读模式下观察真实 WebSocket。

```powershell
cd D:\Project\ReMirror\MiRebuild\Mirror\gateway-rust\artifacts\phase1\probe
py -3 probe_browser_accept.py --no-write     # 只读：加载页面 + 观察 WS 帧，不写任何东西
py -3 probe_browser_accept.py                # 真实验收：一次新建会话，跑完即删
```

要点：

- 复用 `probe.py` 与 `probe_browser_create.py` 的授权桩、进程与凭据读取；网关库 `:memory:`。
- 写入之间默认停 10 秒（`--pause-seconds`），避免被上游当成爬虫脚本。
- 证据只落状态、长度、sha256、信封字段名与 WS 帧计数；提示词、回复正文、标题、Cookie 与
  令牌一律不落盘（正文只落长度与 sha256）。
- 列表检查在 Python 侧发起（页面重载期间 frame 可能在导航，页面内 `fetch` 会是竞态；
  `probe_browser_accept.py` 保留页面内检查仅作旁证）。直连上游的对照组走 curl——纯 Python
  的 TLS 会被 Cloudflare 挑战，curl 不会。
- 删除放在异常路径之外：任何一步失败都会执行清理，避免在真实账号里留下会话。

## 请求头基线采集（`probe_browser_headers.py`，2026-09-24）

`identity::api_baseline()` 的取值来源。起一个本机回环 HTTP 服务，用真 Chromium 发同源
XHR，**在服务端**记录收到的原始头（页面里的 `request.headers` 不含浏览器自动头），并用
`Accept-CH` 区分「默认只发低熵 hints」与「服务端声明后补发高熵 hints」两种形态。

```powershell
py -3 probe_browser_headers.py
```

结论：低熵 hints 默认就发；高熵 hints 只在**导航响应**带 `Accept-CH` 之后才补发（放在 XHR
响应上无效，已实测）；XHR 的 `sec-fetch-*` 三元组是 `empty`/`cors`/`same-origin`，且没有
`priority`。证据写 `evidence/browser-headers-<时间戳>.json`（该目录已 gitignore）。

## 传输指纹采集（`probe_tls_identity.py`，2026-09-24）

抓真 Chromium 的 ClientHello，与候选自己的归一化指纹逐字段对照（对照原文见
`../../evidence/tls-identity-reference.json`）。监听端只收 ClientHello、**不完成握手**，
因此不接触真实上游、不写 Cookie。

```powershell
py -3 probe_tls_identity.py
```

归一化规则与 `source/tests/identity_fingerprint.rs` 相同：去掉 random、会话 id、GREASE 值
与扩展顺序。证据写 `evidence/tls-identity-<时间戳>.json`（已 gitignore）。

## 直连 chatgpt.com 的请求头对照（`probe_browser_chatgpt_headers.py`，2026-09-24）

用真 Chromium **直连** chatgpt.com 匿名加载首页，记录页面自发请求的完整头，用来判断
「候选整组强制覆盖」是否等于「正常用户」。只读：不登录、不写入；只落头名与白名单头值，
Cookie、Authorization 与正文一律不落盘。

```powershell
py -3 probe_browser_chatgpt_headers.py
```

本机结果：首页 403，只取到 Cloudflare 挑战页自身的请求（带 `priority: u=1, i`、
`sec-fetch-dest: script/empty`），据此判断 `priority` 依请求的优先级类别而变，候选只在浏览器
转发路径上原样透传。

## Chrome146 版本匹配参照（`probe_reference_identity.py`，2026-09-24）

用 Chrome for Testing **146.0.7680.165**（与本候选声称的 146 同大版本）做三段采集：裸 TCP 抓
ClientHello（无 SNI/有 SNI 各一条，保留套件与扩展的**原始顺序**）、本地自签 TLS + ALPN `h2`
抓 HTTP/2 首帧（SETTINGS 顺序、窗口增量、伪头顺序）、本地 HTTP + `Accept-CH` 抓同源 XHR 的
完整头顺序。全部只打本机回环。

```powershell
$tmp = "$env:TEMP\cft-146"
curl.exe -L --fail -o "$tmp\chrome-win64.zip" `
  "https://storage.googleapis.com/chrome-for-testing-public/146.0.7680.165/win64/chrome-win64.zip"
Expand-Archive -LiteralPath "$tmp\chrome-win64.zip" -DestinationPath $tmp -Force
py -3 probe_reference_identity.py --chrome "$tmp\chrome-win64\chrome.exe" `
  --openssl "C:\Program Files\Git\usr\bin\openssl.exe" `
  --evidence ..\..\evidence\reference-chrome146-001
```

结果与结论见 [`evidence/reference-chrome146-001/SUMMARY.md`](../../evidence/reference-chrome146-001/SUMMARY.md)：
ClientHello 归一化 sha256 与候选逐位相同、H2 SETTINGS/窗口/伪头顺序一致、同源 XHR 头顺序与
`identity::REQUEST_HEADER_ORDER` 逐项一致。Windows 实测 `sec-ch-ua-platform-version = "15.0.0"`；
Linux 侧取值待 WSL 复采。二进制不入库。

## WebSocket 握手头采集（`probe_browser_ws_headers.py`，2026-09-24）

起一个本机回环 WS 服务（只读 ClientHello 级的握手头，回一帧关闭帧即断开），用真 Chromium 发起
同源 `new WebSocket`，在**服务端**记录浏览器实际发送的握手头与顺序。

```powershell
py -3 probe_browser_ws_headers.py
```

实测顺序：`host, connection, pragma, cache-control, user-agent, accept-language, upgrade,
origin, sec-websocket-version, accept-encoding, sec-websocket-key, sec-websocket-extensions`。
入库副本见 [`evidence/ws-handshake-headers-001.json`](../../evidence/ws-handshake-headers-001.json)
（一次性 `sec-websocket-key` 已占位），`chat_ws` 的转发名单由库内单测对照该文件锁定。

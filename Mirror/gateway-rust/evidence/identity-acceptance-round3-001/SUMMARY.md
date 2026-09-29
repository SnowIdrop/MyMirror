# 传输身份第三轮的真实上游验收（2026-09-29）

用**真实 SessionToken** 跑 `artifacts/phase1/probe/probe_browser_accept.py`，验证
`cd6b6d5` 那一轮的改动在真实 chatgpt.com 上成立：新导航头序、WS 握手形状、
三跳 `accept-language` 收口、去代理链痕迹，都没有把这条链路打坏。

## 运行环境

| 项 | 取值 |
|---|---|
| 驱动浏览器 | cfbypass 镜像内的系统 chromium **146.0.7680.177**（与身份表声称的版本同源，不是 Playwright 自带浏览器） |
| 探针 | `probe_browser_accept.py`，写入开启（一次真实新建 + 生成 + 重命名 + 删除） |
| 网关 | 当前源码的 Linux debug 构建，`GATEWAY_UPSTREAM_MODE=configured`、`DATABASE_PATH=:memory:`、本地 Django 授权桩、未配置 `CF_BYPASS_URL` |
| 凭据 | `probe/session-token.txt` 里的真实 SessionToken（文件不入库；证据只存 sha256） |

探针源码未改：容器里没有 Playwright 自带的 chromium，用一个只覆盖
`BrowserType.launch` 的**运行器**把它指到 `/usr/bin/chromium`（运行器在容器外的
临时目录，不在本仓）。

## 结果

| 环节 | 观测 |
|---|---|
| 登录交接 | `/api/login` 200 → 交接页 200，标题 `ChatGPT`，注入控制条命中（首屏含 accessToken 标记），composer 找到 |
| 页面发出的请求 | **930 条**：914×200、6×202、2×201、2×204、1×302（交接本身）；**0 次 Cloudflare 挑战**，无任何 4xx/5xx |
| `/backend-api/*` | 75 条，全部 2xx（3 条长连不返回：`POST /realtime/wm` 等） |
| 真实生成 | 新建 200 `text/event-stream`；流式回复渲染完成且已收尾，正文回 `probe-ok`（8 字符，sha256 `86d90d7c…`） |
| 停止生成 | 停止按钮存在，点击后消失 |
| 重命名 | 200 |
| 重载后历史 | URL 变为 `/c/<uuid>`；侧栏链接数 0（探针在重载后立刻取样，未等到侧栏渲染；同一次运行的网关列表接口查到 1 条且 id 一致，见下） |
| 经网关的会话列表 | 200，`items/limit/offset/total` 信封，1 条，conversation_id 与本次新建一致 |
| 跨用户读取 | 同账号第二个镜像用户带同一 conversation_id 取会话：**404 `acl_not_found`**，未触上游 |
| WebSocket | 经 `/ws-chatgpt/p4/ws/user/…` 桥到 `wss://ws.chatgpt.com`：发出 1 帧、收到 3 帧、785 字节，连接保持——**新握手形状在真上游可用** |
| 删除 | 经网关 `DELETE /backend-api/conversation/id/<uuid>` 返回 200 |

入库前脱敏：本目录的证据 JSON 是探针原始输出的副本，只把 WS URL 里的
`verify=<上游短时校验值>` 与 `user-<上游账号标识>` 换成 `<redacted>`（探针原样保留了这两个值，
但它们不属于「状态码 + sha256」的证据面，不该进版本库）。原始文件仍在
`artifacts/phase1/probe/evidence/`（该目录不入库）。

页面 JS 可见身份（注入脚本覆盖后）：UA `…Chrome/146.0.0.0 Safari/537.36`、
platform `Linux x86_64`、brands `[Chromium/146, Not-A.Brand/24, Google Chrome/146]`、
arch `x86`、bitness `64`、`fullVersionList` 三项均 `146.0.7680.177`、
`platformVersion` 空串、`model` 空串——与网络层声称值一致。

## 账号没有残留

探针的「直连上游对照组」在容器里跑不了（那里没有 curl，且容器出口的 curl 会被
Cloudflare 挑战：`/api/auth/session` 实测 403 + 8830 字节 HTML）。改在宿主机用
curl 8.13（Schannel）复核同一份会话 cookie：

| 请求 | 结果 |
|---|---|
| `GET /api/auth/session` | 200，返回 accessToken（1918 字符） |
| `GET /backend-api/conversations?offset=0&limit=50` | 200，`total=3`，3 条 |
| 本次新建后删除的 conversation_id | **不在列表里** |

## 探针侧的两处噪声（不是网关缺陷）

- `创建响应正文读取失败：Error`：浏览器侧读取 SSE 正文的动作失败；创建请求本身返回
  200 `text/event-stream`，且流式回复正常渲染。
- `FileNotFoundError: 'curl.exe'`：探针的直连上游对照组按 Windows 宿主机写死了
  `curl.exe`；已按上文改用宿主机 curl 单独复核。
- 6 条 console 错误均为镜像域下的正常噪声：前端 addAction/Datadog 在非授权域初始化、
  React #418（注入改写 HTML 后的 hydration 差异）。

## 本次验收暴露的一个未收敛点：语言维度

同一轮只读测量（`lang-headers-20260929.txt`，起网关 + 授权桩 + 真实 SessionToken，
加载页面并记录页面打到网关的 `/backend-api/*` 头）：

（该文件保留了原样输出，末尾那段 `TargetClosedError` 是记录器在浏览器关闭后又取了一次
请求头导致的，与网关无关；有效结论是下面的那一行。）

```
x42  accept-language='en-US,en;q=0.9'  oai-language='zh-CN'
     sec-ch-ua-platform='"Linux"'  ua[:40]='Mozilla/5.0 (X11; Linux x86_64) AppleWeb'
页面内 navigator.language = en-US
```

也就是说：本轮把出网跳的 `accept-language` 钉成 `zh-CN,zh;q=0.9,en;q=0.8` 之后，
上游看到的是**线网说 zh-CN、页面 JS 说 en-US**。真 Chrome 的 `Accept-Language`
就是从 `navigator.languages` 派生的，这一对矛盾真浏览器不会产生；而
`oai-language=zh-CN` 与 `Accept-Language` 不同则是**正常**的——它取自账号/应用语言，
本轮实测里 chatgpt.com 自己就是从 `navigator.language=en-US` 的浏览器发出
`oai-language=zh-CN` 的。另外 `Intl` 的默认 locale 仍随宿主（en-US），
只改 `navigator.language` 会留下第三条不一致。

相关事实：

- `identity::ACCEPT_LANGUAGE` 的取值来自 2026-09-24 的参照采集，而那个探针
  （`probe_browser_headers.py`）用的是 `browser.new_context(locale="zh-CN")`——
  该值是**探针浏览器的语言**，不是 Chrome146/Linux 的固有属性。
- 逆向材料里原版的出网请求是 `Accept-Language: en-US,en;q=0.9`
  （`MirrorNiXiang/reverse/reports/06-sandbox-verification.md` §9.5），即原版不吃
  这一口。
- 注入脚本只覆盖 `navigator.userAgent/appVersion/platform/userAgentData`，
  不覆盖 `language/languages`（第二轮就是这么定的）。

结论：这是本轮修复 `oai-language` 与 `Accept-Language` 不一致时，用另一种不一致换来的，
需要产品决定后再动：

1. 维持现状；
2. 连 `navigator.language/languages` 一起伪造——但 `Intl` 默认 locale 仍是宿主值，
   要真正自洽得连 `Intl.DateTimeFormat/NumberFormat/toLocale*` 的默认 locale 一并处理；
3. 撤掉出网跳的 `accept-language` 强覆盖，让它跟随访客浏览器（与 JS、`Intl` 自洽，
   与原版行为一致），代价是 cfbypass 那一跳仍用固定语言、且不同访客之间语言不一致。

# 匿名上游前端实测证据（2026-09-23）

本文件只记录本轮实际执行过的观测，不含推测。所有结论都能用下列命令在本机复现。

**本阶段验收基准（产品口径）**：匿名对话即验收标准，不依赖真实 ChatGPT 账号。
`accessToken` 只属于真实账号登录；匿名链路以 Cloudflare cookies 为唯一凭据，
因此不尝试换取 `accessToken`，也不把它的缺失当作失败。

## 环境

| 项 | 值 |
|---|---|
| 上游 | `https://chatgpt.com`（真实公网，`GATEWAY_UPSTREAM_MODE=configured`） |
| 网关 | 本工程 `target/debug/mirror-gateway.exe`，`GATEWAY_COMPAT_PROFILE=original`、`GATEWAY_ALLOW_ANONYMOUS_SESSION=true`、`COOKIE_SECURE=false`、监听 `127.0.0.1:18002` |
| CF 放行 | 原版 cfbypass（`MirrorNiXiang/reverse/extracted/cfbypass/app.py`，`/cloudflare5s/bypass-v1`），本机 uvicorn `127.0.0.1:18001`，`CF_BYPASS_HEADLESS=true`，浏览器用 Playwright chromium-1234（Chrome 146） |
| 浏览器 | 无头 Chromium 146，UA `Mozilla/5.0 (X11; Linux x86_64) … Chrome/146.0.0.0 Safari/537.36`，`locale=zh-CN` |
| 数据 | 一次性临时库（`%TEMP%\mirror-anon-verify\gw*.db`），未使用任何真实 ChatGPT 账号 |

## 1. Cloudflare 观测（未带 cookies）

普通 HTTP 客户端直连 `GET https://chatgpt.com/`：

```
status: 403
cf-mitigated: challenge
server: cloudflare
```

无头 Chromium 首次访问（默认 UA）停在 `Just a moment...`；改用 Chrome146 UA + `locale=zh-CN`
后返回 200 并渲染未登录界面。⇒ 该端点对普通客户端返回的是挑战，不是内容。

## 2. cfbypass 取 cookies

`POST http://127.0.0.1:18001/cloudflare5s/bypass-v1`（Bearer = `GATEWAY_ADMIN_SECRET`，
body `{"url":"https://chatgpt.com/"}`）返回 `user_agent` + `cookies[]`，其中包含
`cf_clearance`、`__cf_bm`、`__cflb`、`_cfuvid`；**部分轮次只返回 `__cf_bm/_cfuvid/__cflb`，
没有 `cf_clearance`（cfbypass 日志 `partial cookies accepted`），页面与对话仍然正常**
⇒ 网关按“整组下发 cookies、不要求单一 cf_clearance”实现。

## 3. 匿名身份（cookies-only）

`GET https://chatgpt.com/api/auth/session`（带上述 cookies）返回 **200 `{}`**，没有 `accessToken`。
⇒ 匿名身份就是 cookies-only：网关不请求该端点、不发 `Authorization`，
只用整组 Cloudflare cookies 通过上游。真实账号登录才使用 `accessToken` 链路。

## 4. 镜像端验收（浏览器，`mirror_token` 走网关）

登录：`POST /api/login`（Bearer = 网关密钥，body `{"user_name":"verify-visitor"}`）→ 200，
`login_mode":"anonymous"`、`chatgpt_username":"anonymous"`，下发 `mirror_token` cookie。

| 项 | 结果 |
|---|---|
| `GET /` | 200，`text/html; charset=utf-8`，685 871 B；注入的 `gateway-user-logout-button` 位于 `</head>` **之前**（在原站 `<script src="/assets/app.js">` 之后） |
| 页面渲染 | 未登录界面正常：`新聊天 / 图片 / 插件 / 深度研究 / 查看套餐和定价`，“你今天在想些什么？”输入框可见 |
| 同源率 | 一次完整加载 298 个请求中 297 个指向 `127.0.0.1:18002`，仅 1 个直连 `cdn.openai.com`（`/external/*` 门禁 503，见下） |
| 静态资源 | `/cdn/*` 343 个请求全部 200，0 失败 |
| 匿名对话 | 输入“用一句话介绍你自己” → 助手返回“我是 ChatGPT，一个由 OpenAI 训练的 AI 助手，可以帮助你学习、创作、分析问题、获取信息和解决各种任务。”；18 个 `/backend-anon/*` 请求（含 SSE `POST /backend-anon/f/conversation`）全部 200 |
| 匿名对话（复测） | 断句改为“只回答两个字：收到” → 助手返回“收到” |
| 匿名链路凭据 | 上游记录只有 Cookie 头（无 `Authorization`）；匿名链路未请求 `/api/auth/session` |
| 匿名上传 | `POST /backend-anon/files`（`use_case:"multimodal"`）→ 200 + 签名地址；`PUT /internal-upstream/https/files.oaiusercontent.com/file-…?se=…&sp=cw…` → **201** |

## 5. 已知缺口（观测到的非 2xx）

| 响应 | 原因 |
|---|---|
| `503 /backend-api/sentinel/sdk.js` | `/backend-api/*` 本批仅放行 me/conversations；不阻塞渲染与对话 |
| `503 /external/https/accounts.google.com/gsi/client` | `/external/*` 外链代理本批未开放 |
| `403 /backend-anon/bazaar/obi/sync-token` | 上游对具体请求的业务拒绝；**不得**据此清空匿名身份缓存（否则每个请求都会重启一次浏览器） |

## 6. 未执行项

- QEMU 三态（BASELINE 原版二进制 → MODIFIED → ROLLBACK）对比：本工作区没有 QEMU 与 guest
  initramfs（`qemu-system-x86_64.exe`、`.build/sandbox.cpio.gz` 均不存在，逆向归档明确未上传 VM 镜像），
  因此**未执行**。等价契约由 134 项离线测试覆盖。
- 真实账号联调（登录后历史/项目/MCP/Skills/语音）与 WS/realtime：本批范围外，未执行。
- Docker 与 All-in-One 镜像构建：后置，未执行。

## 7. 同日后续复测：上游匿名流程发生变化（未通过）

同日晚间复测时，上游对未登录访客改成了另一套流程，镜像端出现**新的缺口**：

- 直接访问 `https://chatgpt.com/`（无镜像）在首页输入后 **跳转到 `/uc/<uuid>`**，
  由 `/unauth-mweb/assets/conversation-*.js`、`POST /unauth-mweb/conversation/{updates,prepare}`
  完成访客对话；该路径下浏览器文本出现 `ChatGPT 说： 收到`，**直连可用**。
- 经镜像时，`POST /backend-anon/conversation/init` 与 `/backend-anon/f/conversation/prepare`
  仍返回 200，但随后页面请求 NextAuth 命名空间：
  `GET /api/auth/providers` → 404、`POST /api/auth/_log` → 404、`GET /api/auth/error` → 404，
  浏览器最终停在错误页 `/api/auth/error`，**没有**发出 `/unauth-mweb/*` 的访客请求。
- 用真实站点实测这三个端点的匿名响应：`providers` 200 + `{"openai":{...,"type":"oauth",...}}`、
  `csrf` 200 `{"csrfToken":...}`、`_log` 200 空正文、`error` 200 HTML。
  镜像只实现了 `/api/auth/session`，其余 `/api/*` 一律 404。
- 已把 `/uc/*`、`/unauth-mweb/*` 加入放行（证据见上），但这**不足以**通过：
  缺少 NextAuth 命名空间时应用仍走 `signIn` 失败路径。

结论：匿名对话在**当日早些时候**经镜像实测通过（§4 两条对话记录），此后上游切换到
访客（guest session）流程，镜像尚未覆盖该流程的会话引导。当前状态为**未通过**，不是回归，
也不是本批改动的结果——同一时段直连站点也出现 CF 挑战/超时波动。

要下一阶段通过该流程，二选一（需产品决策，本批未实施）：

1. **为匿名会话补 NextAuth 兼容面**：本地实现 `providers`/`csrf`/`_log`/`error`，
   并把匿名会话的 `Set-Cookie` 透传给浏览器（真实匿名流程依赖浏览器持有的访客会话 cookie）。
2. **按访客流程实现专用引导**：识别 `/uc/*` 首次进入，由网关侧完成访客会话初始化，
   再将页面注入改写为同源路径。

## 8. 收尾复测：只补 next-auth 兼容端点（2026-09-23 晚）

产品决定：**不做游客功能**，`/uc/*`、`/unauth-mweb/*` 只保持放行透传，不实现访客会话引导；
匿名对话只是开发期入口。本轮只补齐前端自带 next-auth 客户端依赖的四个本地端点，然后重跑真实上游端到端。

环境与 §4 同源：本地 cfbypass `127.0.0.1:18001`（`CF_BYPASS_HEADLESS=true`，chromium-1234），
网关 `target/debug/mirror-gateway.exe` 监听 `127.0.0.1:18002`（`GATEWAY_UPSTREAM_MODE=configured`、
`GATEWAY_COMPAT_PROFILE=original`、`GATEWAY_ALLOW_ANONYMOUS_SESSION=true`、`COOKIE_SECURE=false`、
一次性临时库 `%TEMP%\mirror-anon-verify\gw-nextauth.db`），浏览器为无头 chromium-1234（Chrome146 UA、`zh-CN`）。

### 8.1 上游取样（直连站点，非镜像）

普通 HTTP 客户端即使带上 cfbypass 返回的 cookies 也只拿到 Cloudflare 挑战
（`providers`/`csrf`/`_log`/`error`/`session` 全部 403 + 挑战页，原始字节见
`evidence/anonymous-nextauth-001/plain-http-403/`），因此取样在浏览器页内 `fetch` 完成，
脚本与原始结果见 `evidence/anonymous-nextauth-001/sample-*.{body,hdr}` 与
`in-page-samples.json`、`direct-navigation.json`。

| 端点 | 状态 | Content-Type | 正文（原始） |
|---|---|---|---|
| `GET /api/auth/providers` | 200 | `application/json; charset=utf-8` | `{"openai":{"id":"openai","name":"openai","type":"oauth","signinUrl":"https://chatgpt.com/api/auth/signin/openai","callbackUrl":"https://chatgpt.com/api/auth/callback/openai"},"openai-dev":…,"openai-sidetron":…,"openai-sidetron-dev":…}`（共 4 项） |
| `GET /api/auth/csrf` | 200 | `application/json` | `{"csrfToken":"4d0d39df4bb34515efedd09728b465f6fd3772bbdf79c83e9e50bd489f6fc388"}`（64 位十六进制） |
| `POST /api/auth/_log` | 200 | 无 | 空正文（`content-length: 0`） |
| `GET /api/auth/error?error=Configuration` | 200 | `text/html; charset=utf-8` | 站点整页错误页（685 KB 级，含站点 CSP/nonce） |
| `GET /api/auth/session` | 200 | `application/json` | 本轮为 `{"WARNING_BANNER":"…"}`（早前同端点为空对象 `{}`，两次都没有 `accessToken`） |

### 8.2 镜像侧实现

`src/server.rs` 在 `/api/auth/session` 旁显式注册四个本地 handler：
`providers`（四个 oauth 条目，`signinUrl`/`callbackUrl` 改写为同源相对路径）、
`csrf`（随机 64 位十六进制 token，不新增下游 cookie）、
`_log`（限长读取正文后丢弃，返回 200 空正文）、
`error`（不引用任何上游资源的最小同源 HTML）。
四者都不校验镜像会话、都不下发 `Set-Cookie`，与方法不匹配时返回 405 + `Allow`；
`/api/auth/signin/*`、`/api/auth/callback/*` 等其余 `/api/*` 仍然 404（实测）。

### 8.3 镜像端到端（浏览器经镜像）

原始数据：`evidence/anonymous-nextauth-001/mirror-run-002/{run.json,requests.json,conversation-bodies.json,page.png}`。

| 项 | 结果 |
|---|---|
| 页面 | `GET /` 200，604 051 B，`client-bootstrap` 里 `authStatus="logged_out"` |
| 注入位置 | 注入脚本 `<script id="gateway-user-logout-button">` 位于下标 9291，`</head>` 在 107 012 ⇒ 位于 `</head>` **之前** |
| 匿名对话 | 输入“只回答两个字：收到”后渲染出助手节点内容“收到”；`POST /backend-anon/f/conversation` 200 且响应体是真实 SSE（`event: delta_encoding` / `resume_conversation_token` / `conversation_detail_metadata`） |
| 请求瀑布 | 一次完整会话共 834 个请求；其中 `/cdn/*` 375 个响应**全部 200**；非 2xx 只有 3 个，即 §5 已记录的既有缺口（`/external/https/accounts.google.com/gsi/client`、`/external/https/bzr.openai.com/v1/obi/sync`、`/backend-api/sentinel/sdk.js`） |
| 直连外域 | 仅 1 个：`https://cdn.openai.com/common/fonts/openai-sans/v4/OpenAISans-Semibold.woff2`（CSS 内字体，与 §4 记录的同一处既有缺口） |
| next-auth 调用 | 本轮页面在正常路径下**没有**请求 `/api/auth/*`；四个端点为按实测形状补齐的兜底兼容面 |

### 8.4 匿名上传（走站点自身的上传入口）

驱动页面自带的 `input[type=file]`（`accept=image/*`）上传 8×8 PNG，原始数据见
`evidence/anonymous-nextauth-001/mirror-run-007|008/{requests.json,upload.json,files-response.json,composer.png}`：

| 步骤 | 结果 |
|---|---|
| `POST /backend-anon/files` | 200，`{"status":"success","upload_url":"https://files.oaiusercontent.com/file-…?sp=cw&sig=…","file_id":"file-…"}` |
| 签名地址上传 | `PUT /internal-upstream/https/files.oaiusercontent.com/file-…` → **201**（镜像媒体前缀转发白名单签名主机） |
| `POST /backend-anon/files/process_upload_stream` | 200（上游接受并解析该文件） |
| 界面回显 | 输入框出现该图片缩略图（`mirror-run-008/composer.png`） |
| `GET /backend-anon/files/download/<file_id>` | 403，正文为上游原文 `{"detail":"User does not have permission to download this file"}` |

回读限制的归因：同一浏览器身份上传后，镜像与直连站点都只能拿到签名写入地址，站点自身发出的
`download/<id>` 调用被上游拒绝（`mirror-run-009/download-classification.json` 记录用站点同款
`oai-*` 头重放仍是 403）。镜像对这些路径只做透传，不合成 403；直连对照上传同样以
`PUT …/file-…` 201 结束（`direct-upload-009|010`）。因此“文件可回读”在匿名通道下的上限是：
**上游确认接收并在镜像内可见，但上游不允许按 file_id 重新下载**——这是上游访客策略，不是镜像缺口。

另记：用页面内合成 `fetch`（不带站点 `oai-*` 头）直接 POST `/backend-anon/files` 会得到
上游 401/422（`mirror-run-004|005|006`）；这三次是取样探针，不是站点真实调用路径。

### 8.5 判定

§7 的阻塞症状本轮**未再复现**：匿名对话（SSE）、站点自身上传、媒体加载与页面注入都在真实上游
通过，`/uc/*`、`/unauth-mweb/*` 也没有进入实际请求路径，因此无需访客会话引导。
需要区分的是归因：本轮如实测所记，正常路径下页面**没有**请求 `/api/auth/*`，
所以上面这条通过不等于“四个端点必然修复了它”——本轮只是按实测形状把该兼容面补齐并保持最小；
§7 当时那条错误页链路未在本轮复现，也没有用旧二进制做对照。
仍存在的缺口与 §5 一致：`/external/*` 外链代理、`/backend-api/sentinel/sdk.js`、
CSS 内 `cdn.openai.com` 字体，以及上游不允许的 file_id 回读。

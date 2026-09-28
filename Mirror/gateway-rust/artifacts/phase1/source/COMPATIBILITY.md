# v3 兼容矩阵：本批未完整通过

旧 101 项与新增契约分开验收。下列计数存在重叠，不可相加为产品覆盖率。
四角色已更新为同一最终 Linux x86-64 候选；原版和旧证据不变。

| 契约/制品 | 比较量 | 一致 | 差异 |
|---|---:|---:|---:|
| core/candidate | 101 | 101 | 0 |
| core/rollback | 101 | 101 | 0 |
| headers/candidate | 86 | 86 | 0 |
| headers/candidate/audit | 85 | wire integrity | 0 |
| headers/rollback | 86 | 86 | 0 |
| headers/rollback/audit | 85 | wire integrity | 0 |
| management/candidate | 283 | 278 | 5 |
| management/candidate/audit | 47 | 32 | 15 |
| management/rollback | 283 | 283 | 0 |
| management/rollback/audit | 47 | 47 | 0 |
| proxy/candidate | 68 | 66 | 2 |
| proxy/candidate/audit | 75 | 71 | 4 |
| proxy/rollback | 68 | 68 | 0 |
| proxy/rollback/audit | 75 | 75 | 0 |
| backup/candidate | 84 | 84 | 0 |
| backup/rollback | 84 | 84 | 0 |

## 判定与边界

BASELINE 使用已记录原版结果，MODIFIED 与 ROLLBACK 使用完全相同脚本哈希、独立 QEMU 无网卡实例、合成数据和本地模拟上游。
回滚逐套实际执行 ROLLBACK.sh、验证恢复 SHA-256，再执行同输入。它只恢复程序，不处理数据库。
145 个 Rust 测试（含 8 项匿名前端契约、6 项 Cloudflare 加固契约与 55 项库内单测，`cargo test --locked --offline` 实测）、Clippy -D warnings 已通过；历史 Linux musl 构建结论按旧批次保留。强制防御性审查见 DEFENSIVE_REVIEW.md。
响应 JSON 按结构比较，HTTP Date/随机令牌使用原有校验规则；未新增随机字段忽略规则。
Header 压缩审计绑定原始字节长度、摘要、gzip 校验和及解码正文，不要求不同编码器输出相同 DEFLATE 字节。
管理 DB 审计验证签发令牌与持久化摘要、认证解密、明示时间列；ID 偏移未归为随机性。备份另比恢复前后八表与输入。
历史子代理 contract.md 是当时的移交笔记，不代表当前实现；本文件与 STATUS.json、delivery 报告为最新判定。

## 未完成/显式差异

- 审核 provider 成功请求/校准协议未获原版 TLS 观测；5 个扩展响应用例保留显式 503 门禁差异（该面已列为显式非目标，见下节）
- 管理非空数据库 gateway_sessions 自增 ID 偏移与上游调用序列仍有差异，未忽略 ID
- auth/session 上游 accounts/check + me 刷新链未对齐
- Connection 命名头按安全要求过滤，与原版泄漏行为显式不同
- 两个未知 chat 探针路径继续 503；不为通过测试整体开放聊天路由
- login extra_cookies 字符串/缺失/错误类型的严格原版提取契约仍需完善
- SSE 与 `/ws-chatgpt` 桥接已按本批契约落地（见下节）；指纹传输、MCP/Skills 请求侧与限额、
  项目/分支级归属（缺口 3 完整批次）、`/realtime` 升级桥接与 `/api/livekit/` 语音仍是独立门禁
- Docker 未验证；真实账号/真实上游/浏览器联调未批准，本次未运行

## 本批新增的显式差异（匿名上游前端，2026-09-23 真实上游实测）

真实上游观测环境：`GATEWAY_UPSTREAM_MODE=configured`、`CHATGPT_BASE_URL=https://chatgpt.com`、
`CF_BYPASS_URL` 指向本地 cfbypass（原版 `/cloudflare5s/bypass-v1` 协议）、Windows 本机出口、headless Chromium 146。

| 项 | 原版 | 本候选 | 说明 |
|---|---|---|---|
| 未认证 `/` | 302 `/admin#/` | 401 `未登录` | 本批没有改动镜像自身的登录门禁，仍是候选既有行为 |
| 匿名上游身份 | 单份共享上游身份 | 相同 | 全局共享，不按访客拆分；本地归属表负责隔离 |
| 无凭据会话入口 | 无 | `GATEWAY_ALLOW_ANONYMOUS_SESSION=true` 时 `/api/login` 接受空凭据 | 开发阶段入口，默认关闭 |
| HTML 注入位置 | 第一个 `</head>` 之前；无 `</head>` 时追加正文末尾 | 相同 | 逐字节对照 page-original-001 与 proxy-v3-original-010 |
| 媒体代理 | `/files/*` 等专用前缀 + `/external/*` 外链代理 | `/internal-upstream/https/<host>/...`（主机表限定），`/external/*` 保持 503 | 媒体只放行内置主机表；`/external` 仍未开放 |
| 上游 HTML 解码 | 未见同环境观测 | gzip/deflate/br/zstd 全量解码后注入 | 未识别编码时不注入并保持原字节，避免破坏正文 |
| 匿名身份失效判定 | 未见同环境观测 | 仅 `403 + cf-mitigated: challenge` 触发重新获取 | 实测 `403 /backend-anon/bazaar/obi/sync-token`、`401` 缺头部等业务拒绝不得清缓存，否则每个请求都会重启一次浏览器 |
| 匿名上游凭据 | 单份共享上游身份（cookies 为主） | 相同：整组 Cloudflare cookies，不发 `Authorization` | `accessToken` 只属于真实账号登录；实测匿名 `/api/auth/session` 返回 200 且无 `accessToken`（§4 为空对象 `{}`，§8.1 直连取样为 `{"WARNING_BANNER":…}`），因此匿名链路不请求该端点，也不把它当作失败 |
| next-auth 命名空间 | 仅 `/api/auth/session`（报告 08 §7.1 表内无 `/api/auth*` 专有行） | 另补本地 `providers`/`csrf`/`_log`/`error` 四个端点 | 上游未登录前端会调用这四个端点（镜像 404 的观测见证据文档 §7，直连取样见 evidence/anonymous-nextauth-001）；只补形状，不做登录、不做访客引导、不下发上游 cookie，`signin`/`callback` 仍 404 |
| 服务端 URL/HTML 改写 | `rewrite_location`、`rewrite_origin_prefix_to_local`、estuary/connector/deep-research 特例（规则未证实） | 本批未实现服务端改写 | 原规则在报告 08 §7.2 只有符号名，没有可证实的触发条件；真实上游实测显示运行期客户端改写已足够，故不猜测实现 |

匿名链路实测结果（同一环境，逐条可复现）：页面 `GET /` 200 且注入位于 `</head>` 之前；
匿名对话 `POST /backend-anon/f/conversation` 200（SSE，助手返回中文回答）；
匿名上传 `POST /backend-anon/files` 200 + `PUT /internal-upstream/https/files.oaiusercontent.com/...` 201；
首页同源 `/cdn/*` 343 个请求全部 200、0 失败。
已知缺口（本批未开放，非缺陷）：`/external/*`（例如账号登录用的 `accounts.google.com`）返回 503；
页面还会请求 `/backend-api/sentinel/sdk.js`，因 `/backend-api/*` 除 me/conversations 外全部关闭而返回 503
——该请求不阻塞页面渲染与匿名对话（实测两者均正常），是否放行留给下一批决定。

完整逐条证据（环境、命令、原始状态码、已知缺口、未执行项）见 [ANONYMOUS_FRONTEND_EVIDENCE.md](ANONYMOUS_FRONTEND_EVIDENCE.md)。

### 当日后续复测：上游流程变更后按“只补 next-auth 兼容端点”收尾

上游把未登录访客改成 `/uc/<uuid>` + `/unauth-mweb/*` 的访客流程，并在发送前调用 NextAuth 命名空间
（`providers`/`csrf`/`_log`/`error`）。镜像当时只实现 `/api/auth/session`，其余 `/api/*` 为 404，
应用因此落入 `signIn` 失败路径并跳到错误页；直连站点同一时段可用，证明不是网络出口问题。

本轮按产品决定**只补四个本地兼容端点**（不实现登录、不做访客会话引导、不改 `Set-Cookie` 不变式），
随后重跑真实上游端到端：页面 200 且显示未登录界面、注入位于 `</head>` 之前、匿名消息经
`/backend-anon/f/conversation` SSE 返回并渲染、站点自身的图片上传走通
（`POST /backend-anon/files` 200 → 签名 `PUT` 201 → `process_upload_stream` 200）、
`/cdn/*` 375 个请求全部 200。因此本阶段匿名对话与上传的验收状态为**通过**（§7 的错误页症状本轮未复现；
该轮正常路径未请求 `/api/auth/*`，端点本身属按实测形状补齐的兼容面，不作因果声明）；
逐条原始记录与仍存在的缺口见证据文档 §8。

## 凭据换取路径的 Cloudflare 加固（有意偏离，2026-09-23）

原版在 `session_token → access_token` 换取、`/api/get-user-info`、`/api/diagnose-chatgpt-auth`
与会话刷新链上不注入 CF cookies、也不在挑战后重放，CF 的 403 拦截页被当成 token 校验失败
（报告 07 §3 粘连文案 `session_token 校验失败: api/auth/session 返回状态 `），
Django 健康检测据此把凭据标成不可用、可能发告警，刷新 cron 还可能清空 token。
替代网关不复制该缺陷：

| 项 | 原版 | 本候选 | 说明 |
|---|---|---|---|
| 凭据类上游 Cookie | 换取只带 `__Secure-next-auth.session-token`；`me` 不带 cookie | 会话/提交 cookies 在前 + CF 白名单 cookies（`cf_clearance`/`__cf_bm`/`__cflb`/`_cfuvid`）在后 | 同名保留会话侧取值；顺序沿用 proxy-v3-original-006 观测 |
| 挑战处理 | 不刷新、不重放，403 正文进错误消息 | 幂等 GET 刷新一次并重放一次；生成/SSE/上传不重放，只失效缓存 | 冷却 30 秒；并发挑战共用一次 cfbypass 刷新 |
| 失败上报 | `message` 里拼接状态码与上游正文 | `502` + `{"message":"…","code":"upstream_blocked"}` | 只含端点、状态码与本地刷新结论，绝不回传上游 HTML/Cookie/token |
| 诊断接口 | 只有两个布尔位 | 增加 `upstream_blocked` | 受阻时布尔位含义是“无法验证”，消费方必须优先看该标志 |
| Django 健康检测/告警/刷新 cron | 受阻即判失效、可能告警、可能清空 token | 受阻保留原凭据状态与 token，不告警，按确认间隔重试 | 见 `app/chatgpt/health_monitor.py`、`app/chatgpt/models.py`、`app/cron.py` |

合成回归：`tests/cloudflare_credentials.rs` 6 项（注入与重放、持续拦截、未配置 cfbypass、
诊断标志、生成类不重放、并发单飞）与 Django 侧 5 项新增用例（三态健康检测、按需诊断、刷新 cron）。
真实账号与真实 chatgpt.com 联调仍未执行。

## 显式非目标：计量 / 配额 / 限流 / 审核 / PoW（产品决定，2026-09-23）

本项目的用途是个人小团体内部共享同一个上游账号，**不对外收费分发**，因此原版的计量与风控面
不列入替代实现范围，也不再作为验收缺口：

| 项 | 原版 | 本候选 | 说明 |
|---|---|---|---|
| 请求计量 | 写 `visit_logs` 的 `proxy` 行，供 `get-user-use-count`/`get-chatgpt-use-count`/`operations-overview` 统计 | 只读不写 | 管理端“今日请求”“配额已用”恒为 0；Django 侧仅保留自己的 `login`/`choose-gpt` 日志 |
| 配额与限流 | `enforce_metered_request`、`is_metered_proxy_request`、`limit_per_minute` | 不执行 | 字段与登录载荷保留（`Policy::from_login` 要求 `daily_quota`/`monthly_quota` 等），删除反而破坏兼容 |
| 审核 provider | 10 个函数的完整审核链、`x-mirror-moderation` 响应头 | 仅保留配置 CRUD；`/api/political-moderation-config/test` 维持 503 | 不把“未拨号”伪报为连接失败，也不伪造成功协议 |
| PoW / 降智风险 | `/api/pow-risk-stream`（SSE）与 `PowRiskSnapshot` 等符号 | 不实现；注入模板已删除写死的“当前降智风险 / POW难度检测值”横幅与其样式 | 该横幅原本没有调用者，会永久停在“未知 / 等待检测” |

连带影响（必须知道）：删掉计量与限流后，共享账号剩下的安全边界只有**归属隔离**
（`conversation_owners`/`project_owners`、`claim_conversation_owner`）、撤权与凭据隔离。
因此开放 `/backend-api/*` 读写时，归属登记链必须同时落地，否则同一共享账号下任何镜像用户
都能看到他人创建的会话。

## 缺口 1 + 2 同批落地（2026-09-23）

本批把 `/backend-api/*` 从「两个只读端点 + 503 门禁」推进到可用的已登录读写，
并同时落地归属登记最小核心（对应上面那条连带影响）。

### 已登录业务面与会话归属

| 项 | 原版 | 本候选 | 说明 |
|---|---|---|---|
| `/backend-api/*` | 已登录通道，方法语义交给上游 | 相同；六类资源先做 ACL 判权（缺口 3 起，取代名称式判定） | `server/proxy.rs` + `server/acl.rs` |
| 会话归属登记 | `claim_conversation_owner` 等（报告 08 §3.1-C、§6.1） | 创建响应里出现 `"conversation_id":"<uuid>"` 即登记；跨块用尾窗重叠识别，**在把含该 id 的块交给客户端之前**写库 | 冲突不覆盖属主；2xx 创建响应认不出 id 时记 warn（只记路径） |
| 未知归属 | 未确证 | 一律拒绝：`404 {"message":"会话不存在或不属于当前用户"}`，不接触上游 | 含本批之前创建、或直接在上游站点创建的会话；唯一恢复途径是管理员在后端重新分配（未实现，见 NEXT_WORK） |
| 项目/分支级归属 | `enforce_project_owner` 等 | 已接线（见下方「缺口 3 完整批次」） | 项目/文件/图片/任务/连接器与项目动态共享统一由 `resource_acl.rs` 判定 |
| estuary 内容 URL 绝对化 | `absolutize_estuary_content_urls`（规则未证实，报告 08 §7.2） | 不做；`/backend-api/estuary/*` 按普通已登录路径转发 | 已知差异，规则只有符号名 |

### WebSocket 与实时通道

| 项 | 原版 | 本候选 | 说明 |
|---|---|---|---|
| `/ws-chatgpt[/…]` | `bridge_chatgpt_ws`，目标校验为 `wss://ws.chatgpt.com` | 同主机桥接，双向透传文本/二进制，任一侧关闭即转交关闭帧 | configured 模式固定 `wss://ws.chatgpt.com/`；offline 模式用回环基址（合成回归） |
| WS 凭据 | 未见同环境观测 | 会话 `extra_cookies` 在前 + CF 白名单在后，`Authorization` 只用会话 access_token | 与 HTTP chat 路径同规则；镜像 token 与客户端 cookie 不转发 |
| WS 出口 | 可按代理分流（符号证据） | 代理出口上 fail-closed：`503 {"message":"WebSocket 桥接尚未支持代理出口"}` | 不静默改走直连；缺口 5 的出口抽象之后再补分流 |
| `/realtime/*` | 实时通道 | HTTP/SSE 按已登录业务面转发；`Upgrade: websocket` 显式 `503 {"message":"实时通道升级未开放"}` | 升级桥接与 `/api/livekit/` 语音不在本批 |

### 公共前缀策略表（缺口 2）

注入脚本的改写目标由一张服务端策略表逐条接管（`server/public_prefixes.rs`），
不再出现「改写成功但服务端 503」的静默断裂。全部不带账号凭据、拒绝重定向与 HTML 正文，
路径余段拒绝空段、`.`/`..`、反斜杠与编码分隔符，因此客户端不能借前缀选择任意目标。

| 类别 | 前缀 | 方法 | 凭据 |
|---|---|---|---|
| 无凭据反代 | `/common/`（cdn.openai.com）、`/static-rsc-1/`、`/static-rsc-4/`、`/images-openai/`（images.openai.com）、`/images-app/`、`/persistent-deep-research/`（persistent.oaistatic.com）、`/files/`、`/files-southcentral/`、`/files-north/`（对应分片 oaiusercontent）、`/openai-files/`（files.openai.com）、`/connector-assets/`、`/mapbox/`、`/mapbox/styles/v1/oai-data/`（api.mapbox.com）、`/google-s2/`、`/google-avatar/a/`、`/gstatic-t0..t3/` | GET/HEAD | 无（与 `/assets/`、`/cdn/` 同边界） |
| 配置驱动 | `/ab/` → `CHATGPT_AB_BASE_URL` | GET/HEAD | 无；未配置时 `503` + 可行动文案 |
| 外链代理（2026-09-28 起） | `/external/<scheme>/<host>[:port]/<path>`（目标由客户端给出） | GET/HEAD/POST/PUT/PATCH/DELETE | 无；只允许解析到公网的目标、每请求钉扎解析结果，拒绝重定向与 HTML，见下方「前端自愈」 |
| 有意不代理 | `/v1/*`、`/vendor-script/`、`/vendor-static`、`/cloudflare-insights/`、`/vendor-batch/collect`、`/ga/collect`、`/mapbox-events/events/`、`/connector-deep-research[/]` | — | 已登录 `503` + 按类别区分的文案；未登录保持既有 `401` 门禁顺序 |
| 本地语义 | `/api/*` 未实现子路径 | — | `404 {"message":"本地未实现的 /api 路径"}`（含 `/api/livekit/`） |

契约测试解析 `src/assets/gateway-client.html` 的两张改写表（2026-09-23 实测 63 条 pair、
39 个去重目标前缀，加运行时拼出的 `/external/` 与 `/internal-upstream/` 共 41 个），
断言每个前缀都有「已处理」或「显式拒绝」语义；将来新增或改名而不更新策略表即失败。
2026-09-28 起 `/external/` 从「显式拒绝」改为「已处理」（见下方「前端自愈」），其余分类不变。

### 本批验证

`cargo test --locked --offline` 64 项库内单测 + 107 项集成用例全过（新增
`tests/backend_api_surface.rs` 7 项、`tests/public_prefixes.rs` 7 项、`tests/ws_bridge.rs` 3 项），
`cargo clippy --locked --offline --all-targets -- -D warnings` 通过；
Django `DJANGO_ENV=LOCAL manage.py test` 93 项通过（本批未改 Django 代码，作为回归确认）。
证据全部来自合成回环 fixture：真实账号、真实 chatgpt.com 与真实 WS 上游联调未执行。

### 新建对话的前端真实形状（2026-09-24 分块取证，只读）

为了判定真实探针三次新建尝试被上游 JSON 403 拒绝的原因，从公开前端 CDN 重新取回
`cdn.oaistatic.com/assets/` 的三个分块（`4813494d-i6uoff53a7o08h8b.js` 2558090 B
`6fbde837…0ed012f`、`8b34dbc2-oz862wcamnpza3ku.js` 3691919 B `dbf21758…8dfc495d`、
`conversation-small-c1t85fv7s1nl9k7s.js` 5562125 B `766bba7e…98dfa38c`，sha256 全部与
`src/assets/chatgpt-api-routes.json` 冻结值一致），只做静态阅读，不接触账号。

| 项 | 确证内容 |
|---|---|
| 创建端点 | 前缀由 `P0t()` 在 `https://chatgpt.com/backend-api`（登录态）与 `…/backend-anon`（匿名态）间切换，后缀为 `/f/conversation`（`f_completion` 关闭时退化为 `/conversation`）；另有 `POST /f/conversation/prepare` 前置调用。**探针用的 `/backend-api/f/conversation` 与 `/backend-api/conversation/id/{id}` 选择正确** |
| 请求体 | 顶层约 40 个键（`action`/`messages`/`model`/`parent_message_id`/`conversation_id`/`timezone`/`history_and_training_disabled` 等）；`messages[]` 元素为前端原样透传（仅删 `clientMetadata`），键名 `id`/`author{role,name}`/`content{content_type,parts}`/`recipient`/`metadata`/`status`/`weight` |
| sentinel 头族 | 枚举 `TYt`：`OpenAI-Sentinel-Chat-Requirements-Token`、`…-Prepare-Token`、`OpenAI-Sentinel-Turnstile-Token`、`…-Proof-Token`、`…-SO-Token`、`OpenAI-Sentinel-Token`、`OAI-Telemetry`；创建请求把它们与 `OAI-Echo-Logs`、`x-conduit-token`、`x-oai-turn-trace-id` 一起合并 |
| 握手顺序 | `POST /backend-api/sentinel/chat-requirements/prepare`，体为 `{p: <requirements token>}`，`p` 由页面内 SDK 本地算出（`gAAAAAC` 前缀）→ 响应取 `prepare_token`/`persona`/`turnstile`/`proofofwork`/`so`/`force_login` → `POST …/finalize`，体为 `{prepare_token, proofofwork?, turnstile?}` → 响应的 `token` 回填进 `OpenAI-Sentinel-Chat-Requirements-Token` |
| PoW / Turnstile | **条件触发**：仅当 prepare 响应里 `proofofwork.required`（用 `seed`+`difficulty`）/ `turnstile.required` 为真时由浏览器求解；不需要时不计算 |
| SDK 来源 | `sdkVariant` 默认 `chatgpt` → `https://chatgpt.com/backend-api/sentinel/sdk.js`（仅 `openai` 变体用 `sentinel.openai.com`），以动态插入 `<script>` 加载，并靠 `SentinelSDK.token()/sessionObserverToken()/timing()` 产出上述令牌，`/sentinel/heartbeat` 定时续期 |

结论与候选的关系：

1. **403 的原因是缺 sentinel 握手，不是路由或载荷选错**；合成探针不会产生这一族头，被拒属预期。
2. **候选无需为写路径实现 sentinel**：令牌由浏览器产生，原版网关同样只透传（其二进制查无
   `f/conversation`、`openai-sentinel`、`chat-requirements-token`、`proof-token` 字面量）。
3. 链路已具备：请求头按黑名单过滤后原样透传（`openai-sentinel-*`、`oai-*` 不在剔除集内）；
   改写表第 37 行 `https://chatgpt.com/backend-api/` → `/backend-api/` 覆盖 SDK 与握手请求；
   CSP 的 `script-src` 同时允许 `'self'` 与 `https://chatgpt.com`（改写漏掉时也不被拦）；
   ACL 把 `/backend-api/sentinel/*`（`UNOWNED` 含 `sentinel`）与 `/backend-api/f/conversation/prepare`
   按账号级放行，后者另有单测。
4. **剩下的是验收方式而非实现**：要证明「浏览器经镜像能新建并续聊」，必须做真实浏览器驱动的
   端到端流程；合成回环只能证明「没有丢掉浏览器的材料」。

## 缺口 3 完整批次：资源 ACL 产品接线（2026-09-24）

共享上游账号下唯一的内容级边界从「会话名称式归属」换成 ACL v1（`src/resource_acl.rs` +
`server/acl.rs` + `server/acl_admin.rs`）。判权在网关单锁内用 IMMEDIATE 事务完成，
路由分类来自 2026-09-23 冻结的公开前端路由快照（`src/assets/chatgpt-api-routes.json`，
349 个分块 sha256、923 条 `/backend-api/*` 模板）。

### 分类与拒绝契约

| 判定 | 路径示例 | 行为 |
|---|---|---|
| 资源作用域 | `conversation/{uuid}*`、`projects/{id}*`、`websites/{project_id}*`、`files/{id}*`、`files/library/**`、`images/{id}*`、`my/image/**`、`tasks/{id}`、`task/cancel`、`aip/connectors/{id}*`、`aip/connectors/links/{id}`、`v2/connectors|links/{id}`、`ecosystem/file_*` | 转发前判权；未登记或他人资源 `404 {"message":"会话不存在或不属于当前用户","code":"acl_not_found"}`，**不接触上游** |
| 集合读取 | `conversations?…`、`conversations/search`、`projects`、`files`、`files/library/*`、`images`、`images/image-tags`、`my/recent/image_gen|uploaded_images`、`tasks` | 转发后按 ACL 过滤元素并把 `total` 重算为可见条数；上游非 2xx 或正文不可解析时仍是 `{"items":[],"total":0}` |
| 创建登记 | `POST conversation`、`f/conversation`、`sidebar/conversation`、`projects`、`files`、`files/import_image`、`images`、`images/image-tags`、`tasks` | 只在**已确认 2xx** 的响应流上按块扫描资源 id，在把含该 id 的块交给客户端之前写入 `acl_resources`；冲突不覆盖；2xx 未认领到 id 时只记路径与状态码 |
| 账号级路径 | `me`、`models`、`accounts/*`、`settings/*`、`conversation/init`、`f/conversation/prepare`、`sidebar/*` 反馈族、`aip/ledger/*`、`aip/first-party/*`、`ecosystem/widget*`、`task_suggestions`、遥测族 | 与六类资源无关，按原版行为透传（`acl.rs` 的 `UNOWNED` 显式清单） |
| 未分类 | 未出现在快照、也未登记的前缀 | `503 {"message":"该路径尚未完成归属分类，候选制品未启用","code":"acl_unclassified_route"}`；新增路由必须显式分类后可用，库内单测对 923 条模板逐条断言 |

访客（Django `FREE_ACCOUNT` 的 `free_account:<sid>`，`principal_kind="visitor"`）不参与 ACL：
作用域与创建路径 `403 {"code":"acl_visitor_denied"}`，集合读取直接返回空信封且**不向上游取数**，
账号级路径与页面/匿名通道保持既有可用性。这是产品决定：访客没有稳定的镜像身份，
无法把资源安全地登记给某个主体；若今后要让访客参与会话，必须单独定义访客归属策略。

### 身份、账号键与写入面

| 项 | 实现 |
|---|---|
| 可信身份 | Django 授权响应的 `active/version/expires_at/user_id/is_admin/subject/principal_kind` 在登录时固定进会话，**每个资源请求前**从固定 Django 源复验 `user_id/is_admin/version/subject`，任一变化即 `401`；浏览器自报的同名字段一律被覆盖 |
| 稳定账号键 | `chatgpt_account_id`（`ChatgptAccount.pk` 十进制串）随登录载荷与 `/api/get-mirror-token` 下发并存入 `gateway_sessions.chatgpt_account_id`；mirror profile 下缺失即拒绝签发登录态，不用用户名顶替 |
| 生成互斥 | `(account_id, conversation_id)` 独占租约，同一会话已有在途生成时 `409 {"code":"generation_busy"}`；不排队、不重放；成功/失败/取消/断开随响应体 Drop 释放；重启不重建上游任务 |
| 撤权屏障 | 活动 SSE/WS 按 subject 登记，`/api/revoke-authorization` 命中后中止匹配流；登出同样中止该用户在途流 |
| 管理 API | `GET /api/acl/resources`、`POST /api/acl/claim|share|move`、`GET /api/acl/audit|unclaimed-conversations`：服务密钥由中间件校验（Django 侧走 `x-gateway-secret`），操作者身份另行从固定 Django 源 fresh 校验并要求 `is_admin`，服务密钥本身不代表管理员 |
| 旧归属回填 | 启动时若未写过 `acl_backfill_v1` 标记，调用 `POST /0x/user/gateway-acl-mapping` 一次性把 `conversation_owners`/`project_owners` 搬进 `acl_resources`；只有能唯一映射的行才认领，访客主体（含 `:`）与无法映射的行保持未认领并记清单日志；幂等、不修改旧表 |
| 备份 | 网关备份升 v3：新增 `acl_resources`/`acl_project_links`/`acl_shares`/`acl_audit` 四个集合；`version` 为 2 或更早（不含 ACL）以及更高版本一律显式拒绝并给出重新导出的行动指引，不按旧格式局部恢复 |

### 已知残项（本批未做）

- **连接器创建不自动登记**：`POST /backend-api/aip/connectors/*` 的响应形状没有实测证据
  （同一前缀下既有创建也有 `list_repos`/`search_contacts` 这类动作），凭响应里的 `id`
  自动认领会把动作结果误登记成连接器资源。当前连接器只能由管理员用 `/api/acl/claim` 认领；
  自动登记留待有真实观测后再做。
- **上传预约 id 不认领**：`files/upload_reservations*`、`files/process_upload_stream` 返回的是
  预约/会话 id 而非文件 id，文件实体随后由 `/files` 或文件库接口登记，因此这些路径按账号级放行。
- **项目/分支级归属只在项目维度落地**：原版 `enforce_project_owner` 的「分支」维度在逆向材料里
  只有符号名，本批按项目 ACL + 动态共享实现，未猜测分支语义。
- **真实上游探针只完成读路径**：2026-09-24 用真实 AccessToken 执行（见下方「真实上游探针」），
  凭据换取与四条读路径在真实上游通过；真实新建会话被上游以 JSON `403` 拒绝，因此跨用户隔离
  在真实会话上仍未验证，真实 WebSocket 上游也未联调。
- **管理界面只做认领**：`/api/acl/{resources,share,move,audit}` 仍只有 API；Vue 只补了
  「未登记会话 → 认领给某个镜像用户」这一条最常用的运营路径（见下方「残项收敛与
  管理员会话认领」）。
- **`GATEWAY_COMPAT_PROFILE=original` 下资源路径不判权**：该 profile 没有 Django 可信身份与
  `chatgpt_account_id`，六类资源路径按「无账号键」fail-closed（作用域/创建 403、集合空信封）。
  `original` 只用于原版契约观测，产品面使用默认的 `mirror` profile；若要在该 profile 下恢复
  按名称的归属，需要另行定义账号键与回填规则。

### 本批验证

`cargo test --locked --offline` 176 项全过（63 项库内单测 + 113 项集成用例，其中本批新增
`tests/acl_product_wiring.rs` 6 项，并在 `coord_acl_contract.rs` 保留 28 项离线 ACL 契约用例），
`cargo clippy --locked --offline --all-targets -- -D warnings` 通过；
Django `DJANGO_ENV=LOCAL manage.py test` 101 项通过（新增身份字段、映射端点、备份 v3 与旧版拒绝用例）。

### 真实上游探针（2026-09-24）

用真实 AccessToken 执行 `artifacts/phase1/probe/probe.py`（证据
`Mirror/gateway-rust/evidence/gap3-real-probe-001/`）。环境：`configured` 模式、
`DATABASE_PATH=:memory:`、本地 Django 授权桩、未配置 `CF_BYPASS_URL`、Windows 本机出口。

| 观测 | 结果 |
|---|---|
| 真实凭据换取 + `/backend-api/me` + `accounts/check` + `conversations` | 4 次运行全部 `200`：真实 AccessToken 的换取、校验与集合转发在真实上游成立。`conversations` 的 `items`/`total` 是 **ACL 过滤后**的视图，不能用来判断账号里原有会话数 |
| `files/library/nodes`、`tasks` | 各有至少一次 `200`，也有若干次发送阶段失败（见下） |
| `GET /projects` | 每次都 `405`：上游不支持该 GET。冻结快照里此路径只有 `POST`，因此候选的集合分支在这里不生效（无害，归属判权仍只作用于真实存在的端点） |
| `task_suggestions` | `404`：该账号下上游无此端点 |
| `POST /f/conversation` | 唯一一次尝试被上游以 JSON `{"detail":…}` + `403` 拒绝：未创建任何会话，未重试、未改写请求形状 |

两点必须知道：

1. **直连存在间歇性发送阶段失败**：表现为网关自己的 `502 {"message":"上游请求失败"}`
   （无上游响应头、无 `cf-mitigated`、非 HTML），不同路径在不同运行间随机出现。
   网关客户端刻意关闭了自动重放（生成类绝不可重放），因此这类抖动会如实变成 502，
   不会变成「看起来成功」。缓解手段是配置 `CF_BYPASS_URL` 或走代理出口（缺口 5）。
   本机 `127.0.0.1:18001` 的 cfbypass 探针运行期间未启动，故 CF 刷新/重放分支未在真实上游触发。
2. **真实写入未取得证据**：创建会话的请求体形状在逆向材料里只有路由模板，没有实测样本；
   上游 403 之后按既定边界停止（不猜第二个端点、不做第二次真实写入、不重放生成类请求）。
   探针的创建请求是合成的：它只带 `accept`/`content-type`，`extra_cookies` 为空且无 CF 缓存，
   因此上游看到的是一个**没有 Cookie 头**的写请求；而网关的 chat 路径会转发浏览器自己的
   端到端请求头，生产路径下 Django 也会把账号 `extra_cookies` 一起下发。所以这条 403 证明的是
   「合成请求被拒」，不等于镜像写路径不可用；要取得真实写证据，需要前端真实请求的观测样本
   （DevTools 复制为 cURL / HAR）来对齐请求头与 Cookie。
   代码里的自动登记逻辑因此仍只在合成回环上验证过。
   该 403 本身说明这次尝试没有创建会话，无需清理；但「列表为 0 条」不是「账号为空」的证据——
   未登记资源经 ACL 过滤后一律呈现为空信封，这正是缺口 3 的预期行为。

探针证据只落状态码、内容类型、正文长度与 sha256、字段名、集合条数、本候选自己的错误码与
文案；令牌、Cookie、镜像会话 token、上游正文与标题一律不落盘。

## 残项收敛与管理员会话认领（2026-09-24）

本轮从缺口 3 的残项清单里挑出「有真实观测证据」或「运营上必须有人做」的两项落地，
其余显式判定为不做，不再作为待办悬挂。

### 真实前端请求新增的账号级前缀

真实页面的四份请求清单（`artifacts/phase1/probe/evidence/accept-*.json`，485 个不同请求键）
里，每个已登录页面固定请求 4 次 `GET /backend-api/checkout_pricing_config/configs/US`。
该路径**不在** 2026-09-23 冻结的 923 条路由快照里（属快照之后新增），按 `acl_unclassified_route`
返回 503。它不是对话路径，与六类可归属资源无关，因此按账号级前缀登记进 `acl.rs` 的 `UNOWNED`，
并由库内单测直接断言该路径判为账号级（它不会被快照用例覆盖，因为快照里没有它）。

### 未登记会话的发现与认领

同一上游账号下的旧会话（迁移前创建、或直接在上游站点创建）在 ACL 下不可见，此前唯一的恢复
途径是管理员手工构造 `/api/acl/claim` 请求。本批把这条运营路径接通：

| 层 | 契约 |
|---|---|
| 网关 | `GET /api/acl/unclaimed-conversations?account_id=<十进制账号 id>&page=<0..20>`：读号池账号凭据（AccessToken 优先，只有 SessionToken 时按登录同一条链路换取一次），带上号池 `extra_cookies`、合成的 `__Secure-next-auth.session-token`、与 `oai-did` 同值的 `oai-device-id` 头以及 CF 白名单请求上游 `GET /backend-api/conversations?offset=page*50&limit=50`，与 `acl_resources` 做差集后只返回**未登记**条目：`{"account_id","page","page_size":50,"upstream_total","has_more","items":[{"upstream_id","title","update_time"}]}` |
| 网关错误 | CF 拦截 `502 upstream_blocked`；两极凭据都不可用 `502 acl_account_credentials_invalid`；上游其它失败 `502 acl_upstream_unavailable`；账号不存在 `404 acl_not_found`；页码越界/账号 id 非数字 `400 acl_invalid_input`；非管理员 `403 acl_admin_required` |
| Django | `GET /0x/user/<user_id>/unassigned-conversations`（账号下拉限定该用户的可用账号，缺省取首个；无可用账号时直接返回空态且不请求网关）与 `POST /0x/user/<user_id>/claim-conversation`（`owner_user_id` 固定为路径上的 user_id，不接受请求体自报归属） |
| 凭据携带 | 服务密钥改走 `x-gateway-secret`，`authorization` 留给 Django 签发的 `gateway_authorization(request)`，另带 `subject`；服务密钥本身仍不代表管理员，网关一律以固定 Django 源的 fresh 响应判定 `is_admin` |
| 管理界面 | 「用户」页的对话统计弹窗内新增「未登记会话」区块：账号选择、刷新、逐条分配（二次确认）、分页与两种空态 |

认领沿用既有 `POST /api/acl/claim`：已登记资源返回 `409 acl_already_registered`，**不覆盖**他人归属；
每次认领仍写 `acl_audit`。清单本身只读上游，不改任何归属。

上游信封缺 `items` 或 `total` 时按 `502 acl_upstream_unavailable` 上报，不回退成空清单、
也不伪造页数：那会让管理员把「上游改了形状」误读成「没有未登记会话」。真实上游对空账号
返回的也是 `total: 0`（见「真实上游探针」），因此这两个键属于既有契约。

清单会展示上游会话标题。`allow_admin_view_conversation_titles` 约束的是**已登记**会话的统计视图；
未登记会话没有归属用户，而管理员手里本来就持有该上游账号，判断一条会话该分给谁必须看标题，
因此这里不额外加标题开关，作为有意决定记录在此。

### 明确不做（保留登记，不再作为待办反复评估）

- **缺口 5 整组**：wreq/curl-impersonate 指纹传输、代理节点分流、`CF_BYPASS_PROXY_SERVER`、
  `TRUSTED_PROXY_IPS`、`MIRROR_API_PREFIX`、`ADMIN_UPSTREAM`。产品形态是单机直连 AWS 出口的
  内部共享账号，`egress.rs` 现有的 fail-closed 已覆盖真实部署形态，补齐既没有可观测验收目标，
  也会把未验证组合放进来。
- **`/external/*` 主机白名单**：2026-09-28 改为「只允许公网目标」的公网策略落地（原白名单内容
  仍未还原，也不再尝试还原；见下方「前端自愈」），不再作为待办。
- **语音 `/api/livekit/`、`/realtime` 升级桥接**：小团体共享账号不使用语音通话。
- **estuary 内容 URL 绝对化、连接器创建自动登记、分支维度归属**：逆向材料只有符号名，没有协议证据。
- **访客策略**：访客不参与 ACL 是既有产品决定。
- **观测类差异**：初次登录不调 `accounts/check`、管理非空库自增 ID 偏移、`login extra_cookies`
  严格提取契约、`gateway_sessions.device_cookie` 遗留列、`oai-allow-ne…` 未定名比较。
- **All-in-One 打包与第六阶段交付**：需要时另行开工。
- **模型隔离与 `/api/account-models`、`/api/account-capabilities`**：产品决定「上游有什么模型就
  显示什么」，这两个端点不实现；Django 管理端对应的两个页面维持报错现状。

### 本批验证

`cargo test --locked --offline` 71 项库内单测 + 130 项集成用例全过（本批新增
`tests/acl_product_wiring.rs` 3 项：清单差集与挑战重放一次、SessionToken 换取与合成会话 Cookie、
管理端鉴权与输入边界；新增 `tests/ws_bridge.rs` 1 项：只有 SessionToken 的会话在 WS 握手时
合成会话 Cookie 并持有换取得来的 AccessToken）。`cargo clippy --locked --offline --all-targets -- -D warnings` 通过。Django `DJANGO_ENV=LOCAL manage.py test` 107 项通过（新增 6 项：非管理员 403、
服务密钥与操作者身份分头携带、无账号池空态、认领固定路径 user_id 并透出 audit_id、池外账号 400、
网关拒绝的 code 与文案原样透出）。
全部为合成回环 fixture：清单端点对真实上游的读取未在本轮执行（需要真实账号时另行批准）。
前端仓库没有 `node_modules`，`user.vue` 的改动只做源码回读与 diff 检查，未做构建验证。

## 上游 cookie 捕获与恢复（2026-09-24，静态实施 + 真实上游只读验证）

共享账号下所有镜像会话必须呈现同一套上游 cookie 身份。原版有完整 jar，候选此前只补
`cf_clearance`：本批按逆向证据把它补齐（`server/upstream_cookies.rs`），与「凭据换取路径的
Cloudflare 加固」属同一类补强（原版有、候选原先没有）。

| 项 | 原版（逆向证据） | 本候选 |
|---|---|---|
| 数据结构 | `db::SupplementalCookie` 9 字段（serde 名表 0xD914DD 起）：`domain`/`host_only`/`secure`/`http_only`/`expires`/`source`/`name`/`value`/`path` | 相同字段与序列化名（`upstream_cookies::Cookie` 的 `to_json`/`from_json`） |
| 抓取范围 | 只排除两张名字表：`is_mirror_local`(0x248780) 与 `is_browser_preference_cookie_name`(0x1872F0) | 相同（`MIRROR_LOCAL_NAMES` 10 项 / `BROWSER_PREFERENCE_NAMES` 7 项，含 `__Secure-next-auth.session-token`）；比较大小写不敏感 |
| 作用域 | `applies_to_url`(0x248E40) 按域（host_only 精确 / 否则后缀）+ 安全位 + 路径判定，`is_current_at`(0x2488E0) 判过期 | 相同（`Cookie::applies_to_url`；路径匹配与缺省路径按 RFC6265 §5.1.4） |
| 来源标记 | `source` 字段（`browser` 等）；设备 cookie 按 `name == "oai-did"` + `source == browser` 筛（`server_oai_device_cookie` 0x187E40 闭包 0x188230） | 相同语义：浏览器播种记 `browser`，上游响应记 `upstream`，Django 原文记 `session`；只有前两类回写落库 |
| 捕获 | `capture_upstream_cookies`（闭包 0x18C4C0），失败日志「保存上游 Cookie 失败」 | 每个带凭据上游响应的 `set-cookie` 条目录入 jar（含 `Max-Age`/`Expires` 与 `Max-Age<=0` 删除指令）；失败只记同名日志，不判定凭据失效 |
| 双存储 | 账号池行 `chatgpt_accounts.extra_cookies` + 会话行 `gateway_sessions.extra_cookies`；`clear_stored_cloudflare_cookies`(0x24EEC0) 同时清两张表 | 账号级写号池行（逐条目就地更新、保留行内未知字段），会话级写**新列** `gateway_sessions.upstream_cookies`（加密） |
| 恢复 | `restore_account_device_cookie_if_needed`（闭包 0x18BFF0/0x18C0A0）「if needed」：会话缺值才从号池补 | 相同优先级：会话凭据 → 会话列 → 号池行；后两级只补缺口（`fill_gaps`），同名以先到者为准 |
| CF 冲突 | `clear_stored_cloudflare_cookies`(0x24EEC0) 定向清除陈旧 CF cookie，避免与 jar 同名冲突 | 相同：CF 刷新成功后 `forget_cloudflare` 清掉 jar 里的 `cf_clearance`/`__cf_bm`/`__cflb`/`_cfuvid` 并落库——jar 排在 CF 缓存之前，留着旧值会让重放继续被判挑战 |
| 浏览器来源 | `browser_oai_device_id`(0x187D30) 读 13 字节头名 `oai-device-id`（字面量字节偏移 0xD64C07/0xD64C88）；2026-09-23 匿名链路实测浏览器确实发送该头（`evidence/anonymous-nextauth-001/mirror-run-007`） | 相同：先 `oai-device-id` 头，头缺失时看 Cookie 头里的 `oai-did`；jar 里已有 `oai-did` 时不覆盖（由首个请求定型） |
| 上游请求 | `build_upstream_auth_cookie_header`(0x186100) 拼 Cookie 头（`oai-device-id` 字面量在其 +0x12D，函数内 0x186207 处取设备标识）；WS 桥显式写 `oai-device-id` 头（错误串 `写入 WebSocket oai-device-id 失败`，0xD64C77 邻区） | Cookie 顺序 = 会话凭据 → jar 作用域内条目 → CF 缓存（同名取先）；`oai-device-id` 头与 jar 里的 `oai-did` 同值；WS 握手同规则 |
| 落点 | 设备值并入 `gateway_sessions.extra_cookies` | **有意偏离**：`rust_credential_binding` 绑定 `extra_cookies` 原文，改写会让会话立刻失效，故 jar 单独存加密列；号池一侧只改写实测捕获条目，Django 管理的既有条目原样保留 |
| 号池行不存在 | 未确证 | 只写会话列，不凭一次业务响应创建账号池记录 |

备份与迁移：`gateway_sessions.upstream_cookies`（加密列）随 v3 备份一起导出/恢复；本轮之前导出
的 v3 备份缺该字段时按 NULL 恢复（其余列仍严格要求），恢复后由上游响应或浏览器请求重新捕获。
存量库由 `ensure_legacy_columns` 的 `ALTER TABLE … ADD COLUMN upstream_cookies TEXT` 补列；
上一版候选写过的 `device_cookie` 列（单个裸设备值）留在库里不再读写，设备身份由号池行或浏览器
请求在下一个请求内重建，不做一次性搬运。

跨组件契约：号池行 `extra_cookies` 是 Django 的 `EncryptedJSONField`，候选回写的是 9 字段条目；
Django 侧只读 `name`/`value`（`chatgpt/models.py`），多余字段被忽略，不影响登录态或账号页。

验证状态（2026-09-24，用户批准后执行）：`cargo test --locked --offline` **193 项全过**
（71 项库内单测 + 122 项集成用例；本批 8 项库内单测、`tests/device_cookie.rs` 5 项、
`tests/upstream_cookie_jar.rs` 4 项），`cargo clippy --locked --offline --all-targets -- -D warnings`
通过。

`tests/device_cookie.rs` 覆盖：浏览器 `oai-device-id` 播种后请求头与 Cookie 同值、且后续请求
不再依赖该头即复用会话值（并断言落库为 `enc:v1:` 密文且不含明文设备值）；上游
`set-cookie: oai-did=…` 捕获后下一请求即带上（fixture 上游是明文 http，真实形态带 `Secure`，
故回注体现在 `oai-device-id` 头，Cookie 侧按 RFC6265 正确地不发）；号池行恢复对 alice/bob 两个
镜像用户给出同一设备标识；上游轮换设备标识后覆盖号池，另一镜像用户随即跟上新值；生成路径
（创建会话）同样捕获。`tests/upstream_cookie_jar.rs` 覆盖：名字表
（`oai-did`/`oai-sc`/`__oailb`/`__cf_bm`/`__cflb`/`_cfuvid`）整组捕获并回注，镜像自有与浏览器
偏好名字既不落库也不回注；回注侧的域（host_only / 后缀）、安全位、路径与 `Max-Age=0` 删除指令
过滤，且捕获与回注分离（作用域外条目照样留库）；号池行与两个镜像用户共享账号级条目、会话凭据
不写进号池也不串用、行内未知字段保留、无捕获时不凭空写会话列；CF 刷新后重放只带新
`cf_clearance` 且旧条目已从落库 jar 清掉。库内单测覆盖两张排除表、作用域与路径匹配、
`Set-Cookie` 属性解析（`Max-Age` 优先于 `Expires` 与 HTTP 日期）、upsert 与删除指令、同名取先、
设备值白名单、9 字段 JSON 往返与历史 name/value 行缺省。另有 `backup_contract` 断言旧 v3 信封
（行内无 `upstream_cookies`）按 NULL 恢复。

强制防御性审查已执行（`$peropero-defensive-programming-review`）：删掉 `capturable()` 里由各
构造点已保证的空名判断，并把「空域」从提前返回改为只豁免域判定（安全位与路径照旧生效，避免
历史行绕过路径过滤）；保留的校验都对应可达边界（外部头 / Cookie 输入、号池列非 JSON 数组、
旧备份缺列、上游 `set-cookie` 透传）。本轮未改动 Django，因此未重跑 Django 测试。

### 真实上游验证（2026-09-24，用户批准真实写入后执行）

探针 `artifacts/phase1/probe/probe_device_cookie.py`（文件库 + `set-cookie` 名字 + 每个上游
请求之间随机停 8–12 秒），四个原始 JSON 与说明见
[`evidence/device-cookie-real-001/`](../../evidence/device-cookie-real-001/SUMMARY.md)。

| 结论 | 证据 |
|---|---|
| 逆向还原的 cookie 名正确：真实上游确实下发 `oai-did` | `GET /` 与 `GET /sentinel/20260423af3c/sdk.js` 的 `set-cookie` 名字里出现 `oai-did`（页面另含 `__Host-next-auth.csrf-token`/`__Secure-next-auth.callback-url`） |
| 设备 cookie 出现在页面/SDK 路径，而非已登录 API 路径 | `GET /backend-api/me`、`sentinel/frame.html` 只有 `__oailb`/`__cf_bm`/`__cflb`/`_cfuvid`；`chat-requirements/prepare` 另发 `oai-sc` |
| 捕获链路对真实上游成立 | 不发送任何浏览器设备标识时，会话设备列在 `sdk.js`（带 `oai-did`）响应之后由 0 变 1；`capture-first` 轮次在 `GET /` 之后同样由 0 变 1 |
| 浏览器播种链路成立 | 不发送设备头时为 0，发送 `oai-device-id` 的下一跳之后为 1 |
| 设备 cookie 不是写路径的阻塞点 | 三次真实新建尝试（含一次携带上游自己下发的 `oai-did`）全部返回 **JSON 403**（无 `cf-mitigated`、非 HTML、`conversation_id_found=false`），均未创建会话，账号无残留 |

写路径仍被上游拒绝的剩余原因指向浏览器侧材料（`chat-requirements` 的 sentinel/PoW 令牌与
前端自身请求头），合成客户端不产生这些材料；验证它需要真实浏览器驱动流程，已登记为残项。
真实上游另外下发的 `__oailb`/`__cf_bm`/`__cflb`/`_cfuvid`/`oai-sc` 已随本批整组纳入捕获与
回注，`oai-did` 只是其中一项。

## 证据

## 会话 Cookie 合成与浏览器端到端验收（2026-09-24，真实上游实测）

浏览器驱动验收发现：账号用 SessionToken（`login_mode = web`）登录时，候选不给上游带
会话 Cookie，前端因此拿到上游的未登录页面、整体退回匿名通道。本批按原版补齐。

| 项 | 原版（逆向证据） | 本候选 |
|---|---|---|
| 会话 Cookie 来源 | `append_session_cookies`、`supplemental_has_next_auth_cookie`、`build_upstream_auth_cookie_header`、`cookie_value`、`rebuild_split_cookie_value`（符号各 1 处）；cookie 名字面量 `__Secure-next-auth.session-token` 5 处、`next-auth.session-token` 8 处、`__Secure-` 7 处、`__Host-` 1 处 | Django 把 SessionToken 作为独立字段下发（`backend/app/chatgpt/views/chatgpt.py` 的 payload），候选把它合成为 `__Secure-next-auth.session-token` 再发上游（`proxy::session_cookie_group`） |
| 已有同名 Cookie | `supplemental_has_next_auth_cookie` 判定「补充 cookie 里已经有就跳过」 | 相同：本次请求确实会发出同名 Cookie（会话 `extra_cookies` 或 jar）时不再合成，管理员导入的会话态优先 |
| Cookie 顺序 | 会话 cookies → 其余 → CF | 会话 `extra_cookies` → 合成的会话 Cookie → jar 作用域内条目 → CF 缓存（同名取先） |
| 落库 | 会话 Cookie 并入 `gateway_sessions.extra_cookies` | **有意偏离**：不落库。它是账号凭据，落在会话列会随 v3 备份一起搬走；jar 的两张排除表本就把 `next-auth.session-token` 系列为镜像自有名字 |
| 号池行 | 未确证 | 不写号池行，不凭一次请求创建账号池记录 |

**凭据绑定变更（会影响存量会话）**：`rust_credential_binding` 原本只覆盖
`[account, access_token, extra_cookies]`；会话 Cookie 现在参与上游请求字节，因此一并纳入
绑定（`proxy::credential_binding`，四处调用点：登录、`session()` 解析、`refresh_auth_session`、
`load_credentials`，外加 `management::mirror_token` 批量签发）。后果：**本批之前建立的全部
镜像会话立即失效并需要重新登录**，而不是继续发出过期会话 Cookie。`None` 与空串归一为同一
输入，因为号池行的 `session_token` 允许是空串（Django 字段 `blank=True`）。尚未部署过候选，
因此没有存量会话需要迁移。

### 浏览器驱动验收（`artifacts/phase1/probe/probe_browser_create.py`）

真实 Chromium（系统 Python 的 Playwright 1.62 + chromium-1234）经候选网关加载真实
chatgpt.com 页面；`:memory:` 库、无常驻改动、令牌与 Cookie 不落证据。

| 轮次 | 结果 |
|---|---|
| 修复前（AccessToken 登录） | 页面 200、输入框出现，但前端走**匿名通道**：`/backend-anon/me`、`/backend-anon/conversation/init`、`/backend-anon/sentinel/chat-requirements/{prepare,finalize}` 全 200，`/backend-api/` 请求为 0 |
| 修复后（SessionToken 登录，只读） | 走**登录通道**：`/backend-api/me`、`/backend-api/accounts/check/…`、`/backend-api/conversations` 200，sentinel `prepare` → `finalize` → `/f/conversation/prepare` 200；首屏 HTML 含 `accessToken`；`/backend-anon/` 请求为 0 |
| 修复后（真实写入） | `POST /backend-api/f/conversation` **200 `text/event-stream`**，会话创建成功；随后 `stream_status`/`textdocs`/`conversations` 读取 200；删除经网关返回 **200** `{"success":…}`，账号无残留 |

删除经网关返回 200 同时证明**创建路径的 ACL 归属登记生效**：未登记会话在作用域路径上会被
网关判 404 且不接触上游。合成回环只能证明「没有丢掉浏览器的材料」，本表是唯一一次
真实浏览器端到端证据。

两个附带结论：

1. **页面加载不需要 cfbypass**：真实浏览器自带 `sec-ch-ua*` 客户端提示头，`GET /` 直接 200
   （507KB 真实页面，700 条子请求里 `/cdn/assets/*` 全部 200）。合成 `curl`/Python 客户端
   缺这些头时会拿到 `403 + cf-mitigated: challenge`，此前的「需要 cfbypass」结论只对合成
   客户端成立。网关自身请求之所以不被挑战，靠的是 jar 里捕获到的 `__cf_bm`/`_cfuvid` 回注。
2. **前端 sentinel 流程与分块取证一致**：`prepare` → `finalize` → `f/conversation/prepare` →
   `f/conversation` 的顺序与头族逐条吻合，候选无需实现 sentinel。

### 端到端验收的第二轮（`artifacts/phase1/probe/probe_browser_accept.py`）

第一轮只覆盖「新建 + 删除」。第二轮补齐流式渲染、停止生成、重命名、历史加载、真实 WS 与
跨用户隔离，全部在真实上游完成，会话用完即删。

| 验收项 | 证据 |
|---|---|
| 流式回复渲染 | `POST /backend-api/f/conversation` 200 `text/event-stream`（12351 B）；页面上助手气泡渲染完成，正文 8 字符、sha256 `86d90d7c…`、含预期串；`is_streaming_settled=true` |
| 停止生成 | 流式中出现停止按钮，点击后按钮消失（`stop_button_found=true`、`present_after_click=false`） |
| 重命名 | `POST /backend-api/conversation/id/{id}/rename` 200（经网关的作用域 Modify 判权） |
| 历史加载 | 重载后页面自行导航到 `/c/<id>`；经网关 `GET /backend-api/conversations?offset=0&limit=50` 返回 200，信封 `items/limit/offset/total`，可见 1 条 |
| 删除 | `DELETE /backend-api/conversation/id/{id}` 经网关 200；随后直连上游列表 `total=0`，账号无残留 |
| 跨用户隔离 | 同账号第二个镜像用户（`probe-bob`）`GET /backend-api/conversation/{id}` → **404 `acl_not_found`**，拒绝发生在接触上游之前 |
| 真实 WS 上游 | 页面经改写打开 `ws://<gateway>/ws-chatgpt/p4/ws/user/<id>?verify=…`，桥接到 `wss://ws.chatgpt.com`：**发送 1 帧 298 B、收到 1 帧 371 B、连接未关闭**，网关日志无 WS 错误 |

第一轮曾观察到「重载后列表 0 条」，第二轮用 Python 侧对比（经网关 vs 直连上游）证明那是
页面导航竞态下的读取假象：两边同为 1 条且都含目标 id，ACL 集合过滤没有丢条目。探针已改为
Python 侧确定性读取，页面内检查降级为旁证。

**验收方式的一个修正**：第一轮首次跑完删除返回 401，原因是登录交接会轮换 mirror_token，
而删除用的是交接前的值；探针改为从浏览器 cookie 取交接后的 token。另有一次因页面内
`fetch` 抛异常导致删除步骤被跳过，账号里留下 1 条会话（已用直连上游清理，`total=0` 复核）；
探针随后把删除移到异常路径之外，任何一步失败都会执行清理。

验证状态：`cargo test --locked --offline` **197 项全过**（71 库内 + 126 集成；
`tests/upstream_cookie_jar.rs` 由 4 项增至 8 项），
`cargo clippy --locked --offline --all-targets -- -D warnings` 通过。

强制防御性审查已执行：`session_cookie_group` 的「已有同名就不合成」不是多余防御
（管理面导入会话态是真实数据形状，已有单测锁定），`credential_binding` 的
`None`/空串归一有明确来源（号池行 `blank=True`），四处绑定调用点收敛到一个函数
正是为了不出现两处公式漂移；未发现需要删除的多余防御。

## 原版的上游 cookie 模型（2026-09-24 二进制复核）

原版不是「只补 `cf_clearance`」，而是一套**完整的账号级 cookie jar**。本节的偏移均为文件
**字节**偏移（早期草稿里引用的 0xD42553/0xD3E785 等是 UTF-8 字符下标，已在上文更正）。

1. **数据结构** `db::SupplementalCookie`：serde 字段名表（0xD914DD 起）逐字为
   `domain`、`host_only`、`secure`、`http_only`、`expires`、`source`、`name`、`value`、`path`；
   行为方法 `is_mirror_local`(0x248780)、`is_current_at`(0x2488E0)、`scope_identity`(0x248920)、
   `applies_to_url`(0x248E40)。即原版按域/路径/安全位/过期时间做作用域判定，而不是只比名字。
2. **两处存储**：账号池行 `chatgpt_accounts.extra_cookies`（账号级，同账号的镜像用户共享）与
   会话行 `gateway_sessions.extra_cookies`（按 `mirror_token` 绑定）。证据：`clear_stored_cloudflare_cookies`
   (0x24EEC0) 同时引用两张表与**动态表名** SQL `SELECT id, extra_cookies FROM ` /
   `UPDATE  SET extra_cookies = ?1 WHERE id = ?2`（0xD8DBF9 邻区）；`update_gateway_session_extra_cookies`
   (0x256D50) 为 `UPDATE gateway_sessions SET extra_cookies = ?2, … WHERE mirror_token = ?1`。
3. **抓取只排除两类**：
   - `is_mirror_local`(0x248780) 排除镜像自有 cookie：`mirror_api_session`(0xD54150)、
     `login_mode`/`model_limits`/`next-auth.session-token`(0xD8C8BA 邻区)、`chatgpt_username`(0xD85FC0)、
     `isolated_session`(0xD85FB0)、`trusted_cdn_sources`、`gateway_user_name`(0xD8BEB0)。
   - `is_browser_preference_cookie_name`(0x1872F0) 排除浏览器偏好：`oai-mweb-route-desktop`/
     `oai-mweb-route-dl-config`(0xD548F0)、`oai-default-mode_personalization`(0xD54910)、
     `oai_consent_personalization`、`oai_consent_analytics`、`oai_consent_marketing`(0xD54930–0xD54980)、
     `oai-last-model-config`(0xD54990)；另有 1 条 12 字节内联比较（解出 `oai-allow-ne…`，未定名）。
   ⇒ `oai-did`、`oai-sc`、`__oailb`、`__cf_bm`、`__cflb`、`_cfuvid` **都不在排除名单里**，
   原版会把它们整组写进 jar；真实上游下发这些名字的观测见
   [`evidence/device-cookie-real-001/`](../../evidence/device-cookie-real-001/SUMMARY.md)。
4. **注入**：`build_upstream_auth_cookie_header`(0x186100, size 0x11EE) 组装 Cookie 头
   （`oai-device-id` 字面量在其 +0x12D，函数内 0x186207 处调用取设备标识）；
   `applies_to_url`(0x248E40) 按域/路径/安全位/过期过滤（含对 `next-auth.session-token` 系的专门分支）；
   `cookies_to_header`(0x188AE0)、`merge_cookie_headers`(0x185CB0)、`same_cookie_scope`(0x173690)、
   `cookie_value`(0x185560) 负责合并多份 Cookie 头与同名去重。
5. **cfbypass 是另一条通道**：`persist_cfbypass_cookies_for_request`、
   `merge_extra_cookies_with_cfbypass`(0x1EB570)、`supplemental_has_cloudflare_cookie`(0x1EEEA0)、
   `is_safe_cfbypass_cookie_name`(0x187CB0，白名单 `cf_clearance`/`__cf_bm`/`__cflb`/`_cfuvid`，
   字面量在 0xD692A1 邻区)、`normalize_cfbypass_cookies`(0x187B60)、
   `clear_stored_cloudflare_cookies`(0x24EEC0) 定向清除陈旧 CF cookie，避免与 jar 里的同名 cookie 冲突。
6. **设备 cookie**：`browser_oai_device_id`(0x187D30) 读浏览器头 →
   `server_oai_device_id`(0x188600) 供拼头 → `server_oai_device_cookie`(0x187E40，闭包 0x188230)
   在 jar 内按 `name == "oai-did"` 与 `source` 字段（7 字节立即数 `browser`）筛选 →
   `restore_account_device_cookie_if_needed` 在会话缺值时从账号池行补。

本节即是本批（「完整上游 cookie 捕获与恢复」）的实施依据：9 字段 jar、两张排除表、域/路径/
安全位/过期判定、双存储与 CF 冲突清理都落在 `server/upstream_cookies.rs`。与上表的已知差异有
三条，均已登记 NEXT_WORK：`oai-allow-ne…`（12 字节内联立即数，未还原完整名字）未纳入排除表；
名称比较按大小写不敏感（更保守），原版常量比较是否如此未确证；登录前的凭据换取/诊断链不走
会话通道，因此不播种也不捕获，账号级一致性可能晚一步。

- evidence/delivery-v3-runs.json：每个进程实际退出状态，比较有差异时 exit 1。
- 备份首轮端口占用失败保留在 delivery；调整监听端口后的最终三方证据为 backup-v3-original-014、backup-v3-{candidate,rollback}-delivery-2 及对应 compare-command。
- evidence/*-v3-{candidate,rollback}-delivery{-diff,-audit}.json：最终比较及差异原值。
- evidence/*-delivery/command.json、serial.log、results.json：执行、原始输出和数据库/上游记录。
- artifacts/VERIFICATION.txt：原版/候选/回滚 literal 命令与输出、退出、哈希。
- evidence/verification-before-v3.txt：上一轮 ledger 原样保留。

## 传输身份统一（缺口 5 第一批：Chrome146 指纹栈，2026-09-24）

原版与上游之间只有一种浏览器身份：TLS/HTTP2 走 `libcurl-impersonate` 的
`chrome146`（`LD_PRELOAD` + `CURL_IMPERSONATE`，见反编译报告 03 §5），请求头走
`apply_chrome_146_network_identity`。候选此前用 `reqwest` + rustls，只补 3 个头，
「UA 说 Chrome146」与「TLS 说 rustls」互相矛盾。本批把整条出网链路统一到同一个
固定身份：传输层换 `wreq`（btls/BoringSSL）+ `wreq-util` 的 `Profile::Chrome146`，
请求头由 `server/identity.rs` 一处给出。

### 传输层

| 项 | 取值 |
|---|---|
| 画像 | `Emulation::builder().profile(Profile::Chrome146).platform(Platform::Linux).build()` |
| 画像预设头 | **关闭**（`.headers(false)`）。预设是导航形状（`sec-fetch-dest: document`、`accept: text/html,…`、`priority: u=0, i`），且 wreq 只在「缺省」时注入；浏览器没给值时发这些等于发错值 |
| 覆盖语义 | **先删除全部 `sec-ch-ua-*`，再整组强制覆盖**（有意偏离原版的「缺失才补」）：未知新提示不透传，已知提示一律替换，否则 Windows 用户或新 Chrome hint 会与 Linux UA 混在一起 |
| 环回服务 | Django / cfbypass 走 http，不受画像影响 |
| 代理边界 | 当前 `wreq` 对 HTTPS-over-proxy 会关闭 ALPN；`https` chat 上游或 `wss` WS 上游启用代理时直接拒绝，不能发出可区分的降级指纹 |

### 身份整组（`identity::IDENTITY_HEADERS`）

| 头 | 值 |
|---|---|
| `user-agent` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36` |
| `sec-ch-ua` | `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"` |
| `sec-ch-ua-mobile` | `?0` |
| `sec-ch-ua-platform` | `"Linux"` |
| `sec-ch-ua-platform-version` | `""` |
| `sec-ch-ua-arch` / `sec-ch-ua-bitness` | `"x86"` / `"64"` |
| `sec-ch-ua-model` | `""` |
| `sec-ch-ua-full-version` | `"146.0.7680.177"` |
| `sec-ch-ua-full-version-list` | `"Chromium";v="146.0.7680.177", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.177"` |

`UA` 与低熵三项与 `wreq-util` 的 Chrome146/Linux 预设逐字一致（库内单测直接拿预设对照，
画像升级而没人改表就会红）。高熵三项的**主版本**与预设绑定，完整版本号沿用原版二进制
字面量与镜像内 chromium 包版本。

`sec-ch-ua-platform-version: ""` 不是随手填的默认值：Chrome 146 在 Linux 上默认启用
`ReduceUserAgentDataLinuxPlatformVersion`，`GetPlatformVersion()` 因此返回空串，头仍照发
（值为 `""`）；这条由源码核对闭合，证据与文件哈希见
`evidence/reference-chrome146-001/04-linux-platform-version.json`。Windows 上同一头是
`"15.0.0"`，所以这张表只在「声称 Linux」时成立。

公共 CDN/静态资源与内部媒体代理同样使用这张身份表；仍然只复制既有白名单中的资源
请求头，且不带浏览器、账号或 CF 凭据。页面注入脚本在 `<head>` 开标签后执行，并把
`navigator.userAgent/platform/userAgentData/languages`、时区与 `window.chrome` 固定为
同一个 Chrome146/Linux 表面，避免前端把宿主 Windows 身份写入请求体或自定义头。

### 网关自发请求的头基线（`identity::api_baseline`）

取值来自 2026-09-24 真 Chromium 同源 XHR 的服务端实录
（`probe/probe_browser_headers.py`）：`accept: application/json, text/plain, */*`、
`accept-language: zh-CN,zh;q=0.9,en;q=0.8`、`accept-encoding: gzip, deflate, br, zstd`、
`sec-fetch-dest: empty` / `sec-fetch-mode: cors` / `sec-fetch-site: same-origin`、
`oai-language`、`referer`、非 GET 才补 `origin`。**不合成** `priority` 与
`oai-client-version`/`-build-number`/`oai-session-id`/`x-openai-web-frontend`：前者在同源 XHR
实录里不出现，后者是页面自己算的前端状态，宁可不发也不发错值。响应体在 JSON 解析前按
`compression::decode_buffered` 解码（只有这条路径解码，代理路径保持字节透传）。

### 传输指纹对照（真 Chromium vs 候选）

采集：`probe/probe_tls_identity.py`（Playwright 直连本机回环，监听端不完成握手，归一化
去掉 random、会话 id、GREASE 值与扩展顺序）；候选侧由
[`tests/identity_fingerprint.rs`](../source/tests/identity_fingerprint.rs) 以同样规则抓自己的
ClientHello 并锁 sha256。对照原文见
[`evidence/tls-identity-reference.json`](../../evidence/tls-identity-reference.json)。

| 字段 | 真 Chromium 151.0.7922.34 | 候选（声称 Chrome146/Linux） | 结论 |
|---|---|---|---|
| `legacy_version` / 会话 id | `0303` / 32 字节 | 同 | 一致 |
| 密码套件（去 GREASE） | 15 项（`1301/1302/1303`、`c02b/c02c/c02f/c030`、`cca8/cca9`…） | 同 | 一致 |
| 压缩方法 | `00` | 同 | 一致 |
| 扩展集合（去 GREASE） | 15 项（`0005/000a/000b/000d/0010/0012/0017/001b/0023/002b/002d/0033/44cd/fe0d/ff01`） | 同 | 一致 |
| ALPN | `h2, http/1.1` | 同 | 一致 |
| 支持组 / 密钥共享组 | `11ec,001d,0017,0018` / `11ec,001d` | 同 | 一致 |
| TLS1.3 与 GREASE | `0304` + 1 个 GREASE 套件 + 2 个 GREASE 扩展 | 同 | 一致 |
| `signature_algorithms` | 11 项（含 `0904/0905/0906` ML-DSA） | 8 项（无 ML-DSA） | **唯一实质差异**，版本类：对照浏览器是 151，候选按 146 画像 |
| SNI | IP 字面量不发；用 `localhost` 复采时为真 | IP 字面量不发 | 与输入同形，一致 |

H2 层（SETTINGS 顺序、伪头顺序）本轮未独立复采：两侧监听端都没有完成 TLS 握手，没有
产生 H2 首帧；该取值只来自 `wreq-util` 画像的 `http2_options`，登记为残余。

### 真 Chrome 对 chatgpt.com 的请求头（只读证据）

`probe_browser_accept.py`/`probe_browser_create.py` 的浏览器实录（浏览器经候选网关加载真实
chatgpt.com 页面）显示，上游文档响应声明 `Accept-CH` 之后，真 Chrome 对
`/backend-api/*` 的请求带**全量高熵 hints**（`sec-ch-ua-arch/bitness/full-version/
full-version-list/model/platform-version`，491 条请求里 488 条带 `sec-ch-ua-arch`），
且这些请求**没有** `priority` 头。结论：「整组强制覆盖」与真浏览器的实际形态一致，
而 `api_baseline` 不补 `priority` 也与实录一致。

对照组 `probe_browser_chatgpt_headers.py`（真 Chromium **直连** chatgpt.com）命中 Cloudflare
挑战页，只取到 challenge 自身请求：它带 `priority: u=1, i`、`sec-fetch-dest: script/empty`。
这说明 `priority` 取决于请求的优先级类别，不能一概而论；候选只在浏览器转发路径上原样
透传浏览器给的值，不自造。

### 有意差异与残余风险

| 项 | 说明 |
|---|---|
| `signature_algorithms` 缺 ML-DSA | **已收敛（第二轮）**：Chrome for Testing 146.0.7680.165 实测同样只有 8 项、不含 ML-DSA，与候选逐项一致；此前的差异纯属 151 vs 146 的版本差 |
| H2 首帧未复采 | **已收敛（第二轮）**：候选在本地自签 TLS 上完成握手抓到 H2 首帧，与 146 参照逐项一致（见下节） |
| `sec-ch-ua-platform-version` | **已闭合（2026-09-24，源码核对）**：Windows 参照实测 `"15.0.0"`；Linux 上 `ReduceUserAgentDataLinuxPlatformVersion` 默认启用 ⇒ `GetPlatformVersion()` 返回空串 ⇒ 照发 `""`（`evidence/reference-chrome146-001/04-linux-platform-version.json`）。候选锁 `""` 在声称 Linux 时成立 |
| HTTP/1.1 头顺序 | **已收敛（第二轮）**：改用 wreq `orig_headers` 按录制顺序输出，网络层/应用层逐项对照见下节 |
| cfbypass 一跳 | **已部分收敛（第二轮）**：镜像改为 Debian trixie + chromium 146.0.7680.177，响应新增实测 `identity`，网关比对不一致即 warn；代理与 headful 仍是残余 |
| 出口 IP | 部署在 AWS 机房（用户判定：chatgpt.com 对 AWS 段是白名单，本轮不处理） |
| WS 握手头子集 | **已收敛（第二轮）**：按真浏览器实录补齐 `pragma`/`cache-control`/`accept-encoding`，逐跳头与握手自有头不转发 |
| JS 覆盖的浏览器行为 | 注入脚本只覆盖与「网络层声称的平台/版本」直接冲突的可见值（UA/appVersion/platform/userAgentData）；语言、时区、字体、WebGL、Canvas、Worker 与子框架保持宿主真值 |

### 契约与影响

- 对外 HTTP 契约只有两处**新增字段**：`/api/refresh-cfbypass` 返回 `cfbypass_identity`；
  cfbypass 的 `/cloudflare5s/bypass-v1|v2`（与 `/bypass` 等价，原版即此契约）返回 `identity`。
  路由、状态码、错误码、Cookie 合成、ACL、CF 挑战策略都不动；**不新增网关环境变量**
  （cfbypass 侧新增 `CF_BYPASS_BROWSER_PATH`，有默认值）。
- `egress` 的 `transport_profile` 变为 `wreq-chrome146-read-v1-no-retry-no-redirect`，参与
  `binding` 哈希 ⇒ 部署后既有镜像会话按既有「凭据/出口变更即失效」规则 fail-closed（401），
  需要重新登录；尚未部署过候选，因此没有存量会话需要迁移。
- 数据库里代理节点的 `transport_mode` 取值仍是字符串 `reqwest`（存量配置的枚举值，代表
  「直连客户端」这一类），本批不改这个字段，避免动存量配置与绑定以外的语义。
- `wreq` 默认 feature 不含 `emulation-compression`，解压由网关按需做，代理路径保持字节透传。

## 跨层身份一致性（第二轮：JS 面、WS、cfbypass、146 参照，2026-09-24）

第一轮把**网关内部**（TLS 画像 + 请求头表）统一成 Chrome146/Linux，但审计发现跨层仍然矛盾：
页面 JS 暴露宿主真实平台、WS 握手是残缺子集、cfbypass 一跳用的是另一版 Chromium、参照浏览器
是 151 而非声称的 146。本轮逐项收敛，并把「自锁常量」升级为「与可运行的同版本参照逐字段对照」。

### 146 参照（`probe/probe_reference_identity.py` + `evidence/reference-chrome146-001/`）

参照浏览器：Chrome for Testing **146.0.7680.165** win64（VersionInfo 与 CDP `browser.version`
同值；二进制在临时目录，不入库）。三段采集都只打本机回环。

| 项 | 真 Chrome 146 | 候选 | 结论 |
|---|---|---|---|
| ClientHello 归一化 sha256 | `01425d3f…0343cb`（排序归一化口径，见参照的 `rust_normalized_sha256`） | 同值；运行时自锁的是**顺序敏感**口径 `01e7ace0…`（IP）/ `15d917f3…`（SNI） | **逐字段一致**（两个常量口径不同、不直接比较；套件原始顺序已单独核对相同） |
| 密码套件（原始顺序，去 GREASE） | `1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035` | 同（2026-09-28 复核 `candidate_client_hello_matches_chrome_shape` 的输出） | 一致 |
| 扩展集合 | 15 项（含 `44cd`/`fe0d`/`ff01`） | 同 | 一致 |
| 扩展顺序 | **逐连接重排** | 逐连接重排 | 一致（`permute_extensions` 行为由测试锁定） |
| `signature_algorithms` | 8 项（无 ML-DSA） | 同 | 一致（此前 151 对照里的 ML-DSA 差异确认为版本差） |
| 支持组 / 密钥共享 | `11ec,001d,0017,0018` / `11ec,001d` | 同 | 一致 |
| H2 SETTINGS | `0001=65536 → 0002=0 → 0004=6291456 → 0006=262144` | 同（**不含** `MAX_CONCURRENT_STREAMS`） | 一致 |
| H2 连接窗口增量 | `15663105` | 同 | 一致 |
| H2 伪头顺序 | `:method → :authority → :scheme → :path` | 同 | 一致 |
| 同源 XHR 头顺序 | 见 `03-request-headers.json` | `REQUEST_HEADER_ORDER` 逐项一致 | 一致 |
| `sec-ch-ua-platform-version` | `"15.0.0"`（Windows） | 候选声称 Linux，发 `""` | **已闭合（源码核对，非运行时）**：Linux 上该 feature 默认 `stable` ⇒ `GetPlatformVersion()` 返回空串 ⇒ 头值 `""`；证据 `04-linux-platform-version.json`（ref/commit/行号/sha256） |
| `sec-ch-ua` 品牌表 | `"Not-A.Brand";v="24", "Chromium";v="146"`（两项） | `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`（三项） | **构建差异**：CfT 是 Chromium 品牌构建，不含 `Google Chrome` 项；候选的品牌表与原版二进制实测字节逐字相同（`reverse/reports/06-sandbox-verification.md` §9.5 的代理链抓包），与自身「Google Chrome 146」的 UA 自洽 |

`tests/identity_fingerprint.rs` 因此有三层断言：自锁常量（顺序敏感 ClientHello ×2 场景
`01e7ace0…`/`15d917f3…` + H2 首帧 `7b3ac4b0…`）、**与 `evidence/reference-chrome146-001/`
的逐字段对照**（参照里存的 `rust_normalized_sha256 = 01425d3f…` 是排序归一化口径，与顺序
敏感的自锁常量口径不同、数值也不同；两边共同的比对口径是逐字段对照）、以及身份相关 crate
（`wreq`/`wreq-util`/`wreq-proto`/`btls`/`btls-sys`/`tokio-btls`/`http2`）的锁定版本。
`cargo update` 或画像误换都会让其中至少一层变红。

Linux 侧的 `sec-ch-ua-platform-version` 没有运行时复采（本机 WSL 无发行版、无 Docker），
改由源码核对闭合：`third_party/blink/renderer/platform/runtime_enabled_features.json5` 里
该开关在 Linux 是 `stable` ⇒ 生成 `FEATURE_ENABLED_BY_DEFAULT` ⇒ Linux 上
`GetPlatformVersion()` 直接返回空串 ⇒ `content/browser/client_hints/client_hints.cc` 把它
序列化成 `""` 并无条件发头（没有空值丢头分支）。结论与两个 ref 的文件摘要见
`evidence/reference-chrome146-001/04-linux-platform-version.json`。

### 页面 JS 可见面（#1）

页面脚本可以读 `navigator.*`、时区、语言，再把结果写进请求体或自定义头——网关无法过滤正文。
注入脚本现在**在第一个 `<head …>` 之后**（而不是 `</head>` 之前）执行，并把与网络层直接冲突的
可见值固定为同一身份：`navigator.userAgent`/`appVersion`/`platform`/`userAgentData`
（低熵 + `getHighEntropyValues` 的 architecture/bitness/fullVersion/fullVersionList/model/
platformVersion）。取值由服务端从 `identity::IDENTITY_HEADERS` 生成（占位符
`@@IDENTITY_JSON@@`），JS 侧不再有第二份字面量，两端不可能各自漂移。

**刻意不覆盖**：语言、时区、`window.chrome`、`navigator.webdriver`、字体、WebGL、Canvas、
Worker 与子框架。理由：这些值不直接矛盾（宿主语言/时区在 Linux 上也合理），而伪造
`webdriver`/`chrome` 反而更容易被反检测手段识别。

真上游只读验收（`probe_browser_accept.py --no-write`，2026-09-24）在页面内实测到：
`UA=Mozilla/5.0 (X11; Linux x86_64) … Chrome/146.0.0.0 Safari/537.36`、
`platform=Linux x86_64`、`brands=[Chromium/146, Not-A.Brand/24, Google Chrome/146]`、
`arch=x86`、`bitness=64`、`fullVersion=146.0.7680.177`、`platformVersion=''`、
`timezone=Asia/Shanghai`（宿主真值）。同一次运行 432 条请求：423×2xx、0 次 CF 挑战、
真实 WS 双向各 1 帧；7 条控制台错误全部属于既有类别（Datadog SDK 两处、React 水合 #418、
`/favicon.ico` 与 `/external/…` 的 503——后者是**有意不代理**的前缀）。

### 代理出口（#2）

已核实 `wreq` 在 HTTPS 目标走代理时调用 `connector.no_alpn()`（`conn/connector.rs:338`），
代理路径的 ClientHello 会缺 ALPN，与直连画像不同形。本批**停用代理出口**：
`egress::client` 在「启用代理 + https/wss 上游」时直接拒绝，`/api/mirror-proxy-config`
在保存前构建一次客户端把错误暴露在配置阶段（两处共用同一条可行动文案）。
保留 ALPN 的代理实现（或改成不经应用层代理的透明出口）留给需要代理的批次。

### WS 握手（#10）

`probe/probe_browser_ws_headers.py` 用真 Chromium 打本机回环 WS 服务，服务端记录到浏览器
实际发送（顺序）：`host, connection, pragma, cache-control, user-agent, accept-language,
upgrade, origin, sec-websocket-version, accept-encoding, sec-websocket-key,
sec-websocket-extensions`（`evidence/ws-handshake-headers-001.json`，key 值已占位）。
`chat_ws::upstream_headers` 现在按此补齐 `pragma`/`cache-control`/`accept-encoding`（浏览器
给值优先、缺省补固定值），`origin`/`referer` 重写为 chatgpt.com，`user-agent` 与 client hints
走身份整组；`host`/`connection`/`upgrade`/`sec-websocket-key|version|extensions` 一律由传输层
重建。库内单测直接读该证据文件断言「转发名单覆盖真浏览器发的每个应用层头、且不含凭空发明的头」。

### cfbypass 一跳（#7）

- 镜像：`cfbypass/Dockerfile` 从 Playwright jammy 镜像改为 **Debian trixie + snapshot 源**，
  精确安装 `chromium=146.0.7680.177-1~deb13u1`（与原版 all-in-one 同版），Playwright 用
  `executable_path=/usr/bin/chromium` 驱动系统浏览器；compose 的 `CF_BYPASS_USER_AGENT` 与
  网关常量同值。
- 可核验：响应新增 `identity`（UA、UA-CH 高熵、语言、时区、Chromium 版本、是否走代理），
  全部取自**实际浏览器会话**；网关每次刷新比对并 warn，`/api/refresh-cfbypass` 把该身份
  回给调用方（`cfbypass_identity`，缺字段时为 null）。
  比对字段（`src/server/cloudflare.rs::log_identity_mismatch`）：`user_agent`，以及
  `user_agent_data` 下的 `full_version`/`platform`/`architecture`/`bitness`/`platform_version`。
  其中 `platform_version` 是 2026-09-24 源码核对后才纳入的：Linux 上正确取值就是空串，报出
  内核版本即说明镜像里的 `ReduceUserAgentDataLinuxPlatformVersion` 被关掉，属于必须处理的
  错配（依据 `evidence/reference-chrome146-001/04-linux-platform-version.json`）。
- `probe_identity.py`（容器内只读探针）用同一浏览器打容器内回环，产出该跳的 ClientHello/H2
  摘要，供有 Docker 的机器上与 wreq 仿真逐字段对照。

### 版本同步机制（#6）

身份版本只有一个来源：`identity::full_version()` + `Profile::Chrome146`。升级清单（写入
NEXT_WORK）：改画像与常量 → 重采 146 参照并更新 `evidence/reference-chrome146-001/` 与
本文件的对照表 → 更新 `identity_fingerprint.rs` 的三个常量 → 同步 cfbypass 镜像的
chromium 版本与 compose 的 UA → 重跑两侧探针。缺任何一步，参照对照测试会红。

## 前端自愈：id 驱动判定、外链开放、快照刷新（2026-09-28）

上游前端每次发版都会带来新路径。本批把三处「一更新就要人工适配」的闸门拆掉：未显式分类的
`/backend-api/*` 不再按路径形状 503，改按请求/响应里的资源 id 判定；`/external/*` 从「有意
不代理」改为公网策略开放；路由快照改成一条命令刷新。改动只落在候选源码与 `Mirror/gateway-rust/tools/`，
不动基线 `src/`、不动 Django/Vue、不新增环境变量、不改数据库 schema。

### 未显式分类的 `/backend-api/*` 改为按资源 id 判定（`Auto`）

| 项 | 行为 |
|---|---|
| 判定结果 | `Verdict::Unclassified` 删除，`acl_unclassified_route` 不再产生；未显式登记的路径判为 `Auto{claim, ids}`，`claim` = 方法不是 GET/HEAD |
| id 材料 | 路径里 UUID 形态的段、query 里 `*_id` 键的值、请求体顶层 `*_id` 键的字符串值（去重后按 `is_resource_id` 过滤） |
| 请求侧 | 无 id → 放行；全部 id 在六族任一登记且当前会话可见 → 放行；已登记但不可见 → `404 acl_not_found`；哪个族都查不到 → `503 acl_unclassified_id`（提示认领或登记为账号级）。三种结果都在接触上游之前定下；访客/匿名会话仍 `403 acl_visitor_denied` |
| 响应侧（仅 Auto） | 2xx 且 `claim`：用同一套分块扫描器（六族 id 键 → 族）把响应里出现的 id **在把含该 id 的块交给客户端之前**登记给当前会话（`claim_if_absent`，`ON CONFLICT DO NOTHING`，只写 `claim_auto` 审计，既有归属永不覆盖）。JSON（`application/json` 或 `+json`，≤8 MiB，非 SSE）再按受众裁剪：顶层数组按条目可见性过滤、已知信封同步 `total`、顶层单对象含他人 id → `503 acl_foreign_resource_in_response`；超过 8 MiB → `502 acl_response_too_large`（解法是把该路径登记进 `UNOWNED`） |
| 流式残余 | SSE/二进制正文无法缓冲，原样透传、不做响应过滤；请求侧 id 判定仍然生效，新流式端点由请求侧兜底 |
| 可观测 | 每个新命中的 `(method, path)` 首次出现写一条 warn 日志 + 一条 `acl_audit`（`resource_type='route'`、`upstream_id="<METHOD> <path>"`、动作 `route_auto_pass`/`route_auto_denied`/`route_auto_filtered`）；进程内按路径去重，上限 1024，超出只记日志。管理员用既有 `GET /api/acl/audit` 就能看到新版前端带来了哪些路径、各自被怎么处理 |
| 逃生口 | `UNOWNED` 显式登记的路径保持既有「不判权、不过滤」透传语义 |
| 生成不重放 | Auto 路径不取生成互斥租约（无法判定是否生成类），`send_chat` 的「非 GET 不重放」规则不变 |

### `/external/*` 按公网策略开放（`server/external.rs`）

原版按 `is_allowed_external_proxy_host` 白名单转发，白名单内容未还原。本候选不复制白名单，
改为等价收口：

- 路径契约不变 `/external/<scheme>/<host>[:port]/<path>`，只接受 http/https；
- 目标主机（含裸 IP 与 IPv6 字面量）解析后要求**每一个**地址都是公网：回环/私网/链路本地/
  CGNAT(100.64/10)/ULA/组播/未指定/保留与文档段，以及单标签主机、`.local`/`.internal` 等
  内网后缀一律拒绝；
- 校验通过后用 `identity::client_builder().resolve_to_addrs(host, 已验证地址)` 把本次请求钉扎到
  该解析结果，校验与连接之间没有第二次解析（防 DNS 重绑定）；
- 请求只带 accept/accept-encoding/accept-language/content-type/range 一类的值类头 + 固定身份组，
  `cookie`/`authorization`/`x-mirror-token` 一律不转发；非 GET/HEAD 补
  `origin`/`referer = https://chatgpt.com`；正文流式、不重放、不跟随重定向；
- 302 与 `text/html` 正文一律 `502`；响应头沿用静态资源白名单（不含 `set-cookie`），
  第三方 cookie 既不进浏览器也不进共享 jar。

### 路由快照一条命令刷新（`Mirror/gateway-rust/tools/refresh_chatgpt_routes.py`）

- 默认从最近一份 `artifacts/phase1/probe/evidence/accept-*.json` 取浏览器实测的
  `/cdn/assets/*.js` 清单（`--chunks-from` 可覆盖），逐个拉上游分块抽 `METHOD 路径模板`
  （`safe(Get|Post|Put|Patch|Delete)` + 反引号路径）；分块缓存默认在系统临时目录，二进制不入库；
- `--check`（默认）只比对并打印新增/消失的模板与分块，有漂移非零退出；`--write` 按现有字段
  形状重写 `src/assets/chatgpt-api-routes.json`：`chunks{name,sha256,bytes}` +
  `routes{method,path,chunk}` + `captured_at`；
- 快照用例的口径从「每条模板都必须人工分类」改成「没有一条模板会落到 id 拒绝」：带六族 id
  占位符的模板必须由族规则显式判定（集合过滤、生成互斥、创建登记仍然生效），不带占位符的
  字面量路由允许走 id 兜底——这正是前端新增路由不再需要改网关代码的原因。六族显式断言、
  `checkout_pricing_config` 账号级断言、改写表 ⊆ 策略分类的契约测试保持；
- 2026-09-28 重抓：339 分块 / 929 路由（上一版 349/923；新增含 `GET /backend-api/bootstrap`、
  `tpp/default-tab-recommendation`、`accounts/{id}/workspace_banner` 等，消失含
  `GET /backend-api/conversations/search`、`GET /backend-api/conversations/{conversation_id}/files`
  等），`--check` 复跑零漂移。

### 新增/变更契约

- 新增错误码：`acl_unclassified_id`(503)、`acl_foreign_resource_in_response`(503)、
  `acl_response_too_large`(502)；移除 `acl_unclassified_route`(503，不再产生)；
- 审计新增动作：`route_auto_pass`/`route_auto_denied`/`route_auto_filtered`/`claim_auto`
  （`acl_audit` 表结构不变）；
- `/external/*` 可达（状态透传）；其余不变：`/api/*` 未实现仍本地 404、`/cdn/*` 与 `/assets/*`
  门禁、CF 挑战策略、凭据与出口 fail-closed、生成不重放、六族判权与集合过滤语义。

### 本批验证

`cargo test --locked --offline` 225 项（82 项库内单测 + 143 项集成用例；本批新增
`tests/auto_route_acl.rs` 6 项、`tests/public_prefixes.rs` 外链用例 1 项，改写
`tests/coord_boundary_regression.rs` 的 `/external/*` 矩阵）全过；
`cargo clippy --locked --offline --all-targets -- -D warnings` 通过；Django
`DJANGO_ENV=LOCAL manage.py test` 107 项通过（本批未改 Django 代码，作为回归）。
快照工具以历史分块 + 历史观测复跑 `--check` 对上一版快照零漂移、对篡改副本非零退出。

真实上游只读冒烟（`probe_browser_accept.py --no-write`，两次：`accept-20260928-100101.json`
432 条请求 / `accept-20260928-100231.json` 434 条）：0 次 CF 挑战（全程无 403）、
`/backend-api/*` 44 条全 2xx、`POST /external/https/bzr.openai.com/v1/obi/sync` 从上一版的
`503` 变为 `204`（页面控制台的 `OBI synchronization failed with status 503` 随之消失，
console error 7 → 5，剩余为 React #418/Datadog/favicon 这类既有噪声）；页面 JS 身份与
网络层声明一致（Chrome146/Linux、`platformVersion=''`）；未做任何真实写入。
**如实记录**：这一版真实前端请求到的 `/backend-api/*` 路径全部命中显式分类（六族规则或
`UNOWNED`），因此本次冒烟没有实际落到 Auto 分支；`/api/acl/audit` 的
`route_auto_pass/denied/filtered` 与 `claim_auto` 留痕由 `tests/auto_route_acl.rs` 的
合成回环用例覆盖（含「同一路径只记一次」与「拒绝也写审计」），Auto 在本批的角色是
未来新路径的兜底。

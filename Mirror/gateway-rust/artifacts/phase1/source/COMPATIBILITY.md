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
| 有意不代理 | `/external/*`（原版按 `is_allowed_external_proxy_host` 白名单转发，白名单未还原）、`/v1/*`、`/vendor-script/`、`/vendor-static`、`/cloudflare-insights/`、`/vendor-batch/collect`、`/ga/collect`、`/mapbox-events/events/`、`/connector-deep-research[/]` | — | 已登录 `503` + 按类别区分的文案；未登录保持既有 `401` 门禁顺序 |
| 本地语义 | `/api/*` 未实现子路径 | — | `404 {"message":"本地未实现的 /api 路径"}`（含 `/api/livekit/`） |

契约测试解析 `src/assets/gateway-client.html` 的两张改写表（2026-09-23 实测 63 条 pair、
39 个去重目标前缀，加运行时拼出的 `/external/` 与 `/internal-upstream/` 共 41 个），
断言每个前缀都有「已处理」或「显式拒绝」语义；将来新增或改名而不更新策略表即失败。

### 本批验证

`cargo test --locked --offline` 64 项库内单测 + 107 项集成用例全过（新增
`tests/backend_api_surface.rs` 7 项、`tests/public_prefixes.rs` 7 项、`tests/ws_bridge.rs` 3 项），
`cargo clippy --locked --offline --all-targets -- -D warnings` 通过；
Django `DJANGO_ENV=LOCAL manage.py test` 93 项通过（本批未改 Django 代码，作为回归确认）。
证据全部来自合成回环 fixture：真实账号、真实 chatgpt.com 与真实 WS 上游联调未执行。

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
| 管理 API | `GET /api/acl/resources`、`POST /api/acl/claim|share|move`、`GET /api/acl/audit`：服务密钥由中间件校验，操作者身份另行从固定 Django 源 fresh 校验并要求 `is_admin`，服务密钥本身不代表管理员 |
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
- **管理界面未做**：`/api/acl/*` 只有 API，Vue 管理界面不在本批。
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

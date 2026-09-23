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
- 完整 SSE/WebSocket、指纹传输、MCP/Skills 请求侧与限额、会话/项目读写隔离独立门禁
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

## 证据

- evidence/delivery-v3-runs.json：每个进程实际退出状态，比较有差异时 exit 1。
- 备份首轮端口占用失败保留在 delivery；调整监听端口后的最终三方证据为 backup-v3-original-014、backup-v3-{candidate,rollback}-delivery-2 及对应 compare-command。
- evidence/*-v3-{candidate,rollback}-delivery{-diff,-audit}.json：最终比较及差异原值。
- evidence/*-delivery/command.json、serial.log、results.json：执行、原始输出和数据库/上游记录。
- artifacts/VERIFICATION.txt：原版/候选/回滚 literal 命令与输出、退出、哈希。
- evidence/verification-before-v3.txt：上一轮 ledger 原样保留。

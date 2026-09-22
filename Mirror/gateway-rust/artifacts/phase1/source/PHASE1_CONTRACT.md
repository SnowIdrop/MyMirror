# 新替换计划：第一阶段配置与公共静态批次（未完成整体替换）

## 当前边界

本候选沿用 `gateway-rust`，没有改为官方 API 产品，没有接入闭源回退。
本候选已实现服务端上游配置拆分及受限公共 JS/CSS 通道，补充离线契约与回归。原始源码、既有二进制证据、
Django 用户库、旧网关库及线上资源均保留；没有导入旧数据。

`Config::from_env` 新增 `GATEWAY_UPSTREAM_MODE`：

- 缺省或 `offline`：继续仅接受数字 HTTP 回环地址；旧测试无需 CDN 配置。
- `configured`：Django、聊天、CDN 必须显式配置；可选 CF 服务单独配置。
  接受 HTTP/HTTPS 服务源（含端口），拒绝 URL 凭据、路径前缀、查询串、片段和其他协议。
  不回退到默认公网目标，不关闭 TLS 证书校验，不跟随上游重定向。
- `CHATGPT_CDN_BASE_URL` 存入 `Config.cdn_upstream`，与 `django`、`upstream` 分离。
  **它现已接入下述受限 JS/CSS 路由；不代表完整静态资源或聊天页面可用。**
- 请求不能覆盖配置目标。已开放路由仍使用服务端固定源；未知业务路径仍失败。
  原有模型、配额、MCP/Skills 策略代码、授权版本检查没有删除或放宽。
- 提供 `.env.configured.example`，仅作候选配置说明；没有改动现有部署 compose。

## 已检查的契约和证据等级

“源码”只表明本地实现；“旧观测”指已有离线模拟上游对原版的观测，不是本次真实环境验收。

| 能力/请求 | 请求、ID、返回/错误 | 证据与结论 |
|---|---|---|
| 登录 | 服务间 `POST /api/login`；`user_name`、`authorization`、上游 token 与已有策略字段；返回 `login_url` | `src/server.rs::login`；`tests/mirror_auth.rs` 合成回归。管理员服务密钥不等于操作者身份 |
| 登录交接 | `GET /api/not-login?user_gateway_token=...`；轮换 `mirror_token` Cookie，跳转 `/` | `src/server.rs::handoff/session_cookies`；原有 `/` 尚未开放，因此聊天闭环未完成 |
| Django 授权 | `POST /0x/user/gateway-authorization`，服务密钥＋`authorization/subject`；返回 `active/version/expires_at` | `chatgpt-mirror-build/backend/app/accounts/session_authority.py:99-151`。签名内含 user_id，但响应尚无稳定 ID/管理员角色；不能从客户端字段补造 |
| 角色失效 | 策略摘要含 `is_staff/is_superuser`，签名校验会核对摘要 | 同文件 `policy_digest/authorization_details`；第二阶段仍需可信角色返回、用户标识与权限接线 |
| 管理代理 | `/0x/*`、`/admin*` 固定 Django 源、保留查询、响应流转发 | `src/server/proxy.rs::django_forward/stream_response`；旧观测 `tools/observe_proxy_v3.py`；不是通往任意主机的代理 |
| 当前用户 | `GET /backend-api/me`，上游账号 token 替换浏览器凭据；原样状态/正文 | `src/server/proxy.rs::me_passthrough`，旧观测 `p1-me-*`；只有读取接口，不代表普通聊天完成 |
| 会话列表 | `GET /backend-api/conversations?offset=&limit=`；`items[].id`、`total`；按账号+user_name 过滤 | `src/server/proxy.rs::conversations_response/rebuild_conversations`；旧观测 `p2-*`。这不是完整统一资源授权，未知资源不认领 |
| 刷新 | `GET /api/auth/session` 当前读取本地账号/plan，返回用户、loginMode、planType | `src/server.rs::auth_session`；`STATUS.json:139-149` 留存 `accounts/check + me` 刷新副作用差异；不能宣称已对齐 |
| 页面、静态、URL 改写 | 旧模板中存在主机改写/拦截代码；聊天 HTML 路径、静态路径与初始化数据边界尚未验证 | `src/assets/gateway-client.html`、`gateway-client-hosts.json` 和 `server/proxy.rs::inject_client_resource` 仅证明模板存在；不能据主机列表开放任意媒体路径 |
| 错误 | 未认证读取 401；未知聊天业务路径 503；未知 `/api/*` 404 | `src/server/proxy.rs::chat_proxy`；新增本地回归保留门禁 |

## 尚无足够证据的必选能力（不得按猜测开放）

| 能力 | 仍需收集的实际契约与隔离条件 |
|---|---|
| 普通聊天、共享续聊 | 创建/续聊请求、conversation/message ID、SSE 事件、停止、历史、重命名/删除；成功创建才登记；单会话生成互斥；断线不得重发 |
| 文件、图片 | 上传步骤、引用字段、下载/生成结果 ID；请求引用鉴权与受控媒体访问；不能透出长期直链 |
| 项目 | 创建/编辑及关联协议；动态继承共享；移动旧私有内容扩大可见性须管理员授权 |
| Pro、研究、搜索 | 任务 ID/状态、引用、查询/取消与已证实恢复协议；重启不重新创建 |
| 语音 | 客户端实际信令与音频协议；不预设 WebSocket；资源权限和撤权断连 |
| 连接器/MCP | 配置、调用、授权各自权限；凭据加密；外部写操作确认；不继承项目共享 |
| 账号记忆、自动检索 | 能否限制到当前授权资源；未证实时暂停，不能只隐藏列表 |

以上不是路由猜测表。没有把网上通用 ChatGPT API 名称当成本项目的已观测协议。

## 按原顺序继续

1. 第一阶段未完：页面/静态/刷新首轮离线观测已经完成；下一步实现有测试约束的认证刷新链，并审查 HTML/初始化数据隔离后再开放页面与同源改写。字体、图片和其他静态类型仍未开放。
2. 第二阶段：Django 可信身份响应 → Rust 新库资源/关联/共享/审计 → 所有访问统一判权 → 后台资源页面及版本化完整备份。既有开关不得关闭默认私有。
3. 第三至五阶段：按用户计划接通普通聊天、文件/图片/项目、研究/搜索/语音/连接器；证据不足或无法隔离时保留未完成门禁。
4. 第六阶段才执行整体镜像、浏览器、三身份隔离、重启/故障/并发、备份与部署回滚验收。

本批未执行真实账号、外部写操作或生产切换。程序/源码回滚不撤销数据库或上游已执行操作。

## 公共静态批次：新增实际观测与实现

证据：`artifacts/phase1/page-original-001/{command.json,results.json,summary.json,serial.log}`。
原版通过既有 oracle 在 **QEMU -nic none** 中执行，三个合成回环服务分别模拟聊天、Django、CDN；
guest_exit=0，共40条记录。不是浏览器真实账号验收。

- 原版匿名 `/assets/fixture.js?v=1` 到 CDN `/assets/fixture.js?v=1`；`/cdn/fixture.css` 到 CDN `/fixture.css`；`/cdn/assets/fixture.js` 到 CDN `/assets/fixture.js`。GET/HEAD、JS/CSS MIME 与路径有观测。
- 原版带浏览器 Authorization 的静态请求会将该头转发 CDN。**明确不兼容这项泄漏行为**：新 `server/static_assets.rs` 只复制静态协商/缓存/Range请求头，不附带任何浏览器、账号、网关或CF凭据；不转发响应 Set-Cookie。
- 新候选仅允许 `/assets/` 下或受限 `/cdn/` 映射的安全 ASCII JS/CSS 路径，GET/HEAD；不接受路径穿越、编码路径或任意 URL。缺 CDN/未证实路径503，其他方法405，重定向及HTML/错误MIME502；上游错误状态保留但不泄出错误正文。
- 静态正文逐块转发，没有数据库锁或完整正文缓冲；首块早于上游完成的合成测试已加入。304、HEAD与ETag有回归，尚未宣称所有浏览器缓存/Range/压缩组合验收。
- 原版匿名首页302到 `/admin#/`；登录后首页和 `/c/guessed-conversation` 会请求聊天HTML并注入脚本。合成页面并不能证明真实初始化数据隔离，因此候选仍不开放这两条页面路径。
- 原版登录以及每次 `/api/auth/session`（含重复、`refresh_account=1`）都依次请求 `accounts/check/v4-2023-04-27` 与 `me`。合成 `accounts.default.account.plan_type=plus` 产生 planType=plus；accounts 500时仍请求me并显示free；me 401时返回空对象。**这些是合成输入下的实测解析行为，不是对全部真实响应结构的推定；候选刷新链尚未实现。**
- 启动CF预热可能与首个案例标签交叠；不把标签下出现的预热记录推断为匿名首页的业务调用。

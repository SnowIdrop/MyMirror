# 下一批优先工作：缺口 1 / 2 / 3 / 5

记录时间：2026-09-23。来源：用户指令「先推进缺口 1、2、3、5」。
编号沿用《距离代替原网关还差什么》的分析结论；**缺口 4（计量 / 配额 / 限流 / 审核 / PoW）
已由产品决定列为显式非目标**，见 [COMPATIBILITY.md](COMPATIBILITY.md) 的对应章节，本批不再开工。

本文件只登记范围、现状证据、依赖与验收要点。

**2026-09-24 更新（三）：缺口 5 第二批已落地（跨层身份一致性）。** 在第一批「网关内部自洽」
之上，把 JS 可见面、WS 握手、cfbypass 一跳纳入同一身份，并用 Chrome for Testing
**146.0.7680.165** 做同版本参照：ClientHello（含扩展集合与逐连接重排行为）、
H2 首帧（SETTINGS/窗口增量/伪头顺序）、同源 XHR 头顺序逐字段一致；`signature_algorithms`
的 ML-DSA 差异确认为版本差并闭合。代理出口因 wreq 关闭 ALPN 而**停用**（fail-closed）。
参照对照见 [COMPATIBILITY.md](COMPATIBILITY.md) 的「跨层身份一致性」与
`evidence/reference-chrome146-001/`。**本批未完成**：cfbypass 镜像的构建与运行验证（本机无
Docker）、保留 ALPN 的代理出口。Linux 侧 `platform-version` 一度列为待采，随后改由源码
核对闭合（`evidence/reference-chrome146-001/04-linux-platform-version.json`：Linux 上该
feature 默认 `stable` ⇒ `GetPlatformVersion()` 返回空串 ⇒ 头值 `""`）；本机没有 Linux
浏览器，运行时复核留给打包批次。

**2026-09-24 更新（二）：缺口 5 第一批已落地（传输身份统一）。** 出网传输层换成
`wreq`/btls 的 `Profile::Chrome146` + Linux 画像，请求头由 `server/identity.rs` 一处强制整组给出，
HTTP 与 WebSocket 同时覆盖；与真 Chromium 的 ClientHello 逐字段对照证据见
[COMPATIBILITY.md](COMPATIBILITY.md) 的「传输身份统一」一节与
[`evidence/tls-identity-reference.json`](../../evidence/tls-identity-reference.json)。
本批**只做实现与本地验证**：Linux 制品、All-in-One 镜像、代理出口分流、
`CF_BYPASS_PROXY_SERVER`/`TRUSTED_PROXY_IPS`/`MIRROR_API_PREFIX`/`ADMIN_UPSTREAM` 仍未做。

**2026-09-24 更新（一）：残项收敛。** 缺口 3 的残项按「有真实观测证据 / 运营上必须有人做」逐条判定，
落地两项并显式关闭一批：`checkout_pricing_config` 登记为账号级前缀（消掉每个已登录页面 4 次 503）、
管理员会话认领链路（网关清单端点 + Django 转发 + 用户页入口）、WS 会话 Cookie 合成的独立用例。
判定不做与保留登记的完整清单见 `COMPATIBILITY.md` 的「残项收敛与管理员会话认领」。下面各节的
现状描述保留为当时的证据。

**2026-09-23 更新：缺口 1 与缺口 2 已按同批实施落地**（提交见 `COMPATIBILITY.md`
「缺口 1 + 2 同批落地」一节），本文件中这两节保留为当时的现状证据。剩余在办项：
缺口 3（项目/分支级归属与 ACL 完整接线）、缺口 5（传输身份与出口策略），
以及本批新增的遗留项（见文末「本批新增遗留」）。

## 为什么是这四个，以及它们的耦合关系

缺口 1 与缺口 2 必须一起做：浏览器侧脚本已经把大量上游地址改写为同源前缀，而服务端只接了其中
一小部分，所以「能渲染」和「能长期用」之间存在一条由未开放前缀构成的断裂带。
缺口 3 必须在开放 `/backend-api/*` 读写**之前或同时**落地：缺口 4 不做之后，共享账号剩下的
安全边界只有归属隔离、撤权与凭据隔离，一旦能写却没有归属登记，同账号下任何镜像用户都能读到
他人创建的会话。缺口 5 可以并行推进，但它是真实上游长期可用性的前提，也是 section12 未通过的
主因之一。

## 缺口 1：已登录业务面未开放

目标：把 `/backend-api/*` 从「两个只读端点 + 503 门禁」推进到可用的已登录读写，并按原版路由面
补齐 WebSocket 与实时/公共端点。

现状证据：

- 放行判定仍是白名单前缀 + 两条精确路径：`src/server/proxy.rs` 的 `CHAT_OPEN_PREFIXES`
  （`/backend-anon/`、`/public-api/`、`/ces/`、`/cdn-cgi/`、`/sentinel/`，第 76 行起）、
  `GUEST_OPEN_PREFIXES`（`/uc/`、`/unauth-mweb/`，第 87 行）、`ME_PATH` / `CONVERSATIONS_PATH`
  （第 70–71 行）；其余路径在 `chat_proxy` 内返回 503。
- 原版路由面（逆向证据）：`/backend-api/*path`、`/backend-anon/*path`、`/v1/chat/completions`、
  `/ga/collect`、`/vendor-batch/collect`、`/realtime/*`、`/images-openai/*`、
  `/cdn-cgi/*`、`/sentinel/20260423af3c/sdk.js`，以及 sources_dropdown / gizmos / pins / feed /
  beacons / amphora / tasks / user_surveys / auth.logout 等子路径特判
  （`MirrorNiXiang/reverse/reports/08-reconstruction-notes.md` §3.1-B/C）。
- WS 完全未实现：`src/` 内没有任何 `tungstenite` 使用点，`Cargo.toml` 虽已声明
  `tokio-tungstenite` 但无调用；原版 `/ws-chatgpt/*` 走 `bridge_chatgpt_ws`，并要求目标必须是
  `wss://ws.chatgpt.com`（同报告 §6.2）。而注入脚本已把浏览器 `WebSocket` 改写到
  `/ws-chatgpt/<path>`（`src/assets/gateway-client.html` 第 1343 行起），即当前该改写一旦被触发
  必然失败。
- 原版的 `/realtime/*`（对话实时通道）、`/api/livekit/`（语音）与 `/api/pow-risk-stream`（SSE）
  在候选中均未注册。PoW/降智风险已列入非目标，因此本缺口只登记 `/realtime` 与语音端点。

依赖顺序：先开放读写与 SSE，再做 WS；WS 需要与出口策略（缺口 5）对齐，因为原版可按代理分流。
**本批已落地**：读写/SSE、归属判定与登记、`/ws-chatgpt` 桥接（代理出口 fail-closed）、
`/realtime/*` HTTP 与升级显式拒绝。

验收要点：登录后新建会话、续聊、SSE 流式回复、停止生成、重命名/删除、历史加载在合成回环 fixture
下逐条可断言；SSE 断线不得自动重发（既有约束）；WS 需与真实上游或合成 WS 上游各有一组证据。
**本批覆盖**：新建/续聊/列表隔离、GET 挑战刷新重放与 POST 严格一次、实时通道 HTTP 与升级分支、
WS 合成回环双向透传与凭据注入、WS 无会话 401 与代理出口 fail-closed。
**仍未覆盖**：真实上游的流式回复渲染、停止生成、重命名/删除、历史加载的端到端断言。

## 缺口 2：注入脚本改写的同源前缀，服务端大半不接

目标：让脚本已经改写出去的每个前缀都有对应的服务端处理或明确的失败语义，不再出现「改写成功
但服务端 503」的静默断裂。

现状证据：

- 脚本改写表：`src/assets/gateway-client.html` 第 35 行起（绝对→相对）与第 809 行起（CSS 文本
  改写）。实测该表共 **63 条 pair、39 个互不相同的同源目标前缀**（http/https/协议相对三种写法
  归并后）：
  - ChatGPT 自身路径：`/`、`/api/`、`/v1/`、`/ces/`、`/public-api/`、`/realtime/`、
    `/backend-api/`、`/backend-api/estuary/`、`/backend-anon/`
  - CDN 与静态：`/assets/`、`/cdn/`、`/cdn/assets/`、`/common/`、`/ab/`
  - 图片与地图：`/images-openai/`、`/static-rsc-1/`、`/static-rsc-4/`、`/mapbox/`、
    `/mapbox/styles/v1/oai-data/`、`/mapbox-events/events/`
  - 文件与沙箱：`/files/`、`/files-southcentral/`、`/files-north/`、`/connector-assets/`、
    `/connector-deep-research`（含尾斜杠变体）、`/openai-files/`
  - 遥测与第三方：`/vendor-script/`、`/vendor-batch/collect`、`/vendor-static`、
    `/cloudflare-insights/`、`/google-s2/`、`/google-avatar/a/`、
    `/gstatic-t0/`、`/gstatic-t1/`、`/gstatic-t2/`、`/gstatic-t3/`、`/images-app/`、
    `/persistent-deep-research/`
  - 未命中内置主机表的外部地址改写到 `/external/<scheme>/<host>/...`
- 服务端实际只接：`/assets/`、`/cdn/`（`src/server/static_assets.rs` 第 21 行起的扩展名白名单）
  与 `/internal-upstream/https/<host>/...`（同文件 `MEDIA_ALLOW`，第 91 行）。
- 逐项比对结果（2026-09-23 实测，可复核）：39 个改写目标前缀中**只有 7 个被服务端接住**
  （`/`、`/assets/`、`/cdn/`、`/cdn/assets/`、`/ces/`、`/public-api/`、`/backend-anon/`），
  其余 **32 个落 503 门禁**。其中 `/api/` 与 `/v1/` 需要区分对待：`/api/*` 的未知路径返回 404
  是本地既有设计（只实现 next-auth 兼容面），不能与「未接的静态/媒体前缀」混为一谈。
- 已观测到的真实缺口（`ANONYMOUS_FRONTEND_EVIDENCE.md` §5 与 §8.5）：`/external/*` 外链代理、
  `/backend-api/sentinel/sdk.js`、CSS 内 `cdn.openai.com` 字体、上游不允许的 file_id 回读。

依赖顺序：与缺口 1 同批推进；`/backend-api/*` 一旦放开，`/backend-api/sentinel/sdk.js` 的 503
自然消失，因此该项与缺口 1 合并验收。媒体/字体类前缀应沿用「不携带账号凭据」的既有边界。
**本批已落地**：可代理前缀按策略表反代，有意不代理的前缀给出按类别区分的文案，
契约测试解析改写表保证「每个前缀都有语义」。**2026-09-28 收敛**：`/external/*` 不再等原版
主机白名单，改为「只允许公网目标」的公网策略落地（见 COMPATIBILITY「前端自愈」）。
**仍未覆盖**：真实上游下这些前缀的渲染验收。

验收要点：逐个前缀确认「脚本会改写到它」与「服务端按什么方法、什么扩展名、是否带凭据」；
新增路径一律不许成为任意目标代理；渲染类前缀至少需要一次真实上游观测或合成 fixture 断言。

## 缺口 3：归属登记与三身份隔离未接线（2026-09-24 已落地，保留当时现状证据）

**状态：已按同批完整实施。** 实现与拒绝契约见 `COMPATIBILITY.md`
「缺口 3 完整批次：资源 ACL 产品接线」；离线契约用例 `tests/coord_acl_contract.rs` 28 项、
产品接线用例 `tests/acl_product_wiring.rs` 6 项、备份契约 `tests/backup_contract.rs` 13 项。
下面保留实施前的现状描述。

目标：把共享账号下的资源归属从「只读过滤」补齐为「创建即登记、读取即校验」，并把已暂存的
ACL 模块接入产品路径。

现状证据：

- 运行期只有读：`src/server/proxy.rs` 第 351、359 行两次 `SELECT ... FROM conversation_owners`
  用于列表过滤与总数计算；全仓没有运行时 `INSERT`（`src/storage.rs` 的 `upsert_sql` 只为备份
  恢复路径生成写入，不是新会话登记）。
- `src/resource_acl.rs` 是孤立文件：`src/lib.rs` 只声明 `config / crypto / policy / server / storage`
  五个模块，ACL 仅由 `tests/coord_acl_contract.rs` 用 `#[path]` 编译测试；文件头自述
  「Not wired into the gateway, its login, or its database」。
- 原版对应符号：`claim_conversation_owner`、`conversation_belongs_to_user` 等，以及
  `/apps/sources_dropdown/...`、`/pins/...`、`/gizmos/...` 等子路径特判
  （报告 08 §3.1-C、§6.1）。

依赖顺序：**必须在开放 `/backend-api/*` 读写之前或同时完成**。缺口 4 不做之后不存在限流兜底，
归属隔离是唯一的内容级边界。

验收要点：同一上游账号、两个镜像用户，A 创建的会话 B 不可见也不可续聊；未知归属不认领；
撤权后旧 token 即刻失效；重启后归属关系不丢，且不导入旧网关数据库。

## 缺口 5：传输身份与出口策略

目标：把「固定 UA + 三个 sec-ch-ua 头」补齐为经过观测的传输身份与出口能力，并补齐缺失的配置面。

**2026-09-24 第一批已完成（传输身份）**：出网客户端（`egress::client`、`server::App::client`、
WS 桥接）统一由 `identity::client_builder()` 构造，画像与身份头同源，整组强制覆盖；
网关自发请求带 `identity::api_baseline()` 并在 JSON 解析前解码响应；代理路径保持字节透传与
「生成不重放」。指纹回归锁在 `tests/identity_fingerprint.rs`（本地裸 TCP 抓 ClientHello +
sha256）。**本批仍不做**：代理节点与出口分流、`CF_BYPASS_PROXY_SERVER`、`TRUSTED_PROXY_IPS`、
`MIRROR_API_PREFIX`、`ADMIN_UPSTREAM`；出口仍是 AWS 机房 IP。

现状证据：

- `src/server/egress.rs` 目前 fail-closed：`node.is_none()` 被强制要求（第 11 行）、
  `transport_mode` 只接受 `reqwest`（第 20–22 行）、启用代理时禁止同时配置 cfbypass 以避免
  复用旧 clearance（第 33–35 行）。
- 原版是双栈：`wreq`（BoringSSL/btls 指纹）+ isahc/curl，运行时 `LD_PRELOAD=libcurl-impersonate.so`、
  `CURL_IMPERSONATE=chrome146`（报告 08 §6.3）。
- 配置面缺 `MIRROR_API_PREFIX`、`ADMIN_UPSTREAM`、`CHATGPT_AB_BASE_URL`、
  `CF_BYPASS_PROXY_SERVER`、`TRUSTED_PROXY_IPS`（`src/config.rs` 现只读 14 个变量；
  报告 03 §8 列出原版全部变量）。
- 未验证：真实 TLS/ALPN/HTTP2 特征、公网 IP/DNS/NAT 出口、上游 device/session/cookie 续期与
  CF 缓存的作用域/profile 绑定（`STATUS.json` 的 `not_verified` 列表）。
  **部分收敛**：ClientHello 层已与真 Chromium 逐字段对照（唯一差异是 ML-DSA 签名算法的版本差）；
  H2 SETTINGS 顺序与伪头顺序、公网出口、CF 缓存 profile 绑定仍未验证。

依赖顺序：可并行；但 WS（缺口 1）与代理出口在选择逻辑上耦合，先定出口抽象再实现 WS 分流更省返工。

验收要点：每个传输 profile 需有可复现的身份证据，而不是「配置成功」；代理出口与 CF clearance
必须绑定到同一 profile，禁止静默复用旧 clearance；未验证的组合继续 fail-closed。

## 其它仍未完成项（不在本批四缺口内，保留登记）

- **缺口 3 实施产生的新增残项（2026-09-24）**：
  - 连接器创建不自动登记：`POST /backend-api/aip/connectors/*` 的响应形状无实测证据
    （同一前缀下既有创建也有 `list_repos`/`search_contacts` 之类动作），凭响应 `id` 自动认领会
    误登记，因此连接器目前只能由管理员用 `/api/acl/claim` 认领。
  - 真实上游探针已执行读路径（2026-09-24，证据 `Mirror/gateway-rust/evidence/gap3-real-probe-001/`）：
    真实 AccessToken 换取、`me`、`accounts/check`、`conversations` 四条路径稳定 200。仍未完成的是：
    - 真实新建会话被上游以 JSON `403` 拒绝，因此跨用户隔离在真实会话上未验证。该请求是合成的
      （无 Cookie、无 `oai-*` 等前端头），所以这条 403 说的是合成请求被拒，不是镜像写路径不可用。
      推进方式：取一份前端真实 `POST /backend-api/f/conversation` 的观测样本（DevTools 复制为
      cURL / HAR）对齐请求头与 Cookie，或改为浏览器驱动前端流程。
    - 本机直连 chatgpt.com 存在间歇性发送阶段失败（网关如实返回自身 502，不重放生成类请求）。
      `127.0.0.1:18001` 的本地 cfbypass 当时未启动，因此 `CF_BYPASS_URL` 的刷新/重放分支未在真实上游触发；
      下次可先起 cfbypass 再跑 `probe.py --cf-bypass-url http://127.0.0.1:18001`。
    - `GET /backend-api/projects` 在真实上游是 405（快照里该路径只有 `POST`）：项目集合的读取入口
      仍未知，需要用前端实际请求观测补齐。
    - `/backend-api/task_suggestions` 在该账号下是 404：上游是否按账号/版本开放待定。
  - 管理界面只做认领：「未登记会话 → 认领给指定镜像用户」已接通（网关 `GET /api/acl/
    unclaimed-conversations`、Django `/0x/user/<id>/{unassigned-conversations,claim-conversation}`、
    用户页对话统计弹窗内的区块）；`/api/acl/{resources,share,move,audit}` 仍只有 API。
  - 「分支」维度归属未做：原版 `enforce_project_owner` 的分支语义在逆向材料里只有符号名，
    本批按项目 ACL + 动态共享实现，未猜测分支协议。
  - 访客策略未定义：访客被拒绝在 ACL 路径之外（`acl_visitor_denied`），若要让免费访客参与会话，
    必须先定义访客归属策略；本批按「访客不参与 ACL」的产品决定实施。
  - 真实上游写入的创建类路径（项目/文件/任务/图片）只有合成回环证据；无实测形状的写路径保持
    账号级放行但不自动登记，需在真实验收时逐条确认。
- **上游 cookie 捕获/恢复的遗留（2026-09-24；本批已收敛主体）**：
  - **已由真实探针回答**（证据 `evidence/device-cookie-real-001/`）：上游在 `GET /` 与
    `/sentinel/20260423af3c/sdk.js` 上确实下发 `oai-did`，捕获与浏览器播种两条链路均成立。
  - **已实现**：真实上游下发的 `oai-did`/`oai-sc`/`__oailb`/`__cf_bm`/`__cflb`/`_cfuvid`
    整组捕获与按作用域回注，双存储（会话列 `upstream_cookies` + 号池行
    `chatgpt_accounts.extra_cookies`），CF 刷新后定向清理旧 CF 条目；见
    `server/upstream_cookies.rs` 与 COMPATIBILITY「上游 cookie 捕获与恢复」。
  - **未定名**：`is_browser_preference_cookie_name`(0x1872F0) 里还有一条 12 字节内联比较
    （解出 `oai-allow-ne…`），完整名字未还原，未纳入排除表；若实测发现它被跨会话搬迁，再按实测
    名字补表。名称比较目前按大小写不敏感（更保守），原版常量比较是否如此未确证。
  - **写路径 JSON 403 的原因已定性（2026-09-24 前端分块取证，见 COMPATIBILITY
    「新建对话的前端真实形状」）**：路由与端点没选错（登录态确为
    `POST /backend-api/f/conversation`，且前面还有 `/f/conversation/prepare`）；缺的是
    **sentinel 握手产生的请求头**。合成探针直接 POST 创建端点、不带
    `OpenAI-Sentinel-Chat-Requirements-Token` 一族的头，上游拒绝属预期，**不是候选实现缺口**。
  - **结论：不需要为写路径实现 sentinel。** 这套令牌全部由浏览器产生（`p` 由页面内 SDK
    本地算出、`prepare_token` 来自上游响应、PoW/Turnstile 在 `required` 时由浏览器求解、
    最终 `token` 来自 finalize），原版网关同样不做令牌合成（其二进制查无 `f/conversation`
    与 `openai-sentinel` 字面量）。候选按黑名单过滤请求头、原样透传该族头，改写表第 37 行已把
    `https://chatgpt.com/backend-api/` 映射为同源 `/backend-api/`，ACL 对
    `/backend-api/sentinel/*` 与 `/backend-api/f/conversation/prepare` 均按账号级放行。
  - **仍未闭环的只剩验收方式**：要证明「浏览器经镜像能新建并续聊」，必须做**真实浏览器驱动**
    的镜像端到端流程（headless Chromium 经镜像登录真实账号、页面自行完成 sentinel/PoW、
    发起一次新建与删除）；本仓库目前没有可复用的浏览器驱动脚本。合成回环最多证明
    「没有丢掉浏览器的材料」，证明不了上游接受。
  - 备选低成本路径：在仍可用的原网关上用 DevTools 抓一份真实
    `POST /backend-api/f/conversation`（cURL / HAR），比对候选转发的头与载荷，
    可在不部署浏览器驱动的前提下先确认头族与 `content-type` 实际取值。
  - **浏览器驱动验收（2026-09-24 第一轮，只读）发现的新差异：`session_token` 登录
    不会给上游带会话 cookie。** 探针 `artifacts/phase1/probe/probe_browser_create.py`
    用真实 Chromium 经候选网关加载页面（真实浏览器自带客户端提示头，因此**不需要
    cfbypass**，页面 200、507KB、输入框出现、700 条子请求里 `/cdn/assets/*` 全 200），
    但前端走的是**匿名通道**（`/backend-anon/me`、`/backend-anon/conversation/init`、
    `/backend-anon/sentinel/chat-requirements/{prepare,finalize}` 全 200），
    没有发出任何 `/backend-api/conversation*`。
    证据链：
    - 前端用上游 SSR 的 HTML 判定登录态：镜像首屏 HTML 不含 `accessToken`；
      实测给 `GET /` 加 `Authorization: Bearer <accessToken>` 也不改变上游 HTML
      （两次 `accessToken` 计数均为 0），因此登录态 HTML 只能来自会话 cookie。
    - 镜像自身的会话面正常：页面内 `fetch('/api/auth/session')` 返回 200，
      键为 `authProvider/expires/loginMode/planType/user`。
    - 候选缺口：`server/proxy.rs` 全文不出现 `session_token`；
      `load_credentials`/`refresh_auth_session` 只用 `extra_cookies` 组装 Cookie 头，
      因此 `session_token` 列（Django 以独立字段下发，见
      `backend/app/chatgpt/views/chatgpt.py` 的 payload）从不进入上游 Cookie 头。
    - 原版有对应逻辑（**符号级证据，未反编译**）：ELF 符号表含
      `append_session_cookies`、`supplemental_has_next_auth_cookie`、
      `build_upstream_auth_cookie_header`、`cookie_value`、`rebuild_split_cookie_value`
      （均 1 处），cookie 名字面量 `__Secure-next-auth.session-token` 5 处、
      `next-auth.session-token` 8 处、`__Secure-` 7 处、`__Host-` 1 处。
  - **影响**：账号用 `session_token`（login_mode `web`）登录时，浏览器拿到的是上游的
    未登录页面，前端退回匿名通道——会话不落账号，ACL/归属层不参与。若账号的
    `extra_cookies` 里本来就有 `__Secure-next-auth.session-token`（管理面导入 cookie），
    则该路径当前可用。
  - **已实现（2026-09-24）**：会话 cookie 合成（`session_token` 列 → 上游
    `__Secure-next-auth.session-token`，`extra_cookies` 或 jar 已有同名条目不重复），
    并纳入凭据绑定。见 COMPATIBILITY「会话 Cookie 合成与浏览器端到端验收」。
  - **登录态端到端验收已通过**：真实 Chromium 经候选网关加载页面后走登录通道
    （`/backend-api/*` 60 次、`/backend-anon/*` 0 次），真实新建会话
    `POST /backend-api/f/conversation` 200 `text/event-stream`，随后经网关删除 200
    `{"success":…}`，账号无残留。删除成功同时证明创建路径的 ACL 归属登记生效。
  - **已端到端验收（2026-09-24 第二轮，`probe_browser_accept.py`）**：流式回复正文渲染
    （创建 200 `text/event-stream`，助手气泡渲染出预期串）、停止生成（按钮点击后消失）、
    重命名 200、重载后历史可见（经网关列表 1 条且含目标 id，页面自行导航到 `/c/<id>`）、
    真实 WS 上游（`/ws-chatgpt/p4/ws/user/…` 经桥接到 `wss://ws.chatgpt.com`，双向各 1 帧，
    连接未关闭）、跨用户隔离（同账号第二个镜像用户 404 `acl_not_found`，未触上游）、
    删除 200 且账号 `total=0` 无残留。逐项证据见 COMPATIBILITY「端到端验收的第二轮」。
  - **已补齐**：WS 握手侧的会话 cookie 合成现有独立 fixture 用例
    （`tests/ws_bridge.rs::websocket_synthesizes_the_session_cookie_for_session_token_logins`，
    断言提交凭据在前、合成会话 Cookie 居中、CF cookies 在后，且拿换取得来的 AccessToken 作上游凭据）。
    语音（`/api/livekit/`）与 `/realtime` 升级仍未开放，且已判定不做。
  - **新发现的上游路由（未分类，503）**：真实页面会请求
    `GET /backend-api/checkout_pricing_config/configs/US`，该路径**不在** 923 条路由快照里
    （快照冻结于 2026-09-23），因此按 ACL 设计返回
    `503 {"code":"acl_unclassified_route"}`。**已收敛**：按账号级前缀登记进 `UNOWNED`
    （快照用例不覆盖这条路径，因此由库内单测直接断言）。2026-09-28 起快照刷新到 929 条、
    未登记路径统一改走 id 兜底（见 COMPATIBILITY「前端自愈」），`acl_unclassified_route`
    不再产生，这条前缀仍留在 `UNOWNED`。
  - **页面加载不需要 cfbypass**：真实浏览器自带 `sec-ch-ua*` 客户端提示头即可 200；
    合成客户端缺这些头才会被挑战。cfbypass 仍是挑战刷新路径的依赖（`CF_BYPASS_URL`）。
  - 真实上游 cookie 名已在证据里固化，可用于后续批次核对捕获名单。
  - 登录/诊断链（`/api/login` 的 session_token 换取、`/api/get-user-info`、
    `/api/diagnose-chatgpt-auth`）在会话建立前调用上游，不走会话通道，因此既不播种也不捕获；
    捕获从第一个带会话的上游响应开始（`/api/auth/session` 的 `me`/`accounts/check` 刷新、
    业务面读写、生成），账号级一致性因此可能晚一步。
  - 直连登录（Django 直接下发凭据、账号未入 `chatgpt_accounts`）时捕获条目只落会话列，
    跨镜像用户不共享；要账号级共享需先让账号入池。
  - 浏览器 Cookie 兜底依赖上游 `set-cookie` 未带 `Domain=chatgpt.com`；带该属性时浏览器不会为
    镜像源保存，此时只剩请求头来源可用。
  - 无撤销/轮换入口：上游轮换 cookie 后，旧值只在下一次响应捕获点被覆盖（CF 条目另有刷新时的
    定向清理）；上一版候选写的 `gateway_sessions.device_cookie` 列留在库里不再读写，
    不做一次性搬运。
- **本批新增遗留（缺口 1 + 2 实施产生）**：
  - 未登记会话（本批之前创建、或直接在上游站点创建）一律拒绝，**唯一恢复途径是管理员在
    后端重新分配**；缺口 3 批次已把该路径落实为 `/api/acl/claim`（管理界面仍未做）。
  - 项目/分支级归属与 `resource_acl.rs` 的产品接线已由缺口 3 批次完成（分支维度除外，见上）。
  - `/realtime` 的 WebSocket 升级桥接与 `/api/livekit/` 语音（后者需真实账号验收）。
  - `/backend-api/estuary/*` 的内容 URL 绝对化（原版规则仅有符号名，未还原）。
  - `/external/*` 的上游主机白名单：2026-09-28 已由「只允许公网目标」的公网策略取代落地
    （原白名单内容仍未还原，也不再尝试还原；见 COMPATIBILITY「前端自愈」）。
  - `/api/account-capabilities`、`/api/account-models`：Django 管理端会调用
    （`backend/app/accounts/views/__init__.py`），候选未注册，逆向路由清单里也没有这两个字面量，
    需实测定性。
- **缺口 5 第一批实施产生的遗留（2026-09-24）**：
  - H2 首帧（SETTINGS 顺序、伪头顺序）未独立复采：抓到它需要给回环监听配测试证书并完成
    握手，本轮没做；取值只来自 `wreq-util` 画像。
  - `signature_algorithms` 缺 ML-DSA（`0904/0905/0906`）：对照浏览器是 Chromium 151，
    候选按 Chrome146 画像；Chrome146 当时的真实取值未取得证据。
  - `sec-ch-ua-platform-version` 在 Linux 真机上的取值未验证（本机只有 Windows Chromium）；
    **已闭合（2026-09-24 源码核对，非运行时）**：Linux 上该开关默认启用 ⇒
    `GetPlatformVersion()` 返回空串 ⇒ 头值 `""`，证据
    `evidence/reference-chrome146-001/04-linux-platform-version.json`。
  - HTTP/1.1 头顺序不受画像控制；上游走 h2，影响有限。
  - WS 握手头是子集：上游 WS 只发身份整组与协商必需头，真浏览器还会带
    `accept-encoding`/`cache-control`/`pragma`；**已收敛（2026-09-24 第二批）**：按真浏览器
    实录补齐，逐跳头与握手自有头不转发，证据 `evidence/ws-handshake-headers-001.json`。
  - **第二批新增遗留（2026-09-24）**：
    - Linux `sec-ch-ua-platform-version`：**已闭合（2026-09-28 运行时复核）**——Linux 上该
      feature 默认 `stable` ⇒ `GetPlatformVersion()` 返回空串 ⇒ 头值 `""`；Windows 参照实测
      `"15.0.0"`。证据 `evidence/reference-chrome146-001/04-linux-platform-version.json`；
      cfbypass 容器内 `probe_identity.py` 与 `/bypass` 的 `identity.user_agent_data.platform_version`
      都实测为空串，与网关声称值一致。
    - cfbypass 镜像（Debian trixie + chromium 146.0.7680.177）与容器内 `probe_identity.py`：
      **已构建并跑通（2026-09-28）**。同一批还修掉两处由此暴露的缺陷：`browser.version()` 让取
      Cookie 接口 500；`new_context(user_agent=...)` 把 UA-CH 换成 Playwright 派生值
      （`architecture` 从原生 `x86` 变 `x64`）。现改为 CDP 覆盖「配置 UA + 浏览器原生 UA-CH」，
      线上头与网关常量逐字段一致，详见 COMPATIBILITY「打包与部署」。
    - cfbypass 仍为 headless-only（原版 all-in-one 是 Xvfb + headful）；需要 headful 时补
      xvfb/xauth 与显示管理。
    - 代理出口停用（wreq 走代理关闭 ALPN）；恢复需要保留 ALPN 的代理实现或透明出口。
    - JS 覆盖不涉及语言/时区/字体/WebGL/Canvas/Worker/子框架：这些保持宿主真值，属已知边界。
  - 打包面：**已闭环（2026-09-28）**。`Dockerfile` 改成 `debian:trixie-slim` 两阶段
    （BoringSSL 需要 cmake/clang/libclang 构建、运行期需要 libstdc++），四镜像构建成功并起
    完整栈验证；编排、端口约定与残余见 COMPATIBILITY「打包与部署」。
  - WSL 路径：**已打通（2026-09-28）**。Ubuntu 26.04 内 `cargo test`（22 套件）与
    `cargo clippy --all-targets -- -D warnings` 全过，Docker 构建与运行也都在 WSL 内完成。
  - 尚未做的部署面：All-in-One 单镜像打包、TLS 终结与公网暴露策略、`/admin` 由网关本体自托管
    （候选仍按既有实现把 `/admin` 透传给 Django，管理界面走 nginx 侧车）。
  - 管理端与镜像面不同源时的登录跳转：**已实现（2026-09-29）**，Django 侧 `MIRROR_PUBLIC_URL`
    把网关返回的相对 `/api/not-login` 补成镜像面绝对地址（同源留空即原语义）。部署方需要按
    浏览器实际访问的镜像面地址填写；All-in-One 单端口打包落地后该项可重新置空。详见
    COMPATIBILITY「管理端与镜像面不同源：登录交接地址」。
- 初次登录只调 `me`，原版登录同样先调 `accounts/check`（COMPATIBILITY「未完成/显式差异」）。
- 管理非空库 `gateway_sessions` 自增 ID 偏移与上游调用序列差异、`login extra_cookies` 严格提取契约。
- 审核 provider 的 5 个扩展响应用例（已列非目标，保留 503 门禁）。
- 第二阶段可信身份与新库 ACL 产品接线；第六阶段统一验收与 All-in-One 镜像交付
  （`MirrorNiXiang/rebuild-reference/README.md` 的六条交付步骤，一条未做）。
- **前端自愈的残余（2026-09-28，见 COMPATIBILITY「前端自愈」）**：
  - 页面路由已改按「导航请求」放行（`GET`/`HEAD` + `Accept: text/html`，2026-09-29），
    不再枚举路径清单；未做的是上游 302 的 `Location` 绝对地址重写（实测上游给的是
    同源相对路径 `/auth/login/?next=…`、`/#settings`，尚未构成跳回真实站点的泄漏）。
  - Auto 路径的响应过滤只覆盖 JSON：SSE/流式与二进制正文原样透传，新流式端点靠请求侧 id 判定兜底；
  - 超过 8 MiB 的 JSON 响应整体拒绝（`acl_response_too_large`），不做部分过滤；
  - 六族之外的新资源族出现在数组里会被裁空（fail-closed）；靠 `acl_audit` 的 `route_auto_*`
    记录发现，再按需把该路径登记为账号级；
  - `/external/*` 的抓取一律从 AWS 出口发出；要收紧成域名白名单是一行改动，本批按公网策略实施。
- **录入上游账号的残余（2026-09-29，见 COMPATIBILITY「录入上游账号」）**：
  - 粘贴形态已归一化（`server.rs::pasted_token`）：赋值行、整段 Cookie 文本、Netscape HTTP
    Cookie File、`.0`/`.1` 分块都能取出令牌值。仍**不解析** cookie 文本里的其它 cookie
    （`__cf_bm` / `oai-device-id` 等）：CF 由网关自行合成，设备 cookie 目前没有录入入口。
  - `refresh_token` 录入未实现，与前缀/段数判定无关；原版自身文案即
    「当前网关未实现 refresh_token 刷新」，候选保持同一文案（不触上游）。
  - 凭据形态按 JWT 段数判定（AccessToken 3 段 / SessionToken 5 段且第 2 段为空）；
   两者都以 `eyJ` 开头，若将来自定义凭据格式变化，需要同步 `server.rs::token_kind`。
- **部署环境出网抖动（2026-09-29，见 COMPATIBILITY「上游连接偶发失败的处理」）**：
  - 现象：真实上游探测 20 次中 4 次在约 5 秒后传输层失败；同一环境 `docker build` 也出现
    `auth.docker.io ... EOF`；容器内与 WSL 主机解析 `chatgpt.com` 得到的地址不一致。
  - 已做：凭据类幂等 GET 自动重放一次（含 200ms 等待），持续失败按
    `502 upstream_unavailable` + 可行动文案上报，不再混入「凭据有问题」的语义。
  - 未做（环境侧，非网关可解）：更换/固定出口 DNS 与网络路径；该抖动仍会让非幂等请求
    （生成、SSE）失败且**刻意不重放**。
  - 既有测试抖动：`anonymous_frontend.rs::internal_upstream_media_is_allowlisted_and_credential_free`
    单独跑 6 次失败 1 次（5 秒超时），与本批改动无关，未修（属另一模块的超时假设）。

## 归档说明

`artifacts/phase1/STATUS.json` 与 `COORDINATION.json` 中记录的候选快照/修复哈希
（`f95fc1ee…`、`a03b3c4a…`）指向更早的候选快照，早于本文件登记的时间点；
它们作为历史证据保留，不代表当前 `source/` 的字节状态。

# 下一批优先工作：缺口 1 / 2 / 3 / 5

记录时间：2026-09-23。来源：用户指令「先推进缺口 1、2、3、5」。
编号沿用《距离代替原网关还差什么》的分析结论；**缺口 4（计量 / 配额 / 限流 / 审核 / PoW）
已由产品决定列为显式非目标**，见 [COMPATIBILITY.md](COMPATIBILITY.md) 的对应章节，本批不再开工。

本文件只登记范围、现状证据、依赖与验收要点；**尚未开始实施**。

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
契约测试解析改写表保证「每个前缀都有语义」。**仍未覆盖**：`/external/*` 的真实主机白名单
（原版 `is_allowed_external_proxy_host` 内容未还原），以及真实上游下这些前缀的渲染验收。

验收要点：逐个前缀确认「脚本会改写到它」与「服务端按什么方法、什么扩展名、是否带凭据」；
新增路径一律不许成为任意目标代理；渲染类前缀至少需要一次真实上游观测或合成 fixture 断言。

## 缺口 3：归属登记与三身份隔离未接线

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

依赖顺序：可并行；但 WS（缺口 1）与代理出口在选择逻辑上耦合，先定出口抽象再实现 WS 分流更省返工。

验收要点：每个传输 profile 需有可复现的身份证据，而不是「配置成功」；代理出口与 CF clearance
必须绑定到同一 profile，禁止静默复用旧 clearance；未验证的组合继续 fail-closed。

## 其它仍未完成项（不在本批四缺口内，保留登记）

- **本批新增遗留（缺口 1 + 2 实施产生）**：
  - 未登记会话（本批之前创建、或直接在上游站点创建）一律拒绝，**唯一恢复途径是管理员在
    后端重新分配**；该管理路径本批未实现，只登记在此。
  - 项目/分支级归属（`project_owners`、`enforce_project_owner`）与 `resource_acl.rs` 的
    产品接线仍属缺口 3 完整批次。
  - `/realtime` 的 WebSocket 升级桥接与 `/api/livekit/` 语音（后者需真实账号验收）。
  - `/backend-api/estuary/*` 的内容 URL 绝对化（原版规则仅有符号名，未还原）。
  - `/external/*` 的上游主机白名单（原版 `is_allowed_external_proxy_host` 内容未还原）。
  - `/api/account-capabilities`、`/api/account-models`：Django 管理端会调用
    （`backend/app/accounts/views/__init__.py`），候选未注册，逆向路由清单里也没有这两个字面量，
    需实测定性。
- 初次登录只调 `me`，原版登录同样先调 `accounts/check`（COMPATIBILITY「未完成/显式差异」）。
- 管理非空库 `gateway_sessions` 自增 ID 偏移与上游调用序列差异、`login extra_cookies` 严格提取契约。
- 审核 provider 的 5 个扩展响应用例（已列非目标，保留 503 门禁）。
- 第二阶段可信身份与新库 ACL 产品接线；第六阶段统一验收与 All-in-One 镜像交付
  （`MirrorNiXiang/rebuild-reference/README.md` 的六条交付步骤，一条未做）。

## 归档说明

`artifacts/phase1/STATUS.json` 与 `COORDINATION.json` 中记录的候选快照/修复哈希
（`f95fc1ee…`、`a03b3c4a…`）指向更早的候选快照，早于本文件登记的时间点；
它们作为历史证据保留，不代表当前 `source/` 的字节状态。

# 第十二节：浏览器 JS 可见特征与直连路径审计

## 范围、输入和结论口径

- **已验证一致（输入校验）**：本次唯一输入为 `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/coordination/integrated-f95fc1eeb7d2.zip`，实际 SHA256 `f95fc1eeb7d239dfc5b5e6e999b7c2443dc082a63bc9f6f6f7007e6bc3c53c6e`。提取33文件至 `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input`；未改输入文件，逐文件末尾验哈希见 results。协调给定提交为 `1e1e30e8d0dd500e38f9d45d416bb911c4778c3a`，ZIP字节校验不独立证明其 Git 提交来源。未沿用旧 b837/verification-final 输入。
- **已验证一致（执行范围）**：仅新增本目录审计、合成检查与证据；15个纯函数离线检查通过。没有真实浏览器、Rust服务运行、TLS/H2抓包、公网、真实登录、外部写或生产操作；没有新增伪装脚本、远程浏览器选型、产品接线或主制品变更。原报告原样保留，未重跑109项。
- **存在可解释差异（总判断）**：固定 HTTP UA、浏览器 JS 环境、TLS/H2、WebRTC 是不同层；当前普通反代不能把它们视作同一受控浏览器身份。不得承诺上游无法识别代理。网络出口/UA相同也**不能合并不同用户的 ACL、Cookie、资源归属或实时连接**。
- **尚未验证（证据限度）**：下文“已验证一致”仅指固定快照源码和指定离线输入的一致性，不是与真实上游浏览器指纹一致。外部 Django/Vue 运行构建、上游实际JS、实际浏览器策略/扩展与自定义脚本配置未取得；本次不读取生产DB或凭据。前端引用只核实快照内模板及其资源路径。

## 1. 浏览器可见特征：哪里控制，哪里不控制

| 判定 | 特征与结论 | 证据及范围 |
|---|---|---|
| **已验证一致** | 代理公共头过滤及公共JS/CSS均使用同一个 Chrome146/Linux UA常量；这是源码字面规则，不是本轮网络观测 | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/proxy.rs:65,393-415`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/static_assets.rs:56-73` |
| **存在可解释差异** | API/Django通路克隆端到端头后覆盖UA，未统一 sec-ch-ua/platform/mobile 等 Client Hints；静态通路只有7个允许头，未透传CH；两通路都可保留客户端 Accept-Language。若客户端CH与固定UA不同，会形成可解释的跨层组合；没有实测某个浏览器发送哪些CH | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/proxy.rs:73-92,393-415`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/static_assets.rs:59-73` |
| **存在可解释差异** | 模板未实现 navigator.userAgent/userAgentData/platform/language(s)、Intl时区/Date时区偏移的一致化；读取到的值仍来自执行页面的浏览器环境，而非HTTP UA常量。本次全文字面检索未见相关覆盖，不能据此推断外部JS也未改写 | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:1-1900` 的限定符号搜索，记录于 `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/url-checks.json`；模板navigator操作实际见 `:1169-1175,1314-1328`（Beacon与用户激活导航，不是身份字段） |
| **尚未验证** | 浏览器能力、字体、屏幕、Canvas/WebGL/音频、权限、媒体设备、locale、存储和浏览器版本没有整体一致性证明；改写URL或HTTP UA不等于控制这些能力 | 同一模板的上述限定检索与各URL封装 `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:1074-1402`；未运行真实浏览器，也未下载上游bundle |
| **存在可解释差异** | 代理上游连接由 reqwest/rustls 建立，不是访客浏览器直接建链。未配置可证明与浏览器相同的TLS/ALPN/H2设置、头顺序或连接复用特征；HTTP UA覆盖不控制握手。实际协商协议/指纹尚未验证，不能从依赖名断言H2一定启用或一定相同 | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server.rs:76-80`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/Cargo.toml:18,25` |
| **尚未验证** | WebRTC/STUN/TURN/ICE和音频传输不是 fetch/WS 改写的同义词；没有 RTCPeerConnection 封装/媒体网络约束证据，不能把CSP connect-src当作WebRTC出口封锁证明 | 模板限定搜索无 RTCPeerConnection，`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:1331-1382` 仅WS封装；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/PHASE1_CONTRACT.md:46` 明示真实语音协议未确证 |

## 2. 直连/改写覆盖及当前可达性

| 判定 | 路径或行为 | 当前可达性与证据 |
|---|---|---|
| **已验证一致** | 部分已知HTTP URL改为同源；host列表仅参与URL生成，**不是服务器放行表**。未知HTTP构造 `/external/...`，名单内构造 `/internal-upstream/https/...` | 3项纯函数检查验证输出。`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:11-128`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client-hosts.json:1`。生成路径的业务代理未开放：`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/proxy.rs:123-154` |
| **存在可解释差异** | A.href刻意跳过改写；点击可用 originalWindowOpen 直接打开外部URL；激活中的 window.open 同样直开，且可把本地 `/external`、`/internal-upstream` 解包为外部地址 | 纯函数证明解包行为；调用点静态可见，未真实触发浏览器。`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:129-147,870-891,1035-1055,1314-1328`。若该脚本运行并发生此交互，离开网关是设计行为，不是代理出口统一；当前聊天首页未开放，不能声称现已泄露 |
| **存在可解释差异** | 仅 ws.chatgpt.com 的几个精确前缀改为同源 `/ws-chatgpt/`；任意其他WS URL原样返回。CSP connect-src允许整个 ws:/wss: scheme，不是仅同源WS | 2项WS纯函数检查。`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:1333-1352`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server.rs:156`。服务器没有开放该WS业务路由（fallback仅两种GET读取）；不等于声音走WS、不证明实际WS已连接 |
| **存在可解释差异** | srcset不在元素属性列表；EventSource、普通Worker/ServiceWorker、模块import没有通用拦截证据。Mapbox Blob只有满足签名条件才注入专门worker代码，不能覆盖所有worker realm | srcset mock检查原值未改。`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:870-901,1149-1164,1181-1184,1271-1305`。唯一核实的模板动态import指向同源MermaidJS `:270-278`；外部bundle的 import/worker/URL列表未取得。若实际URL落入CSP允许范围可能直连；不能把mock的fixture.invalid视为浏览器CSP会放行 |
| **存在可解释差异** | 普通外部CSS/JS正文服务器原样流转，不做完整URL语法分析；脚本的字符串replace仅在特定DOM/CSS调用封装中执行，不覆盖所有CSS转义/相对基址/@import、媒体属性或模块加载 | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/static_assets.rs:108-129`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:797-869,1384-1402`。受限JS/CSS通路当前源码已开放；但没有实际上游bundle与真实页面执行证据，不能宣称已发生外连 |
| **存在可解释差异** | inject_client_resource 把模板追加在原body末尾，而非保证原HTML解析/预加载之前安装；MutationObserver主要监听新增节点，Location补丁取决于可改属性且异常被吞。跨源iframe不会因此自动获得全部fetch/身份控制 | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/proxy.rs:540-576`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:950-1008,1250-1296`。潜在安装时序/原型兼容差异需隔离浏览器测试，目前没有这种验收 |
| **存在可解释差异** | CSP显式允许多个外部 connect/img/font/script/frame 来源及 ws:/wss:，不是“禁止所有直连”的策略；私网URL在JS helper里“不代理”也不等于“阻断请求”，blob/data也保留，最终受浏览器/CSP/内部内容决定 | helper私网/blob/data测试；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/assets/gateway-client.html:104-128`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server.rs:156,235-239`。未测试任何私网服务，不将字面URL处理当作请求或泄露证据 |
| **尚未验证** | 主聊天 `/`、`/c/...` 仍门禁；但不能说整个注入逻辑绝对不可达：已开放 `/backend-api/me` 经 buffered_response，若授权通过且上游返回 text/html 会满足注入条件；conversations也按原MIME检查。正常JSON响应不会执行此脚本 | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/proxy.rs:131-154,184-194,239-249,523-551`。这是条件调用链，不是实测恶意/错误HTML；本轮未启动Rust或请求此路径 |
| **尚未验证** | `/admin`/`/0x` 走Django流式代理，不调用该chat注入；因此不能把此模板覆盖范围直接套在管理前端上 | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server.rs:137-140`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/proxy.rs:162-181`。快照无Django/Vue运行构建，本轮未扩读外部目录 |

## 3. 普通反代保证边界与最小架构取舍（不选型）

- **已验证一致（仅代码职责）**：对实际进入已开放固定源通道的请求，可在服务端控制目标、选用的账户凭据及部分HTTP头；静态仅允许安全JS/CSS并禁止重定向。这不等于控制浏览器所有网络。证据：`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/proxy.rs:450-506`；`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/input/src/server/static_assets.rs:8-28,47-84`。
- **存在可解释差异（不能保证）**：普通反代不能仅凭UA替换，保证JS平台/时区/语言/硬件能力、浏览器实现细节、TLS/H2与本地媒体ICE一致，也不能让未进入代理的导航/WS/worker请求使用同一出口。当前CSP和rewrite不是全路径网络隔离证明；不能承诺代理不可识别。
- **尚未验证（方案A，保留现浏览器+反代）**：改动最小，可继续现聊天界面；文件和页面不增加远程桌面转码开销，语音仍使用本地设备。代价是接受浏览器执行环境差异，后续须按已证实路径做可观测一致性检查；不能以补几段伪装JS宣称一致。多人ACL仍逐身份/账号/资源校验。
- **尚未验证（方案B，只有需求明确要求统一执行环境时才评审）**：服务端受控浏览器可把JS运行时与上游浏览器建链放在同一执行环境，但不是本轮决定。需继续运行现页面、另加显示/交互传输；语音面临麦克风授权、音频转发/延迟与ICE路径取舍；文件需受控上传下载桥；新增CPU/GPU/内存、并发、带宽与冷启动成本。必须按用户/会话隔离profile、Cookie、下载目录、进程/容器和资源ACL；不能共享一个浏览器profile来“统一身份”。客户端到远程环境仍有独立网络特征，也不构成不可识别保证。

## 4. 实际命令、证据与下一步

- **已验证一致（离线函数层）**：运行 `E:/T/NodeJs2026_6/node.exe C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/check_url_boundaries.cjs`，exit0、stderr空；stdout末行：`TOTAL=15 PASS=15 NETWORK_CALLS=0 REAL_BROWSER=false`。脚本只把实际源码中纯URL/元素函数放进无网络API的VM，执行字符串和mock元素输入；“NETWORK_CALLS=0”描述脚本没有调用网络API，不是外网抓包结果。
- **已验证一致（复核边界）**：实际命令argv、输入描述、逐项输出见 `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/commands-section12.json`、`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/VERIFICATION_SECTION12.txt`、`C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/url-checks.json`。最终输入ZIP/33文件稳定检查追加到命令台账。测试只证明上述helper输出，不证明浏览器CSP、HTTP头、Rust路由或真实上游身份一致。新测试仅断言实际边界，没有容错fallback或网络重试。
- **尚未验证（未执行项）**：真实浏览器DOM加载时序、原型可改性、iframe/worker realm、真实CSP执行、CH协商、TLS/H2握手、WebRTC/语音、Django/Vue运行前端及端到端直连流量。源码上未实现/未开放的路径不记为通过。
- **尚未验证（可执行下一步，等待协调安排，不自动扩展）**：先保持页面门禁；可另批用无公网出站的浏览器+回环fixture测试 parser初始加载、srcset/模块import/worker、用户激活导航、WS/CSP 与条件HTML响应，记录请求是否到达fixture。再由唯一owner判断是否需要收紧路径或CSP、补兼容实现。只有业务明确要求执行环境统一时才另行评审远程浏览器，不在此次选择架构。任何阶段网络身份一致性都不能代替或放宽ACL。

交付状态：**已验证一致（本轮审计及指定离线检查完成）**；整体镜像/身份一致性/真实环境验收仍**尚未验证**。协调任务及唯一集成人不变，无交接。

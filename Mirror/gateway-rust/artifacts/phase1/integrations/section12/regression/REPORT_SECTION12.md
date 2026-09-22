# 第十二节：上游可见访问身份一致性——HTTP/下载/WebSocket/语音出口
## 范围与结论
- **已验证一致（仅输入完整性）**：固定提交 `1e1e30e8d0dd500e38f9d45d416bb911c4778c3a`、归档SHA256 `f95fc1eeb7d239dfc5b5e6e999b7c2443dc082a63bc9f6f6f7007e6bc3c53c6e`；33 个输入文件构建/探针后hash逐一未变。只写本section12目录，未改产品/测试源码、主状态或主四角色。
- **存在可解释差异**：业务client是no_proxy直连固定源；已保存代理并未约束业务出口。临时代理诊断client才使用显式proxy，而且其重定向策略不同。这不是完整的统一网络身份实现。
- **已验证一致（限定离线用例）**：17个定点请求probe exit=0，环境proxy陷阱和诱饵直收均0；两个连接故障未观察到改用其他出口。只构建现有binary，未跑全套109。
- **尚未验证**：真实TLS/HTTP2/公网IP/DNS/浏览器身份、文件下载、WS与语音成功通道。不能承诺上游无法识别代理，也不将网络身份合并为跨用户ACL。

## 分项结论（每项均限定证据范围）

### HTTP_FIXED_ORIGINS — 已验证一致
Django、聊天/me、accounts/check刷新、公开JS、CF预热均使用主app.client固定源，环境代理陷阱0；不接受本次target query改选诱饵。
范围：本次明文IPv4回环HTTP配置出口与源码一致，不是与真实浏览器身份一致。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:73-91`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:162-194,263-310,479-508`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\static_assets.rs:47-74`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:1031-1049`
运行证据：chat-fixed-direct、refresh-fixed-direct、django-fixed-direct、cdn-fixed-direct、startup CF egress

### SAVED_PROXY_NOT_BINDING — 存在可解释差异
enabled=true/proxy_url保存及读取成功，但业务仍直达配置源；只有test_proxy临时client使用显式proxy。配置保存不构成所有流量统一出口的保证。
范围：配置持久化、业务请求和诊断请求的出口选择。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:76-80,695-761`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:502-508`
运行证据：save-proxy-config、read-saved-proxy-config、cdn-fixed-direct、explicit-proxy-diagnostic

### REDIRECT_POLICY_DIFFERENCE — 存在可解释差异
me上游302原样回给客户端但未服务器跟随；CDN302被502门禁；诊断client跟随302，将第二个绝对URI送至同一显式proxy。这是策略差异，不是已发生凭据泄露的结论。该proxy只是返回fixture，不代为访问目标；两次请求头仅为本次synthetic记录。
范围：主client vs 代理诊断client。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:76-80,743-761`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\static_assets.rs:81-85`
- `E:\M\Project\MiRebuild\Mirror\gateway-rust\.build\phase1-toolchain\cargo\registry\src\index.crates.io-1949cf8c6b5b557f\reqwest-0.12.28\src\redirect.rs:160-164`
运行证据：chat-redirect-not-followed、cdn-redirect-rejected、diagnostic-follows-redirect-via-proxy

### FAILURE_NO_FALLBACK_CASES — 已验证一致
显式代理端口拒绝返回400且没有直连chat；chat服务关闭后502仅有Django授权调用，未转到proxy/CDN/诱饵；503只收到1次chat HTTP请求。
范围：两个连接拒绝用例和一个HTTP503用例；仅有限观察。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:743-761`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:123-158,502-508`
运行证据：failed-explicit-proxy-no-direct-fallback、failed-chat-no-proxy-or-other-origin-fallback、chat-503-no-app-retry

### LOW_LEVEL_RETRY — 尚未验证
应用没有配置retry策略，不等于禁用重试；reqwest默认ProtocolNacks是库的受限协议错误重试条件，源码上限max_retries_per_request=2（原请求之外），不等于已观察到应用重放。单次503实测只收到一次chat请求；协议NACK/TLS/HTTP2均未实测，本feature没有reqwest http2，生成路径也未开放。不能将源码潜能写成已发生重复生成；未来生成开放前必须显式禁止或界定重试策略。
范围：协议NACK、连接复用重试和所有传输错误分类。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:76-80,748-753`
- `E:\M\Project\MiRebuild\Mirror\gateway-rust\.build\phase1-toolchain\cargo\registry\src\index.crates.io-1949cf8c6b5b557f\reqwest-0.12.28\src\async_impl\client.rs:310-311,1400-1404`
- `E:\M\Project\MiRebuild\Mirror\gateway-rust\.build\phase1-toolchain\cargo\registry\src\index.crates.io-1949cf8c6b5b557f\reqwest-0.12.28\src\retry.rs:192-199,424-460`
运行证据：无对应运行探针；上述实现事实仅源码审计，不记功能通过。

### HTTP_HEADER_PROFILE — 存在可解释差异
初次登录fetch_user未带User-Agent，代理me/刷新/CDN使用固定DEFAULT_USER_AGENT，诊断也无UA；代理me有固定Origin/Referer而CDN没有。凭据差异按作用域保留，不应为统一身份合并用户凭据。
范围：实测登录me、代理me/刷新、CDN与诊断的HTTP头。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:421-446,748-758`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:63-65,393-415,447-475`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\static_assets.rs:54-73`
运行证据：login-despite-enabled-proxy、chat-fixed-direct、refresh-fixed-direct、refresh-fixed-direct、cdn-fixed-direct、explicit-proxy-diagnostic

### TRANSPORT_FINGERPRINT — 尚未验证
Cargo依赖使用reqwest rustls-tls/json/stream/socks；本次feature tree没有reqwest http2，所有fixture收到HTTP/1.1。全程无TLS握手，不能用头值或同一loopback源IP宣称TLS/HTTP2/真实访问身份一致或上游无法识别代理。
范围：TLS ClientHello/ALPN/HTTP2设置、出口公网IP/DNS、真实上游识别。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\Cargo.toml:18,25`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\config.rs:23-55,76-99`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:728-753`
运行证据：cargo tree -e features -i reqwest、http-events.json

### DOWNLOAD_MEDIA — 尚未验证
公开JS/CSS从独立CDN流转发可观测；未知下载sentinel、私有PNG路径503，无媒体上游请求。Rust未开放文件下载业务，所以无法验证其访问身份一致。
范围：私有文件、媒体下载；不把JS/CSS当文件业务验收。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\static_assets.rs:8-28,123-129`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:123-154`
运行证据：cdn-fixed-direct、unopened-download-sentinel、unopened-media-path

### WEBSOCKET — 尚未验证
Rust src检索未见WebSocketUpgrade/connect_async出站或注册；模板将指定ws.chatgpt.com改写为/ws-chatgpt，其他URL原样交给native WebSocket。对应合成子路径Upgrade请求503、不是101。既无成功连接，也未运行浏览器，不能把模板或依赖能力算通过。
范围：服务端WebSocket出口及浏览器实际连接。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:93-145`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:123-154`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\assets\gateway-client.html:1331-1382`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\Cargo.toml:10,25`
运行证据：template-websocket-route-gated

### VOICE — 尚未验证
没有已开放的语音处理器或实际语音流；模板/realtime字符串不是语音协议证据，不能推定WebSocket/WebRTC/UDP，也未对语音做成功模拟。
范围：真实语音信令、媒体通道与协议类型。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\assets\gateway-client.html:23-31`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server.rs:93-145`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:123-154`
运行证据：无对应运行探针；上述实现事实仅源码审计，不记功能通过。

### BROWSER_BYPASS_SCOPE — 尚未验证
模板userActivation下window.open可恢复外部URL直导航；未匹配WS保持原URL。源码存在直接浏览器路径，不表示本轮首页已开放或已实证流量绕行；未来浏览器验收必须覆盖，不能只审计Rustclient。
范围：历史客户端模板的真实浏览器激活路径。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\assets\gateway-client.html:129-146,1314-1328,1333-1376`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\PHASE1_CONTRACT.md:69-72`
运行证据：无对应运行探针；上述实现事实仅源码审计，不记功能通过。

### ACL_SEPARATION — 尚未验证
出口统一不能合并不同用户权限；refresh仍按user/account/token读取，独立resource_acl模块尚未路由接线。本轮仅单一synthetic账号，不复做线2重登录竞态，不声称资源ACL已验证。
范围：本轮不验收跨用户ACL或重登录竞态。
源码证据：
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\src\server\proxy.rs:268-280,313-325`
- `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\input\PHASE1_CONTRACT.md:77-80`
运行证据：无对应运行探针；上述实现事实仅源码审计，不记功能通过。

## 实跑请求、出口与退出码
全部listener、目标、显式代理与环境代理陷阱均为127.0.0.1随机独立端口。先删除全部名称含proxy的继承env，再只注入本机fixture；Python HTTPConnection不读取代理env，不自动跟随redirect。代理fixture只记录绝对URI并返回合成响应，不进行真实转发。出口证据是这些listener收到的HTTP，不是全机网络抓包。

| case | HTTP | 收到请求的fixture顺序 |
|---|---:|---|
| save-proxy-config | 200 | 无 |
| read-saved-proxy-config | 200 | 无 |
| login-despite-enabled-proxy | 200 | django → chat |
| chat-fixed-direct | 200 | django → chat |
| refresh-fixed-direct | 200 | django → chat → chat → django |
| django-fixed-direct | 200 | django |
| cdn-fixed-direct | 200 | cdn |
| chat-503-no-app-retry | 503 | django → chat |
| chat-redirect-not-followed | 302 | django → chat |
| cdn-redirect-rejected | 502 | cdn |
| explicit-proxy-diagnostic | 200 | explicit-proxy |
| diagnostic-follows-redirect-via-proxy | 200 | explicit-proxy → explicit-proxy |
| failed-explicit-proxy-no-direct-fallback | 400 | 无 |
| unopened-download-sentinel | 503 | django |
| template-websocket-route-gated | 503 | django |
| unopened-media-path | 503 | 无 |
| failed-chat-no-proxy-or-other-origin-fallback | 502 | django |

启动CF预热单列在原始events中，不误计入首个case。总出口计数：`{"django": 10, "chat": 6, "cdn": 2, "cf": 1, "explicit-proxy": 3, "env-proxy-trap": 0, "decoy": 0}`。

新binary：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\target\debug\mirror-gateway.exe`；SHA256 `cdfaa8b675973a77aa03425430146602947b05c91ddf244c8574caf9e459ac46`。Cargo build exit=0、cargo tree exit=0、probe runner exit=0。网关是常驻服务，观测后只终止自有PID 41620，实际exit=1；不伪称自然正常退出。stdout中的“代理端口连接失败”来自预期拒绝用例。

实际命令/字面stdout/stderr：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\build-records.json`、`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\probe-command.json`、`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\gateway-command.json`。
完整请求/响应/出口：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\http-events.json` 与 `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\probe-cases.json`；机器读结果：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\section12\results-section12.json`。

## 实现状态、限制与下一步
本轮没有产品实现交付，只有只读审计和自包含离线fixture runner。没有公网/真实账号/生产库/原版QEMU/远程浏览器/伪装脚本操作。与线2重合的保存代理只保留作为比较诊断和业务出口的必要前置，未重做重登录竞态。
1. 由owner评审保存代理与实际client是否应一致，并明确diagnostic redirect边界；发现不等于获得本轮修复授权。
2. 未来生成路径开放前必须显式禁止或界定重试策略，并实测受限ProtocolNacks条件。当前生成路径未开放、reqwest http2 feature未启用；503只收到一次请求。NACK/TLS/HTTP2未实测，不能据源码潜能声称已经应用重放或重复生成。
3. 等媒体/WS/语音真实协议与授权齐备再测成功通道；继续门禁。浏览器端模板的直导航/原样WS也须独立验收。
4. TLS/ALPN/HTTP2身份必须另做明确授权的受控测量，不能以UA/HTTP头一致替代；权限主体始终保持用户、账号与资源ACL分离。

## 历史四角色（已重新打开，未覆盖、未重跑，非本轮输入）
历史b837事务仍为BASELINE 64、MODIFIED 72、ROLLBACK 64，恢复hash一致；本轮不把这些历史值或static60ab 78项当作f95验收。
- `MODIFIED_FILE`：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\MODIFIED_FILE.zip`
- `DIFF_FILE`：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\DIFF_FILE.patch`
- `VERIFICATION`：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\VERIFICATION.txt`
- `ROLLBACK`：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\ROLLBACK.sh`

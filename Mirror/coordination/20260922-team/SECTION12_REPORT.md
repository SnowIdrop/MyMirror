# 第十二节：上游可见访问身份一致性——协调验收补充

## 结论

已将用户第十二节纳入页面开放前的硬门禁，复用三条独立工作线完成实际审计与离线检查。**目前不能认定端到端访问身份一致；本轮未修改产品、未运行真实账号、未增加指纹伪装脚本或远程浏览器方案。** 唯一集成人与原四角色不变，无交接。

本轮输入为 `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/coordination/integrated-f95fc1eeb7d2.zip`，SHA256 `f95fc1eeb7d239dfc5b5e6e999b7c2443dc082a63bc9f6f6f7007e6bc3c53c6e`。与提交 `1e1e30e8d0dd500e38f9d45d416bb911c4778c3a` 比较：32文件逐字节一致，COMPATIBILITY.md仅CRLF/LF不同，无正文差异；测试以该ZIP精确hash为准，不宣称Git与ZIP全部字节相同。

## 三类验收结果

### 已验证一致——仅限本轮列出的离线条件

- 数字回环HTTP探针中，已开放Django、chat、refresh、CDN、CF请求走各自服务端固定源；环境代理陷阱未收到请求。两个连接拒绝用例没有观察到切换出口，单次503只收到一次chat请求。
- 同一上游账号的Alice/Bob保持独立本地会话、凭据和extra_cookies；Alice退出不影响Bob。`auth_session`精确token快照、网络前后校验与相关撤权测试通过。
- 对自有进程使用同一合成DB/key受控重启后，Alice/Bob绑定仍保持。**这不证明公网出口、TLS连接、CF或真实设备身份在重启后不变。**

### 存在可解释差异——不是已接受，也不是验收通过

| 差异 | 实际证据与影响 |
|---|---|
| **代理配置与实际出口脱节** | enabled配置保存200、proxy_node_id落库，但普通业务仍用主client `.no_proxy()`，显式proxy陷阱0；只有诊断端点另造proxy client。应先统一实际出口选择及失败语义，不能把配置保存视为生效。 |
| **普通请求凭据代次未固定** | 旧me请求读旧token后等待Django期间，同Alice/同账号重登录提交新凭据；旧请求恢复后按(user,account)取中新access/cookie并返回200，下一次旧token401。确定性trace已保留。不是跨用户/跨账号泄露；list只定位同helper，未运行其竞态。 |
| **登录/代理/静态/诊断特征不统一** | 初次login与诊断未带固定UA；普通代理、刷新与静态使用固定Chrome146/Linux UA。代理可保留客户端CH，静态白名单不转CH；浏览器JS平台/语言/时区等不由该UA控制。 |
| **浏览器直连覆盖不完整** | 模板主动外链导航、非匹配WS、srcset及一般worker/import等没有统一出口证明；CSP允许外部源及ws:/wss:；末尾注入不能保证先于原HTML加载。15项纯函数测试验证部分URL处理边界，不是真实浏览器流量观测。主页面仍关闭；已开放me收到text/html时存在条件注入调用链，不能声称模板完全不可达，也不能声称已经泄漏。 |
| **不同传输入口的策略不一致** | 主client不跟随302，CDN302返回502；诊断client实际跟随302并将第二个目标送入同一显式proxy。未声称凭据泄露。库ProtocolNacks存在受限重试条件，但本轮未观测NACK或重复生成；生成路径尚未开放。 |
| **语音能力还有浏览器策略门禁** | `server.rs:246`及合成HTTP响应含 `Permissions-Policy: camera=(), microphone=(), geolocation=()`。实际语音未启用/验收，不能仅补网络转发就认为麦克风与媒体链路可用。 |

关键源码复核均在当前候选：
- `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/source/src/server.rs:73-80,743-761,888-942,981-1004`。
- `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/source/src/server/proxy.rs:263-325,393-415,540-576`。
- `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/source/src/assets/gateway-client.html:1314-1352`。

### 尚未验证——不得将未开放记为通过

真实公网IP/DNS/NAT出口、TLS/ALPN/HTTP2特征；真实浏览器UA/Client Hints/平台/语言/时区/能力及完整请求瀑布；文件/私有媒体下载、成功WebSocket、实际语音协议/ICE路径；上游device/session标识、cookie续期及全局CF缓存与账号/出口/profile绑定；全部重连/刷新/重启/故障组合；生成不重放及产品资源ACL全链。

当前回环HTTP为HTTP/1.1，实际Cargo feature tree未启用reqwest http2；不能据依赖支持能力就声称运行了HTTP/2，更不能仅凭UA或HTTP头一致声称完整指纹一致。

## 会话执行上下文：最小契约提案（尚未实现）

每个请求固定以下服务端绑定；这不是新用户系统或指纹伪装层：

1. 可信Django主体和授权版本；独立本地session引用、token绑定代次。
2. 服务端解析的上游账号、已证实的认证会话引用。
3. 加密凭据/Cookie bundle引用及代次；Cookie域、有效期与更新规则只能按已确认协议处理。
4. 已批准的实际出口策略/profile引用与版本；未接通或不可用必须失败，不静默直连/换出口。
5. 实际网关传输及客户端特征profile引用与版本；浏览器JS真实观察单独记录，不能由UA替代。
6. 只有协议已证实时才保存上游device/session引用；未知保持未知，不随机补造。
7. 有效期/撤权状态；重登录、凭据或出口/profile改变产生明确代次转换，旧操作不拿新身份继续，不自动重放生成。

刷新当前只是accounts/me信息刷新，不是真正token续期。普通me/list需补原token/代次绑定；重启应复核保存绑定与实际profile是否仍有效，不能继承失效假设。实时重连尚未实现，必须未来按实际协议保持同代次或明确失效，不能推定语音一定是WS。

**网络执行上下文与资源ACL正交**：账号、出口、UA、上游设备/Cookie不能替代稳定Django user_id，也不能导致不同用户资源权限合并。独立ACL模块仍未接入产品全路径，相关门禁继续保留。

## 架构取舍与批准边界

- **保留本地浏览器＋普通反代**：可继续现界面与本地设备，文件交互与性能开销较小；能统一进入网关的服务端执行上下文，但不能仅靠改头控制JS运行时、所有浏览器网络或媒体路径。端到端目标需逐项验收，不能堆伪装脚本掩盖差异。
- **受控浏览器执行环境（仅备选，未选择）**：可能使JS运行时与浏览器上游连接处于一个受控环境，但需要显示/交互传输；影响麦克风权限、音频转发/延迟与ICE、文件桥接、CPU/GPU/内存/带宽/冷启动。必须逐用户隔离profile、Cookie、下载目录和进程，并继续资源ACL；不能共用profile来“统一身份”。任何这类架构改变须先取得方向确认。

本轮不做架构切换。局部绑定/出口修复可在既有开发范围内由唯一owner另批实施；只有扩大架构、真实账号、外部写或生产操作才需对应的新确认。任何方案均不承诺上游绝对无法识别代理。

## 实际检查与证据

| 工作线 | 本轮实际执行 | 证据 |
|---|---|---|
| 会话/生命周期 | 7项相关既有Rust测试、当前源build、确定性重登录/重启回环probe均exit0 | `C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/REPORT_SECTION12.md`、同目录results-section12.json/commands-section12.json/probe-output |
| 出口/故障 | 当前源build、feature tree、17请求回环probe均exit0；环境代理陷阱0、诱饵直收0 | `C:/Users/Administrator/.codex/worktrees/0bb0/MiRebuild/coordination/regression/section12/REPORT_SECTION12.md`、同目录results-section12.json/probe-command.json/probe-cases.json/http-events.json |
| 浏览器边界 | 15项实际源码纯函数VM检查exit0；`NETWORK_CALLS=0 REAL_BROWSER=false` | `C:/Users/Administrator/.codex/worktrees/42ea/MiRebuild/coordination/admin/section12/REPORT_SECTION12.md`、同目录results-section12.json/commands-section12.json/url-checks.json |

网关常驻进程由各fixture主动terminate，记录exit1，不冒充自然正常退出。没有重跑109全套，也没有把这些新检查相加为产品测试数。所有三方输入33文件前后hash保持；协调重开6份报告/结果并校验来源，事件 `21cb3c exit0`；首次严格Git/ZIP字节断言 `bf925c exit1` 的换行差异已如实保留于section12-provenance.json。

## 原四角色与历史三态

本轮没有产品改动事务。保留历史配置 BASELINE拒绝(exit1)→MODIFIED接受(exit0)→ROLLBACK拒绝(exit1)；静态401→200→401；刷新free→plus→free，恢复hash `bc0b14a57a4e1106ebf0fb5500831f8e659879cd3a6f8a2db466a7f28c8cb6c2`。这些不是本轮指纹验收。

- `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/MODIFIED_FILE.zip`
- `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/DIFF_FILE.patch`
- `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/VERIFICATION.txt`
- `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/ROLLBACK.sh`

下一执行起点：owner接收本补充门禁与确定性trace，优先普通请求凭据代次/实际出口绑定的最小回归与修复设计，再继续无公网浏览器＋回环fixture的HTML初始化、CSP/导航/worker/WS覆盖验证。未满足第十二节前，不以“页面能打开”作为镜像身份一致性通过。

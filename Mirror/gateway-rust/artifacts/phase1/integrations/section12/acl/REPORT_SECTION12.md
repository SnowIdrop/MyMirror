# 第十二节：认证会话、账号、出口与client profile绑定审计

当前：集成快照审计 / 7项相关测试及新增回环probe已执行 / 无产品修改，交由唯一owner评审。

## 1. 范围、输入、证据分层

- 快照：[integrated-f95fc1eeb7d2.zip](E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/coordination/integrated-f95fc1eeb7d2.zip)；SHA256 `f95fc1eeb7d239dfc5b5e6e999b7c2443dc082a63bc9f6f6f7007e6bc3c53c6e`；源码提交 `1e1e30e8d0dd500e38f9d45d416bb911c4778c3a`。
- 只读提取位置：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\section12\input`；33文件前后hash相同；未以旧b837或旧verification目录作为本轮源码依据。
- 所有写入仅在本section12目录：报告、Python合成诊断probe、临时DB、构建产物与证据；不改Config、公共路由、主source、主四角色或STATUS。未启动子代理/新任务。
- 配置意图、源码实际路径与运行观测分开列出；本轮7项相关既有用例，不重跑全套109。真实账号/公网/外部写/生产操作均未执行，不涉及受保护域名。
- **不承诺上游无法识别代理。** 当前HTTP回环fixture不能证明真实出口IP、TLS/HTTP2、设备身份或浏览器指纹一致，也不选择远程浏览器架构。
- 协调任务01a0c9c9-4508-75d1-a709-20aa6dbb69f9、唯一集成人01a0c9af-fab7-7780-af7f-537dde662636不变，无交接。

## 2. 逐项结果（状态只对所列证据范围成立）

### S12-01 【已验证一致】共享账号不合并本地用户会话
gateway_sessions按(user_name,chatgpt_username)唯一，随机mirror token只保存hash；同一上游账号下Alice/Bob可有独立access_token/extra_cookies和login_mode。Alice重登录、handoff、logout不替换Bob的行。本轮也实际观察同账号下两套不同合成凭据/cookie各自被选取。
证据位置：[schema.sql:35-54](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/schema.sql)；[server.rs:328-359,948-978](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[proxy.rs:313-325](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)
运行证据/范围：coord_shared_account_token_rotation_preserves_other_user；coord_local_sessions_distinct_accounts_and_logout_are_isolated；probe-output/observations.json:shared_account,persisted_binding,logout
限制：仅会话行和凭据选择；不是产品资源ACL全链验收，也不保证同账号各用户共享同一个上游device/session。

### S12-02 【存在可解释差异】普通me在重登录期间未固定凭据代次
确定性时序：旧请求先从DB读旧token对应Session并释放锁；其Django授权HTTP已到fixture但尚未返回；同Alice/同账号新登录完成可信fixture授权和me校验并提交新token/新凭据；再释放旧Django响应(active=true、相同v1)，旧session校验通过；load_credentials只按(user,account)取到新access/extra_cookies。旧在途me=200且用synthetic-alice-new，后续旧token请求=401。generation只是本报告的代次概念，当前无该列。
证据位置：[server.rs:888-942,351-359](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[proxy.rs:135-147,185-194,313-325](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)
运行证据/范围：probe-output/observations.json:inflight_relogin；probe-output/synthetic-events.json events 4,5,6,7；probe_lifecycle.py
限制：不是跨用户/跨账号泄露。fixture保留同一授权version；真实Django若同时令旧授权失效，结果可能不同。conversations使用同一load_credentials路径，仅源码推及风险，本轮未运行该路径竞态。

### S12-03 【已验证一致】auth/session刷新有更强的token绑定
refresh_auth_session按user/account/mirror_token精确取凭据快照，不持DB锁等待网络；每次accounts/check后me；拒绝email变更；外层再次session验证，因此等待期间撤权可完成且结果变空对象。accounts HTTP失败仍检查me并显示free，me401/账号不匹配返回{}。
证据位置：[proxy.rs:263-310](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)；[server.rs:981-1004](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[auth_refresh.rs:49-196](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/tests/auth_refresh.rs)
运行证据/范围：auth_refresh:3 tests exit0
限制：这里只是账号计划/用户信息刷新，不是access/session/refresh token续期。不能把该精确token保证外推到普通me/list；UI expires=2099是兼容展示，不是真正授权到期。

### S12-04 【存在可解释差异】出口配置意图没有进入普通请求执行
mirror_proxy.enabled/proxy_url/transport_mode设置可以保存，proxy_node_id可以在会话落库；主App客户端始终no_proxy且无节点选择读取。隔离probe保存enabled配置=200、两行proxy_node_id=71，普通me直接到固定回环上游，proxy-trap命中0。独立test_proxy端点另造代理客户端，不等于普通链路采用该配置。
证据位置：[server.rs:73-85,353-354,695-761](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[schema.sql:47](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/schema.sql)；[proxy.rs:502-508](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)
运行证据/范围：probe-output/observations.json:configured_proxy_unused,persisted_binding
限制：只验证本候选合成回环条件；没有真实代理出口IP、DNS、NAT、TLS或公网归属观测。未运行test_proxy端点。

### S12-05 【存在可解释差异】登录和代理请求未使用同一头/cookie上下文
登录fetch_user直接client.get+bearer，初始三次me实测UA/Cookie/Origin均缺失；之后普通代理me使用固定UA、会话extra_cookies及固定Origin。session_token交换也走独立cookie-only请求路径（该交换仅源码审计）。因此一个账号的登录与后续代理并非统一client profile执行。
证据位置：[server.rs:422-446](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[proxy.rs:64-65,393-415,447-508](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)
运行证据/范围：header-observations.json event_index 1,3,6 vs 7,9,11
限制：不评估哪组头更像浏览器，不实现伪装；UA文本不等于TLS/HTTP2/设备身份。

### S12-06 【尚未验证】上游device/session和cookie生命周期缺专用契约
schema有本地id、mirror_token、access/session token及extra_cookies，没有专用上游device_id/session_id、cookie作用域/有效期/版本、client_profile或credential_generation字段；generic加密payload可以保留未消费字段，但不能算可信绑定。extra_cookies仅解析name/value。合成fixture_device只是任意cookie名，不是已证实的上游设备协议。
证据位置：[schema.sql:11-23,35-54](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/schema.sql)；[server.rs:336-350](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[proxy.rs:256-259,328-342](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)；[config.rs:6-21](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/config.rs)
运行证据/范围：bounded source inspection of schema/storage/server/proxy/config；header-observations.json
限制：真实设备、账号session、cookie过期/换发语义均未观测，不得从名称猜测或补造ID。

### S12-07 【已验证一致】登出和版本撤权阻止后续请求
logout删除指定user_name的所有账号会话及授权行；revoke按subject/version/expiry及明确访客前缀匹配后删除。当前本地测试确认旧版本撤权不误删新版本会话，Alice退出后Alice401/Bob200；mirror_profile下请求还回查Django。
证据位置：[server.rs:493-559,923-940](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[policy.rs:197-259](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/policy.rs)；[mirror_auth.rs:109-166,224-270](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/tests/mirror_auth.rs)
运行证据/范围：mirror_authority_revocation_and_relogin_are_enforced；probe-output/observations.json:logout
限制：只对下一请求及专门测试的refresh结果成立；没有全路由在途取消/实时断连。管理密钥是服务认证，不是可信管理员操作者。

### S12-08 【已验证一致】同DB同key重启保留本地会话绑定
本轮实际终止自己的空闲候选进程后用相同全新DB/key重启，Alice/Bob各自凭据和extra_cookies仍对应原用户，授权重新回查。上游Set-Cookie: fixture_rotated不会被reqwest自动吸收到持久cookie组，后续和重启后请求仍仅携带已保存extra_cookies。
证据位置：[storage.rs:198-220,444-505](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/storage.rs)；[server.rs:73-85,888-942](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[proxy.rs:313-342,420-435](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)
运行证据/范围：probe-output/observations.json:restart；probe-output/processes.json；header-observations.json event_index 13,15
限制：受控terminate而非优雅关机，进程退出码1是测试主动结束；无在途写入压力测试。不能推出公网出口、CF cookie、TLS连接或真实设备重启稳定。

### S12-09 【尚未验证】全局CF缓存没有账号/出口/profile绑定
cf_cache是App级Option<Value>，启动预热或任一有效session刷新后整体替换；发送helper从全局缓存选择cf_clearance，未按账号、节点、profile或代次索引。请求user_agent参数固定，但不足以证明结果属于相同实际出口/传输身份。
证据位置：[server.rs:33-38,73-90,1021-1057](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[proxy.rs:344-364,479-508](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)
运行证据/范围：source execution path only
限制：本轮CF_BYPASS_URL未设置，未调用CF服务；有效期、跨上下文隔离及失败后旧缓存行为没有运行验收。共享网络凭据不能合并用户ACL。

### S12-10 【存在可解释差异】账号凭据复制与真正续期尚未统一
management::mirror_token把账号表access/session/extra_cookies复制到user/account会话行，不消费refresh_token；普通proxy之后只读会话副本。其新行proxy_node_id=NULL，冲突更新又不更新该列，可能保留原值。login仅在显式session_token非空时保存它，仅chatgpt_token作为交换输入时不会存入该列。当前auth/session未实现真正credential续期/Set-Cookie合并。
证据位置：[management.rs:126-183](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/management.rs)；[server.rs:310-340,432-446](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[schema.sql:16-19](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/schema.sql)；[proxy.rs:263-325](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)
运行证据/范围：source audit; mirror_auth covers basic mirror-token reissue only
限制：未模拟账号池令牌更新传播、过期renew、复杂cookie旋转；不把每用户副本等同于单一账号执行profile。

### S12-11 【尚未验证】资源ACL仍未接入生产路径
会话行分离与conversation列表按account+user过滤的源码成立；独立ResourceAcl的同账号默认私有用例本轮单项通过。但lib.rs没有resource_acl导出，router不建ACL表也不调用RequestIdentity，Django可信stable ID/admin字段仍缺接线。不能据共享账号会话测试称所有资源用户权限已经独立。
证据位置：[lib.rs:1-6](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/lib.rs)；[server.rs:73-145,367-400](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server.rs)；[proxy.rs:198-250](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/server/proxy.rs)；[resource_acl.rs:37-100,437-494](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/src/resource_acl.rs)；[PHASE1_CONTRACT.md:75-80](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/input/PHASE1_CONTRACT.md)
运行证据/范围：successful_create_is_private_and_owner_can_read_modify_delete_continue:1 test exit0；source audit
限制：禁止以账号、出口IP、profile或上游cookie/session ID取代稳定Django user_id作为ACL主体；未知/未开放业务不能算通过。

## 3. 已存与缺失字段速查

| 状态 | 实际保存/缺失 | 生命周期含义 |
|---|---|---|
| 已验证一致 | gateway_sessions.id/user_name/chatgpt_username/mirror_token(hash)/login_mode | 本地会话与账号分离；UNIQUE(user,account)，同一pair重登录替换，跨用户不合并。 |
| 已验证一致 | encrypted access_token/session_token/extra_cookies；rust_authorizations的token_hash/encrypted payload/expires_at | 前者会话副本，后者保存签名及version等策略；真实授权期限不取UI固定2099。 |
| 存在可解释差异 | chatgpt_accounts另存refresh_token，但gateway会话无refresh_token；proxy_node_id已存；mirror_proxy全局配置已存 | 字段存在不等于续期/节点选择已执行；本轮普通请求实际未用代理配置。 |
| 尚未验证 | 没有可信typed stable user_id/admin、credential_generation、upstream device/session ID、profile/egress绑定版本、cookie作用域/期限列 | 任意payload/extra_cookie字段不能替代已验证协议或权限主体。详见S12-06/10/11源码锚点。 |

## 4. 重登录竞态的确定性时序

1. 旧Alice token请求先读取旧DB记录/策略并释放SQLite锁；其Django授权请求已经到达fixture，响应被屏障阻塞，此时尚未完成远端授权检查。
2. 同Alice/同账号的新登录另行授权成功，使用新access校验me，提交新token、新access和新extra_cookie，删除旧token授权行。
3. 释放旧Django响应；fixture仍确认同一v1。旧请求按先前policy比对成功，server::session没有重新查询原token行。
4. 普通me的load_credentials只按(user,account)重取，从而选中新凭据；旧在途请求200。其后另发旧token请求401。
5. 这证明的是同用户同账号的执行代次未固定，不是跨用户泄露。auth/session有token精确快照及回查，必须与普通me/list分开；list竞态本轮仅源码审计。
实际到达顺序见 [synthetic-events.json](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/probe-output/synthetic-events.json) 的索引4(旧authority)、5(新login authority)、6(新login me)、7(旧请求恢复后的me)；断言及屏障实现见 [probe_lifecycle.py](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/probe_lifecycle.py)。

## 5. 最小SessionExecutionContext提案【尚未验证；不实现】

这一上下文描述真实服务端执行绑定，不是伪装脚本。共享账号可以共享明确批准的账号执行bundle，但每个请求必须保留独立principal/local session/授权版本；绝不可按出口IP、UA、device/session cookie把不同用户ACL合并。

| 服务端字段 | 信任来源 | 不可变/版本规则 | 失败语义 |
|---|---|---|---|
| principal | 可信Django user_id/is_admin/authorization_version +经验证subject | 与本地会话固定，版本/角色变化使旧context失效 | 未确认、visitor未支持或过期拒绝，不以服务密钥造actor |
| local_session_ref + binding_generation | Rust服务端会话ID及一份绑定代次；不由浏览器指定 | 冻结token/凭据/cookie/profile/出口组合；重登录或任一组合替换建立新代次 | 发送前发现代次已变则拒绝/取消旧操作，不拿新凭据接续旧请求、不自动重发 |
| upstream_account_key | 经服务端账号映射和真实上游身份校验得到的稳定key | 资源账号不可变；当前email仅已有定位键，不能自行当永久vendor ID | 身份不匹配拒绝重新绑定 |
| credential_bundle_ref | 服务端加密凭据引用及有来源的cookie集合，不向浏览器下发 | access/session/refresh/extra cookie必须同代次；可经明确策略共享账号bundle，但仍为各actor独立context | 缺失/解密失败/过期停止；响应cookie更新需来源、作用域和版本校验，不靠透明cookie jar猜测 |
| egress_binding_ref | 服务端已批准的实际出口节点/策略；配置意图不能假装已选中 | 固定到本次代次，账号策略明确哪些会话可共享，变更显式重建 | 节点不可用或未接通时失败，不静默直连或换出口；是否允许直连必须明确 |
| client_profile_ref | 服务端实际传输实现和头配置版本，不是浏览器自报UA | 登录、交换、刷新、普通请求使用同一批准profile或记录明确差异 | 不支持的传输/协议拒绝或保持门禁；不作不可识别代理承诺 |
| upstream_session_device_ref (optional) | 仅真实协议已验证来源的opaque引用和作用域 | 与账号/凭据/出口profile关联；没有事实时保持unknown，不随机造device ID | 需要该绑定但未证实时不开业务；不是ACL主体 |
| validity | Django真实expires_at及服务端撤权状态 | 查库/鉴权/快照/发送前后同代次验证；网络等待不持DB锁 | 旧token401；在途context切换的取消/409等兼容语义由owner审定，禁止伪造成功 |

账号共享的ACL不变量：`principal.user_id`必须来自Django可信身份，`ResourceKey.account_id`只限定资源的上游命名空间；二者不能互相替代。网络身份共享与资源权限共享是独立决策。当前产品尚无此Context，也尚未接通ResourceAcl。

## 6. 实际执行、字面输出与退出码

完整命令数组/工作目录/逐字stdout/stderr：[commands-section12.json](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/commands-section12.json)、[VERIFICATION_SECTION12.txt](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/VERIFICATION_SECTION12.txt)。总执行记录：[run-section12.json](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/run-section12.json)。
实际执行：`C:\Users\Administrator\AppData\Local\Programs\Python\Python314\python.exe -X utf8 C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\section12\run_checks.py`，总退出0。所有cargo命令使用当前input/Cargo.toml、--locked --offline，build/temp/evidence均在本section12。

| 检查 | 实际结果 |
|---|---|
| shared_account token rotation/handoff/logout | 1 passed，exit0；COORD_EVIDENCE events=42 panicking=false |
| distinct_accounts concurrent refresh/logout | 1 passed，exit0；COORD_EVIDENCE events=67 panicking=false |
| auth_refresh三项 | 3 passed，exit0 |
| mirror_authority_revocation_and_relogin | 1 passed，exit0 |
| 独立ACL同账号默认私有 | 1 passed，exit0；不代表产品ACL接通 |
| build当前快照binary | exit0；没有用旧二进制 |
| lifecycle合成probe | exit0；SECTION12_LOOPBACK_PROBE_OK |

probe关键字面输出：
```text
{"id": "inflight_relogin", "old_inflight_status": 200, "next_old_request_status": 401, "selected_credential": "synthetic-alice-new", "selected_cookie": "fixture_device=alice-new", "interpretation": "old validated in-flight request selected replacement credentials for same user/account"}
{"id": "shared_account", "account": "shared@example.invalid", "separate_session_credentials": true, "separate_extra_cookies": true, "user_acl_not_tested_by_http": true}
{"id": "configured_proxy_unused", "save_status": 200, "proxy_trap_hits": 0}
{"id": "persisted_binding", "rows_without_tokens": [["alice", "shared@example.invalid", 71], ["bob", "shared@example.invalid", 71]], "tokens_hashed": true}
{"id": "restart", "same_db_same_key_sessions_survive": true, "cookie_jar_did_not_capture_upstream_set_cookie": true, "real_device_protocol_validity": "not_verified"}
{"id": "logout", "alice_status": 401, "bob_status": 200}
SECTION12_LOOPBACK_PROBE_OK
```

受控重启的两个自有子进程实际terminated_exit_status均为1（主动terminate，非声称优雅关机）；probe总退出0，详见 [processes.json](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/section12/probe-output/processes.json)。全部回环服务/子进程已由probe清理。
当前binary SHA256：`028864a6ca1f6fc13285b00e5faca3d433b41590bd14fce8f2b3c4fe750e7767`。真实device/CF/出口重启一致性仍【尚未验证】。

## 7. 原四角色保留及历史状态（不冒充本轮基线）

本轮只做审计，没有产品MODIFIED/ROLLBACK事务。原ACL补充四角色已重新读取并核对hash，未覆盖；其历史BASELINE=缺resource_acl、exit3；MODIFIED=28项通过、exit0；ROLLBACK=缺resource_acl、exit3且恢复hash一致。这些仅属旧独立ACL交付，不是新f95fc1快照的回滚证据。
- MODIFIED_FILE：[MODIFIED_FILE.zip](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/MODIFIED_FILE.zip)，SHA256 `3d5b43797e945f26cc69723ba3ef526483179e4448bacd039b657f499ed4e695`。
- DIFF_FILE：[DIFF_FILE.patch](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/DIFF_FILE.patch)，SHA256 `5c678238cda0235aeac30fb0d84ddf3a800ab0bacf6502f3d4ceb5f03b7c5ce1`。
- VERIFICATION：[VERIFICATION.txt](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/VERIFICATION.txt)，SHA256 `673f1f9514f4a5e289bf6b5e5c5efefaaba9f8f43a0f2a8f56fc577ed0aac9ce`。
- ROLLBACK：[ROLLBACK.sh](C:/Users/Administrator/.codex/worktrees/24c5/MiRebuild/coordination/acl/ROLLBACK.sh)，SHA256 `a364b4bfca90ad45c86d228461decae56ae474fc1669559644cd6c5f70b8f359`。

## 8. 可执行下一步（先评审，未授权产品修复）

1. owner审阅S12-02的确定性trace；后续获得实现授权时，优先让普通me/list按原token或显式session代次取凭据，并明确发送前/响应后的失效行为；将现有probe转成针对该修复的回归。不要先扩大业务。
2. 明确实际egress选择与配置失败语义，再统一登录、交换、刷新、代理的服务端上下文；不靠UA字符串或伪装脚本宣称传输一致。
3. 可信Django Identity及ResourceAcl接线仍为独立硬门禁；真实device/session、CF与公网出口的验收需要另行范围与授权。当前只交付审计、proposal和隔离证据。

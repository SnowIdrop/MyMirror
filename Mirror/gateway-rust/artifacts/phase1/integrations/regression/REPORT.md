# 工作线 3：独立边界回归交付

## 结论与边界

- **测试实现完成，可集成；尚未写入 owner 候选。** 唯一产品树增量是 `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coord-input\Mirror\gateway-rust\artifacts\phase1\source\tests\coord_boundary_regression.rs`，8 个 `coord_*` 测试；产品代码、公共路由、Config、数据库及依赖没有修改。
- b837 配置快照：BASELINE **64/64** → MODIFIED **72/72** → ROLLBACK **64/64**，三个实跑 exit=0。新增 8 项全部通过。
- owner 静态稳定包 `60ab65054a9aadec73aa222a21ff363295c5fda4e896fcbd7e5453fa3b2eb783`：同一测试文件 SHA256 `e2f09e37db56ff7f25129304933d0b42332bc1da2aa169a90ad7bd2dd0845ecc`，隔离 `target-static` 重新构建，**78/78、exit=0**。其中含 owner 原有 5 项静态测试，未重写或复制其 fixture 到本测试文件。
- 两个快照上的新增测试 Clippy `-D warnings` 均 exit=0；定点 rustfmt --check exit=0。**不是真实账号/浏览器/线上验收**，也不是完整网关替换完成。

## 已观测行为（两个快照的同一 8 项回归）

| 符号与行号 | 观测结果 |
|---|---|
| `coord_unknown_route_matrix_stays_closed:242` | 11 条路径×GET/POST×匿名/登录=44 请求。未知 external/internal-upstream、首页、猜测 conversation/bootstrap/resource 路径：匿名401、登录503；未知 `/api/*` 恒404。除授权检查外没有 chat/CDN/诱饵出口；这些路径只是门禁探针，不是声称上游存在的协议。 |
| `coord_client_target_overrides_cannot_select_egress:296` | 6 种 query 目标字段+1 个 JSON body，并带 Host/X-Upstream-URL/X-Target-URL/X-Forwarded-Host：只到配置 chat，诱饵0次。不是对真实上游内部 query 语义的证明。 |
| `coord_browser_credentials_absent_from_chat_and_responses:342` | 浏览器 Authorization、Cookie、X-Mirror-Token、Proxy-Authorization 未出现在聊天请求；聊天改用指定账号 access token。成功200和上游合成503响应不含这些凭据或管理密钥，cache-control含no-store。 |
| `coord_transport_error_does_not_echo_credentials:376` | 关闭自有聊天监听器后502；含敏感标记的query/headers未反射到响应。 |
| `coord_local_sessions_distinct_accounts_and_logout_are_isolated:402` | 两用户不同账号同时读取4轮，email/loginMode不串；退出alice不影响bob。 |
| `coord_shared_account_token_rotation_preserves_other_user:439` | 两用户共用账号但保持api/web本地模式；alice重登录和handoff使旧token失效，bob不受影响；alice logout后bob仍有效。 |
| `coord_invalid_credentials_fail_without_egress_or_echo:489` | 无效mirror/admin/handoff凭据401，所有出口0次，无凭据反射。 |
| `coord_inactive_authority_blocks_chat_without_cross_user_fallback:535` | Django合成active=false后chat401、本地session为空对象，无新增chat出口。 |

`/api/auth/session` 这里只验证本地状态，未制造 accounts/check 刷新fixture；HTML初始化成功、跨用户bootstrap数据、资源ACL/管理员角色、真实CDN隔离仍不能由本套测试推出。

## 可集成差异与公共接线

源码补丁：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\INTEGRATION.patch`。在 owner 的稳定 source 根执行：

```text
git -c core.autocrlf=false apply --check "C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\INTEGRATION.patch"
git -c core.autocrlf=false apply "C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\INTEGRATION.patch"
cargo test --test coord_boundary_regression --locked --offline -- --nocapture --test-threads=1
```

Cargo 自动发现新测试，无公共入口/Config/schema/依赖接线需求。`COORD_EVIDENCE_DIR` 可选，设置为本地输出目录时落盘完整合成HTTP日志。owner应使用自己的隔离构建/临时DB与输出目录；本任务未执行以上主候选集成命令。

## 证据与复现

- 输入提交：`b837ba2556bc3363570d247e61246e6b8f43421c`，由 git archive 导出，未复制活跃源目录。输入文件hash：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\input_manifest.json`。
- b837逐命令实跑：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\runs\modified-verified\command.json`；8个请求/响应/出口JSON：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\runs\modified-verified\events`。
- 静态包逐命令实跑：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\runs\static-60ab6505\command.json`；同8套独立JSON：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\runs\static-60ab6505\events`。
- 机器结果（含实际command数组、退出码、字面stdout/stderr）：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\results.json`。
- 证据等级：本地源码事实＋合成回环HTTP实跑。出口记录仅四个自有fixture收到的HTTP，不是全机抓包。所有账号/密钥均synthetic，未请求真实账号或公网服务，未运行原版QEMU。
- 工具来自既有phase1-toolchain；CARGO_HOME锁/构建输出/TEMP在本worktree。原cache目录以链接复用；未重装工具链。没有把历史30配置矩阵或D盘二进制证据算成本轮结果。

## 补充四角色（不替换主检查点/主四角色）

1. MODIFIED_FILE：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\MODIFIED_FILE.zip`，b837完整源码+仅新增测试，SHA256 `8d8476e218de3c8bddec3a1c35bc1ae51c69782f2661bc1df3f7b0a3bf704d17`。
2. DIFF_FILE：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\DIFF_FILE.patch`，标准git binary patch，可从以MODIFIED_FILE.zip命名的BASELINE归档重建上述包，实际已应用且hash一致。源码集成使用前述INTEGRATION.patch。
3. VERIFICATION：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\VERIFICATION.txt`，完整命令、输入、stdout、stderr、exit与hash。
4. ROLLBACK：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\ROLLBACK.sh`，可执行shell脚本，接受一个目标副本路径，从同目录BASELINE.zip恢复；已对RESTORED.zip执行后实跑64项。

BASELINE.zip 与 RESTORED.zip SHA256均为 `d5b8b4f2a955d8dfa35c8be129cde4257fd6d676da705cd01dbbc1a2c1e783da`；回滚后再次应用GOAL重建MODIFIED_FILE.zip，且保持上述modified hash。新导出归档的目录前缀/zip元数据与owner历史包不同，不混用hash。源文件hash逐项验证未变。

静态跨批补充：`C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\STATIC_WITH_REGRESSION.zip`，仅给60ab稳定包添加同一测试；不是新的主交付，也未更改上述角色含义。

## 首次失败、审阅与限制

- 初次新增测试 run=modified，7/8通过、cargo exit101：故障测试拿到200而非502。日志确认Axum既有keep-alive连接在监听任务abort后继续服务。只给本地fixture加Connection: close后故障确实注入，原断言不变；原失败包和日志保留在 `C:\Users\Administrator\.codex\worktrees\0bb0\MiRebuild\coordination\regression\runs\modified`。未修改产品来迁就测试。
- 首次源码patch重建因系统Git autocrlf造成LF→CRLF，字节比较失败（退出1），语义规范化后相同。明确core.autocrlf=false后逐字节重建通过。首次diff检查错误地把`--no-index`预期差异exit1当作错误；改为核对exit1且stdout/stderr为空，保留原记录。
- 已按防御式编程审阅当前测试与runner差异：没有产品fallback/额外状态机；保留网络资源清理、凭据断言与输入hash边界；单点cookie选择用find_map，无无关重构。
- 未完成：真实HTML/bootstrap隔离、真实浏览器登录/刷新闭环、管理员/资源ACL、静态Range/压缩/缓存全组合和生产验收。CDN成功凭据fixture继续由owner static_assets.rs独占；本轮仅重跑它，不另造成功协议。
- **刷新演进限制**：测试第336/398行的login固定出口计数、第435行的本地session无chat调用，都是b837/static60ab特定假设。owner后续实现auth_session刷新时，应依实测accounts/check→me契约升级fixture及计数，保留凭据、目标固定、会话隔离等安全断言；不能将本轮计数误当成禁止刷新，也不能以跳过测试代替升级。此批不抢改owner的auth范围。
- 下一步：owner集成新增测试并使用集成候选执行跨模块验证；继续原页面/刷新授权链工作。测试通过不授权开放未知路径或线上切换。

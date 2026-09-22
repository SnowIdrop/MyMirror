# ACL 工作线2交付：隔离实现完成，未接入产品

## 结论及归属

- **实现状态：本批独立权限模块、v1契约和测试完成。** 只新增两份Rust文件，原28份源码输入逐SHA256保持不变；未改lib/schema/Cargo/公共路由/Config/登录或主检查点。
- **基础验证：28项本地合成SQLite测试、限定test target的Clippy `-D warnings`、两文件rustfmt、patch重建、源码包rollback均实际通过。** 不是完整Rust回归，也不是页面新批次或真实上游验收。
- **真实环境/整体第二阶段：未完成。** Django新身份字段、统一路由授权、可信创建adapter、实时断连、生成互斥、资源后台查询、新库初始化及完整备份均尚未接通。本批没有开放业务。
- 协调任务：`01a0c9c9-4508-75d1-a709-20aa6dbb69f9`；唯一最终集成人仍是既有任务 `01a0c9af-fab7-7780-af7f-537dde662636`。没有接管、停止或更改其工作区。
- 本任务worktree：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild`。HEAD `4c7b3fa6d8448b0d7410820c0679365083172b67` 是空基线，**不是本模块输入版本**。

## 输入快照和范围

使用 `git archive` 从固定提交 `b837ba2556bc3363570d247e61246e6b8f43421c` 仅导出候选source子树，未复制活跃源目录、真实凭据或生产DB。

- 实际输入副本：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coord-input\Mirror\gateway-rust\artifacts\phase1\source`
- 固定归档：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\input-source.tar`
- 归档SHA256：`abfca21856f73a2c49078c6ecf61abd6847b1b7c17579d7c5513a916fa3636d2`
- 每文件输入hash：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\input-manifest.json`
- root AGENTS文件在worktree及原仓库不存在，固定提交没有AGENTS路径；遵循任务附带的完整工作约定。
- 补充制品目录：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl`

本目录的BASELINE.zip是固定source子树重新封装的补充基线，hash不同于主四角色配置包的 `a7f812...`，也不同于原始包 `bc0b14...`。不得混用为同一源码包或旧D盘二进制证据。

## 源码事实和v1契约

定点依据（以下行号均在上述固定source副本）：storage.rs:68-188仅备份原8表；schema.sql:35-84会话与资源owner仍使用名字；policy.rs:25-43只有user_name/version，无稳定ID/角色；server.rs:366-400、922-940只检查Django active/version/expires_at。这些公共文件未修改。

契约全文：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\CONTRACT_V1.md`

与admin-prep任务 `01a0c9cb-a4db-7422-8c45-60c730af54d2` 及协调任务明确对齐：

- `Identity { user_id, is_admin, authorization_version }`：user_id是稳定Django pk的规范正十进制字符串；is_admin来自实时可信staff OR superuser；authorization_version映射原wire `version`不透明字符串。
- **新增响应提案** `user_id/is_admin/subject/principal_kind` 不冒充已有Django字段；subject须绑定正在校验的会话；principal_kind由Django真实用户/visitor签名路径派生。本期新ACL拒visitor及缺字段，避免FREE_ACCOUNT共用ID合并归属，**不改变既有访客登录**。
- fresh验证与pinned Identity三字段完全匹配；旧版本、升/降角色、变user ID、subject错误、过期一律拒绝；服务密钥不代表管理员。
- 内部 `ResourceKey {account_id, kind, upstream_id}`；管理wire拟议 `upstream_account_id/resource_type/upstream_id` 显式映射；kind为conversation/project/file/image/task/connector，不新增虚构resource_id/share_id。
- account_id的Django ChatgptAccount.pk到Rust账号键的稳定映射仍由集成人决定，不能把旧username或客户端账号字段直接当作已验证映射。

## 两份可集成差异

1. `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coord-input\Mirror\gateway-rust\artifacts\phase1\source\src\resource_acl.rs`
   - `Identity::from_authority` :46 / `RequestIdentity::verify` :87：严格可信身份形状和版本/角色检查。
   - `ResourceKey` :133 / `ConfirmedCreation` :164 / SCHEMA :207：不可变资源身份，四张独立ACL表，账号/归属不可更新trigger。
   - `ResourceAcl::record_created` :279：None不登记；可信成功receipt才登记；重复receipt/资源不覆盖；项目与同账号校验；原子成功审计。
   - `ResourceAcl::grant/revoke` :314/:323：仅admin；接收者可读改删续聊的权限检查，不可转授权；撤销后下一次SQLite判权立即失败（如无其他有效路径）。
   - `ResourceAcl::move_to_project` :368：动态比较前后受众，旧资源扩大受众必须管理员；失败回滚旧关联。
   - `authorize` :437 / `audience` :478：默认私有；未知只admin读取，未知写/删/续聊/共享拒绝；项目动态继承现有及未来内容；connector绝不继承。
   - `audit_after` :400：admin-only after_id/limit查询，含occurred_at/真实actor ID/version；未实现多维筛选。
2. `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coord-input\Mirror\gateway-rust\artifacts\phase1\source\tests\coord_acl_contract.rs`
   - 用 `#[path = "../src/resource_acl.rs"]` 编译，不需要修改lib.rs或Cargo。
   - 28项合成用例覆盖本批已实现规则、SQLite两连接撤权可见性、失败审计回滚、固定账号、重复创建、跨账号关联、角色失效及访客拒绝。

**只集成两份新增文件/补丁，绝不能用本源码包覆盖owner正在更新的页面/刷新批次。** 建议集成人先在其仓库根以 `git -c core.autocrlf=false apply --check --directory=Mirror/gateway-rust/artifacts/phase1/source <本补丁绝对路径>` 检查；此处仅为接线建议，未在主工作区执行。并行批次整合后必须重跑组合回归。

## 实际命令与字面结果

全部命令数组、cwd、逐字stdout/stderr、退出码在：

- `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\VERIFICATION.txt`
- `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\results.json`
- `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\execution.json`

实际最终总执行：

```text
C:\Users\Administrator\AppData\Local\Programs\Python\Python314\python.exe C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\validate_delivery.py --run-id verified-final
exit=0
```

测试命令（环境只复用既有工具链/cache；CARGO_TARGET_DIR隔离到本补充目录build）：

```text
E:\M\Project\MiRebuild\Mirror\gateway-rust\.build\phase1-toolchain\cargo\bin\cargo.exe test --locked --offline --manifest-path C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coord-input\Mirror\gateway-rust\artifacts\phase1\source\Cargo.toml --test coord_acl_contract -- --test-threads=1
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
exit=0
```

`clippy --test coord_acl_contract -- -D warnings` 退出0；stdout为空；stderr最后为 ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.42s``（完整字面见ledger）。两文件rustfmt --check退出0、stdout/stderr为空。未把历史64项Rust/30配置结果计入本批。

### BASELINE / MODIFIED / ROLLBACK

三态均调用同一个 `run_gate.py --source SOURCE`，同一离线coord_acl_contract v1输入，仅SOURCE路径不同。

| 状态 | 观察到的行为 | 退出码 |
|---|---|---|
| BASELINE | `ACL_CONTRACT_V1_UNAVAILABLE: resource_acl module absent` | 3（预期缺模块） |
| MODIFIED | `running 28 tests`；`test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s` | 0 |
| ROLLBACK.sh | `ROLLBACK_RESTORED_PRISTINE_ARCHIVE`，恢复独立源码包副本 | 0 |
| ROLLBACK gate | `ACL_CONTRACT_V1_UNAVAILABLE: resource_acl module absent` | 3（与基线一致） |

BASELINE/ROLLBACK只证明新能力不存在，**不代表旧网关ACL放行或拒绝某真实用户**。源码回滚不恢复数据库，也不撤销上游操作。

- BASELINE.zip与ROLLBACK_COPY.zip SHA256均为 `6364509a6f79f7739e63cc24ec7c9e1e0cf33953c30c9546149f1100674d6585`。
- MODIFIED_FILE.zip SHA256为 `3d5b43797e945f26cc69723ba3ef526483179e4448bacd039b657f499ed4e695`。
- 两份新增源hash：module `80ee34100574d8b746905ae71ea42b67d25c13410e247b4408e47db4ea0caa39`；test `8b06f74d703632fce6546d0b5463d50c8f830d81547f605ce4e8f180b419dbfa`。
- DIFF_FILE从原始source重建两份新增文件，重新封装包与MODIFIED_FILE逐字hash相同。ROLLBACK在单独副本执行，最终MODIFIED角色重新封装并保留新模块。

### 执行错误及修复（均保留，不隐瞒）

- ls-tree不支持glob pathspec：改为对git树清单限定AGENTS路径匹配；无仓库源码修改。
- 初次cargo版本探测缺RUSTUP_HOME失败：从现有validate.py恢复CARGO_HOME/RUSTUP_HOME后实际运行cargo 1.98.1；没有安装工具链。
- 首轮patch在父git的嵌套目录被跳过，文件存在性校验报错；改为临时独立git根。
- 第二轮patch受Windows core.autocrlf转换，hash断言失败；十六进制确认LF/CRLF差异，以 `git -c core.autocrlf=false apply` 重跑后逐字一致。
- 最终附加readback单行脚本默认GBK读取UTF-8 ledger报UnicodeDecodeError；改为显式UTF-8的final_readback.py，未改变代码或四角色。原最终验证脚本已用UTF-8重开成功；新增错误记录为 `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\final-readback.error.txt`。
- 记录：`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\preparation-errors.json`、`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\validation-attempt1.error.txt`、`C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\validation-attempt2.json`。这些是制品验证准备失败，不是伪造的测试通过。

防御编程复核：删去move/check_project里已由authorize保证的两次重复known-resource查询；保留真实边界所需的严格身份检查、SQLite事务、immutable trigger和扩可见受众比较。最终28项/Clippy/格式/重建/回滚均在简化后重跑。

## 四角色绝对路径（均已重新打开验证）

1. `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\MODIFIED_FILE.zip`
2. `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\DIFF_FILE.patch`
3. `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\VERIFICATION.txt`
4. `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\ROLLBACK.sh`

ROLLBACK依赖同目录 `C:\Users\Administrator\.codex\worktrees\24c5\MiRebuild\coordination\acl\BASELINE.zip`；脚本实际chmod +x/test -x通过并在Git sh执行成功。

## 风险、公共接线需求及下一步

1. 先实现可信Django字段和Rust会话固定Identity/fresh校验，recipient用户目录解析与账号ID映射。当前Value/receipt只是库边界，**模块本身无法证明HTTP响应来源或某ID确为本次新建**。不要把浏览器JSON直接传入；创建失败/未确认不登记，成功但本地记录失败需要明确补偿/人工核对，禁止自动重发创建或认领旧资源。
2. RequestIdentity只是一请求校验结果，不是跨请求缓存，也不是网络等待后仍有效的租约；调用方必须建立撤权/版本屏障。授权判定与上游副作用尚不原子。
3. AclChange只有提交后的失效意图，无持久outbox/可靠投递；撤权后下一次SQLite判权已验证，但SSE/语音实际断连未实现。项目变更需重验子资源，connector除外；owner/仍有效其他共享路径不能误当撤权完成。
4. 单会话生成互斥、冲突busy、取消/故障释放、多进程与重启协调尚未实现，仅v1接口语义。不要开放共享生成。
5. 新库初始化/迁移和全量备份必须涵盖四ACL表；旧8表v2备份不覆盖新权限，接线前应禁止其静默丢ACL。无数据库备份恢复验收。
6. 所有列表/详情/写删/引用/上传下载/任务/实时路径及管理员资源查询/筛选仍须公共接线；未知路径继续门禁。本模块没有发送、删除或修改任何真实资源。
7. admin-prep已经对齐同一Identity/复合key，负责提案而不建Django ACL。管理transport需保留401/403/409/503，不沿用仅HTTP200成功的旧helper吞语义；此项来自其只读源码汇报，非本模块运行证据。
8. 唯一集成人按依赖整合后重跑跨模块回归；真实双普通用户+管理员、上游创建、并发生成、撤权断连、备份和浏览器流程仍未验收。无线上切换、外部写、用户重置、真实凭据读取或旧资源删除。

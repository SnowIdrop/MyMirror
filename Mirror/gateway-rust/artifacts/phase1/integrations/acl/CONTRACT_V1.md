# Resource ACL v1 — 隔离模块契约，未接入产品

## 固定输入及事实

- 输入固定为提交 `b837ba2556bc3363570d247e61246e6b8f43421c` 的 `Mirror/gateway-rust/artifacts/phase1/source`；不读取活跃候选做实现基线。
- `src/storage.rs:68-188` 仅备份原8表；`src/schema.sql:35-84` 会话和归属仍用 user_name/chatgpt_username，没有稳定用户ID或共享表。
- `src/policy.rs:25-43` Policy 有 user_name/version，无可信 user_id/is_admin；`src/server.rs:366-400,922-940` Django授权仅检查 active/version/expires_at。不得以登录客户端字段或服务密钥补造管理员。
- 当前模块是 SQLite 权限方案及合成离线测试，不是已观测的上游资源协议。原 schema、路由、Cargo、登录、备份均未改动。

## 可信身份

`Identity { user_id: String, is_admin: bool, authorization_version: String }` 不实现 Deserialize，字段只读。

可信 Django `POST /0x/user/gateway-authorization` v1响应提案：

```json
{"active":true,"version":"opaque-digest","expires_at":2000000000,"user_id":"123","is_admin":false,"subject":"verified-session-subject","principal_kind":"user"}
```

`user_id=str(user.pk)` 为正整数规范十进制；`is_admin=bool(is_staff or is_superuser)`；`version` 原wire名不改，映射 authorization_version；subject必须绑定正在校验的会话。字段缺失/错型/空值、inactive、过期、visitor均拒绝。FREE_ACCOUNT访客共用user_id，因此本期可信principal_kind必须是user；visitor由Django基于真实签名/visitor session判定，不允许浏览器自报或服务端静态填user。

登录时 `Identity::from_authority` 固定三字段；每个资源/管理请求从固定Django源获取新响应，以 `RequestIdentity::verify` 比较已固定Identity的三个字段和subject，任何变化拒绝旧会话，不能把旧会话静默升权。缺Django、错误状态、无可解析body时入口拒绝；模块不发HTTP，也不保存第二份用户/角色真相。RequestIdentity仅限单个同步操作，不缓存、不复用跨请求；调用方须在上游副作用开始前再次确认撤权/版本屏障。visitor门禁仅作用于尚未开放的新资源/共享能力，不改变既有访客登录。

## 数据及不变量

- `ResourceKey(account_id, kind, upstream_id)`：account_id是服务端解析的稳定上游账号键，不接受浏览器选择任意账号；同一upstream_id在不同账号属不同资源。登记后账号、种类、ID、所有者和creation_id不可变（无更新API，并有SQLite trigger）。
- `acl_resources`：归属及唯一creation_id；仅从已成功的上游新建响应构造 `ConfirmedCreation`，字段crate可见且无Deserialize。`record_created(..., None)`不登记；Some本身不是网络证明，可信adapter必须证实它是本次创建成功而非读旧ID。模块不能单独判断上游历史，未实现的业务adapter保持门禁。重复receipt或重复资源冲突，不认领/覆盖旧资源。
- `acl_project_links`：每个非project资源最多一个同账号project；不支持嵌套project。项目owner与直接共享接收者构成继承受众；每次授权动态查表，不复制共享。connector可以有关联元数据，但绝不继承project访问权。
- `acl_shares`：仅当前可信管理员能授予/撤销；owner也不能转授权。接收者获得读、改、删、续聊的授权判定（续聊限conversation），不能授予/撤销共享。模块不执行上游改删或聊天；管理入口须先经Django解析接收者稳定ID/确认其为可授权普通账号，模块只做规范ID校验，不伪造用户目录。
- 默认私有，无隔离关闭开关。未登记资源只有管理员可读取；未知资源的写、删、续聊、共享、关联均拒绝，避免猜测ID认领。旧资源导入/管理员认领不在本批实现范围。
- `move_to_project` 对旧资源比较变更前后有效受众；增加任何非管理员受众必须管理员，非管理员只能在自己有Modify权限的资源及目标项目间做不扩大可见性的变更。新资源在可信创建receipt内指定project则成功后登记并立即继承。跨账号关联拒绝。
- `acl_audit`：所有成功登记/授予/撤销/关联变更与状态写入同一IMMEDIATE事务；记录递增id、SQLite UTC秒时间occurred_at、actor稳定ID/version、动作、资源、接收者和目标project，不记录令牌/凭据。失败不产生成功审计，失败审计由统一入口补充（尚未实现）。审计查询仅管理员，支持after_id游标和1..1000条limit；尚无资源查询/筛选管理接口。
- SQLite连接属于独立ResourceAcl；不直接访问原Database，不在网络等待期间持锁。SQLite是唯一ACL真相，Django无ACL副本。

## 失败语义与拟议HTTP映射（不是开放的路由）

| 模块错误 | 调用方拟议语义 |
|---|---|
| Unauthorized | 401；身份无效/过期/版本或角色变化；需重新登录 |
| Forbidden / UnknownResource | 对普通用户统一404，避免枚举；管理员管理操作可404/403 |
| InvalidInput / InvalidOperation / CrossAccount | 400，不转发上游 |
| AlreadyRegistered | 409，不覆盖、不重试创建 |
| Sqlite | 503/500不泄露内部文本；事务失败不放行 |
| Busy（接口要求，未实现） | 409 generation_busy；不得等待后自动重发 |

## 撤权和生成接口要求（明确未接通）

`AclChange { audit_id, scope: ResourceKey, include_project_children, user_id }` 在提交后返回：撤销直接授权定向user；项目授权变更需重算该项目及所有非connector子资源；移动资源使其所有连接重新判权。它只是提交后通知数据，不是已可靠投递的事件/持久outbox。失败通知不能以成功响应掩盖；接线前需要在统一授权屏障内保证事务提交→禁止新请求→重验并关闭失权SSE/语音/其他实时连接。已有直接共享仍有效者不应误断权；断连实现、崩溃恢复与多进程协调尚未实现。

生成接口由集成负责人实现：`try_acquire_generation(RequestIdentity, ResourceKey) -> GenerationLease | Busy`，原子再鉴权+按(account,conversation)独占，结束/失败/取消释放；断线不重发；重启不重建上游任务。撤权与acquire必须共享屏障；不得把本批SQLite权限事务当成已完成生成互斥。

## 接线门禁

必须由唯一集成人修改：Django可信响应和访客判定；Rust登录/session固定Identity与每请求fresh验证；新库迁移及严格版本化全量备份（覆盖四张ACL表，拒绝旧格式静默丢ACL）；全部列表/详情/写删/引用/下载/任务/实时路径统一授权；可信新建adapter；管理员入口实际操作者、CSRF及固定服务路径；可靠撤权和生成协调。完成前不添加公共mod导出或业务路由，不把旧8表备份当作ACL备份。

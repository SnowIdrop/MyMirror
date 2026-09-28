//! 资源 ACL v1：共享上游账号下每个镜像用户只能看到自己登记的会话/项目/文件/
//! 图片/任务/连接器。
//!
//! 信任边界：`Identity` 只能由已校验的 Django 授权响应或本地 profile 的镜像会话
//! 构造；`ConfirmedCreation` 只能由服务端在**已确认成功**的上游创建响应后构造。
//! 本模块不做任何网络 I/O。
//!
//! 接线方式：产品路径直接调用本文件的自由函数，并传入网关自己的 SQLite 连接
//! （`Database::conn`），因此所有判权与登记都在网关单锁内、用 IMMEDIATE 事务完成；
//! [`ResourceAcl`] 句柄仅保留给不接入网关库的独立使用与离线测试。

use std::collections::BTreeSet;
use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;

#[derive(Debug)]
pub enum AclError {
    Unauthorized,
    Forbidden,
    UnknownResource,
    InvalidInput,
    InvalidOperation,
    CrossAccount,
    AlreadyRegistered,
    Sqlite(rusqlite::Error),
}

impl fmt::Display for AclError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AclError {}
impl From<rusqlite::Error> for AclError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}
pub type Result<T> = std::result::Result<T, AclError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    user_id: String,
    is_admin: bool,
    authorization_version: String,
}

impl Identity {
    /// `details` MUST come from the fixed trusted Django authority, never JSON
    /// submitted by the browser or possession of the service management key.
    pub fn from_authority(details: &Value, expected_subject: &str, now: i64) -> Result<Self> {
        let user_id = details["user_id"].as_str().ok_or(AclError::Unauthorized)?;
        let version = details["version"].as_str().ok_or(AclError::Unauthorized)?;
        let is_admin = details["is_admin"]
            .as_bool()
            .ok_or(AclError::Unauthorized)?;
        if details["active"] != true
            || details["principal_kind"] != "user"
            || expected_subject.is_empty()
            || details["subject"].as_str() != Some(expected_subject)
            || details["expires_at"]
                .as_i64()
                .is_none_or(|expiry| expiry <= now)
            || !valid_user_id(user_id)
            || version.trim().is_empty()
        {
            return Err(AclError::Unauthorized);
        }
        Ok(Self {
            user_id: user_id.to_owned(),
            is_admin,
            authorization_version: version.to_owned(),
        })
    }

    /// 原始 profile（`GATEWAY_COMPAT_PROFILE=original`）没有 Django 可信源：
    /// 身份直接取本地镜像会话的 `user_name`，信任边界是镜像会话 token 本身，
    /// 与原始网关按 `user_name` 判定归属的既有语义一致。版本留空，不冒充 Django 版本。
    pub fn local(subject: &str) -> Result<Self> {
        if subject.trim().is_empty() {
            return Err(AclError::Unauthorized);
        }
        Ok(Self {
            user_id: subject.to_owned(),
            is_admin: false,
            authorization_version: String::new(),
        })
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    pub fn authorization_version(&self) -> &str {
        &self.authorization_version
    }
}

/// Fresh verification for one synchronous ACL operation. Never cache across
/// requests. The caller owns the revocation barrier before upstream side effects.
pub struct RequestIdentity(Identity);

impl RequestIdentity {
    /// 会话在建立时已固定身份：本类型只包装该固定身份，供需要 `RequestIdentity`
    /// 的判权入口使用；mirror profile 的每请求复验在 `server::session` 内完成。
    pub fn from_session(identity: Identity) -> Self {
        Self(identity)
    }

    pub fn verify(
        pinned: &Identity,
        details: &Value,
        expected_subject: &str,
        now: i64,
    ) -> Result<Self> {
        let current = Identity::from_authority(details, expected_subject, now)?;
        if &current != pinned {
            return Err(AclError::Unauthorized);
        }
        Ok(Self(current))
    }

}

fn valid_user_id(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|c| (b'1'..=b'9').contains(c))
        && value.bytes().all(|c| c.is_ascii_digit())
}

/// 访客会话的每请求复验：访客没有可固定的 ACL 身份（不参与归属判权），但仍须确认
/// 固定 Django 源继续把同一 subject 判为有效访客——版本与过期时间未变、没有被提升成
/// `user`。任何变化都返回 `Unauthorized`，调用方据此拒绝该会话。
pub fn verify_visitor(
    details: &Value,
    expected_subject: &str,
    expected_version: &str,
    now: i64,
) -> Result<()> {
    let version = details["version"].as_str().ok_or(AclError::Unauthorized)?;
    let valid = details["active"] == true
        && details["principal_kind"] == "visitor"
        && !expected_subject.is_empty()
        && details["subject"].as_str() == Some(expected_subject)
        && version == expected_version
        && details["expires_at"]
            .as_i64()
            .is_some_and(|expiry| expiry > now);
    if valid {
        Ok(())
    } else {
        Err(AclError::Unauthorized)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Conversation,
    Project,
    File,
    Image,
    Task,
    Connector,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conversation => "conversation",
            Self::Project => "project",
            Self::File => "file",
            Self::Image => "image",
            Self::Task => "task",
            Self::Connector => "connector",
        }
    }
}

/// 库内 `resource_type` 文本 → 枚举；未知取值说明库被外部改写，按输入错误拒绝。
fn kind_from_str(value: &str) -> Option<ResourceKind> {
    match value {
        "conversation" => Some(ResourceKind::Conversation),
        "project" => Some(ResourceKind::Project),
        "file" => Some(ResourceKind::File),
        "image" => Some(ResourceKind::Image),
        "task" => Some(ResourceKind::Task),
        "connector" => Some(ResourceKind::Connector),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceKey {
    account_id: String,
    kind: ResourceKind,
    upstream_id: String,
}

impl ResourceKey {
    pub fn new(account_id: &str, kind: ResourceKind, upstream_id: &str) -> Result<Self> {
        if account_id.trim().is_empty() || upstream_id.trim().is_empty() {
            return Err(AclError::InvalidInput);
        }
        Ok(Self {
            account_id: account_id.into(),
            kind,
            upstream_id: upstream_id.into(),
        })
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn kind(&self) -> ResourceKind {
        self.kind
    }
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }
}

/// Construct only inside a trusted upstream CREATE adapter after confirmed
/// success, not from a client-provided ID or an upstream GET of an old resource.
/// These fields are deliberately not deserializable from an HTTP body.
pub struct ConfirmedCreation {
    pub(crate) creation_id: String,
    pub(crate) resource: ResourceKey,
    pub(crate) project: Option<ResourceKey>,
}

/// 未显式分类的路径带着资源 id 出现时的判定结果：按 id 的登记与受众给出，
/// 不看路径形状（上游前端新增路由时不需要再登记）。
#[derive(Debug, PartialEq, Eq)]
pub enum AutoAuthority {
    /// 已登记且当前会话有权执行该动作。
    Visible(ResourceKind),
    /// 已登记但当前会话无权（他人资源）：与「不存在」同形拒绝。
    Foreign,
    /// 该账号下没有这个 id 的任何登记：未登记资源不可用。
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Modify,
    Delete,
    ContinueChat,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Access {
    Registered,
    UnknownAdministratorRead,
}

/// Post-commit invalidation intent, NOT a delivered notification or durable outbox.
#[derive(Debug)]
pub struct AclChange {
    pub audit_id: i64,
    pub scope: ResourceKey,
    pub include_project_children: bool,
    pub user_id: Option<String>,
}

#[derive(Debug)]
pub struct AuditRecord {
    pub id: i64,
    pub occurred_at: i64,
    pub actor_user_id: String,
    pub authorization_version: String,
    pub action: String,
    pub account_id: String,
    pub resource_type: String,
    pub upstream_id: String,
    pub recipient_user_id: Option<String>,
    pub project_id: Option<String>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS acl_resources (
    account_id TEXT NOT NULL,
    resource_type TEXT NOT NULL CHECK(resource_type IN ('conversation','project','file','image','task','connector')),
    upstream_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    creation_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(account_id, resource_type, upstream_id)
);
CREATE TRIGGER IF NOT EXISTS acl_resource_identity_immutable
BEFORE UPDATE ON acl_resources
BEGIN SELECT RAISE(ABORT, 'resource identity and ownership are immutable'); END;
CREATE TABLE IF NOT EXISTS acl_project_links (
    account_id TEXT NOT NULL,
    resource_type TEXT NOT NULL CHECK(resource_type <> 'project'),
    upstream_id TEXT NOT NULL,
    project_type TEXT NOT NULL DEFAULT 'project' CHECK(project_type = 'project'),
    project_id TEXT NOT NULL,
    PRIMARY KEY(account_id, resource_type, upstream_id),
    FOREIGN KEY(account_id, resource_type, upstream_id)
        REFERENCES acl_resources(account_id, resource_type, upstream_id),
    FOREIGN KEY(account_id, project_type, project_id)
        REFERENCES acl_resources(account_id, resource_type, upstream_id)
);
CREATE TABLE IF NOT EXISTS acl_shares (
    account_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    upstream_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL,
    PRIMARY KEY(account_id, resource_type, upstream_id, recipient_user_id),
    FOREIGN KEY(account_id, resource_type, upstream_id)
        REFERENCES acl_resources(account_id, resource_type, upstream_id)
);
CREATE TABLE IF NOT EXISTS acl_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at INTEGER NOT NULL DEFAULT (unixepoch()),
    actor_user_id TEXT NOT NULL,
    authorization_version TEXT NOT NULL,
    action TEXT NOT NULL,
    account_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    upstream_id TEXT NOT NULL,
    recipient_user_id TEXT,
    project_id TEXT
);
"#;

/// 建表并打开外键约束；幂等，`Database::open` 与独立句柄都会调用。
pub fn init(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    let tx = immediate(conn)?;
    tx.execute_batch(SCHEMA)?;
    tx.commit()?;
    Ok(())
}

/// IMMEDIATE 写事务：写路径先取写锁再读受众，避免两次判权之间被别人改掉归属。
fn immediate(conn: &Connection) -> Result<Transaction<'_>> {
    Ok(Transaction::new_unchecked(
        conn,
        TransactionBehavior::Immediate,
    )?)
}

pub fn authorize(
    conn: &Connection,
    actor: &RequestIdentity,
    resource: &ResourceKey,
    action: Action,
) -> Result<Access> {
    authorize_in(conn, &actor.0, resource, action)
}

/// 未显式分类的路径带 id 时的判定：同一个 id 在六族里逐个查登记与受众。
/// 「已登记但无权」与「未登记」必须区分——前者是他人资源（404），后者需要
/// 管理员认领或把路径登记为账号级（503）。
pub fn auto_authority(
    conn: &Connection,
    actor: &RequestIdentity,
    account_id: &str,
    upstream_id: &str,
    action: Action,
) -> Result<AutoAuthority> {
    let mut statement = conn.prepare(
        "SELECT resource_type FROM acl_resources WHERE account_id=?1 AND upstream_id=?2",
    )?;
    let kinds = statement
        .query_map(params![account_id, upstream_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut foreign = false;
    for kind in kinds {
        // 表内取值受 CHECK 约束，非法取值说明库被外部改写：按未知处理，不放行。
        let Some(kind) = kind_from_str(&kind) else {
            foreign = true;
            continue;
        };
        let key = ResourceKey {
            account_id: account_id.to_owned(),
            kind,
            upstream_id: upstream_id.to_owned(),
        };
        match authorize_in(conn, &actor.0, &key, action) {
            Ok(_) => return Ok(AutoAuthority::Visible(kind)),
            Err(AclError::Forbidden) => foreign = true,
            Err(error) => return Err(error),
        }
    }
    Ok(if foreign {
        AutoAuthority::Foreign
    } else {
        AutoAuthority::Unknown
    })
}

/// `None` 表示上游创建失败或未被确认：不登记任何东西。
pub fn record_created(
    conn: &Connection,
    actor: &RequestIdentity,
    receipt: Option<ConfirmedCreation>,
) -> Result<Option<AclChange>> {
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    if receipt.creation_id.trim().is_empty() {
        return Err(AclError::InvalidInput);
    }
    let key = &receipt.resource;
    let tx = immediate(conn)?;
    if let Some(project) = &receipt.project {
        check_project(&tx, &actor.0, key, project)?;
    }
    let duplicate: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM acl_resources WHERE creation_id=?1 OR (account_id=?2 AND resource_type=?3 AND upstream_id=?4))",
        params![receipt.creation_id,key.account_id,key.kind.as_str(),key.upstream_id], |r| r.get(0))?;
    if duplicate {
        return Err(AclError::AlreadyRegistered);
    }
    tx.execute("INSERT INTO acl_resources(account_id,resource_type,upstream_id,owner_user_id,creation_id) VALUES(?1,?2,?3,?4,?5)",
        params![key.account_id,key.kind.as_str(),key.upstream_id,actor.0.user_id,receipt.creation_id])?;
    if let Some(project) = &receipt.project {
        tx.execute("INSERT INTO acl_project_links(account_id,resource_type,upstream_id,project_id) VALUES(?1,?2,?3,?4)",
            params![key.account_id,key.kind.as_str(),key.upstream_id,project.upstream_id])?;
    }
    let id = audit(&tx, &actor.0, "create", key, None, receipt.project.as_ref())?;
    tx.commit()?;
    Ok(Some(change(id, key, None)))
}

/// 未显式分类路径的成功响应登记：只在未登记时插入，绝不覆盖既有归属
/// （`ON CONFLICT DO NOTHING` 同时覆盖主键与 `creation_id` 唯一冲突）。
/// 返回 true 表示本次真的登记了，调用方据此决定是否记日志。
pub fn claim_if_absent(
    conn: &Connection,
    actor: &RequestIdentity,
    key: &ResourceKey,
) -> Result<bool> {
    let tx = immediate(conn)?;
    let creation_id = format!("auto:{}:{}:{}", key.account_id, key.kind.as_str(), key.upstream_id);
    let inserted = tx.execute(
        "INSERT INTO acl_resources(account_id,resource_type,upstream_id,owner_user_id,creation_id) \
         VALUES(?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING",
        params![key.account_id, key.kind.as_str(), key.upstream_id, actor.0.user_id, creation_id],
    )?;
    if inserted == 0 {
        return Ok(false);
    }
    audit(&tx, &actor.0, "claim_auto", key, None, None)?;
    tx.commit()?;
    Ok(true)
}

/// 管理员认领/重新分配**未登记**资源：把 key 登记到 `owner_user_id` 名下。
/// 已登记资源不改属主（返回 `AlreadyRegistered`），避免管理员误覆盖他人归属。
pub fn claim(
    conn: &Connection,
    actor: &RequestIdentity,
    resource: &ResourceKey,
    owner_user_id: &str,
) -> Result<AclChange> {
    if !actor.0.is_admin {
        return Err(AclError::Forbidden);
    }
    if !valid_user_id(owner_user_id) {
        return Err(AclError::InvalidInput);
    }
    let tx = immediate(conn)?;
    let duplicate: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM acl_resources WHERE account_id=?1 AND resource_type=?2 AND upstream_id=?3)",
        params![resource.account_id, resource.kind.as_str(), resource.upstream_id],
        |r| r.get(0),
    )?;
    if duplicate {
        return Err(AclError::AlreadyRegistered);
    }
    let creation_id = format!(
        "claim:{}:{}:{}",
        resource.account_id,
        resource.kind.as_str(),
        resource.upstream_id
    );
    tx.execute(
        "INSERT INTO acl_resources(account_id,resource_type,upstream_id,owner_user_id,creation_id) VALUES(?1,?2,?3,?4,?5)",
        params![resource.account_id, resource.kind.as_str(), resource.upstream_id, owner_user_id, creation_id],
    )?;
    let id = audit(&tx, &actor.0, "claim", resource, Some(owner_user_id), None)?;
    tx.commit()?;
    Ok(change(id, resource, Some(owner_user_id)))
}

pub fn grant(
    conn: &Connection,
    actor: &RequestIdentity,
    resource: &ResourceKey,
    recipient_user_id: &str,
) -> Result<AclChange> {
    set_share(conn, actor, resource, recipient_user_id, true)
}

pub fn revoke(
    conn: &Connection,
    actor: &RequestIdentity,
    resource: &ResourceKey,
    recipient_user_id: &str,
) -> Result<AclChange> {
    set_share(conn, actor, resource, recipient_user_id, false)
}

fn set_share(
    conn: &Connection,
    actor: &RequestIdentity,
    resource: &ResourceKey,
    recipient: &str,
    grant: bool,
) -> Result<AclChange> {
    if !actor.0.is_admin {
        return Err(AclError::Forbidden);
    }
    if !valid_user_id(recipient) {
        return Err(AclError::InvalidInput);
    }
    let tx = immediate(conn)?;
    require_known(&tx, resource)?;
    if grant {
        tx.execute("INSERT OR IGNORE INTO acl_shares(account_id,resource_type,upstream_id,recipient_user_id) VALUES(?1,?2,?3,?4)",
            params![resource.account_id,resource.kind.as_str(),resource.upstream_id,recipient])?;
    } else {
        tx.execute("DELETE FROM acl_shares WHERE account_id=?1 AND resource_type=?2 AND upstream_id=?3 AND recipient_user_id=?4",
            params![resource.account_id,resource.kind.as_str(),resource.upstream_id,recipient])?;
    }
    let id = audit(
        &tx,
        &actor.0,
        if grant { "grant" } else { "revoke" },
        resource,
        Some(recipient),
        None,
    )?;
    tx.commit()?;
    Ok(change(id, resource, Some(recipient)))
}

pub fn move_to_project(
    conn: &Connection,
    actor: &RequestIdentity,
    resource: &ResourceKey,
    project: Option<&ResourceKey>,
) -> Result<AclChange> {
    if resource.kind == ResourceKind::Project {
        return Err(AclError::InvalidOperation);
    }
    let tx = immediate(conn)?;
    authorize_in(&tx, &actor.0, resource, Action::Modify)?;
    if let Some(project) = project {
        check_project(&tx, &actor.0, resource, project)?;
    }
    let before = audience(&tx, resource)?;
    tx.execute("DELETE FROM acl_project_links WHERE account_id=?1 AND resource_type=?2 AND upstream_id=?3",
        params![resource.account_id,resource.kind.as_str(),resource.upstream_id])?;
    if let Some(project) = project {
        tx.execute("INSERT INTO acl_project_links(account_id,resource_type,upstream_id,project_id) VALUES(?1,?2,?3,?4)",
            params![resource.account_id,resource.kind.as_str(),resource.upstream_id,project.upstream_id])?;
    }
    if !actor.0.is_admin && !audience(&tx, resource)?.is_subset(&before) {
        return Err(AclError::Forbidden); // Dropping transaction restores previous link.
    }
    let id = audit(&tx, &actor.0, "move", resource, None, project)?;
    tx.commit()?;
    Ok(change(id, resource, None))
}

/// 管理员资源查询：按账号/类型/属主过滤，返回有界页（不是备份导出）。
pub fn list_resources(
    conn: &Connection,
    actor: &RequestIdentity,
    account_id: Option<&str>,
    kind: Option<ResourceKind>,
    owner_user_id: Option<&str>,
    limit: u32,
) -> Result<Vec<ResourceRecord>> {
    if !actor.0.is_admin {
        return Err(AclError::Forbidden);
    }
    if limit == 0 || limit > 1000 {
        return Err(AclError::InvalidInput);
    }
    let kind = kind.map(ResourceKind::as_str);
    let mut statement = conn.prepare(
        "SELECT account_id,resource_type,upstream_id,owner_user_id FROM acl_resources \
         WHERE (?1 IS NULL OR account_id=?1) AND (?2 IS NULL OR resource_type=?2) \
           AND (?3 IS NULL OR owner_user_id=?3) \
         ORDER BY account_id,resource_type,upstream_id LIMIT ?4",
    )?;
    let rows = statement.query_map(params![account_id, kind, owner_user_id, limit], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (account_id, resource_type, upstream_id, owner_user_id) = row?;
        let kind = kind_from_str(&resource_type).ok_or(AclError::InvalidInput)?;
        records.push(ResourceRecord {
            owner_user_id,
            resource: ResourceKey {
                account_id,
                kind,
                upstream_id,
            },
        });
    }
    Ok(records)
}

/// 管理员用的「已登记 id 集合」：管理端把它与上游清单做差集，得到**未登记**
/// 资源供认领。只读、无副作用；SQL 留在本模块内，调用方不直接碰 ACL 表。
pub fn registered_ids(
    conn: &Connection,
    actor: &RequestIdentity,
    account_id: &str,
    kind: ResourceKind,
) -> Result<BTreeSet<String>> {
    if !actor.0.is_admin {
        return Err(AclError::Forbidden);
    }
    let mut statement = conn.prepare(
        "SELECT upstream_id FROM acl_resources WHERE account_id=?1 AND resource_type=?2",
    )?;
    let rows = statement.query_map(params![account_id, kind.as_str()], |row| {
        row.get::<_, String>(0)
    })?;
    let mut ids = BTreeSet::new();
    for row in rows {
        ids.insert(row?);
    }
    Ok(ids)
}

/// Admin-only paginated audit read; a bounded page is not a backup export.
pub fn audit_after(
    conn: &Connection,
    actor: &RequestIdentity,
    after_id: i64,
    limit: u32,
) -> Result<Vec<AuditRecord>> {
    if !actor.0.is_admin {
        return Err(AclError::Forbidden);
    }
    if after_id < 0 || limit == 0 || limit > 1000 {
        return Err(AclError::InvalidInput);
    }
    let mut statement = conn.prepare("SELECT id,actor_user_id,authorization_version,action,account_id,resource_type,upstream_id,recipient_user_id,project_id,occurred_at FROM acl_audit WHERE id>?1 ORDER BY id LIMIT ?2")?;
    let rows = statement.query_map(params![after_id, limit], |r| {
        Ok(AuditRecord {
            id: r.get(0)?,
            occurred_at: r.get(9)?,
            actor_user_id: r.get(1)?,
            authorization_version: r.get(2)?,
            action: r.get(3)?,
            account_id: r.get(4)?,
            resource_type: r.get(5)?,
            upstream_id: r.get(6)?,
            recipient_user_id: r.get(7)?,
            project_id: r.get(8)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// 未显式分类路径的运营审计：只记「哪个方法+路径首次出现、被怎么处理」，
/// 不涉及具体归属，因此 `resource_type` 固定为 `route`、`upstream_id` 是模板键。
pub fn audit_route(
    conn: &Connection,
    actor: &RequestIdentity,
    account_id: &str,
    action: &str,
    route: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO acl_audit(actor_user_id,authorization_version,action,account_id,resource_type,upstream_id) \
         VALUES(?1,?2,?3,?4,'route',?5)",
        params![
            actor.0.user_id,
            actor.0.authorization_version,
            action,
            account_id,
            route
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// 已登记资源行（管理员查询输出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub owner_user_id: String,
    pub resource: ResourceKey,
}

/// 某账号下当前会话可见的全部资源 id：集合响应的过滤与 `total` 共用这条受众
/// 规则，逐条判权与集合计数不会漂移。
pub fn visible_ids(
    conn: &Connection,
    actor: &RequestIdentity,
    account_id: &str,
    kind: ResourceKind,
) -> Result<BTreeSet<String>> {
    let mut statement =
        conn.prepare("SELECT upstream_id FROM acl_resources WHERE account_id=?1 AND resource_type=?2")?;
    let rows = statement.query_map(params![account_id, kind.as_str()], |r| {
        r.get::<_, String>(0)
    })?;
    let mut visible = BTreeSet::new();
    for row in rows {
        let upstream_id = row?;
        let key = ResourceKey {
            account_id: account_id.to_owned(),
            kind,
            upstream_id: upstream_id.clone(),
        };
        if authorize_in(conn, &actor.0, &key, Action::Read).is_ok() {
            visible.insert(upstream_id);
        }
    }
    Ok(visible)
}

/// 独立拥有的 ACL 句柄：只用于不接入网关库的独立使用与离线测试；
/// 产品路径直接调用上面的自由函数，与网关共用同一个 SQLite 连接。
pub struct ResourceAcl {
    conn: Connection,
}

impl ResourceAcl {
    pub fn new(conn: Connection) -> Result<Self> {
        init(&conn)?;
        Ok(Self { conn })
    }

    pub fn authorize(
        &self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        action: Action,
    ) -> Result<Access> {
        authorize(&self.conn, actor, resource, action)
    }

    pub fn record_created(
        &self,
        actor: &RequestIdentity,
        receipt: Option<ConfirmedCreation>,
    ) -> Result<Option<AclChange>> {
        record_created(&self.conn, actor, receipt)
    }

    pub fn grant(
        &self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        recipient_user_id: &str,
    ) -> Result<AclChange> {
        grant(&self.conn, actor, resource, recipient_user_id)
    }

    pub fn revoke(
        &self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        recipient_user_id: &str,
    ) -> Result<AclChange> {
        revoke(&self.conn, actor, resource, recipient_user_id)
    }

    pub fn move_to_project(
        &self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        project: Option<&ResourceKey>,
    ) -> Result<AclChange> {
        move_to_project(&self.conn, actor, resource, project)
    }

    pub fn audit_after(
        &self,
        actor: &RequestIdentity,
        after_id: i64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>> {
        audit_after(&self.conn, actor, after_id, limit)
    }
}

fn require_known(conn: &Connection, key: &ResourceKey) -> Result<String> {
    conn.query_row("SELECT owner_user_id FROM acl_resources WHERE account_id=?1 AND resource_type=?2 AND upstream_id=?3",
        params![key.account_id,key.kind.as_str(),key.upstream_id], |r| r.get(0)).optional()?
        .ok_or(AclError::UnknownResource)
}

fn authorize_in(
    conn: &Connection,
    actor: &Identity,
    key: &ResourceKey,
    action: Action,
) -> Result<Access> {
    if action == Action::ContinueChat && key.kind != ResourceKind::Conversation {
        return Err(AclError::InvalidOperation);
    }
    let owner = match require_known(conn, key) {
        Ok(owner) => owner,
        Err(AclError::UnknownResource) if actor.is_admin && action == Action::Read => {
            return Ok(Access::UnknownAdministratorRead)
        }
        Err(error) => return Err(error),
    };
    if actor.is_admin || owner == actor.user_id || audience(conn, key)?.contains(&actor.user_id) {
        Ok(Access::Registered)
    } else {
        Err(AclError::Forbidden)
    }
}

fn check_project(
    conn: &Connection,
    actor: &Identity,
    resource: &ResourceKey,
    project: &ResourceKey,
) -> Result<()> {
    if resource.kind == ResourceKind::Project || project.kind != ResourceKind::Project {
        return Err(AclError::InvalidOperation);
    }
    if resource.account_id != project.account_id {
        return Err(AclError::CrossAccount);
    }
    authorize_in(conn, actor, project, Action::Modify)?;
    Ok(())
}

/// Compute, never persist, the effective non-admin audience. Connectors omit
/// project inheritance even when linked for metadata purposes.
fn audience(conn: &Connection, key: &ResourceKey) -> Result<BTreeSet<String>> {
    let mut statement = conn.prepare(r#"
        SELECT owner_user_id FROM acl_resources WHERE account_id=?1 AND resource_type=?2 AND upstream_id=?3
        UNION SELECT recipient_user_id FROM acl_shares WHERE account_id=?1 AND resource_type=?2 AND upstream_id=?3
        UNION SELECT p.owner_user_id FROM acl_project_links l JOIN acl_resources p
          ON p.account_id=l.account_id AND p.resource_type='project' AND p.upstream_id=l.project_id
          WHERE l.account_id=?1 AND l.resource_type=?2 AND l.upstream_id=?3 AND ?2<>'connector'
        UNION SELECT s.recipient_user_id FROM acl_project_links l JOIN acl_shares s
          ON s.account_id=l.account_id AND s.resource_type='project' AND s.upstream_id=l.project_id
          WHERE l.account_id=?1 AND l.resource_type=?2 AND l.upstream_id=?3 AND ?2<>'connector'
    "#)?;
    let rows = statement.query_map(
        params![key.account_id, key.kind.as_str(), key.upstream_id],
        |r| r.get(0),
    )?;
    Ok(rows.collect::<rusqlite::Result<BTreeSet<_>>>()?)
}

fn audit(
    conn: &Connection,
    actor: &Identity,
    action: &str,
    resource: &ResourceKey,
    recipient: Option<&str>,
    project: Option<&ResourceKey>,
) -> Result<i64> {
    conn.execute("INSERT INTO acl_audit(actor_user_id,authorization_version,action,account_id,resource_type,upstream_id,recipient_user_id,project_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![actor.user_id,actor.authorization_version,action,resource.account_id,resource.kind.as_str(),resource.upstream_id,recipient,project.map(|p|p.upstream_id.as_str())])?;
    Ok(conn.last_insert_rowid())
}

fn change(id: i64, key: &ResourceKey, user: Option<&str>) -> AclChange {
    AclChange {
        audit_id: id,
        scope: key.clone(),
        include_project_children: key.kind == ResourceKind::Project,
        user_id: user.map(str::to_owned),
    }
}

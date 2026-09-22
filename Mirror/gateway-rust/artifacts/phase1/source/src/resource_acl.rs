//! Isolated ACL v1. Not wired into the gateway, its login, or its database.
//! Trust boundary: only a verified Django response and a server-side successful
//! creation adapter may construct the inputs. This module performs no network I/O.

use std::collections::BTreeSet;
use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct ResourceAcl {
    conn: Connection,
}

impl ResourceAcl {
    /// Use an independent, caller-owned SQLite connection. No legacy migration,
    /// no user database, no implicit connection to production or original storage.
    pub fn new(mut conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.commit()?;
        Ok(Self { conn })
    }

    pub fn authorize(
        &self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        action: Action,
    ) -> Result<Access> {
        authorize(&self.conn, &actor.0, resource, action)
    }

    /// None means upstream creation failed/was not confirmed: nothing is recorded.
    pub fn record_created(
        &mut self,
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
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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

    pub fn grant(
        &mut self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        recipient_user_id: &str,
    ) -> Result<AclChange> {
        self.set_share(actor, resource, recipient_user_id, true)
    }

    pub fn revoke(
        &mut self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        recipient_user_id: &str,
    ) -> Result<AclChange> {
        self.set_share(actor, resource, recipient_user_id, false)
    }

    fn set_share(
        &mut self,
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
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        &mut self,
        actor: &RequestIdentity,
        resource: &ResourceKey,
        project: Option<&ResourceKey>,
    ) -> Result<AclChange> {
        if resource.kind == ResourceKind::Project {
            return Err(AclError::InvalidOperation);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorize(&tx, &actor.0, resource, Action::Modify)?;
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

    /// Admin-only paginated audit read; a bounded page is not a backup export.
    pub fn audit_after(
        &self,
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
        let mut statement = self.conn.prepare("SELECT id,actor_user_id,authorization_version,action,account_id,resource_type,upstream_id,recipient_user_id,project_id,occurred_at FROM acl_audit WHERE id>?1 ORDER BY id LIMIT ?2")?;
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
}

fn require_known(conn: &Connection, key: &ResourceKey) -> Result<String> {
    conn.query_row("SELECT owner_user_id FROM acl_resources WHERE account_id=?1 AND resource_type=?2 AND upstream_id=?3",
        params![key.account_id,key.kind.as_str(),key.upstream_id], |r| r.get(0)).optional()?
        .ok_or(AclError::UnknownResource)
}

fn authorize(
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
    authorize(conn, actor, project, Action::Modify)?;
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

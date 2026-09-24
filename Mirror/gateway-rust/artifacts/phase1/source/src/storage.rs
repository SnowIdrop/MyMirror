// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : storage.rs
// Created : 2026-09-22
// Summary : 网关 SQLite 存储层：8 张原版表 + 4 张 ACL 表、settings 读写、
//           v3 备份导出/事务恢复（v2 备份显式拒绝，避免静默丢失 ACL 权限）、
//           HTTP 兼容备份恢复分派（restore_http_backup）、
//           旧库只读迁移（新库清空会话）。DDL 与行为证据来自
//           reverse/reports/05-database-schema.md 与 04-gateway-disassembly.md。
// -----------------------------------------------------------------------------

//! 存储层实现（证据：reports/05-database-schema.md §3/§5/§6/§7）。
//!
//! 关键判读（静态证据，动态未证实，若动态结果出现需复核）：
//! - `export_backup` 按库内原样导出（敏感列保持 `enc:v1:` 密文形态，不假设明文），
//!   与 `restore_backup` 严格互逆；报告 §7.1 的“导出明文”为静态判读。
//! - `restore_backup` 为“先清空再回填”的整表替换语义：信封未知键、行内未知字段、
//!   缺字段、类型错误一律失败，且清空与回填在同一事务内，任何错误整体回滚。
//! - `migrate` 以只读方式打开旧库，把非会话数据重加密写入新库，并清空新库
//!   `gateway_sessions`（登录会话与旧密钥绑定，迁移后需重新登录；此语义源自任务约定，
//!   报告内没有对应的原版函数）。
//! - `restore_http_backup` 复刻原版 `/api/backup/restore` 的 HTTP 分派（动态证据
//!   evidence/backup-v3-original-*）：`version==2` 为完整备份路径（8 表键必须为数组，
//!   先清空再回填），其余输入为旧格式局部路径（仅对出现的数组键逐表 upsert，不清空）。

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension, Transaction};
use serde_json::{json, Map, Value};

use crate::crypto::{self, Crypto};

/// 建库 DDL（8 表 + 3 索引 + 存量回填），逐字复刻报告 §3。
const SCHEMA_SQL: &str = include_str!("schema.sql");

/// 备份版本号。原版 export_backup 恒写 2；本候选新增 ACL 权限后升为 3，
/// 并显式拒绝 v2 备份：旧信封不含 ACL 表，静默恢复会让所有归属失效。
const BACKUP_VERSION: u64 = 3;

/// 恢复前清空语句：按原版 DELETE 批（@0xD8FF3A）的“子表 → 父表”顺序删除，
/// ACL 四表按共享/关联/审计 → 资源 的顺序插在同批最前（外键要求先删子表）。
const RESTORE_DELETE_SQL: &str = "\
DELETE FROM acl_audit;
DELETE FROM acl_shares;
DELETE FROM acl_project_links;
DELETE FROM acl_resources;
DELETE FROM conversation_model_statistics;
DELETE FROM conversation_statistics;
DELETE FROM conversation_owners;
DELETE FROM project_owners;
DELETE FROM gateway_sessions;
DELETE FROM visit_logs;
DELETE FROM chatgpt_accounts;
DELETE FROM gateway_settings;";

/// 表描述：库内表名、备份 JSON 键、备份覆盖列、冲突键、加密列。
struct TableSpec {
    /// 库内表名。
    name: &'static str,
    /// 备份 JSON 信封中的键（`gateway_settings` → `settings`，报告 §7.1）。
    json_key: &'static str,
    /// 备份/恢复覆盖的列，顺序与报告 §7.1 的 SELECT、§7.2 的 INSERT 参数一致。
    columns: &'static [&'static str],
    /// `ON CONFLICT` 目标（报告 §7.2）。
    conflict: &'static str,
    /// 加密存储的列（报告 §6）；`gateway_settings.value` 的加密由行内 key 决定。
    encrypted_columns: &'static [&'static str],
}

/// 备份/恢复顺序：先 8 张原版表（与报告 §7.1 一致），再接 4 张 ACL 表。
const TABLES: [TableSpec; 12] = [
    TableSpec {
        name: "chatgpt_accounts",
        json_key: "chatgpt_accounts",
        columns: &[
            "id",
            "chatgpt_username",
            "auth_status",
            "plan_type",
            "access_token",
            "session_token",
            "extra_cookies",
            "refresh_token",
            "remark",
            "created_time",
            "updated_time",
        ],
        conflict: "id",
        encrypted_columns: &[
            "access_token",
            "session_token",
            "extra_cookies",
            "refresh_token",
        ],
    },
    TableSpec {
        name: "gateway_sessions",
        json_key: "gateway_sessions",
        columns: &[
            "id",
            "user_name",
            "chatgpt_username",
            "access_token",
            "session_token",
            "extra_cookies",
            "login_mode",
            "mirror_token",
            "isolated_session",
            "force_chat_mode",
            "limits",
            "proxy_node_id",
            "daily_quota",
            "monthly_quota",
            "chatgpt_account_id",
            "created_at",
            "updated_at",
        ],
        conflict: "id",
        encrypted_columns: &["access_token", "session_token", "extra_cookies"],
    },
    TableSpec {
        name: "gateway_settings",
        json_key: "settings",
        columns: &["key", "value", "updated_at"],
        conflict: "key",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "conversation_owners",
        json_key: "conversation_owners",
        columns: &[
            "chatgpt_username",
            "conversation_id",
            "user_name",
            "created_at",
            "updated_at",
        ],
        conflict: "chatgpt_username, conversation_id",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "project_owners",
        json_key: "project_owners",
        columns: &[
            "chatgpt_username",
            "project_id",
            "user_name",
            "created_at",
            "updated_at",
        ],
        conflict: "chatgpt_username, project_id",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "visit_logs",
        json_key: "visit_logs",
        columns: &[
            "id",
            "username",
            "chatgpt_username",
            "log_type",
            "created_at",
            "ip",
            "user_agent",
        ],
        conflict: "id",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "conversation_statistics",
        json_key: "conversation_statistics",
        columns: &[
            "chatgpt_username",
            "conversation_id",
            "user_name",
            "title",
            "message_count",
            "conversation_counted",
            "created_at",
            "updated_at",
        ],
        conflict: "chatgpt_username, conversation_id",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "conversation_model_statistics",
        json_key: "conversation_model_statistics",
        columns: &["user_name", "model_name", "message_count", "updated_at"],
        conflict: "user_name, model_name",
        encrypted_columns: &[],
    },
    // ACL 四表：权限真相在网关库内，必须随备份一起搬迁，否则恢复后归属全丢。
    TableSpec {
        name: "acl_resources",
        json_key: "acl_resources",
        columns: &[
            "account_id",
            "resource_type",
            "upstream_id",
            "owner_user_id",
            "creation_id",
        ],
        conflict: "account_id, resource_type, upstream_id",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "acl_project_links",
        json_key: "acl_project_links",
        columns: &[
            "account_id",
            "resource_type",
            "upstream_id",
            "project_type",
            "project_id",
        ],
        conflict: "account_id, resource_type, upstream_id",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "acl_shares",
        json_key: "acl_shares",
        columns: &[
            "account_id",
            "resource_type",
            "upstream_id",
            "recipient_user_id",
        ],
        conflict: "account_id, resource_type, upstream_id, recipient_user_id",
        encrypted_columns: &[],
    },
    TableSpec {
        name: "acl_audit",
        json_key: "acl_audit",
        columns: &[
            "id",
            "occurred_at",
            "actor_user_id",
            "authorization_version",
            "action",
            "account_id",
            "resource_type",
            "upstream_id",
            "recipient_user_id",
            "project_id",
        ],
        conflict: "id",
        encrypted_columns: &[],
    },
];

/// ACL 表不属于原版 8 表：旧库迁移与旧格式恢复都不搬运它们
/// （归属由映射端点回填，不能从没有 ACL 表的旧库凭空生成）。
fn is_acl_table(name: &str) -> bool {
    name.starts_with("acl_")
}

/// 网关存储句柄：外层自行加锁，本结构内部不持 `Mutex`。
pub struct Database {
    /// SQLite 连接（原版以 0x8046 = READ_WRITE|CREATE|URI|NO_MUTEX 打开）。
    pub conn: Connection,
    /// 敏感列加解密器（`SHA-256(trim(key))` 派生 AES-256-GCM）。
    pub crypto: Crypto,
}

impl Database {
    /// 打开（或创建）数据库：建表 → 旧库补列 → 敏感列迁移加密。
    pub fn open(path: &Path, key: &str) -> Result<Self> {
        let crypto = Crypto::new(key)?;
        if let Some(parent) = path.parent() {
            // 相对路径（如 "db.sqlite"）没有父目录，此时无需创建目录
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("创建数据库目录失败: {}", parent.display()))?;
            }
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)
            .with_context(|| format!("打开数据库失败: {}", path.display()))?;
        conn.execute_batch(SCHEMA_SQL)
            .context("初始化 schema 失败")?;
        ensure_legacy_columns(&conn)?;
        crate::resource_acl::init(&conn)?;
        let db = Self { conn, crypto };
        db.migrate_sensitive_rows()?;
        Ok(db)
    }

    /// 读取设置：`is_encrypted_setting_key` 列出的键为整值加密，先解密再解析 JSON。
    pub fn get_setting(&self, key: &str) -> Result<Option<Value>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM gateway_settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let text = if is_encrypted_setting_key(key) {
            self.crypto.decrypt(&raw)?
        } else {
            raw
        };
        let value =
            serde_json::from_str(&text).with_context(|| format!("设置 {key} 的值不是合法 JSON"))?;
        Ok(Some(value))
    }

    /// 写入设置：加密键整值加密后落库（已加密值幂等），非加密键明文 JSON。
    pub fn set_setting(&self, key: &str, value: &Value) -> Result<()> {
        let mut text = serde_json::to_string(value).context("序列化设置值失败")?;
        if is_encrypted_setting_key(key) {
            text = self.crypto.encrypt(&text)?;
        }
        self.conn.execute(
            "INSERT INTO gateway_settings (key, value, updated_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, text, now_ts()],
        )?;
        Ok(())
    }

    /// 导出 v2 备份信封：`version` + 8 个表数组（`settings` 对应 `gateway_settings`）。
    pub fn export_backup(&self) -> Result<Value> {
        let mut envelope = Map::new();
        envelope.insert("version".to_string(), json!(BACKUP_VERSION));
        for spec in &TABLES {
            envelope.insert(
                spec.json_key.to_string(),
                Value::Array(read_rows(&self.conn, spec)?),
            );
        }
        Ok(Value::Object(envelope))
    }

    /// 恢复 v2 备份：校验信封 → 事务内清空 8 表 → 逐表 upsert；任何错误整体回滚。
    pub fn restore_backup(&mut self, payload: &Value) -> Result<()> {
        let obj = payload
            .as_object()
            .ok_or_else(|| anyhow!("备份必须是 JSON 对象"))?;
        for key in obj.keys() {
            if key != "version" && !TABLES.iter().any(|spec| spec.json_key == key) {
                bail!("备份含未知字段 {key}");
            }
        }
        if obj.get("version").and_then(Value::as_u64) != Some(BACKUP_VERSION) {
            bail!("备份 version 必须为 {BACKUP_VERSION}");
        }
        let mut arrays = Vec::with_capacity(TABLES.len());
        for spec in &TABLES {
            let array = obj
                .get(spec.json_key)
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("备份字段 {} 缺失或不是数组", spec.json_key))?;
            let mut validated = array.clone();
            for row in &mut validated {
                for column in spec.encrypted_columns {
                    if let Some(value) = row.get(*column).and_then(Value::as_str) {
                        self.crypto.decrypt(value)?;
                        row[*column] = json!(self.crypto.encrypt(value)?);
                    }
                }
                if spec.name == "gateway_settings"
                    && row["key"]
                        .as_str()
                        .map(is_encrypted_setting_key)
                        .unwrap_or(false)
                {
                    let value = row["value"].as_str().context("敏感配置值必须是字符串")?;
                    self.crypto.decrypt(value)?;
                    row["value"] = json!(self.crypto.encrypt(value)?);
                }
            }
            arrays.push(validated);
        }
        let tx = self.conn.transaction()?;
        tx.execute_batch(RESTORE_DELETE_SQL)?;
        for (spec, rows) in TABLES.iter().zip(arrays) {
            upsert_rows(&tx, spec, &rows)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// HTTP 兼容恢复：原版 `/api/backup/restore` 分派（证据 evidence/backup-v3-original-003..012），
    /// 其中整包格式随 ACL 接线升到 v3。
    ///
    /// - `version == 3`（当前版本）→ 完整备份路径：12 个表键必须齐全且为数组
    ///   （否则报 `完整备份缺少 <键>`），事务内先清空再回填；
    /// - 其它数字版本 → 显式拒绝：v2 及更早的信封不含 ACL 四表，按原版
    ///   「非 2 版本走局部 upsert」处理会静默丢掉全部归属；更高版本的语义未知。
    ///   两者都不能退化成局部写入，文案给出重新导出的行动指引；
    /// - 无 `version` 或 `version` 不是非负整数 → 旧格式局部路径：
    ///   只处理出现且为数组的表键，逐表 upsert 且不清空；非数组值与未知信封键忽略；
    /// - 行内未知字段忽略；密文与明文一律按原样存储（本函数不做加解密）；
    /// - 缺失/类型不符的必填字段按观测文案报错，事务内失败整体回滚。
    pub fn restore_http_backup(&mut self, payload: &Value) -> Result<()> {
        self.restore_http_backup_validated(payload, |_, _| Ok(()))
    }

    /// 运行时配置校验在同一写事务内执行；失败由 Transaction 回滚，不能发布半恢复状态。
    pub fn restore_http_backup_validated(
        &mut self,
        payload: &Value,
        validate: impl FnOnce(&Connection, &Crypto) -> Result<()>,
    ) -> Result<()> {
        // 带 version 的信封只接受当前版本：v2 及更早不含 ACL 四表（静默恢复会让
        // 归属全丢），更高版本的信封语义未知，都不能退化成“局部 upsert”。
        if let Some(version) = payload.get("version").and_then(Value::as_u64) {
            if version != BACKUP_VERSION {
                if version < BACKUP_VERSION {
                    bail!(
                        "网关备份 v{version} 不含 ACL 权限表，拒绝静默丢失权限；\
                         请使用 v{BACKUP_VERSION} 备份重新导出"
                    );
                }
                bail!(
                    "网关备份版本 v{version} 不受支持（当前 v{BACKUP_VERSION}），\
                     拒绝按旧格式局部恢复"
                );
            }
        }
        let full = payload.get("version").and_then(Value::as_u64) == Some(BACKUP_VERSION);
        let mut planned = Vec::new();
        for spec in &TABLES {
            let Some(array) = payload.get(spec.json_key).and_then(Value::as_array) else {
                if full {
                    bail!("完整备份缺少 {}", spec.json_key);
                }
                // 缺失或非数组：原版忽略该键（证据 backup-v3-original-011 settings 对象载荷 200 且无变化）
                continue;
            };
            let mut rows = Vec::with_capacity(array.len());
            for row in array {
                rows.push(http_row_values(spec, row)?);
            }
            planned.push((spec, rows));
        }
        let tx = self.conn.transaction()?;
        if full {
            tx.execute_batch(RESTORE_DELETE_SQL)?;
        }
        for (spec, rows) in &planned {
            upsert_value_rows(&tx, spec, rows)?;
        }
        validate(&tx, &self.crypto)?;
        tx.commit()?;
        Ok(())
    }

    /// 旧库只读迁移：把非会话数据重加密写入新库，并清空新库 `gateway_sessions`。
    pub fn migrate(source: &Path, dest: &Path, source_key: &str, dest_key: &str) -> Result<()> {
        // 迁移是新库事务，拒绝覆盖已有路径（包括源库本身及链接），避免破坏回滚基线。
        if dest.exists() || fs::symlink_metadata(dest).is_ok() {
            bail!("迁移目标必须是不存在的新文件");
        }
        let source_crypto = Crypto::new(source_key)?;
        let dest_crypto = Crypto::new(dest_key)?;
        let source_flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let source_conn = Connection::open_with_flags(source, source_flags)
            .with_context(|| format!("打开源数据库失败: {}", source.display()))?;
        for spec in &TABLES {
            // 会话不迁移，源库无需存在该表
            // ACL 表是候选新增能力，旧库没有；归属由映射端点回填，不从旧库搬运
            if spec.name == "gateway_sessions" || is_acl_table(spec.name) {
                continue;
            }
            if !table_exists(&source_conn, spec.name)? {
                bail!("源库缺少表 {}", spec.name);
            }
        }
        let mut prepared = Vec::new();
        for spec in &TABLES {
            // 登录会话与旧密钥/旧登录态绑定，不迁移（迁移完成需在新库重新登录）
            if spec.name == "gateway_sessions" || is_acl_table(spec.name) {
                continue;
            }
            let columns: Vec<String> = source_conn
                .prepare(&format!("PRAGMA table_info({})", spec.name))?
                .query_map([], |row| row.get(1))?
                .collect::<std::result::Result<_, _>>()?;
            for column in columns {
                if !spec.columns.contains(&column.as_str()) {
                    bail!("源库含未知字段 {}.{column}", spec.name);
                }
            }
            let rows = read_rows(&source_conn, spec)?;
            prepared.push((
                spec,
                transform_for_migration(spec, rows, &source_crypto, &dest_crypto)?,
            ));
        }
        // 所有解密/字段校验先于目标创建；create_new 阻止并发覆盖同名目标。
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)?;
        let result = (|| -> Result<()> {
            let mut dest_db = Self::open(dest, dest_key)?;
            let tx = dest_db.conn.transaction()?;
            for (spec, rows) in prepared {
                upsert_rows(&tx, spec, &rows)?;
            }
            tx.commit()?;
            Ok(())
        })();
        if result.is_err() {
            fs::remove_file(dest).context("迁移失败后清理新建目标失败")?;
        }
        result?;
        Ok(())
    }

    /// 解密：非 `enc:v1:` 输入原样透传（与原版 decrypt_secret 一致）。
    pub fn decrypt(&self, value: &str) -> Result<String> {
        self.crypto.decrypt(value)
    }

    /// 加密：已带 `enc:v1:` 输入原样返回（幂等，与原版 encrypt_secret 一致）。
    pub fn encrypt(&self, value: &str) -> Result<String> {
        self.crypto.encrypt(value)
    }

    /// 存量数据迁移（原版 `db::migrate_sensitive_rows`，幂等）：
    /// 凭证列补加密、`mirror_token` 补 `sha256:` 前缀、`mirror_proxy` 设置整值加密。
    fn migrate_sensitive_rows(&self) -> Result<()> {
        let sessions = {
            let mut stmt = self.conn.prepare(
                "SELECT id, access_token, session_token, extra_cookies, mirror_token FROM gateway_sessions",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (id, access_token, session_token, extra_cookies, mirror_token) in sessions {
            let mirror_token = if crypto::is_sha256_hashed(&mirror_token) {
                mirror_token
            } else {
                crypto::sha256_hex(&mirror_token)
            };
            self.conn.execute(
                "UPDATE gateway_sessions SET access_token = ?1, session_token = ?2, \
                 extra_cookies = ?3, mirror_token = ?4 WHERE id = ?5",
                params![
                    self.crypto.encrypt(&access_token)?,
                    encrypt_optional(&self.crypto, session_token)?,
                    encrypt_optional(&self.crypto, extra_cookies)?,
                    mirror_token,
                    id
                ],
            )?;
        }

        let accounts = {
            let mut stmt = self.conn.prepare(
                "SELECT id, access_token, session_token, extra_cookies, refresh_token FROM chatgpt_accounts",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (id, access_token, session_token, extra_cookies, refresh_token) in accounts {
            self.conn.execute(
                "UPDATE chatgpt_accounts SET access_token = ?1, session_token = ?2, \
                 extra_cookies = ?3, refresh_token = ?4 WHERE id = ?5",
                params![
                    self.crypto.encrypt(&access_token)?,
                    encrypt_optional(&self.crypto, session_token)?,
                    encrypt_optional(&self.crypto, extra_cookies)?,
                    encrypt_optional(&self.crypto, refresh_token)?,
                    id
                ],
            )?;
        }

        let mirror_proxy: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM gateway_settings WHERE key = 'mirror_proxy'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(raw) = mirror_proxy {
            let encrypted = self.crypto.encrypt(&raw)?;
            self.conn.execute(
                "UPDATE gateway_settings SET value = ?1 WHERE key = 'mirror_proxy'",
                params![encrypted],
            )?;
        }
        Ok(())
    }
}

/// 读取整表为 JSON 行数组（列顺序同 `TableSpec::columns`）。
fn read_rows(conn: &Connection, spec: &TableSpec) -> Result<Vec<Value>> {
    let sql = format!("SELECT {} FROM {}", spec.columns.join(", "), spec.name);
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut obj = Map::new();
        for (index, column) in spec.columns.iter().enumerate() {
            let mut value = sqlite_to_json(row.get_ref(index)?)?;
            if matches!(
                *column,
                "auth_status" | "isolated_session" | "force_chat_mode" | "conversation_counted"
            ) {
                if let Some(number) = value.as_i64() {
                    value = Value::Bool(number != 0);
                }
            }
            obj.insert(column.to_string(), value);
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
}

/// SQLite 值 → JSON 标量（schema 无 BLOB 列，遇到 BLOB 直接失败而不是猜测编码）。
fn sqlite_to_json(value: ValueRef<'_>) -> Result<Value> {
    Ok(match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(number) => json!(number),
        ValueRef::Real(number) => json!(number),
        ValueRef::Text(bytes) => {
            let text = String::from_utf8(bytes.to_vec())
                .map_err(|_| anyhow!("备份读取到非法 UTF-8 文本"))?;
            Value::String(text)
        }
        ValueRef::Blob(_) => bail!("备份读取到不支持的 BLOB 列值"),
    })
}

/// JSON 标量 → SQLite 值；行内未知字段已在校验阶段拦截。
fn json_scalar_to_sql(value: &Value, table: &str, column: &str) -> Result<SqlValue> {
    Ok(match value {
        Value::Null => SqlValue::Null,
        Value::Bool(flag) => SqlValue::Integer(i64::from(*flag)),
        Value::Number(number) => match number.as_i64() {
            Some(int) => SqlValue::Integer(int),
            None => bail!("备份 {table}.{column} 必须是整数"),
        },
        Value::String(text) => SqlValue::Text(text.clone()),
        Value::Array(_) | Value::Object(_) => {
            bail!("备份 {table}.{column} 不是标量值")
        }
    })
}

/// 时间戳列缺失时以当前时间补默认（报告 §7.2 的缺省字段处理）。
fn is_default_time_column(column: &str) -> bool {
    matches!(column, "created_at" | "updated_at" | "created_time")
}

/// 生成 upsert 语句：冲突键固定，其余列 `= excluded.<列>`。
///
/// 冲突键覆盖全部列时（`acl_shares` 的主键就是全部列）没有可更新的列，
/// 此时退化为 `DO NOTHING`：SQLite 不接受空的 `DO UPDATE SET`，而语义上也不存在
/// 需要覆盖的字段（整行相同即重复授予，重复插入本就应当无副作用）。
fn upsert_sql(spec: &TableSpec) -> String {
    let conflict_columns: Vec<&str> = spec.conflict.split(", ").collect();
    let placeholders: Vec<String> = (1..=spec.columns.len())
        .map(|index| format!("?{index}"))
        .collect();
    let assignments: Vec<String> = spec
        .columns
        .iter()
        .copied()
        .filter(|column| !conflict_columns.contains(column))
        .map(|column| format!("{column} = excluded.{column}"))
        .collect();
    let conflict_action = if assignments.is_empty() {
        "DO NOTHING".to_owned()
    } else {
        format!("DO UPDATE SET {}", assignments.join(", "))
    };
    format!(
        "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT({}) {conflict_action}",
        spec.name,
        spec.columns.join(", "),
        placeholders.join(", "),
        spec.conflict,
    )
}

/// 事务内按已绑定列值逐行 upsert（唯一 INSERT 执行点，严格路径与 HTTP 兼容路径共用）。
fn upsert_value_rows(tx: &Transaction<'_>, spec: &TableSpec, rows: &[Vec<SqlValue>]) -> Result<()> {
    let sql = upsert_sql(spec);
    let mut stmt = tx.prepare(&sql)?;
    for values in rows {
        stmt.execute(params_from_iter(values.iter()))?;
    }
    Ok(())
}

/// 事务内逐行 upsert：未知字段、缺字段、类型错误立即失败（由外层事务回滚）。
fn upsert_rows(tx: &Transaction<'_>, spec: &TableSpec, rows: &[Value]) -> Result<()> {
    let mut bound = Vec::with_capacity(rows.len());
    for row in rows {
        let obj = row
            .as_object()
            .ok_or_else(|| anyhow!("备份 {} 行不是 JSON 对象", spec.name))?;
        for key in obj.keys() {
            if !spec.columns.contains(&key.as_str()) {
                bail!("备份 {} 含未知字段 {key}", spec.name);
            }
        }
        let mut values = Vec::with_capacity(spec.columns.len());
        for column in spec.columns {
            match obj.get(*column) {
                Some(value) => values.push(json_scalar_to_sql(value, spec.name, column)?),
                None => {
                    if is_default_time_column(column) {
                        values.push(SqlValue::Integer(now_ts()));
                    } else {
                        bail!("备份 {} 缺少字段 {column}", spec.name);
                    }
                }
            }
        }
        bound.push(values);
    }
    upsert_value_rows(tx, spec, &bound)
}

/// HTTP 兼容恢复的单行转换：按观测结果处理必填字段与缺省值（证据 backup-v3-original-*）。
/// 返回值的列顺序与 `TableSpec::columns` 一一对应；非对象行按“全字段缺失”处理
/// （原版对字符串行报该表首个必填字段缺失）。
fn http_row_values(spec: &TableSpec, row: &Value) -> Result<Vec<SqlValue>> {
    let empty = Map::new();
    let obj = row.as_object().unwrap_or(&empty);
    match spec.name {
        "chatgpt_accounts" => Ok(vec![
            SqlValue::Integer(http_required_i64(obj, "id", "备份上游账号缺少 ID")?),
            SqlValue::Text(http_required_str(
                obj,
                "chatgpt_username",
                "备份上游账号缺少用户名",
            )?),
            http_bool_or(obj, "auth_status", true),
            http_text_or(obj, "plan_type", "free"),
            SqlValue::Text(http_required_str(
                obj,
                "access_token",
                "备份上游账号缺少 AccessToken",
            )?),
            http_opt_text(obj, "session_token"),
            http_text_or(obj, "extra_cookies", "[]"),
            http_opt_text(obj, "refresh_token"),
            http_opt_text(obj, "remark"),
            http_opt_int(obj, "created_time"),
            http_opt_int(obj, "updated_time"),
        ]),
        "gateway_sessions" => Ok(vec![
            SqlValue::Integer(http_required_i64(obj, "id", "备份 Gateway 会话缺少 ID")?),
            SqlValue::Text(http_required_str(
                obj,
                "user_name",
                "备份 Gateway 会话缺少用户",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "chatgpt_username",
                "备份 Gateway 会话缺少上游账号",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "access_token",
                "备份 Gateway 会话缺少 AccessToken",
            )?),
            http_opt_text(obj, "session_token"),
            http_text_or(obj, "extra_cookies", "[]"),
            http_text_or(obj, "login_mode", "api"),
            SqlValue::Text(http_required_str(
                obj,
                "mirror_token",
                "备份 Gateway 会话缺少令牌",
            )?),
            http_bool_or(obj, "isolated_session", true),
            http_bool_or(obj, "force_chat_mode", true),
            http_text_or(obj, "limits", "[]"),
            http_opt_int(obj, "proxy_node_id"),
            http_int_or(obj, "daily_quota", 0),
            http_int_or(obj, "monthly_quota", 0),
            http_opt_text(obj, "chatgpt_account_id"),
            http_opt_int(obj, "created_at"),
            http_opt_int(obj, "updated_at"),
        ]),
        "gateway_settings" => {
            let now = now_ts();
            Ok(vec![
                SqlValue::Text(http_required_str(obj, "key", "备份设置缺少 key")?),
                SqlValue::Text(http_required_str(obj, "value", "备份设置缺少 value")?),
                http_time_or(obj, "updated_at", now),
            ])
        }
        "conversation_owners" => {
            let now = now_ts();
            Ok(vec![
                SqlValue::Text(http_required_str(
                    obj,
                    "chatgpt_username",
                    "备份会话缺少上游账号",
                )?),
                SqlValue::Text(http_required_str(
                    obj,
                    "conversation_id",
                    "备份会话缺少 ID",
                )?),
                SqlValue::Text(http_required_str(obj, "user_name", "备份会话缺少用户")?),
                http_time_or(obj, "created_at", now),
                http_time_or(obj, "updated_at", now),
            ])
        }
        "project_owners" => {
            let now = now_ts();
            Ok(vec![
                SqlValue::Text(http_required_str(
                    obj,
                    "chatgpt_username",
                    "备份项目缺少上游账号",
                )?),
                SqlValue::Text(http_required_str(obj, "project_id", "备份项目缺少 ID")?),
                SqlValue::Text(http_required_str(obj, "user_name", "备份项目缺少用户")?),
                http_time_or(obj, "created_at", now),
                http_time_or(obj, "updated_at", now),
            ])
        }
        "visit_logs" => {
            let now = now_ts();
            Ok(vec![
                SqlValue::Integer(http_required_i64(obj, "id", "备份日志缺少 ID")?),
                SqlValue::Text(http_required_str(obj, "username", "备份日志缺少用户")?),
                http_opt_text(obj, "chatgpt_username"),
                SqlValue::Text(http_required_str(obj, "log_type", "备份日志缺少类型")?),
                http_time_or(obj, "created_at", now),
                http_text_or(obj, "ip", ""),
                http_text_or(obj, "user_agent", ""),
            ])
        }
        "conversation_statistics" => {
            let now = now_ts();
            Ok(vec![
                SqlValue::Text(http_required_str(
                    obj,
                    "chatgpt_username",
                    "备份统计缺少上游账号",
                )?),
                SqlValue::Text(http_required_str(
                    obj,
                    "conversation_id",
                    "备份统计缺少对话 ID",
                )?),
                SqlValue::Text(http_required_str(obj, "user_name", "备份统计缺少用户")?),
                http_text_or(obj, "title", ""),
                http_int_or(obj, "message_count", 0),
                http_bool_or(obj, "conversation_counted", true),
                http_time_or(obj, "created_at", now),
                http_time_or(obj, "updated_at", now),
            ])
        }
        "conversation_model_statistics" => {
            let now = now_ts();
            Ok(vec![
                SqlValue::Text(http_required_str(obj, "user_name", "备份模型统计缺少用户")?),
                SqlValue::Text(http_required_str(
                    obj,
                    "model_name",
                    "备份模型统计缺少模型",
                )?),
                http_int_or(obj, "message_count", 0),
                http_time_or(obj, "updated_at", now),
            ])
        }
        // ACL 四表：v3 起随网关备份一起搬迁。缺字段按“该表必填字段缺失”拒绝，
        // 不用默认值伪造归属（owner/creation_id 缺失会让权限失真）。
        "acl_resources" => Ok(vec![
            SqlValue::Text(http_required_str(obj, "account_id", "备份 ACL 资源缺少账号")?),
            SqlValue::Text(http_required_str(
                obj,
                "resource_type",
                "备份 ACL 资源缺少类型",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "upstream_id",
                "备份 ACL 资源缺少 ID",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "owner_user_id",
                "备份 ACL 资源缺少属主",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "creation_id",
                "备份 ACL 资源缺少创建回执",
            )?),
        ]),
        "acl_project_links" => Ok(vec![
            SqlValue::Text(http_required_str(obj, "account_id", "备份 ACL 项目关联缺少账号")?),
            SqlValue::Text(http_required_str(
                obj,
                "resource_type",
                "备份 ACL 项目关联缺少类型",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "upstream_id",
                "备份 ACL 项目关联缺少 ID",
            )?),
            http_text_or(obj, "project_type", "project"),
            SqlValue::Text(http_required_str(
                obj,
                "project_id",
                "备份 ACL 项目关联缺少项目 ID",
            )?),
        ]),
        "acl_shares" => Ok(vec![
            SqlValue::Text(http_required_str(obj, "account_id", "备份 ACL 共享缺少账号")?),
            SqlValue::Text(http_required_str(
                obj,
                "resource_type",
                "备份 ACL 共享缺少类型",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "upstream_id",
                "备份 ACL 共享缺少 ID",
            )?),
            SqlValue::Text(http_required_str(
                obj,
                "recipient_user_id",
                "备份 ACL 共享缺少接收者",
            )?),
        ]),
        "acl_audit" => {
            let now = now_ts();
            Ok(vec![
                SqlValue::Integer(http_required_i64(obj, "id", "备份 ACL 审计缺少 ID")?),
                http_time_or(obj, "occurred_at", now),
                SqlValue::Text(http_required_str(
                    obj,
                    "actor_user_id",
                    "备份 ACL 审计缺少操作者",
                )?),
                http_text_or(obj, "authorization_version", ""),
                SqlValue::Text(http_required_str(obj, "action", "备份 ACL 审计缺少动作")?),
                SqlValue::Text(http_required_str(
                    obj,
                    "account_id",
                    "备份 ACL 审计缺少账号",
                )?),
                SqlValue::Text(http_required_str(
                    obj,
                    "resource_type",
                    "备份 ACL 审计缺少类型",
                )?),
                SqlValue::Text(http_required_str(
                    obj,
                    "upstream_id",
                    "备份 ACL 审计缺少 ID",
                )?),
                http_opt_text(obj, "recipient_user_id"),
                http_opt_text(obj, "project_id"),
            ])
        }
        // TABLES/TableSpec 为闭集；新增表时必须同步补充此处的 HTTP 绑定
        other => bail!("备份表 {other} 缺少 HTTP 绑定"),
    }
}

/// HTTP 兼容恢复的必填字符串：缺失或类型不符时按观测文案报错。
fn http_required_str(obj: &Map<String, Value>, key: &str, message: &str) -> Result<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{message}"))
}

/// HTTP 兼容恢复的必填整数（id 等）：缺失或类型不符时按观测文案报错。
fn http_required_i64(obj: &Map<String, Value>, key: &str, message: &str) -> Result<i64> {
    obj.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("{message}"))
}

/// 文本列缺省：缺失/类型不符时取观测默认（如 `extra_cookies` "[]"、`plan_type` "free"）。
fn http_text_or(obj: &Map<String, Value>, key: &str, default: &str) -> SqlValue {
    SqlValue::Text(
        obj.get(key)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_string(),
    )
}

/// 整数列缺省：缺失/类型不符时取观测默认（如 `message_count` 0）。
fn http_int_or(obj: &Map<String, Value>, key: &str, default: i64) -> SqlValue {
    SqlValue::Integer(obj.get(key).and_then(Value::as_i64).unwrap_or(default))
}

/// 布尔列缺省：缺失/类型不符时取观测默认（如 `auth_status` TRUE）。
fn http_bool_or(obj: &Map<String, Value>, key: &str, default: bool) -> SqlValue {
    SqlValue::Integer(i64::from(
        obj.get(key).and_then(Value::as_bool).unwrap_or(default),
    ))
}

/// 可空文本列：缺失/类型不符存 NULL。
fn http_opt_text(obj: &Map<String, Value>, key: &str) -> SqlValue {
    match obj.get(key).and_then(Value::as_str) {
        Some(text) => SqlValue::Text(text.to_string()),
        None => SqlValue::Null,
    }
}

/// 可空整数列：缺失/类型不符存 NULL（如 accounts 时间戳、sessions.created_at）。
fn http_opt_int(obj: &Map<String, Value>, key: &str) -> SqlValue {
    match obj.get(key).and_then(Value::as_i64) {
        Some(number) => SqlValue::Integer(number),
        None => SqlValue::Null,
    }
}

/// 时间戳列缺省：观测上 owners / visit_logs / statistics / settings 取当前时间。
fn http_time_or(obj: &Map<String, Value>, key: &str, now: i64) -> SqlValue {
    SqlValue::Integer(obj.get(key).and_then(Value::as_i64).unwrap_or(now))
}

/// 迁移时对加密列重加密：旧密钥解密（明文输入原样透传）→ 新密钥加密。
fn transform_for_migration(
    spec: &TableSpec,
    rows: Vec<Value>,
    source: &Crypto,
    dest: &Crypto,
) -> Result<Vec<Value>> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Object(mut obj) = row else {
            bail!("源库表 {} 行不是 JSON 对象", spec.name);
        };
        if !spec.encrypted_columns.is_empty() {
            reencrypt_columns(&mut obj, spec.encrypted_columns, source, dest)?;
        }
        if spec.name == "gateway_settings" {
            let need_reencrypt = obj
                .get("key")
                .and_then(Value::as_str)
                .map(is_encrypted_setting_key)
                .unwrap_or(false);
            if need_reencrypt {
                reencrypt_columns(&mut obj, &["value"], source, dest)?;
            }
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
}

/// 对指定列执行“解密 + 重新加密”；NULL 等非文本值保持原样（可空列）。
fn reencrypt_columns(
    obj: &mut Map<String, Value>,
    columns: &[&str],
    source: &Crypto,
    dest: &Crypto,
) -> Result<()> {
    for column in columns {
        // NULL 等非文本值保持原样（可空列不写占位密文）
        if let Some(Value::String(raw)) = obj.get(*column).cloned() {
            let plain = source.decrypt(&raw)?;
            let encrypted = dest.encrypt(&plain)?;
            obj.insert((*column).to_string(), Value::String(encrypted));
        }
    }
    Ok(())
}

/// 需要整值加密的 settings 键（报告 §6）。
fn is_encrypted_setting_key(key: &str) -> bool {
    matches!(
        key,
        "mirror_proxy" | "political_moderation" | "anonymous_upstream"
    )
}

/// 可空列加密辅助：`None` 保持 NULL，不写入占位密文。
fn encrypt_optional(crypto: &Crypto, value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(raw) => Ok(Some(crypto.encrypt(&raw)?)),
        None => Ok(None),
    }
}

/// 旧库补列（原版 init_db 的 PRAGMA table_info + ALTER TABLE 序列，报告 §5）。
fn ensure_legacy_columns(conn: &Connection) -> Result<()> {
    ensure_column(
        conn,
        "chatgpt_accounts",
        "extra_cookies",
        "ALTER TABLE chatgpt_accounts ADD COLUMN extra_cookies TEXT DEFAULT '[]'",
    )?;
    ensure_column(
        conn,
        "gateway_sessions",
        "session_token",
        "ALTER TABLE gateway_sessions ADD COLUMN session_token TEXT",
    )?;
    ensure_column(
        conn,
        "gateway_sessions",
        "extra_cookies",
        "ALTER TABLE gateway_sessions ADD COLUMN extra_cookies TEXT DEFAULT '[]'",
    )?;
    ensure_column(
        conn,
        "gateway_sessions",
        "login_mode",
        "ALTER TABLE gateway_sessions ADD COLUMN login_mode TEXT NOT NULL DEFAULT 'api'",
    )?;
    ensure_column(
        conn,
        "gateway_sessions",
        "force_chat_mode",
        "ALTER TABLE gateway_sessions ADD COLUMN force_chat_mode BOOLEAN NOT NULL DEFAULT TRUE",
    )?;
    ensure_column(
        conn,
        "gateway_sessions",
        "proxy_node_id",
        "ALTER TABLE gateway_sessions ADD COLUMN proxy_node_id INTEGER",
    )?;
    ensure_column(
        conn,
        "gateway_sessions",
        "daily_quota",
        "ALTER TABLE gateway_sessions ADD COLUMN daily_quota INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "gateway_sessions",
        "monthly_quota",
        "ALTER TABLE gateway_sessions ADD COLUMN monthly_quota INTEGER NOT NULL DEFAULT 0",
    )?;
    // ACL 的稳定账号键（Django ChatgptAccount.pk）。存量行补为 NULL：
    // 无法证明账号身份的老会话在 ACL 路径上按未验证处理，不回填猜测值。
    ensure_column(
        conn,
        "gateway_sessions",
        "chatgpt_account_id",
        "ALTER TABLE gateway_sessions ADD COLUMN chatgpt_account_id TEXT",
    )?;
    Ok(())
}

/// 缺失列时执行 ALTER；`table` 只传入本文件内的常量名。
fn ensure_column(conn: &Connection, table: &str, column: &str, alter_sql: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(());
        }
    }
    conn.execute_batch(alter_sql)?;
    Ok(())
}

/// 源库表存在性检查（只读迁移前置校验）。
fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// 当前 Unix 秒（原版 `db::now_ts`）。
fn now_ts() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    elapsed.as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_db(dir: &tempfile::TempDir, name: &str, key: &str) -> Database {
        Database::open(&dir.path().join(name), key).expect("打开数据库失败")
    }

    fn table_names(db: &Database) -> Vec<String> {
        let mut stmt = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
        rows.map(|row| row.unwrap()).collect()
    }

    /// 库内表：8 张原版表 + 4 张 ACL 表（共享账号下的内容级边界）。
    #[test]
    fn schema_has_original_and_acl_tables_and_settings_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = new_db(&dir, "new.sqlite", &"k".repeat(32));
        assert_eq!(
            table_names(&db),
            vec![
                "acl_audit",
                "acl_project_links",
                "acl_resources",
                "acl_shares",
                "chatgpt_accounts",
                "conversation_model_statistics",
                "conversation_owners",
                "conversation_statistics",
                "gateway_sessions",
                "gateway_settings",
                "project_owners",
                "visit_logs",
            ]
        );
        assert!(db.get_setting("custom_scripts").unwrap().is_none());

        let value = json!({"enabled": true, "nodes": []});
        db.set_setting("mirror_proxy", &value).unwrap();
        let raw: String = db
            .conn
            .query_row(
                "SELECT value FROM gateway_settings WHERE key = 'mirror_proxy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(raw.starts_with(crate::crypto::ENC_PREFIX));
        assert_eq!(db.get_setting("mirror_proxy").unwrap().unwrap(), value);

        db.set_setting("blocked_paths", &json!({"paths": ["/a"]}))
            .unwrap();
        let raw: String = db
            .conn
            .query_row(
                "SELECT value FROM gateway_settings WHERE key = 'blocked_paths'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!raw.starts_with(crate::crypto::ENC_PREFIX));
    }

    #[test]
    fn backup_roundtrip_rejects_bad_payload_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = new_db(&dir, "new.sqlite", &"k".repeat(32));
        db.set_setting("mirror_proxy", &json!({"enabled": false}))
            .unwrap();
        let token = db.crypto.encrypt("tok-1").unwrap();
        db.conn
            .execute(
                "INSERT INTO chatgpt_accounts (chatgpt_username, access_token) VALUES (?1, ?2)",
                params!["u1", token],
            )
            .unwrap();

        let backup = db.export_backup().unwrap();
        assert_eq!(backup["version"], json!(BACKUP_VERSION));
        assert_eq!(backup["chatgpt_accounts"].as_array().unwrap().len(), 1);
        assert_eq!(backup["settings"].as_array().unwrap().len(), 1);

        // 未知信封字段必须失败
        let mut bad_envelope = backup.clone();
        bad_envelope["surprise"] = json!([]);
        assert!(db.restore_backup(&bad_envelope).is_err());

        // version 不是当前版本必须失败（v2 不含 ACL 表，静默恢复会丢全部归属）
        let mut wrong_version = backup.clone();
        wrong_version["version"] = json!(1);
        assert!(db.restore_backup(&wrong_version).is_err());
        let mut legacy = backup.clone();
        legacy["version"] = json!(2);
        assert!(db.restore_backup(&legacy).is_err());

        // 行内未知字段必须失败，且失败后原数据完好（事务回滚）
        let mut bad_row = backup.clone();
        bad_row["conversation_statistics"] = json!([{
            "chatgpt_username": "x",
            "conversation_id": "c",
            "user_name": "u",
            "title": "t",
            "message_count": 0,
            "conversation_counted": true,
            "created_at": 1,
            "updated_at": 1,
            "surprise": 1
        }]);
        assert!(db.restore_backup(&bad_row).is_err());
        assert_eq!(
            db.get_setting("mirror_proxy").unwrap().unwrap(),
            json!({"enabled": false})
        );
        let restored: String = db
            .conn
            .query_row(
                "SELECT access_token FROM chatgpt_accounts WHERE chatgpt_username = 'u1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(db.crypto.decrypt(&restored).unwrap(), "tok-1");

        // 合法恢复：先清空再回填
        db.conn.execute("DELETE FROM chatgpt_accounts", []).unwrap();
        db.restore_backup(&backup).unwrap();
        let restored: String = db
            .conn
            .query_row(
                "SELECT access_token FROM chatgpt_accounts WHERE chatgpt_username = 'u1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(db.crypto.decrypt(&restored).unwrap(), "tok-1");
        assert_eq!(
            db.get_setting("mirror_proxy").unwrap().unwrap(),
            json!({"enabled": false})
        );
    }

    #[test]
    fn migrate_reencrypts_and_clears_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.sqlite");
        let new_path = dir.path().join("new.sqlite");
        let old_key = "o".repeat(32);
        let new_key = "n".repeat(32);
        {
            let old = Database::open(&old_path, &old_key).unwrap();
            // 模拟旧库明文残留：打开后再写，绕开自动迁移
            old.conn
                .execute(
                    "INSERT INTO chatgpt_accounts (chatgpt_username, access_token) VALUES (?1, ?2)",
                    params!["legacy", "plain-token"],
                )
                .unwrap();
            old.conn
                .execute(
                    "INSERT INTO gateway_sessions (user_name, chatgpt_username, access_token, mirror_token) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params!["u", "legacy", "sess-token", "raw-mirror-token"],
                )
                .unwrap();
            old.set_setting("mirror_proxy", &json!({"enabled": true}))
                .unwrap();
        }

        Database::migrate(&old_path, &new_path, &old_key, &new_key).unwrap();

        let dest = Database::open(&new_path, &new_key).unwrap();
        let token: String = dest
            .conn
            .query_row(
                "SELECT access_token FROM chatgpt_accounts WHERE chatgpt_username = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(token.starts_with(crate::crypto::ENC_PREFIX));
        assert_eq!(dest.crypto.decrypt(&token).unwrap(), "plain-token");
        assert_eq!(
            dest.get_setting("mirror_proxy").unwrap().unwrap(),
            json!({"enabled": true})
        );
        let sessions: i64 = dest
            .conn
            .query_row("SELECT COUNT(*) FROM gateway_sessions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(sessions, 0);
    }

    #[test]
    fn migrate_wrong_source_key_stops_without_writes() {
        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.sqlite");
        let new_path = dir.path().join("wrong-key.sqlite");
        let old_key = "o".repeat(32);
        let wrong_key = "x".repeat(32);
        let new_key = "n".repeat(32);
        {
            let old = Database::open(&old_path, &old_key).unwrap();
            // 用旧密钥加密写入设置值：新库用错误源密钥解密时必须失败
            old.set_setting("mirror_proxy", &json!({"enabled": true}))
                .unwrap();
            old.conn
                .execute(
                    "INSERT INTO chatgpt_accounts (chatgpt_username, access_token) VALUES (?1, ?2)",
                    params!["legacy", "plain-token"],
                )
                .unwrap();
        }

        assert!(Database::migrate(&old_path, &new_path, &wrong_key, &new_key).is_err());

        let dest = Database::open(&new_path, &new_key).unwrap();
        let count: i64 = dest
            .conn
            .query_row("SELECT COUNT(*) FROM chatgpt_accounts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        assert!(dest.get_setting("mirror_proxy").unwrap().is_none());
    }

    #[test]
    fn open_backfills_legacy_columns_and_encrypts_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE chatgpt_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chatgpt_username TEXT UNIQUE NOT NULL,
                    auth_status BOOLEAN DEFAULT TRUE,
                    plan_type TEXT DEFAULT 'free',
                    access_token TEXT NOT NULL,
                    session_token TEXT,
                    refresh_token TEXT,
                    remark TEXT,
                    created_time INTEGER,
                    updated_time INTEGER
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chatgpt_accounts (chatgpt_username, access_token) VALUES ('legacy', 'plain-token')",
                [],
            )
            .unwrap();
        }

        let db = Database::open(&path, &"k".repeat(32)).unwrap();
        let columns: Vec<String> = {
            let mut stmt = db
                .conn
                .prepare("PRAGMA table_info(chatgpt_accounts)")
                .unwrap();
            let rows = stmt.query_map([], |row| row.get::<_, String>(1)).unwrap();
            rows.map(|row| row.unwrap()).collect()
        };
        assert!(columns.iter().any(|column| column == "extra_cookies"));

        let token: String = db
            .conn
            .query_row(
                "SELECT access_token FROM chatgpt_accounts WHERE chatgpt_username = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(token.starts_with(crate::crypto::ENC_PREFIX));
        assert_eq!(db.crypto.decrypt(&token).unwrap(), "plain-token");
    }
}

// Author: MingTea. HTTP backup-restore contract tests grounded in evidence/backup-v3-original-*.
use mirror_gateway::storage::Database;
use rusqlite::params;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

fn key() -> String {
    "k".repeat(32)
}

#[test]
fn runtime_validation_failure_rolls_back_the_complete_restore() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let before = db.export_backup().unwrap();
    let mut replacement = before.clone();
    replacement["settings"] =
        json!([{ "key":"custom_scripts", "value":"bad-json", "updated_at":1700000999 }]);
    let result = db.restore_http_backup_validated(&replacement, |conn, _| {
        let value: String = conn.query_row(
            "SELECT value FROM gateway_settings WHERE key='custom_scripts'",
            [],
            |row| row.get(0),
        )?;
        serde_json::from_str::<Value>(&value)?;
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(db.export_backup().unwrap(), before);
}

fn open(dir: &tempfile::TempDir) -> Database {
    Database::open(&dir.path().join("db.sqlite"), &key()).expect("打开数据库失败")
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

fn count(db: &Database, table: &str) -> i64 {
    db.conn
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn text(db: &Database, sql: &str) -> String {
    db.conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn opt_text(db: &Database, sql: &str) -> Option<String> {
    db.conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn opt_int(db: &Database, sql: &str) -> Option<i64> {
    db.conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// 每表写入合成数据（与原版观测 seed 同形；ID 与时间戳均为固定合成值）。
fn seed(db: &Database) {
    for (id, name, status, plan, remark) in [
        (1, "one@example.invalid", 1, "plus", "one"),
        (2, "two@example.invalid", 0, "free", "two"),
    ] {
        db.conn
            .execute(
                "INSERT INTO chatgpt_accounts (id, chatgpt_username, auth_status, plan_type, \
                 access_token, session_token, extra_cookies, refresh_token, remark, created_time, \
                 updated_time) VALUES (?1, ?2, ?3, ?4, ?5, ?6, '[]', ?7, ?8, ?9, ?10)",
                params![
                    id,
                    name,
                    status,
                    plan,
                    format!("tok-{id}"),
                    format!("sess-{id}"),
                    format!("ref-{id}"),
                    remark,
                    1700000000 + id,
                    1700000010 + id
                ],
            )
            .unwrap();
    }
    db.conn
        .execute(
            "INSERT INTO gateway_sessions (id, user_name, chatgpt_username, access_token, \
             session_token, extra_cookies, login_mode, mirror_token, isolated_session, \
             force_chat_mode, limits, proxy_node_id, daily_quota, monthly_quota, created_at, \
             updated_at) VALUES (1, 'seed-user', 'one@example.invalid', 'sess-tok', 'sess-2', \
             '[]', 'api', 'mirror-1', 1, 1, '[]', NULL, 5, 50, 1700000020, 1700000021)",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO gateway_settings (key, value, updated_at) \
             VALUES ('blocked_paths', '{\"paths\":[\"/seed\"]}', 1700000013)",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO conversation_owners (chatgpt_username, conversation_id, user_name, \
             created_at, updated_at) VALUES ('one@example.invalid', 'conv-1', 'seed-user', \
             1700000030, 1700000031)",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO project_owners (chatgpt_username, project_id, user_name, created_at, \
             updated_at) VALUES ('one@example.invalid', 'proj-1', 'seed-user', 1700000040, \
             1700000041)",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO visit_logs (id, username, chatgpt_username, log_type, created_at, ip, \
             user_agent) VALUES (1, 'seed-user', 'one@example.invalid', 'login', 1700000050, \
             '127.0.0.1', 'Seed/1')",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO conversation_statistics (chatgpt_username, conversation_id, user_name, \
             title, message_count, conversation_counted, created_at, updated_at) VALUES \
             ('one@example.invalid', 'conv-1', 'seed-user', 'seed-title', 3, 1, 1700000060, \
             1700000061)",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO conversation_model_statistics (user_name, model_name, message_count, \
             updated_at) VALUES ('seed-user', 'gpt-5', 2, 1700000070)",
            [],
        )
        .unwrap();
}

fn assert_strict_error(
    db: &mut Database,
    base: &Value,
    mutate: impl Fn(&mut Value),
    expected: &str,
) {
    let mut payload = base.clone();
    mutate(&mut payload);
    let error = db
        .restore_http_backup(&payload)
        .expect_err("该载荷必须失败");
    assert_eq!(error.to_string(), expected);
}

#[test]
fn http_restore_empty_object_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let before = db.export_backup().unwrap();
    db.restore_http_backup(&json!({})).unwrap();
    assert_eq!(db.export_backup().unwrap(), before);
}

#[test]
fn http_restore_legacy_settings_upsert_keeps_other_rows() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    db.restore_http_backup(&json!({"settings": [
        {"key": "blocked_paths", "value": "{\"paths\":[\"/updated\"]}", "updated_at": 888},
        {"key": "legacy_probe_key", "value": "{\"probe\":1}", "updated_at": 999}
    ]}))
    .unwrap();
    assert_eq!(count(&db, "gateway_settings"), 2);
    assert_eq!(
        text(
            &db,
            "SELECT value FROM gateway_settings WHERE key = 'blocked_paths'"
        ),
        "{\"paths\":[\"/updated\"]}"
    );
    assert_eq!(
        text(
            &db,
            "SELECT value FROM gateway_settings WHERE key = 'legacy_probe_key'"
        ),
        "{\"probe\":1}"
    );
    assert_eq!(count(&db, "chatgpt_accounts"), 2);
}

#[test]
fn http_restore_legacy_updates_existing_account_row() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    db.restore_http_backup(&json!({"chatgpt_accounts": [{
        "id": 1,
        "chatgpt_username": "one@example.invalid",
        "auth_status": true,
        "plan_type": "plus",
        "access_token": "tok-1",
        "session_token": "sess-1",
        "extra_cookies": "[]",
        "refresh_token": "ref-1",
        "remark": "changed-remark",
        "created_time": 1700000000,
        "updated_time": 1700000001
    }]}))
    .unwrap();
    assert_eq!(
        text(&db, "SELECT remark FROM chatgpt_accounts WHERE id = 1"),
        "changed-remark"
    );
    assert_eq!(count(&db, "chatgpt_accounts"), 2);
}

#[test]
fn http_restore_legacy_ignores_non_array_and_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let before = db.export_backup().unwrap();
    db.restore_http_backup(&json!({"settings": {"unexpected": true}, "surprise": []}))
        .unwrap();
    assert_eq!(db.export_backup().unwrap(), before);
}

#[test]
fn http_restore_non_v2_version_uses_legacy_upsert() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let mut payload = db.export_backup().unwrap();
    payload["version"] = json!(3);
    payload["chatgpt_accounts"][0]["remark"] = json!("changed-remark");
    db.restore_http_backup(&payload).unwrap();
    assert_eq!(count(&db, "chatgpt_accounts"), 2);
    assert_eq!(
        text(&db, "SELECT remark FROM chatgpt_accounts WHERE id = 1"),
        "changed-remark"
    );
}

#[test]
fn http_restore_strict_requires_every_table() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let error = db
        .restore_http_backup(&json!({"version": 2, "settings": []}))
        .unwrap_err();
    assert_eq!(error.to_string(), "完整备份缺少 chatgpt_accounts");

    let mut payload = db.export_backup().unwrap();
    payload
        .as_object_mut()
        .unwrap()
        .remove("conversation_statistics");
    let error = db.restore_http_backup(&payload).unwrap_err();
    assert_eq!(error.to_string(), "完整备份缺少 conversation_statistics");

    let mut payload = db.export_backup().unwrap();
    payload["settings"] = json!({"unexpected": true});
    let error = db.restore_http_backup(&payload).unwrap_err();
    assert_eq!(error.to_string(), "完整备份缺少 settings");
}

#[test]
fn http_restore_strict_requires_row_fields_with_observed_messages() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let base = db.export_backup().unwrap();
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["chatgpt_accounts"][0]
                .as_object_mut()
                .unwrap()
                .remove("access_token");
        },
        "备份上游账号缺少 AccessToken",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["chatgpt_accounts"][0]["id"] = json!([]);
        },
        "备份上游账号缺少 ID",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["chatgpt_accounts"][0] = json!("oops");
        },
        "备份上游账号缺少 ID",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["chatgpt_accounts"][0]["chatgpt_username"] = json!(7);
        },
        "备份上游账号缺少用户名",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["gateway_sessions"][0]
                .as_object_mut()
                .unwrap()
                .remove("mirror_token");
        },
        "备份 Gateway 会话缺少令牌",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["settings"][0]["value"] = json!(123);
        },
        "备份设置缺少 value",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["settings"][0]["key"] = json!(null);
        },
        "备份设置缺少 key",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["conversation_owners"][0]["user_name"] = json!(null);
        },
        "备份会话缺少用户",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["project_owners"][0]
                .as_object_mut()
                .unwrap()
                .remove("project_id");
        },
        "备份项目缺少 ID",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["visit_logs"][0]
                .as_object_mut()
                .unwrap()
                .remove("log_type");
        },
        "备份日志缺少类型",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["conversation_statistics"][0]
                .as_object_mut()
                .unwrap()
                .remove("conversation_id");
        },
        "备份统计缺少对话 ID",
    );
    assert_strict_error(
        &mut db,
        &base,
        |payload| {
            payload["conversation_model_statistics"][0]
                .as_object_mut()
                .unwrap()
                .remove("model_name");
        },
        "备份模型统计缺少模型",
    );
    assert_eq!(db.export_backup().unwrap(), base);
}

#[test]
fn http_restore_strict_defaults_match_observations() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let now_before = now_secs();
    let mut payload = db.export_backup().unwrap();
    payload["chatgpt_accounts"] = json!([{
        "id": 1,
        "chatgpt_username": "one@example.invalid",
        "auth_status": "yes",
        "access_token": "tok-1"
    }]);
    payload["gateway_sessions"] = json!([{
        "id": 1,
        "user_name": "seed-user",
        "chatgpt_username": "one@example.invalid",
        "access_token": "sess-tok",
        "mirror_token": "mirror-1"
    }]);
    payload["settings"] = json!([{"key": "custom_scripts", "value": "{\"scripts\":[]}"}]);
    payload["conversation_owners"] = json!([{
        "chatgpt_username": "one@example.invalid",
        "conversation_id": "conv-1",
        "user_name": "seed-user"
    }]);
    payload["project_owners"] = json!([{
        "chatgpt_username": "one@example.invalid",
        "project_id": "proj-1",
        "user_name": "seed-user"
    }]);
    payload["visit_logs"] = json!([{"id": 1, "username": "seed-user", "log_type": "login"}]);
    payload["conversation_statistics"] = json!([{
        "chatgpt_username": "one@example.invalid",
        "conversation_id": "conv-1",
        "user_name": "seed-user"
    }]);
    payload["conversation_model_statistics"] =
        json!([{"user_name": "seed-user", "model_name": "gpt-5"}]);
    db.restore_http_backup(&payload).unwrap();
    let now_after = now_secs();

    // accounts：类型不符的 auth_status 取默认 TRUE，plan_type/extra_cookies 取默认，可空列 NULL
    assert_eq!(
        text(&db, "SELECT plan_type FROM chatgpt_accounts WHERE id = 1"),
        "free"
    );
    assert_eq!(
        opt_int(&db, "SELECT auth_status FROM chatgpt_accounts WHERE id = 1"),
        Some(1)
    );
    assert_eq!(
        text(
            &db,
            "SELECT extra_cookies FROM chatgpt_accounts WHERE id = 1"
        ),
        "[]"
    );
    assert_eq!(
        opt_text(
            &db,
            "SELECT session_token FROM chatgpt_accounts WHERE id = 1"
        ),
        None
    );
    assert_eq!(
        opt_text(&db, "SELECT remark FROM chatgpt_accounts WHERE id = 1"),
        None
    );
    assert_eq!(
        opt_text(
            &db,
            "SELECT created_time FROM chatgpt_accounts WHERE id = 1"
        ),
        None
    );
    assert_eq!(
        opt_text(
            &db,
            "SELECT updated_time FROM chatgpt_accounts WHERE id = 1"
        ),
        None
    );

    // sessions：文本/布尔/配额缺省，created_at/updated_at 存 NULL
    assert_eq!(
        text(&db, "SELECT login_mode FROM gateway_sessions WHERE id = 1"),
        "api"
    );
    assert_eq!(
        text(&db, "SELECT limits FROM gateway_sessions WHERE id = 1"),
        "[]"
    );
    assert_eq!(
        opt_text(
            &db,
            "SELECT session_token FROM gateway_sessions WHERE id = 1"
        ),
        None
    );
    assert_eq!(
        opt_int(&db, "SELECT daily_quota FROM gateway_sessions WHERE id = 1"),
        Some(0)
    );
    assert_eq!(
        opt_int(
            &db,
            "SELECT isolated_session FROM gateway_sessions WHERE id = 1"
        ),
        Some(1)
    );
    assert_eq!(
        opt_text(&db, "SELECT created_at FROM gateway_sessions WHERE id = 1"),
        None
    );

    // settings / owners / projects / visit_logs / statistics / model stats 时间戳缺省取当前时间
    let settings_updated = opt_int(
        &db,
        "SELECT updated_at FROM gateway_settings WHERE key = 'custom_scripts'",
    )
    .unwrap();
    assert!(settings_updated >= now_before && settings_updated <= now_after);
    let owner_created = opt_int(
        &db,
        "SELECT created_at FROM conversation_owners WHERE conversation_id = 'conv-1'",
    )
    .unwrap();
    assert!(owner_created >= now_before && owner_created <= now_after);
    let project_updated = opt_int(
        &db,
        "SELECT updated_at FROM project_owners WHERE project_id = 'proj-1'",
    )
    .unwrap();
    assert!(project_updated >= now_before && project_updated <= now_after);
    assert_eq!(
        opt_text(&db, "SELECT chatgpt_username FROM visit_logs WHERE id = 1"),
        None
    );
    assert_eq!(text(&db, "SELECT ip FROM visit_logs WHERE id = 1"), "");
    assert_eq!(
        text(&db, "SELECT user_agent FROM visit_logs WHERE id = 1"),
        ""
    );
    let log_created = opt_int(&db, "SELECT created_at FROM visit_logs WHERE id = 1").unwrap();
    assert!(log_created >= now_before && log_created <= now_after);
    assert_eq!(
        text(
            &db,
            "SELECT title FROM conversation_statistics WHERE conversation_id = 'conv-1'"
        ),
        ""
    );
    assert_eq!(
        opt_int(
            &db,
            "SELECT message_count FROM conversation_statistics WHERE conversation_id = 'conv-1'"
        ),
        Some(0)
    );
    assert_eq!(
        opt_int(
            &db,
            "SELECT conversation_counted FROM conversation_statistics WHERE conversation_id = 'conv-1'"
        ),
        Some(1)
    );
    assert_eq!(
        opt_int(
            &db,
            "SELECT message_count FROM conversation_model_statistics WHERE model_name = 'gpt-5'"
        ),
        Some(0)
    );
}

#[test]
fn http_restore_stores_values_as_is_without_crypto() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let mut payload = db.export_backup().unwrap();
    payload["chatgpt_accounts"][0]["access_token"] = json!("plain-token-x");
    payload["chatgpt_accounts"][0]["session_token"] = json!("enc:v1:AAAA");
    db.restore_http_backup(&payload).unwrap();
    assert_eq!(
        text(
            &db,
            "SELECT access_token FROM chatgpt_accounts WHERE id = 1"
        ),
        "plain-token-x"
    );
    assert_eq!(
        text(
            &db,
            "SELECT session_token FROM chatgpt_accounts WHERE id = 1"
        ),
        "enc:v1:AAAA"
    );
}

#[test]
fn http_restore_strict_all_empty_arrays_clears_tables() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    db.restore_http_backup(&json!({
        "version": 2,
        "chatgpt_accounts": [],
        "gateway_sessions": [],
        "settings": [],
        "conversation_owners": [],
        "project_owners": [],
        "visit_logs": [],
        "conversation_statistics": [],
        "conversation_model_statistics": []
    }))
    .unwrap();
    for table in [
        "chatgpt_accounts",
        "gateway_sessions",
        "gateway_settings",
        "conversation_owners",
        "project_owners",
        "visit_logs",
        "conversation_statistics",
        "conversation_model_statistics",
    ] {
        assert_eq!(count(&db, table), 0, "表 {table} 应被清空");
    }
}

#[test]
fn http_restore_failure_rolls_back_every_table() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let base = db.export_backup().unwrap();
    let mut payload = base.clone();
    payload["chatgpt_accounts"][0]["remark"] = json!("changed-remark");
    payload["conversation_model_statistics"][0]
        .as_object_mut()
        .unwrap()
        .remove("model_name");
    assert!(db.restore_http_backup(&payload).is_err());
    assert_eq!(db.export_backup().unwrap(), base);
}

#[test]
fn restore_backup_keeps_strict_v2_contract() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir);
    seed(&db);
    let base = db.export_backup().unwrap();

    let mut payload = base.clone();
    payload["visit_logs"][0]["surprise"] = json!(1);
    assert!(db.restore_backup(&payload).is_err(), "行内未知字段必须失败");

    let mut payload = base.clone();
    payload["surprise"] = json!([]);
    assert!(db.restore_backup(&payload).is_err(), "信封未知字段必须失败");

    let mut payload = base.clone();
    payload["version"] = json!(1);
    assert!(db.restore_backup(&payload).is_err(), "version 必须为 2");

    assert_eq!(db.export_backup().unwrap(), base);
}

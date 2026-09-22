// Author: MingTea. Migration never overwrites an existing path or modifies source bytes.
use mirror_gateway::storage::Database;
use serde_json::json;

#[test]
fn migration_preserves_source_and_refuses_repeated_destination() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    let dest = dir.path().join("dest.sqlite");
    let source_key = "source-key-000000000000000000000001";
    let dest_key = "dest-key-0000000000000000000000001";
    {
        let db = Database::open(&source, source_key).unwrap();
        db.set_setting("mirror_proxy", &json!({"password":"synthetic-secret"}))
            .unwrap();
    }
    let before = std::fs::read(&source).unwrap();
    assert!(Database::migrate(&source, &source, source_key, dest_key).is_err());
    assert!(Database::migrate(
        &source,
        &dest,
        "wrong-key-0000000000000000000000001",
        dest_key
    )
    .is_err());
    assert!(!dest.exists());
    Database::migrate(&source, &dest, source_key, dest_key).unwrap();
    let dest_before = std::fs::read(&dest).unwrap();
    assert!(Database::migrate(&source, &dest, source_key, dest_key).is_err());
    assert_eq!(std::fs::read(&dest).unwrap(), dest_before);
    assert_eq!(std::fs::read(&source).unwrap(), before);
}

#[test]
fn unknown_source_column_stops_before_destination_creation() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    let dest = dir.path().join("dest.sqlite");
    let key = "fixture-key-000000000000000000000001";
    {
        let db = Database::open(&source, key).unwrap();
        db.conn
            .execute(
                "ALTER TABLE chatgpt_accounts ADD COLUMN unknown_payload TEXT",
                [],
            )
            .unwrap();
    }
    assert!(Database::migrate(&source, &dest, key, key).is_err());
    assert!(!dest.exists());
}

#[test]
fn restore_wrong_key_leaves_existing_database_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let key = "fixture-key-000000000000000000000001";
    let mut db = Database::open(&dir.path().join("db.sqlite"), key).unwrap();
    db.set_setting("custom_scripts", &json!({"scripts":["preserve"]}))
        .unwrap();
    let before = db.export_backup().unwrap();
    let other = mirror_gateway::crypto::Crypto::new("other-key-0000000000000000000000001").unwrap();
    let mut payload = before.clone();
    payload["settings"] =
        json!([{"key":"mirror_proxy","value":other.encrypt("{}").unwrap(),"updated_at":1}]);
    assert!(db.restore_backup(&payload).is_err());
    assert_eq!(db.export_backup().unwrap(), before);
}

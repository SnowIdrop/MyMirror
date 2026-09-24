// `resource_acl.rs` 以独立模块编译：产品侧接线（网关库、每请求复验）不参与本用例，
// 只用模块自身的判权/登记/审计自由函数，因此关掉未接线入口的 dead_code 警告。
#[allow(dead_code)]
#[path = "../src/resource_acl.rs"]
mod resource_acl;

use resource_acl::*;
use rusqlite::Connection;
use serde_json::{json, Value};

const NOW: i64 = 1000;

fn details(id: &str, admin: bool) -> Value {
    json!({"active":true,"user_id":id,"is_admin":admin,"version":"opaque-v1",
        "expires_at":2000,"subject":"fixture-subject","principal_kind":"user"})
}
fn actor(id: &str, admin: bool) -> RequestIdentity {
    let response = details(id, admin);
    let pinned = Identity::from_authority(&response, "fixture-subject", NOW).unwrap();
    RequestIdentity::verify(&pinned, &response, "fixture-subject", NOW).unwrap()
}
fn key(id: &str, kind: ResourceKind) -> ResourceKey {
    ResourceKey::new("account-a", kind, id).unwrap()
}
fn database() -> ResourceAcl {
    ResourceAcl::new(Connection::open_in_memory().unwrap()).unwrap()
}
fn receipt(resource: &ResourceKey, project: Option<&ResourceKey>) -> ConfirmedCreation {
    ConfirmedCreation {
        creation_id: format!(
            "{}:{}:{}",
            resource.account_id(),
            resource.kind().as_str(),
            resource.upstream_id()
        ),
        resource: resource.clone(),
        project: project.cloned(),
    }
}
fn create(
    db: &mut ResourceAcl,
    who: &RequestIdentity,
    resource: &ResourceKey,
    project: Option<&ResourceKey>,
) {
    db.record_created(who, Some(receipt(resource, project)))
        .unwrap()
        .unwrap();
}

#[test]
fn trusted_identity_is_strict_and_wire_version_stays_opaque() {
    let response = details("123", false);
    let identity = Identity::from_authority(&response, "fixture-subject", NOW).unwrap();
    assert_eq!(identity.user_id(), "123");
    assert!(!identity.is_admin());
    assert_eq!(identity.authorization_version(), "opaque-v1");
    for field in [
        "active",
        "user_id",
        "is_admin",
        "version",
        "expires_at",
        "subject",
        "principal_kind",
    ] {
        let mut missing = response.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            matches!(
                Identity::from_authority(&missing, "fixture-subject", NOW),
                Err(AclError::Unauthorized)
            ),
            "missing {field}"
        );
    }
    for (field, value) in [
        ("active", json!(false)),
        ("is_admin", json!("true")),
        ("user_id", json!(123)),
        ("expires_at", json!("2000")),
        ("version", json!(" ")),
        ("principal_kind", json!("visitor")),
        ("subject", json!("other")),
    ] {
        let mut invalid = response.clone();
        invalid[field] = value;
        assert!(
            matches!(
                Identity::from_authority(&invalid, "fixture-subject", NOW),
                Err(AclError::Unauthorized)
            ),
            "invalid {field}"
        );
    }
}

#[test]
fn visitor_missing_identity_and_service_key_do_not_supply_an_actor() {
    for response in [
        json!({"active":true,"version":"v1","expires_at":2000}),
        json!({"service_key":"synthetic-only","is_admin":true}),
        {
            let mut v = details("1", true);
            v["principal_kind"] = json!("visitor");
            v
        },
    ] {
        assert!(matches!(
            Identity::from_authority(&response, "fixture-subject", NOW),
            Err(AclError::Unauthorized)
        ));
    }
}

#[test]
fn user_ids_must_be_canonical_positive_decimal_strings() {
    for id in ["", "0", "01", "-1", " 1", "1 ", "1.0", "alice", "１２"] {
        assert!(matches!(
            Identity::from_authority(&details(id, false), "fixture-subject", NOW),
            Err(AclError::Unauthorized)
        ));
    }
}

#[test]
fn fresh_version_role_user_subject_and_expiry_are_rechecked() {
    let response = details("1", false);
    let pinned = Identity::from_authority(&response, "fixture-subject", NOW).unwrap();
    for (field, value) in [
        ("version", json!("v2")),
        ("is_admin", json!(true)),
        ("user_id", json!("2")),
        ("subject", json!("other")),
        ("expires_at", json!(NOW)),
        ("active", json!(false)),
    ] {
        let mut changed = response.clone();
        changed[field] = value;
        assert!(
            matches!(
                RequestIdentity::verify(&pinned, &changed, "fixture-subject", NOW),
                Err(AclError::Unauthorized)
            ),
            "changed {field}"
        );
    }
    assert!(matches!(
        Identity::from_authority(&response, "", NOW),
        Err(AclError::Unauthorized)
    ));
}

#[test]
fn failed_create_records_nothing_and_unknown_is_admin_read_only() {
    let db = database();
    let owner = actor("1", false);
    let admin = actor("3", true);
    let resource = key("missing", ResourceKind::Conversation);
    assert!(db.record_created(&owner, None).unwrap().is_none());
    assert!(db.audit_after(&admin, 0, 100).unwrap().is_empty());
    assert!(matches!(
        db.authorize(&owner, &resource, Action::Read),
        Err(AclError::UnknownResource)
    ));
    assert_eq!(
        db.authorize(&admin, &resource, Action::Read).unwrap(),
        Access::UnknownAdministratorRead
    );
    for action in [Action::Modify, Action::Delete, Action::ContinueChat] {
        assert!(matches!(
            db.authorize(&admin, &resource, action),
            Err(AclError::UnknownResource)
        ));
    }
    assert!(matches!(
        db.grant(&admin, &resource, "2"),
        Err(AclError::UnknownResource)
    ));
}

#[test]
fn successful_create_is_private_and_owner_can_read_modify_delete_continue() {
    let mut db = database();
    let owner = actor("1", false);
    let stranger = actor("2", false);
    let resource = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &resource, None);
    for action in [
        Action::Read,
        Action::Modify,
        Action::Delete,
        Action::ContinueChat,
    ] {
        assert_eq!(
            db.authorize(&owner, &resource, action).unwrap(),
            Access::Registered
        );
        assert!(matches!(
            db.authorize(&stranger, &resource, action),
            Err(AclError::Forbidden)
        ));
    }
}

#[test]
fn only_administrator_can_grant_and_revoke_even_owner_cannot_reshare() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let resource = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &resource, None);
    assert!(matches!(
        db.grant(&owner, &resource, "2"),
        Err(AclError::Forbidden)
    ));
    db.grant(&admin, &resource, "2").unwrap();
    for action in [
        Action::Read,
        Action::Modify,
        Action::Delete,
        Action::ContinueChat,
    ] {
        assert_eq!(
            db.authorize(&recipient, &resource, action).unwrap(),
            Access::Registered
        );
    }
    assert!(matches!(
        db.grant(&recipient, &resource, "4"),
        Err(AclError::Forbidden)
    ));
    assert!(matches!(
        db.revoke(&recipient, &resource, "2"),
        Err(AclError::Forbidden)
    ));
    assert!(matches!(
        db.revoke(&owner, &resource, "2"),
        Err(AclError::Forbidden)
    ));
}

#[test]
fn revoke_rejects_next_check_and_returns_invalidation_intent() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let resource = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &resource, None);
    db.grant(&admin, &resource, "2").unwrap();
    let event = db.revoke(&admin, &resource, "2").unwrap();
    assert_eq!(event.scope, resource);
    assert_eq!(event.user_id.as_deref(), Some("2"));
    assert_eq!(event.audit_id, 3);
    assert!(!event.include_project_children);
    assert!(matches!(
        db.authorize(&recipient, &resource, Action::Read),
        Err(AclError::Forbidden)
    ));
    assert!(db.authorize(&owner, &resource, Action::Read).is_ok());
}

#[test]
fn projects_dynamically_share_existing_and_future_content() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let project = key("project", ResourceKind::Project);
    let old = key("old", ResourceKind::Conversation);
    let new = key("new", ResourceKind::File);
    create(&mut db, &owner, &project, None);
    create(&mut db, &owner, &old, Some(&project));
    assert!(db.authorize(&recipient, &old, Action::Read).is_err());
    let event = db.grant(&admin, &project, "2").unwrap();
    assert!(event.include_project_children);
    create(&mut db, &owner, &new, Some(&project));
    assert!(db.authorize(&recipient, &old, Action::ContinueChat).is_ok());
    assert!(db.authorize(&recipient, &new, Action::Delete).is_ok());
    db.revoke(&admin, &project, "2").unwrap();
    assert!(matches!(
        db.authorize(&recipient, &old, Action::Read),
        Err(AclError::Forbidden)
    ));
    assert!(matches!(
        db.authorize(&recipient, &new, Action::Read),
        Err(AclError::Forbidden)
    ));
}

#[test]
fn project_owner_inherits_new_content_created_by_a_recipient() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let project = key("project", ResourceKind::Project);
    let child = key("new-by-recipient", ResourceKind::Conversation);
    create(&mut db, &owner, &project, None);
    db.grant(&admin, &project, "2").unwrap();
    create(&mut db, &recipient, &child, Some(&project));
    assert!(db.authorize(&owner, &child, Action::Read).is_ok());
    db.revoke(&admin, &project, "2").unwrap();
    assert!(db.authorize(&recipient, &child, Action::Read).is_ok()); // Immutable owner.
}

#[test]
fn connector_permissions_never_inherit_from_project() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let project = key("project", ResourceKind::Project);
    let connector = key("connector", ResourceKind::Connector);
    create(&mut db, &owner, &project, None);
    db.grant(&admin, &project, "2").unwrap();
    create(&mut db, &owner, &connector, Some(&project));
    assert!(matches!(
        db.authorize(&recipient, &connector, Action::Read),
        Err(AclError::Forbidden)
    ));
    db.grant(&admin, &connector, "2").unwrap();
    db.revoke(&admin, &project, "2").unwrap();
    assert!(db.authorize(&recipient, &connector, Action::Modify).is_ok());
}

#[test]
fn attaching_old_private_resource_with_new_viewers_requires_admin() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let project = key("project", ResourceKind::Project);
    let old = key("old", ResourceKind::Conversation);
    create(&mut db, &owner, &project, None);
    create(&mut db, &owner, &old, None);
    db.grant(&admin, &project, "2").unwrap();
    assert!(matches!(
        db.move_to_project(&owner, &old, Some(&project)),
        Err(AclError::Forbidden)
    ));
    assert!(db.authorize(&recipient, &old, Action::Read).is_err());
    assert_eq!(db.audit_after(&admin, 0, 100).unwrap().len(), 3);
    db.move_to_project(&admin, &old, Some(&project)).unwrap();
    assert!(db.authorize(&recipient, &old, Action::Read).is_ok());
}

#[test]
fn nonexpanding_move_and_detach_are_allowed_without_admin() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let project = key("project", ResourceKind::Project);
    let old = key("old", ResourceKind::Conversation);
    create(&mut db, &owner, &project, None);
    create(&mut db, &owner, &old, None);
    db.move_to_project(&owner, &old, Some(&project)).unwrap();
    db.grant(&admin, &project, "2").unwrap();
    let event = db.move_to_project(&owner, &old, None).unwrap();
    assert!(event.user_id.is_none());
    assert!(matches!(
        db.authorize(&recipient, &old, Action::Read),
        Err(AclError::Forbidden)
    ));
}

#[test]
fn moving_between_projects_compares_entire_audience_and_rolls_back() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let other = actor("4", false);
    let admin = actor("3", true);
    let a = key("a", ResourceKind::Project);
    let b = key("b", ResourceKind::Project);
    let child = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &a, None);
    create(&mut db, &owner, &b, None);
    create(&mut db, &owner, &child, Some(&a));
    db.grant(&admin, &a, "2").unwrap();
    db.grant(&admin, &b, "4").unwrap();
    assert!(matches!(
        db.move_to_project(&owner, &child, Some(&b)),
        Err(AclError::Forbidden)
    ));
    assert!(db.authorize(&recipient, &child, Action::Read).is_ok());
    assert!(db.authorize(&other, &child, Action::Read).is_err());
}

#[test]
fn direct_share_survives_project_revocation_and_does_not_allow_reshare() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let project = key("p", ResourceKind::Project);
    let child = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &project, None);
    create(&mut db, &owner, &child, Some(&project));
    db.grant(&admin, &project, "2").unwrap();
    db.grant(&admin, &child, "2").unwrap();
    db.revoke(&admin, &project, "2").unwrap();
    assert!(db.authorize(&recipient, &child, Action::Read).is_ok());
    assert!(matches!(
        db.grant(&recipient, &child, "4"),
        Err(AclError::Forbidden)
    ));
}

#[test]
fn account_namespace_cannot_be_changed_and_cross_account_links_fail() {
    let mut db = database();
    let owner = actor("1", false);
    let stranger = actor("2", false);
    let admin = actor("3", true);
    let a = key("same", ResourceKind::Conversation);
    let b = ResourceKey::new("account-b", ResourceKind::Conversation, "same").unwrap();
    let project = ResourceKey::new("account-b", ResourceKind::Project, "p").unwrap();
    create(&mut db, &owner, &a, None);
    create(&mut db, &stranger, &b, None);
    create(&mut db, &owner, &project, None);
    assert!(matches!(
        db.authorize(&owner, &b, Action::Read),
        Err(AclError::Forbidden)
    ));
    assert!(matches!(
        db.move_to_project(&admin, &a, Some(&project)),
        Err(AclError::CrossAccount)
    ));
    assert!(matches!(
        db.record_created(
            &admin,
            Some(receipt(&key("new", ResourceKind::File), Some(&project)))
        ),
        Err(AclError::CrossAccount)
    ));
}

#[test]
fn duplicate_resource_or_creation_receipt_never_reassigns_owner() {
    let mut db = database();
    let owner = actor("1", false);
    let stranger = actor("2", false);
    let resource = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &resource, None);
    assert!(matches!(
        db.record_created(&stranger, Some(receipt(&resource, None))),
        Err(AclError::AlreadyRegistered)
    ));
    let mut duplicate = receipt(&resource, None);
    duplicate.resource = key("other", ResourceKind::Conversation);
    assert!(matches!(
        db.record_created(&stranger, Some(duplicate)),
        Err(AclError::AlreadyRegistered)
    ));
    assert!(db.authorize(&stranger, &resource, Action::Read).is_err());
}

#[test]
fn sqlite_trigger_prevents_rebinding_even_with_direct_update() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("acl.sqlite");
    let mut db = ResourceAcl::new(Connection::open(&path).unwrap()).unwrap();
    let owner = actor("1", false);
    create(
        &mut db,
        &owner,
        &key("chat", ResourceKind::Conversation),
        None,
    );
    let raw = Connection::open(&path).unwrap();
    for field in [
        "account_id",
        "resource_type",
        "upstream_id",
        "owner_user_id",
        "creation_id",
    ] {
        assert!(raw
            .execute(&format!("UPDATE acl_resources SET {field}='changed'"), [])
            .is_err());
    }
}

#[test]
fn audit_contains_real_actor_and_is_admin_only() {
    let mut db = database();
    let owner = actor("1", false);
    let admin = actor("3", true);
    let resource = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &resource, None);
    db.grant(&admin, &resource, "2").unwrap();
    assert!(matches!(
        db.audit_after(&owner, 0, 100),
        Err(AclError::Forbidden)
    ));
    let records = db.audit_after(&admin, 0, 1).unwrap();
    assert_eq!(records.len(), 1);
    let first = &records[0];
    assert!(first.occurred_at > 0);
    assert_eq!(first.actor_user_id, "1");
    assert_eq!(first.authorization_version, "opaque-v1");
    assert_eq!(first.action, "create");
    assert_eq!(first.account_id, "account-a");
    assert_eq!(first.resource_type, "conversation");
    assert_eq!(first.upstream_id, "chat");
    assert!(first.project_id.is_none());
    let records = db.audit_after(&admin, first.id, 100).unwrap();
    assert_eq!(records[0].actor_user_id, "3");
    assert_eq!(records[0].recipient_user_id.as_deref(), Some("2"));
    assert!(matches!(
        db.audit_after(&admin, 0, 1001),
        Err(AclError::InvalidInput)
    ));
}

#[test]
fn audit_failure_rolls_back_acl_mutation_instead_of_granting() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("acl.sqlite");
    let mut db = ResourceAcl::new(Connection::open(&path).unwrap()).unwrap();
    let owner = actor("1", false);
    let admin = actor("3", true);
    let resource = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &resource, None);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER reject_audit BEFORE INSERT ON acl_audit BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;").unwrap();
    match db.grant(&admin, &resource, "2") {
        Err(AclError::Sqlite(error)) => {
            assert!(error.to_string().contains("fixture audit failure"))
        }
        _ => panic!("expected sqlite audit failure"),
    }
    assert!(matches!(
        db.authorize(&actor("2", false), &resource, Action::Read),
        Err(AclError::Forbidden)
    ));
    assert_eq!(db.audit_after(&admin, 0, 100).unwrap().len(), 1);
}

#[test]
fn acl_survives_reopen_without_importing_legacy_state() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("acl.sqlite");
    let owner = actor("1", false);
    let admin = actor("3", true);
    let resource = key("chat", ResourceKind::Conversation);
    {
        let mut db = ResourceAcl::new(Connection::open(&path).unwrap()).unwrap();
        create(&mut db, &owner, &resource, None);
        db.grant(&admin, &resource, "2").unwrap();
    }
    let db = ResourceAcl::new(Connection::open(&path).unwrap()).unwrap();
    assert!(db
        .authorize(&actor("2", false), &resource, Action::Read)
        .is_ok());
    assert_eq!(db.audit_after(&admin, 0, 100).unwrap().len(), 2);
}

#[test]
fn invalid_associations_and_inputs_fail_before_commit() {
    let mut db = database();
    let owner = actor("1", false);
    let admin = actor("3", true);
    let project = key("p", ResourceKind::Project);
    let child = key("chat", ResourceKind::Conversation);
    create(&mut db, &owner, &project, None);
    create(&mut db, &owner, &child, None);
    assert!(matches!(
        ResourceKey::new("", ResourceKind::File, "f"),
        Err(AclError::InvalidInput)
    ));
    assert!(matches!(
        ResourceKey::new("a", ResourceKind::File, " "),
        Err(AclError::InvalidInput)
    ));
    assert!(matches!(
        db.move_to_project(&admin, &project, Some(&project)),
        Err(AclError::InvalidOperation)
    ));
    assert!(matches!(
        db.move_to_project(&admin, &child, Some(&child)),
        Err(AclError::InvalidOperation)
    ));
    assert!(matches!(
        db.grant(&admin, &child, "0"),
        Err(AclError::InvalidInput)
    ));
    let mut invalid = receipt(&key("new", ResourceKind::File), None);
    invalid.creation_id.clear();
    assert!(matches!(
        db.record_created(&owner, Some(invalid)),
        Err(AclError::InvalidInput)
    ));
    assert_eq!(db.audit_after(&admin, 0, 100).unwrap().len(), 2);
}

#[test]
fn every_resource_kind_is_private_and_only_conversations_can_continue() {
    let mut db = database();
    let owner = actor("1", false);
    let stranger = actor("2", false);
    for kind in [
        ResourceKind::File,
        ResourceKind::Image,
        ResourceKind::Task,
        ResourceKind::Connector,
        ResourceKind::Project,
    ] {
        let resource = key("same", kind);
        create(&mut db, &owner, &resource, None);
        assert!(db.authorize(&owner, &resource, Action::Read).is_ok());
        assert!(db.authorize(&stranger, &resource, Action::Read).is_err());
        assert!(matches!(
            db.authorize(&owner, &resource, Action::ContinueChat),
            Err(AclError::InvalidOperation)
        ));
    }
}

#[test]
fn separate_connections_observe_revoke_on_the_next_authorization() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("acl.sqlite");
    let mut writer = ResourceAcl::new(Connection::open(&path).unwrap()).unwrap();
    let reader = ResourceAcl::new(Connection::open(&path).unwrap()).unwrap();
    let resource = key("chat", ResourceKind::Conversation);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    create(&mut writer, &actor("1", false), &resource, None);
    writer.grant(&admin, &resource, "2").unwrap();
    assert!(reader
        .authorize(&recipient, &resource, Action::Read)
        .is_ok());
    writer.revoke(&admin, &resource, "2").unwrap();
    assert!(matches!(
        reader.authorize(&recipient, &resource, Action::Read),
        Err(AclError::Forbidden)
    ));
}

#[test]
fn administrative_demotion_and_version_change_reject_pinned_admin() {
    let response = details("3", true);
    let pinned = Identity::from_authority(&response, "fixture-subject", NOW).unwrap();
    for (field, value) in [
        ("is_admin", json!(false)),
        ("version", json!("changed-role-digest")),
    ] {
        let mut fresh = response.clone();
        fresh[field] = value;
        assert!(matches!(
            RequestIdentity::verify(&pinned, &fresh, "fixture-subject", NOW),
            Err(AclError::Unauthorized)
        ));
    }
}

#[test]
fn attaching_old_content_to_a_different_project_owner_expands_visibility() {
    let mut db = database();
    let owner = actor("1", false);
    let other_owner = actor("4", false);
    let admin = actor("3", true);
    let project = key("p", ResourceKind::Project);
    let child = key("c", ResourceKind::File);
    create(&mut db, &other_owner, &project, None);
    db.grant(&admin, &project, "1").unwrap();
    create(&mut db, &owner, &child, None);
    assert!(matches!(
        db.move_to_project(&owner, &child, Some(&project)),
        Err(AclError::Forbidden)
    ));
    assert!(db.authorize(&other_owner, &child, Action::Read).is_err());
}

#[test]
fn connector_metadata_link_does_not_expand_visibility() {
    let mut db = database();
    let owner = actor("1", false);
    let recipient = actor("2", false);
    let admin = actor("3", true);
    let project = key("p", ResourceKind::Project);
    let connector = key("c", ResourceKind::Connector);
    create(&mut db, &owner, &project, None);
    create(&mut db, &owner, &connector, None);
    db.grant(&admin, &project, "2").unwrap();
    db.move_to_project(&owner, &connector, Some(&project))
        .unwrap();
    assert!(matches!(
        db.authorize(&recipient, &connector, Action::Read),
        Err(AclError::Forbidden)
    ));
}

#[test]
fn unknown_parent_or_unprivileged_parent_cannot_register_a_child() {
    let mut db = database();
    let owner = actor("1", false);
    let stranger = actor("2", false);
    let admin = actor("3", true);
    let project = key("p", ResourceKind::Project);
    let child = key("c", ResourceKind::File);
    assert!(matches!(
        db.record_created(&owner, Some(receipt(&child, Some(&project)))),
        Err(AclError::UnknownResource)
    ));
    create(&mut db, &owner, &project, None);
    assert!(matches!(
        db.record_created(&stranger, Some(receipt(&child, Some(&project)))),
        Err(AclError::Forbidden)
    ));
    assert_eq!(
        db.authorize(&admin, &child, Action::Read).unwrap(),
        Access::UnknownAdministratorRead
    );
    assert_eq!(db.audit_after(&admin, 0, 100).unwrap().len(), 1);
}

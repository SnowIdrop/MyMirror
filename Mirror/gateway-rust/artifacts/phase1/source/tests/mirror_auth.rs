// Author: MingTea. All listeners bind numeric loopback; all identities are synthetic.
use axum::{routing::post, Json, Router};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn mirror_authority_revocation_and_relogin_are_enforced() {
    let stub=Router::new()
        .route("/0x/user/gateway-authorization",post(|Json(v):Json<Value>|async move{
            let version=match v["authorization"].as_str(){Some("signature-v1")=>"v1",Some("signature-v2")=>"v2",_=>""};
            Json(json!({"active":!version.is_empty(),"version":version,"expires_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+3600}))
        }))
        .route("/backend-api/me",axum::routing::get(|headers:axum::http::HeaderMap|async move{
            assert_eq!(headers["authorization"],"Bearer synthetic-access-token");
            Json(json!({"email":"fixture@example.invalid","id":"fixture","name":"Fixture"}))
        }));
    let stub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_url = format!("http://{}", stub_listener.local_addr().unwrap());
    let stub_task = tokio::spawn(async move { axum::serve(stub_listener, stub).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        database: dir.path().join("db.sqlite"),
        secret: "fixture-admin-secret-0001".into(),
        key: "fixture-encryption-key-000000000001".into(),
        django: loopback_url(&stub_url).unwrap(),
        upstream: loopback_url(&stub_url).unwrap(),
        cdn_upstream: None,
        cfbypass: None,
        timeout: Duration::from_secs(3),
        mirror_profile: true,
        cookie_secure: false,
        allow_anonymous_session: false,
    };
    let app = server::router(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut payload = json!({"user_name":"alice","authorization":"signature-v1","access_token":"synthetic-access-token","login_mode":"api","isolated_session":true,"mcp_isolation":true,"skills_isolation":true,"model_isolation":true,"daily_quota":20,"monthly_quota":100,"model_allowed_ids":["fixture-model"],"model_rate_limits":{},"limits":[],"mcp_allowed_ids":[],"skills_allowed_ids":[]});
    assert_eq!(
        client
            .post(format!("{base}/api/login"))
            .json(&payload)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let result: Value = client
        .post(format!("{base}/api/login"))
        .bearer_auth("fixture-admin-secret-0001")
        .json(&payload)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = result["login_url"]
        .as_str()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();
    let response = client
        .get(format!("{base}/backend-api/me"))
        .header("x-mirror-token", token)
        .header("authorization", "Bearer must-not-reach-chat-upstream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    // A client-supplied URL stays request data; only the configured chat origin
    // is contacted. The fixture verifies the account's upstream credential.
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me?url=http://192.0.2.99/&target=https://example.invalid"))
            .header("x-mirror-token", token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // 页面路由 `/` 已按本批契约放行（见 coord_boundary_regression 的
    // coord_page_and_anonymous_routes_are_open），这里只保留仍然关闭的路径。
    for path in ["/backend-api/conversation", "/assets/unverified.js"] {
        assert_eq!(
            client
                .get(format!("{base}{path}"))
                .header("x-mirror-token", token)
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
    }
    let event = json!({"subject":"alice","version":"v1","include_visitors":false,"expires_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+3600});
    let response = client
        .post(format!("{base}/api/revoke-authorization"))
        .bearer_auth("fixture-admin-secret-0001")
        .json(&event)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("x-mirror-token", token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    payload["authorization"] = json!("signature-v2");
    let result: Value = client
        .post(format!("{base}/api/login"))
        .bearer_auth("fixture-admin-secret-0001")
        .json(&payload)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_token = result["login_url"]
        .as_str()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();
    assert_eq!(
        client
            .post(format!("{base}/api/revoke-authorization"))
            .bearer_auth("fixture-admin-secret-0001")
            .json(&event)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("x-mirror-token", new_token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let conn = rusqlite::Connection::open(dir.path().join("db.sqlite")).unwrap();
    conn.execute("INSERT INTO chatgpt_accounts(chatgpt_username,access_token,auth_status) VALUES('fixture@example.invalid','synthetic-access-token',1)", []).unwrap();
    let mut mint = payload.clone();
    mint["chatgpt_list"] = json!(["fixture@example.invalid"]);
    mint["model_policies"] = json!({"fixture@example.invalid":{"model_isolation":true,"model_allowed_ids":["fixture-model"],"model_rate_limits":{}}});
    mint["authorization"] = json!("invalid-signature");
    assert_eq!(
        client
            .post(format!("{base}/api/get-mirror-token"))
            .bearer_auth("fixture-admin-secret-0001")
            .json(&mint)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("x-mirror-token", new_token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    mint["authorization"] = json!("signature-v2");
    let minted: Value = client
        .post(format!("{base}/api/get-mirror-token"))
        .bearer_auth("fixture-admin-secret-0001")
        .json(&mint)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let minted_token = minted[0]["login_url"]
        .as_str()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("x-mirror-token", minted_token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    client
        .post(format!("{base}/api/revoke-authorization"))
        .bearer_auth("fixture-admin-secret-0001")
        .json(&event)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("x-mirror-token", minted_token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let closed: Value = client
        .post(format!("{base}/api/close-chatgpt-memory"))
        .bearer_auth("fixture-admin-secret-0001")
        .json(&json!({"user_name":"alice"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(closed["affected"], 1);
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("x-mirror-token", minted_token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM rust_authorizations", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    payload["authorization"] = json!("invalid-signature");
    assert_eq!(
        client
            .post(format!("{base}/api/login"))
            .bearer_auth("fixture-admin-secret-0001")
            .json(&payload)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    task.abort();
    stub_task.abort();
    let _ = task.await;
    let _ = stub_task.await;
}

#[test]
fn offline_transport_rejects_external_and_ambiguous_targets() {
    for target in [
        "https://example.invalid",
        "http://localhost",
        "http://127.0.0.1.example.invalid",
        "http://user:pass@127.0.0.1",
    ] {
        assert!(loopback_url(target).is_err());
    }
    assert!(loopback_url("http://127.0.0.1:18090").is_ok());
}

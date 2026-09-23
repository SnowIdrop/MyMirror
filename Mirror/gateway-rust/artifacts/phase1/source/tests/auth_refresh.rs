use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify};

#[derive(Default)]
struct Upstream {
    paths: Mutex<Vec<String>>,
    accounts_failure: AtomicBool,
    me_status: AtomicU16,
    wrong_account: AtomicBool,
    block_accounts: AtomicBool,
    entered: Notify,
    release: Notify,
}

struct Fixture {
    base: String,
    token: String,
    client: reqwest::Client,
    state: Arc<Upstream>,
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn fixture() -> Fixture {
    let state = Arc::new(Upstream::default());
    state.me_status.store(200, Ordering::SeqCst);
    let stub = Router::new()
        .route("/0x/user/gateway-authorization", post(|| async { Json(json!({"active":true,"version":"v1","expires_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+3600})) }))
        .route("/backend-api/accounts/check/v4-2023-04-27", get(|State(s): State<Arc<Upstream>>, headers: axum::http::HeaderMap| async move {
            s.paths.lock().await.push("accounts".into());
            assert_eq!(headers["authorization"], "Bearer synthetic-access-token");
            assert_eq!(headers["cookie"], "fixture_extra=synthetic");
            if s.block_accounts.load(Ordering::SeqCst) { s.entered.notify_one(); s.release.notified().await; }
            if s.accounts_failure.load(Ordering::SeqCst) { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
            Json(json!({"accounts":{"default":{"account":{"plan_type":"plus"}}}})).into_response()
        }))
        .route("/backend-api/me", get(|State(s): State<Arc<Upstream>>| async move {
            s.paths.lock().await.push("me".into());
            let email = if s.wrong_account.load(Ordering::SeqCst) { "other@example.invalid" } else { "fixture@example.invalid" };
            (StatusCode::from_u16(s.me_status.load(Ordering::SeqCst)).unwrap(), Json(json!({"email":email,"id":"fixture","name":"Fixture"})))
        })).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = loopback_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let stub_task = tokio::spawn(async move { axum::serve(listener, stub).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(Config {
        host: "127.0.0.1".into(),
        port: 0,
        database: dir.path().join("fresh.db"),
        secret: "fixture-admin-secret-0001".into(),
        key: "fixture-encryption-key-000000000001".into(),
        django: upstream.clone(),
        upstream,
        // 这些用例不经过 WS 桥接：给一个不会用到的回环 WS 基址即可。
        ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
        cdn_upstream: None,
        ab_upstream: None,
        public_prefix_base: None,
        cfbypass: None,
        timeout: Duration::from_secs(3),
        mirror_profile: true,
        cookie_secure: false,
        allow_anonymous_session: false,
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let result: Value = client.post(format!("{base}/api/login")).bearer_auth("fixture-admin-secret-0001")
        .json(&json!({"user_name":"alice","authorization":"signature-v1","access_token":"synthetic-access-token","login_mode":"api","isolated_session":true,"mcp_isolation":true,"skills_isolation":true,"model_isolation":true,"daily_quota":20,"monthly_quota":100,"model_allowed_ids":["fixture-model"],"model_rate_limits":{},"limits":[],"mcp_allowed_ids":[],"skills_allowed_ids":[],"extra_cookies":[{"name":"fixture_extra","value":"synthetic"}]}))
        .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    let token = result["login_url"]
        .as_str()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .to_owned();
    state.paths.lock().await.clear();
    Fixture {
        base,
        token,
        client,
        state,
        _dir: dir,
        tasks: vec![task, stub_task],
    }
}

#[tokio::test]
async fn refreshes_account_then_me_on_every_request() {
    let f = fixture().await;
    for query in ["", "", "?refresh_account=1"] {
        let response: Value = f
            .client
            .get(format!("{}/api/auth/session{query}", f.base))
            .header("x-mirror-token", &f.token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["planType"], "plus");
        assert_eq!(response["user"]["email"], "fixture@example.invalid");
    }
    assert_eq!(
        *f.state.paths.lock().await,
        ["accounts", "me", "accounts", "me", "accounts", "me"]
    );
}

#[tokio::test]
async fn preserves_observed_failure_shapes_without_rebinding_accounts() {
    let f = fixture().await;
    f.state.accounts_failure.store(true, Ordering::SeqCst);
    let request = || {
        f.client
            .get(format!("{}/api/auth/session", f.base))
            .header("x-mirror-token", &f.token)
    };
    let value: Value = request().send().await.unwrap().json().await.unwrap();
    assert_eq!(value["planType"], "free");
    assert_eq!(*f.state.paths.lock().await, ["accounts", "me"]);
    f.state.accounts_failure.store(false, Ordering::SeqCst);
    f.state.me_status.store(401, Ordering::SeqCst);
    assert_eq!(
        request()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!({})
    );
    f.state.me_status.store(200, Ordering::SeqCst);
    f.state.wrong_account.store(true, Ordering::SeqCst);
    assert_eq!(
        request()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!({})
    );
}

#[tokio::test]
async fn revocation_completes_during_network_wait_and_invalidates_refresh_result() {
    let f = fixture().await;
    f.state.block_accounts.store(true, Ordering::SeqCst);
    let request = f
        .client
        .get(format!("{}/api/auth/session", f.base))
        .header("x-mirror-token", &f.token);
    let task =
        tokio::spawn(async move { request.send().await.unwrap().json::<Value>().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(1), f.state.entered.notified())
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(1), f.client.post(format!("{}/api/revoke-authorization", f.base)).bearer_auth("fixture-admin-secret-0001").json(&json!({"subject":"alice","version":"v1","include_visitors":false,"expires_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+3600})).send()).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    f.state.release.notify_one();
    assert_eq!(task.await.unwrap(), json!({}));
}

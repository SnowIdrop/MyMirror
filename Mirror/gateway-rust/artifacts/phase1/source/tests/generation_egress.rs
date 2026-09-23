use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify};

const SECRET: &str = "generation-fixture-admin-secret";
#[derive(Default)]
struct Seen {
    calls: Mutex<Vec<Value>>,
    hold_auth: AtomicBool,
    auth_entered: Notify,
    auth_release: Notify,
    hold_me: AtomicBool,
    me_entered: Notify,
    me_release: Notify,
    redirect: AtomicBool,
}
struct Fixture {
    base: String,
    proxy_a: String,
    proxy_b: String,
    state: Arc<Seen>,
    client: reqwest::Client,
    config: Config,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn bind(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, task)
}
async fn upstream(role: &'static str, state: Arc<Seen>) -> (String, tokio::task::JoinHandle<()>) {
    bind(Router::new().fallback(move |request: Request| {
        let s = state.clone();
        async move {
            s.calls.lock().await.push(json!({"role":role,"method":request.method().as_str(),"path":request.uri().path(),"authorization":request.headers().get("authorization").and_then(|h|h.to_str().ok()),"cookie":request.headers().get("cookie").and_then(|h|h.to_str().ok())}));
            if s.redirect.load(Ordering::SeqCst) {
                return (StatusCode::FOUND, [("location", "/next"), ("connection", "close")]).into_response();
            }
            if s.hold_me.swap(false, Ordering::SeqCst) { s.me_entered.notify_one(); s.me_release.notified().await; }
            let value = if request.uri().path()=="/backend-api/conversations" { json!({"items":[],"total":0}) }
                else if request.uri().path().starts_with("/backend-api/accounts/check/") { json!({"accounts":{"default":{"account":{"plan_type":"plus"}}}}) }
                else { json!({"email":"shared@example.invalid","id":"fixture","name":"Fixture"}) };
            ([("connection","close")],Json(value)).into_response()
        }
    })).await
}
impl Fixture {
    async fn new() -> Self {
        let state = Arc::new(Seen::default());
        let authority=Router::new().route("/0x/user/gateway-authorization",post(|State(s):State<Arc<Seen>>|async move{
            if s.hold_auth.swap(false,Ordering::SeqCst) { s.auth_entered.notify_one();s.auth_release.notified().await; }
            Json(json!({"active":true,"version":"v1","expires_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+3600}))
        })).with_state(state.clone());
        let (django, django_task) = bind(authority).await;
        let (chat, chat_task) = upstream("direct", state.clone()).await;
        let (proxy_a, proxy_a_task) = upstream("proxy-a", state.clone()).await;
        let (proxy_b, proxy_b_task) = upstream("proxy-b", state.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: dir.path().join("fresh.db"),
            secret: SECRET.into(),
            key: "generation-fixture-encryption-key-001".into(),
            django: loopback_url(&django).unwrap(),
            upstream: loopback_url(&chat).unwrap(),
            cdn_upstream: None,
            cfbypass: None,
            timeout: Duration::from_secs(2),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
        };
        let (base, task) = bind(server::router(config.clone()).await.unwrap()).await;
        Self {
            base,
            proxy_a,
            proxy_b,
            state,
            config,
            _dir: dir,
            tasks: vec![django_task, chat_task, proxy_a_task, proxy_b_task, task],
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }
    fn payload(access: &str) -> Value {
        json!({"user_name":"alice","authorization":"signature-v1","access_token":access,"login_mode":"api","isolated_session":true,"mcp_isolation":true,"skills_isolation":true,"model_isolation":true,"daily_quota":20,"monthly_quota":100,"model_allowed_ids":["fixture-model"],"model_rate_limits":{},"limits":[],"mcp_allowed_ids":[],"skills_allowed_ids":[],"extra_cookies":[{"name":"fixture_generation","value":access}]})
    }
    fn login_request(&self, access: &str) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}/api/login", self.base))
            .bearer_auth(SECRET)
            .json(&Self::payload(access))
    }
    async fn login(&self, access: &str) -> String {
        let r = self.login_request(access).send().await.unwrap();
        let status = r.status();
        let value: Value = r.json().await.unwrap();
        assert_eq!(status, 200, "{value}");
        value["login_url"]
            .as_str()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_owned()
    }
    async fn save(&self, enabled: bool, url: &str) {
        let r = self
            .client
            .post(format!("{}/api/mirror-proxy-config", self.base))
            .bearer_auth(SECRET)
            .json(&json!({"enabled":enabled,"proxy_url":url,"transport_mode":"reqwest"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    }
    fn read(&self, token: &str, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(format!("{}{path}", self.base))
            .header("x-mirror-token", token)
    }
}

#[tokio::test]
async fn old_me_and_list_requests_never_adopt_relogin_credentials() {
    for path in ["/backend-api/me", "/backend-api/conversations"] {
        let f = Fixture::new().await;
        let old = f.login("synthetic-old").await;
        f.state.hold_auth.store(true, Ordering::SeqCst);
        let pending = f.read(&old, path);
        let task = tokio::spawn(async move { pending.send().await.unwrap().status() });
        tokio::time::timeout(Duration::from_secs(1), f.state.auth_entered.notified())
            .await
            .unwrap();
        let new = f.login("synthetic-new").await;
        f.state.calls.lock().await.clear();
        f.state.auth_release.notify_one();
        assert_eq!(task.await.unwrap(), 401);
        assert!(f.state.calls.lock().await.is_empty());
        assert_eq!(f.read(&old, path).send().await.unwrap().status(), 401);
        assert_eq!(f.read(&new, path).send().await.unwrap().status(), 200);
        let calls = f.state.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["authorization"], "Bearer synthetic-new");
        assert_eq!(calls[0]["cookie"], "fixture_generation=synthetic-new");
    }
}

#[tokio::test]
async fn enabled_proxy_is_used_by_login_reads_and_refresh() {
    let f = Fixture::new().await;
    f.save(true, &f.proxy_a).await;
    let token = f.login("synthetic-old").await;
    for path in [
        "/backend-api/me",
        "/backend-api/conversations",
        "/api/auth/session",
    ] {
        assert_eq!(f.read(&token, path).send().await.unwrap().status(), 200);
    }
    let calls = f.state.calls.lock().await;
    assert_eq!(calls.len(), 5);
    assert!(
        calls.iter().all(|call| call["role"] == "proxy-a"),
        "{calls:?}"
    );
}

#[tokio::test]
async fn profile_changes_and_aba_require_new_login_and_disabled_proxy_is_direct() {
    let f = Fixture::new().await;
    f.save(true, &f.proxy_a).await;
    let token = f.login("synthetic-old").await;
    f.save(true, &f.proxy_b).await;
    f.state.calls.lock().await.clear();
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    f.save(true, &f.proxy_a).await;
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert!(f.state.calls.lock().await.is_empty());
    let token = f.login("synthetic-new").await;
    f.save(false, &f.proxy_b).await;
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    f.state.calls.lock().await.clear();
    let direct = f.login("synthetic-direct").await;
    assert_eq!(
        f.read(&direct, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(f
        .state
        .calls
        .lock()
        .await
        .iter()
        .all(|call| call["role"] == "direct"));
}

#[tokio::test]
async fn unavailable_proxy_does_not_fall_back_to_direct() {
    let mut f = Fixture::new().await;
    f.save(true, &f.proxy_a).await;
    let token = f.login("synthetic-old").await;
    f.tasks[2].abort();
    let task = f.tasks.remove(2);
    let _ = task.await;
    f.state.calls.lock().await.clear();
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    assert!(f.state.calls.lock().await.is_empty());
}

#[tokio::test]
async fn unsupported_node_and_transport_fail_before_upstream() {
    let f = Fixture::new().await;
    let mut payload = Fixture::payload("synthetic-old");
    payload["proxy_node_id"] = json!(71);
    let r = f
        .client
        .post(format!("{}/api/login", f.base))
        .bearer_auth(SECRET)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error() || r.status().is_server_error());
    assert!(f.state.calls.lock().await.is_empty());
    let r = f
        .client
        .post(format!("{}/api/mirror-proxy-config", f.base))
        .bearer_auth(SECRET)
        .json(&json!({"enabled":true,"proxy_url":f.proxy_a,"transport_mode":"curl-impersonate"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn profile_change_during_authority_or_login_wait_is_not_silently_applied() {
    let f = Fixture::new().await;
    let token = f.login("synthetic-old").await;
    f.state.hold_auth.store(true, Ordering::SeqCst);
    let pending = f.read(&token, "/backend-api/me");
    let task = tokio::spawn(async move { pending.send().await.unwrap().status() });
    tokio::time::timeout(Duration::from_secs(1), f.state.auth_entered.notified())
        .await
        .unwrap();
    f.save(true, &f.proxy_a).await;
    f.state.calls.lock().await.clear();
    f.state.auth_release.notify_one();
    assert_eq!(task.await.unwrap(), 401);
    assert!(f.state.calls.lock().await.is_empty());
    f.state.hold_me.store(true, Ordering::SeqCst);
    let pending = f.login_request("synthetic-new");
    let task = tokio::spawn(async move { pending.send().await.unwrap().status() });
    tokio::time::timeout(Duration::from_secs(1), f.state.me_entered.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), f.save(true, &f.proxy_b))
        .await
        .unwrap();
    f.state.me_release.notify_one();
    assert_eq!(task.await.unwrap(), 409);
}

#[tokio::test]
async fn unchanged_profile_survives_restart_with_same_database_and_key() {
    let mut f = Fixture::new().await;
    f.save(true, &f.proxy_a).await;
    let token = f.login("synthetic-old").await;
    let task = f.tasks.pop().unwrap();
    task.abort();
    let _ = task.await;
    let (base, task) = bind(server::router(f.config.clone()).await.unwrap()).await;
    f.base = base;
    f.tasks.push(task);
    f.state.calls.lock().await.clear();
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(f
        .state
        .calls
        .lock()
        .await
        .iter()
        .all(|call| call["role"] == "proxy-a"));
}

#[tokio::test]
async fn proxy_diagnostic_does_not_follow_redirects() {
    let f = Fixture::new().await;
    f.state.redirect.store(true, Ordering::SeqCst);
    let value: Value = f
        .client
        .post(format!("{}/api/test-mirror-proxy-config", f.base))
        .bearer_auth(SECRET)
        .json(&json!({"enabled":true,"proxy_url":f.proxy_a,"transport_mode":"reqwest"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value["upstream_status"], 302);
    assert_eq!(f.state.calls.lock().await.len(), 1);
}

#[tokio::test]
async fn in_memory_access_diagnosis_is_read_only_and_uses_selected_egress() {
    let mut f = Fixture::new().await;
    let task = f.tasks.pop().unwrap();
    task.abort();
    let _ = task.await;
    f.config.database = ":memory:".into();
    let (base, task) = bind(server::router(f.config.clone()).await.unwrap()).await;
    f.base = base;
    f.tasks.push(task);
    f.save(true, &f.proxy_a).await;
    let response = f
        .client
        .post(format!("{}/api/diagnose-chatgpt-auth", f.base))
        .bearer_auth(SECRET)
        .json(&json!({"access_token":"synthetic-access-only"}))
        .send()
        .await
        .unwrap();
    assert!(!response.headers().contains_key("set-cookie"));
    let value: Value = response.error_for_status().unwrap().json().await.unwrap();
    assert_eq!(value["access_token_valid"], true);
    assert_eq!(value["supported_login_modes"], json!(["api"]));
    let calls = f.state.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["role"], "proxy-a");
    assert_eq!(calls[0]["method"], "GET");
    assert_eq!(calls[0]["path"], "/backend-api/me");
    drop(calls);
    let backup: Value = f
        .client
        .get(format!("{}/api/backup/export", f.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(backup["gateway_sessions"], json!([]));
    assert_eq!(backup["chatgpt_accounts"], json!([]));
    let db = mirror_gateway::storage::Database::open(
        std::path::Path::new(":memory:"),
        "generation-fixture-encryption-key-001",
    )
    .unwrap();
    let filename: String = db
        .conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(filename.is_empty());
}

#[tokio::test]
async fn proxy_with_unbound_cf_clearance_is_explicitly_rejected() {
    let mut f = Fixture::new().await;
    let task = f.tasks.pop().unwrap();
    task.abort();
    let _ = task.await;
    f.config.cfbypass = Some(loopback_url(&f.proxy_b).unwrap());
    let (base, task) = bind(server::router(f.config.clone()).await.unwrap()).await;
    f.base = base;
    f.tasks.push(task);
    f.state.calls.lock().await.clear();
    let response = f
        .client
        .post(format!("{}/api/mirror-proxy-config", f.base))
        .bearer_auth(SECRET)
        .json(&json!({"enabled":true,"proxy_url":f.proxy_a,"transport_mode":"reqwest"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(f.state.calls.lock().await.is_empty());
}

#[tokio::test]
async fn changing_credential_bundle_without_rotating_token_fails_closed() {
    let f = Fixture::new().await;
    let token = f.login("synthetic-old").await;
    let db = mirror_gateway::storage::Database::open(&f.config.database, &f.config.key).unwrap();
    db.conn
        .execute(
            "UPDATE gateway_sessions SET access_token=?1,extra_cookies=?2",
            rusqlite::params![
                db.encrypt("synthetic-replaced").unwrap(),
                db.encrypt("[]").unwrap()
            ],
        )
        .unwrap();
    f.state.calls.lock().await.clear();
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert!(f.state.calls.lock().await.is_empty());
}

#[tokio::test]
async fn restoring_old_profile_settings_does_not_reactivate_old_session() {
    let f = Fixture::new().await;
    f.save(true, &f.proxy_a).await;
    let token = f.login("synthetic-old").await;
    let backup: Value = f
        .client
        .get(format!("{}/api/backup/export", f.base))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    f.save(true, &f.proxy_b).await;
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let response = f
        .client
        .post(format!("{}/api/backup/restore", f.base))
        .bearer_auth(SECRET)
        .json(&backup)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    f.state.calls.lock().await.clear();
    assert_eq!(
        f.read(&token, "/backend-api/me")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert!(f.state.calls.lock().await.is_empty());
}

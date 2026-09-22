//! Owner-integrated boundary tests, upgraded from b837 to observed auth refresh.
//! No real-upstream/page initialization or product resource-ACL validation is implied.
use axum::{body::to_bytes, extract::Request, http::StatusCode, response::IntoResponse, Router};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ADMIN: &str = "coord-synthetic-admin-secret-0001";
const ACCESS_A: &str = "coord-synthetic-access-alice";
const ACCESS_B: &str = "coord-synthetic-access-bob";
const BROWSER_AUTH: &str = "coord-browser-authorization-must-not-leak";
const BROWSER_COOKIE: &str = "coord-browser-cookie-must-not-leak";
type Events = Arc<Mutex<Vec<Value>>>;

fn headers_json(headers: &axum::http::HeaderMap) -> Value {
    json!(headers
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect::<Vec<_>>())
}

async fn spawn_fixture(
    role: &'static str,
    events: Events,
    active: Arc<AtomicBool>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().fallback(move |request: Request| {
        let events = events.clone();
        let active = active.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = to_bytes(body, 1024 * 1024).await.unwrap();
            events.lock().unwrap().push(json!({"kind":"egress", "role":role, "method":parts.method.as_str(),
                "uri":parts.uri.to_string(), "headers":headers_json(&parts.headers), "body":String::from_utf8_lossy(&body)}));
            if role == "django" && parts.uri.path() == "/0x/user/gateway-authorization" {
                let input: Value = serde_json::from_slice(&body).unwrap();
                let known = ["alice", "bob"].contains(&input["subject"].as_str().unwrap_or(""));
                return axum::Json(json!({"active":active.load(Ordering::SeqCst) && known && input["authorization"] == "coord-signature-v1",
                    "version":"v1", "expires_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+3600})).into_response();
            }
            if role == "chat" && parts.uri.path() == "/backend-api/accounts/check/v4-2023-04-27" {
                if !matches!(parts.headers.get("authorization").and_then(|v| v.to_str().ok()),
                    Some("Bearer coord-synthetic-access-alice" | "Bearer coord-synthetic-access-bob")) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                return axum::Json(json!({"accounts":{"default":{"account":{"plan_type":"plus"}}}})).into_response();
            }
            if role == "chat" && parts.uri.path() == "/backend-api/me" {
                if parts.uri.query().unwrap_or("").contains("fixture_status=503") {
                    return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({"message":"synthetic upstream unavailable"}))).into_response();
                }
                let email = match parts.headers.get("authorization").and_then(|v| v.to_str().ok()) {
                    Some("Bearer coord-synthetic-access-alice") => "account-a@example.invalid",
                    Some("Bearer coord-synthetic-access-bob") => "account-b@example.invalid",
                    _ => return StatusCode::UNAUTHORIZED.into_response(),
                };
                return axum::Json(json!({"email":email,"id":email,"name":"Synthetic account"})).into_response();
            }
            (StatusCode::IM_A_TEAPOT, "unexpected fixture route").into_response()
        }
    });
    // Closing each fixture connection makes aborting its listener a real transport
    // failure; an existing Axum keep-alive connection otherwise survives that abort.
    let app = app.layer(axum::middleware::from_fn(
        |request: Request, next: axum::middleware::Next| async move {
            let mut response = next.run(request).await;
            response
                .headers_mut()
                .insert("connection", axum::http::HeaderValue::from_static("close"));
            response
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, task)
}

struct Harness {
    name: &'static str,
    _dir: tempfile::TempDir,
    events: Events,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    active: Arc<AtomicBool>,
    client: reqwest::Client,
    base: String,
    decoy: String,
}

struct Observed {
    status: u16,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Harness {
    async fn new(name: &'static str) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicBool::new(true));
        let (django, django_task) = spawn_fixture("django", events.clone(), active.clone()).await;
        let (chat, chat_task) = spawn_fixture("chat", events.clone(), active.clone()).await;
        let (cdn, cdn_task) = spawn_fixture("cdn-unwired", events.clone(), active.clone()).await;
        let (decoy, decoy_task) =
            spawn_fixture("client-target-decoy", events.clone(), active.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let app = server::router(Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: dir.path().join("db.sqlite"),
            secret: ADMIN.into(),
            key: "coord-fixture-encryption-key-00000001".into(),
            django: loopback_url(&django).unwrap(),
            upstream: loopback_url(&chat).unwrap(),
            cdn_upstream: Some(loopback_url(&cdn).unwrap()),
            cfbypass: None,
            timeout: Duration::from_secs(2),
            mirror_profile: true,
            cookie_secure: false,
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gateway_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        events.lock().unwrap().push(json!({"kind":"setup","gateway":base,"django":django,"chat":chat,"cdn-unwired":cdn,"client-target-decoy":decoy,
            "database":dir.path().join("db.sqlite"),"evidence_level":"synthetic loopback HTTP; owner auth refresh and closed-page candidate"}));
        Self {
            name,
            _dir: dir,
            events,
            tasks: vec![django_task, chat_task, cdn_task, decoy_task, gateway_task],
            active,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            base,
            decoy,
        }
    }

    async fn request(&self, label: &str, builder: reqwest::RequestBuilder) -> Observed {
        let request = builder.build().unwrap();
        let request_id = {
            let mut events = self.events.lock().unwrap();
            let id = events.len();
            events.push(json!({"kind":"client_request","request_id":id,"label":label,"method":request.method().as_str(),"url":request.url().as_str(),
                "headers":headers_json(request.headers()),"body":request.body().and_then(|b|b.as_bytes()).map(|b|String::from_utf8_lossy(b).to_string())}));
            id
        };
        let response = self.client.execute(request).await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap();
        self.events.lock().unwrap().push(json!({"kind":"client_response","request_id":request_id,"label":label,"status":status,"headers":headers_json(&headers),"body":body}));
        Observed {
            status,
            headers,
            body,
        }
    }

    async fn login(&self, user: &str, access: &str, mode: &str) -> String {
        // Same authorization shape as tests/mirror_auth.rs; page routes stay closed.
        let response = self.request("service-login", self.client.post(format!("{}/api/login", self.base)).bearer_auth(ADMIN).json(&json!({
            "user_name":user,"authorization":"coord-signature-v1","access_token":access,"login_mode":mode,
            "isolated_session":true,"mcp_isolation":true,"skills_isolation":true,"model_isolation":true,
            "daily_quota":20,"monthly_quota":100,"model_allowed_ids":["fixture-model"],"model_rate_limits":{},
            "limits":[],"mcp_allowed_ids":[],"skills_allowed_ids":[]}))).await;
        assert_eq!(response.status, 200, "{}", response.body);
        let value: Value = serde_json::from_str(&response.body).unwrap();
        value["login_url"]
            .as_str()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_owned()
    }

    fn egress(&self, role: &str) -> Vec<Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == "egress" && v["role"] == role)
            .cloned()
            .collect()
    }

    async fn local_session(&self, token: &str) -> Observed {
        self.request(
            "local-session",
            self.client
                .get(format!("{}/api/auth/session", self.base))
                .header("cookie", format!("mirror_token={token}")),
        )
        .await
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        let events = self.events.lock().unwrap();
        let result =
            json!({"test":self.name,"panicking":std::thread::panicking(),"events":*events});
        if let Ok(path) = std::env::var("COORD_EVIDENCE_DIR") {
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(
                std::path::Path::new(&path).join(format!("{}.json", self.name)),
                serde_json::to_vec_pretty(&result).unwrap(),
            )
            .unwrap();
        }
        println!(
            "COORD_EVIDENCE test={} events={} panicking={}",
            self.name,
            events.len(),
            std::thread::panicking()
        );
    }
}

fn no_credential_echo(response: &Observed, secrets: &[&str]) {
    let all = format!("{} {}", headers_json(&response.headers), response.body);
    for secret in secrets {
        assert!(
            !all.contains(secret),
            "credential appeared in response: {secret}; {all}"
        );
    }
}

#[tokio::test]
async fn coord_unknown_route_matrix_stays_closed() {
    let h = Harness::new("unknown_route_matrix").await;
    let token = h.login("alice", ACCESS_A, "api").await;
    let chat_before = h.egress("chat").len();
    // Guessed HTML/bootstrap/resource paths are gate probes, not proposed routes.
    // Static assets are deliberately left to the owner's static_assets.rs.
    for path in [
        "/external",
        "/external/unknown.js",
        "/external/http://127.0.0.1/unknown",
        "/internal-upstream",
        "/internal-upstream/backend-api/me",
        "/",
        "/c/coord-guessed-resource",
        "/_next/data/coord-guessed-build/index.json",
        "/backend-api/conversation/coord-guessed-resource",
        "/backend-api/coord-unknown",
        "/api/coord-unknown",
    ] {
        for method in [reqwest::Method::GET, reqwest::Method::POST] {
            for authenticated in [false, true] {
                let mut request = h
                    .client
                    .request(method.clone(), format!("{}{path}", h.base))
                    .query(&[("url", h.decoy.as_str()), ("target", h.decoy.as_str())]);
                if authenticated {
                    request = request.header("x-mirror-token", &token);
                }
                let response = h
                    .request(
                        &format!("{method} {path} authenticated={authenticated}"),
                        request,
                    )
                    .await;
                assert_eq!(
                    response.status,
                    if path.starts_with("/api/") {
                        404
                    } else if authenticated {
                        503
                    } else {
                        401
                    }
                );
                no_credential_echo(&response, &[&token, ADMIN, ACCESS_A]);
            }
        }
    }
    assert_eq!(h.egress("chat").len(), chat_before);
    assert!(h.egress("cdn-unwired").is_empty());
    assert!(h.egress("client-target-decoy").is_empty());
}

#[tokio::test]
async fn coord_client_target_overrides_cannot_select_egress() {
    let h = Harness::new("target_overrides").await;
    let token = h.login("alice", ACCESS_A, "api").await;
    for key in [
        "url",
        "target",
        "upstream",
        "base_url",
        "CHATGPT_BASE_URL",
        "CHATGPT_CDN_BASE_URL",
    ] {
        let response = h
            .request(
                key,
                h.client
                    .get(format!("{}/backend-api/me", h.base))
                    .query(&[(key, h.decoy.as_str())])
                    .header("host", h.decoy.strip_prefix("http://").unwrap())
                    .header("x-upstream-url", &h.decoy)
                    .header("x-target-url", &h.decoy)
                    .header("x-forwarded-host", h.decoy.strip_prefix("http://").unwrap())
                    .header("x-mirror-token", &token),
            )
            .await;
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_str::<Value>(&response.body).unwrap()["email"],
            "account-a@example.invalid"
        );
    }
    let response = h
        .request(
            "body-target-override",
            h.client
                .get(format!("{}/backend-api/me", h.base))
                .header("x-mirror-token", &token)
                .json(&json!({"url":h.decoy,"target":h.decoy,"upstream":h.decoy})),
        )
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(h.egress("chat").len(), 8); // one login + seven probes
    assert!(h.egress("client-target-decoy").is_empty());
    assert!(h.egress("cdn-unwired").is_empty());
}

#[tokio::test]
async fn coord_browser_credentials_absent_from_chat_and_responses() {
    let h = Harness::new("browser_credentials").await;
    let token = h.login("alice", ACCESS_A, "api").await;
    for suffix in ["", "?fixture_status=503"] {
        let response = h.request("browser-credentials",h.client.get(format!("{}/backend-api/me{suffix}",h.base))
            .header("x-mirror-token",&token).bearer_auth(BROWSER_AUTH).header("proxy-authorization",BROWSER_AUTH)
            .header("cookie",format!("access_token={BROWSER_COOKIE}; session_token={BROWSER_COOKIE}; next-auth.session-token={BROWSER_COOKIE}; mirror_token={token}"))).await;
        assert_eq!(response.status, if suffix.is_empty() { 200 } else { 503 });
        no_credential_echo(
            &response,
            &[&token, BROWSER_AUTH, BROWSER_COOKIE, ADMIN, ACCESS_A],
        );
        assert!(response.headers["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store"));
    }
    for request in h.egress("chat").iter().skip(1) {
        let headers = request["headers"].to_string();
        assert!(headers.contains(&format!("Bearer {ACCESS_A}")));
        for secret in [&token, BROWSER_AUTH, BROWSER_COOKIE, ADMIN] {
            assert!(!headers.contains(secret));
        }
        for name in ["cookie", "x-mirror-token", "proxy-authorization"] {
            assert!(!request["headers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|pair| pair[0] == name));
        }
    }
}

#[tokio::test]
async fn coord_transport_error_does_not_echo_credentials() {
    let mut h = Harness::new("transport_error").await;
    let token = h.login("alice", ACCESS_A, "api").await;
    let chat = h.tasks.remove(1);
    chat.abort();
    assert!(chat.await.unwrap_err().is_cancelled());
    let response = h
        .request(
            "chat-transport-failure",
            h.client
                .get(format!("{}/backend-api/me", h.base))
                .query(&[("authorization", BROWSER_AUTH), ("cookie", BROWSER_COOKIE)])
                .header("x-mirror-token", &token)
                .bearer_auth(BROWSER_AUTH)
                .header("cookie", BROWSER_COOKIE),
        )
        .await;
    assert_eq!(response.status, 502);
    no_credential_echo(
        &response,
        &[&token, BROWSER_AUTH, BROWSER_COOKIE, ADMIN, ACCESS_A],
    );
    assert_eq!(h.egress("chat").len(), 1);
}

#[tokio::test]
async fn coord_local_sessions_distinct_accounts_and_logout_are_isolated() {
    let h = Harness::new("distinct_accounts").await;
    let alice = h.login("alice", ACCESS_A, "api").await;
    let bob = h.login("bob", ACCESS_B, "web").await;
    let chat_before = h.egress("chat").len();
    for _ in 0..4 {
        let (a, b) = tokio::join!(h.local_session(&alice), h.local_session(&bob));
        for (response, email, mode) in [
            (a, "account-a@example.invalid", "api"),
            (b, "account-b@example.invalid", "web"),
        ] {
            assert_eq!(response.status, 200);
            let value: Value = serde_json::from_str(&response.body).unwrap();
            assert_eq!(value["user"]["email"], email);
            assert_eq!(value["loginMode"], mode);
            no_credential_echo(&response, &[&alice, &bob, ACCESS_A, ACCESS_B, ADMIN]);
        }
    }
    let logout = h
        .request(
            "logout-alice",
            h.client
                .post(format!("{}/api/logout", h.base))
                .bearer_auth(ADMIN)
                .json(&json!({"user_name":"alice"})),
        )
        .await;
    assert_eq!(logout.status, 200);
    assert_eq!(h.local_session(&alice).await.body, "{}");
    assert_eq!(
        serde_json::from_str::<Value>(&h.local_session(&bob).await.body).unwrap()["user"]["email"],
        "account-b@example.invalid"
    );
    let chat = h.egress("chat");
    assert_eq!(chat.len(), chat_before + 18); // Eight concurrent refreshes + Bob after logout.
    for (credential, refreshes) in [
        (format!("Bearer {ACCESS_A}"), 4),
        (format!("Bearer {ACCESS_B}"), 5),
    ] {
        let paths: Vec<&str> = chat[chat_before..]
            .iter()
            .filter(|event| {
                event["headers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|header| header[0] == "authorization" && header[1] == credential)
            })
            .map(|event| event["uri"].as_str().unwrap())
            .collect();
        assert_eq!(paths.len(), refreshes * 2);
        for pair in paths.as_chunks::<2>().0 {
            assert_eq!(
                *pair,
                [
                    "/backend-api/accounts/check/v4-2023-04-27",
                    "/backend-api/me"
                ]
            );
        }
    }
}

#[tokio::test]
async fn coord_shared_account_token_rotation_preserves_other_user() {
    let h = Harness::new("shared_account").await;
    let alice = h.login("alice", ACCESS_A, "api").await;
    let bob = h.login("bob", ACCESS_A, "web").await;
    let replacement = h.login("alice", ACCESS_A, "api").await;
    assert_ne!(alice, replacement);
    assert_eq!(h.local_session(&alice).await.body, "{}");
    let handoff = h
        .request(
            "alice-handoff",
            h.client
                .get(format!("{}/api/not-login", h.base))
                .query(&[("user_gateway_token", replacement.as_str())]),
        )
        .await;
    assert_eq!(handoff.status, 302);
    let cookie = handoff
        .headers
        .get_all("set-cookie")
        .iter()
        .find_map(|v| v.to_str().unwrap().strip_prefix("mirror_token="))
        .unwrap();
    let rotated = cookie.split(';').next().unwrap();
    assert_ne!(rotated, replacement);
    assert_eq!(h.local_session(&replacement).await.body, "{}");
    for (token, mode) in [(rotated, "api"), (bob.as_str(), "web")] {
        let response = h.local_session(token).await;
        let value: Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(value["user"]["email"], "account-a@example.invalid");
        assert_eq!(value["loginMode"], mode);
        no_credential_echo(&response, &[rotated, &bob, ADMIN, ACCESS_A]);
    }
    let logout = h
        .request(
            "logout-alice",
            h.client
                .post(format!("{}/api/logout", h.base))
                .bearer_auth(ADMIN)
                .json(&json!({"user_name":"alice"})),
        )
        .await;
    assert_eq!(logout.status, 200);
    assert_eq!(h.local_session(rotated).await.body, "{}");
    assert_eq!(
        serde_json::from_str::<Value>(&h.local_session(&bob).await.body).unwrap()["loginMode"],
        "web"
    );
}

#[tokio::test]
async fn coord_invalid_credentials_fail_without_egress_or_echo() {
    let h = Harness::new("invalid_credentials").await;
    for path in [
        "/backend-api/me",
        "/internal-upstream/unknown",
        "/external/unknown",
    ] {
        let response = h
            .request(
                "invalid-mirror-token",
                h.client
                    .get(format!("{}{path}", h.base))
                    .header("x-mirror-token", BROWSER_AUTH)
                    .header("cookie", BROWSER_COOKIE),
            )
            .await;
        assert_eq!(response.status, 401);
        no_credential_echo(&response, &[BROWSER_AUTH, BROWSER_COOKIE, ADMIN]);
    }
    let invalid_login = h
        .request(
            "invalid-admin-key",
            h.client
                .post(format!("{}/api/login", h.base))
                .bearer_auth(BROWSER_AUTH)
                .json(&json!({"user_name":"alice","access_token":BROWSER_COOKIE})),
        )
        .await;
    assert_eq!(invalid_login.status, 401);
    no_credential_echo(&invalid_login, &[BROWSER_AUTH, BROWSER_COOKIE, ADMIN]);
    let handoff = h
        .request(
            "invalid-handoff",
            h.client
                .get(format!("{}/api/not-login", h.base))
                .query(&[("user_gateway_token", BROWSER_AUTH)]),
        )
        .await;
    assert_eq!(handoff.status, 401);
    no_credential_echo(&handoff, &[BROWSER_AUTH, BROWSER_COOKIE, ADMIN]);
    for role in ["chat", "django", "cdn-unwired", "client-target-decoy"] {
        assert!(h.egress(role).is_empty());
    }
}

#[tokio::test]
async fn coord_inactive_authority_blocks_chat_without_cross_user_fallback() {
    let h = Harness::new("inactive_authority").await;
    let token = h.login("alice", ACCESS_A, "api").await;
    let chat_before = h.egress("chat").len();
    h.active.store(false, Ordering::SeqCst);
    let response = h
        .request(
            "inactive-authority",
            h.client
                .get(format!("{}/backend-api/me", h.base))
                .header("x-mirror-token", &token),
        )
        .await;
    assert_eq!(response.status, 401);
    no_credential_echo(&response, &[&token, ADMIN, ACCESS_A]);
    assert_eq!(h.local_session(&token).await.body, "{}");
    assert_eq!(h.egress("chat").len(), chat_before);
    assert!(h.egress("client-target-decoy").is_empty());
}

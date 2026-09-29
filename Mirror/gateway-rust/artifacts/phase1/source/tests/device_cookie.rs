//! 设备 Cookie（`oai-did`）的合成回环回归：浏览器播种、上游捕获、号池恢复与
//! 跨镜像用户一致性、加密落库。
//! 全部为本机 fixture，不接触真实 chatgpt.com，也不使用任何真实账号。
use axum::{
    body::to_bytes,
    extract::Request,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const ADMIN: &str = "device-cookie-admin-secret";
const KEY: &str = "device-cookie-encryption-key-00000";
/// 上游账号名：登录时网关用它作为 `chatgpt_username`（来自 `/backend-api/me`）。
const ACCOUNT: &str = "fixture@example.invalid";
const CONVERSATION: &str = "6ab350c7-5d3c-83ea-be1f-a87b536c1c6c";
const UPSTREAM_DID: &str = "upstream-did-7";
const POOL_DID: &str = "pool-did-9";
const BROWSER_DID: &str = "browser-did-1";

type Events = Arc<Mutex<Vec<Value>>>;

struct Upstream {
    events: Events,
    /// `/backend-api/me` 是否下发设备 cookie（捕获路径）。
    set_device_on_me: AtomicBool,
    /// 创建会话是否下发设备 cookie（生成路径的捕获）。
    set_device_on_create: AtomicBool,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            events: Arc::default(),
            set_device_on_me: AtomicBool::new(false),
            set_device_on_create: AtomicBool::new(false),
        }
    }
}

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

/// 设备 cookie 的 `set-cookie` 形态：与真实上游一致带 Secure/HttpOnly/SameSite。
fn device_set_cookie() -> HeaderValue {
    HeaderValue::from_str(&format!(
        "oai-did={UPSTREAM_DID}; Path=/; HttpOnly; Secure; SameSite=None"
    ))
    .unwrap()
}

async fn chat_upstream(state: Arc<Upstream>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let _ = to_bytes(body, 1024 * 1024).await.unwrap();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    state.events.lock().unwrap().push(json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "cookie": header("cookie"),
        "device_header": header("oai-device-id"),
    }));
    let with_device = |body: Value, enabled: bool| {
        let mut response = axum::Json(body).into_response();
        if enabled {
            response
                .headers_mut()
                .insert("set-cookie", device_set_cookie());
        }
        response
    };
    match (parts.method.as_str(), parts.uri.path()) {
        ("POST", "/backend-api/f/conversation") => with_device(
            json!({"conversation_id":CONVERSATION}),
            state.set_device_on_create.load(Ordering::SeqCst),
        ),
        ("GET", "/backend-api/me") => with_device(
            json!({"email":ACCOUNT}),
            state.set_device_on_me.load(Ordering::SeqCst),
        ),
        _ => with_device(json!({"path":parts.uri.path()}), false),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    base: String,
    client: reqwest::Client,
    upstream: Arc<Upstream>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn new() -> Self {
        let upstream = Arc::new(Upstream::default());
        let chat_url = {
            let state = upstream.clone();
            serve(
                Router::new()
                    .fallback(move |request: Request| chat_upstream(state.clone(), request)),
            )
            .await
        };
        let django_url = {
            serve(Router::new().fallback(|request: Request| async move {
                if request.uri().path() == "/0x/user/gateway-authorization" {
                    // 身份字段恒来自本响应；subject 回显请求里的 subject，与真实 Django 同形。
                    let (_, body) = request.into_parts();
                    let body = to_bytes(body, 64 * 1024).await.unwrap();
                    let input: Value = serde_json::from_slice(&body).unwrap_or_default();
                    let subject = input["subject"].as_str().unwrap_or("");
                    let user_id = if subject == "alice" { "11" } else { "12" };
                    return axum::Json(json!({
                        "active": true,
                        "version": "v1",
                        "user_id": user_id,
                        "is_admin": false,
                        "principal_kind": "user",
                        "subject": subject,
                        "expires_at": 4_102_444_800_i64,
                    }))
                    .into_response();
                }
                StatusCode::NOT_FOUND.into_response()
            }))
            .await
        };
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: dir.path().join("db.sqlite"),
            secret: ADMIN.into(),
            key: KEY.into(),
            django: loopback_url(&django_url.0).unwrap(),
            upstream: loopback_url(&chat_url.0).unwrap(),
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            cfbypass: None,
            timeout: Duration::from_secs(5),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
            admin_public_url: None,
        };
        let app = server::router(config).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            _dir: dir,
            tasks: vec![django_url.1, chat_url.1, gateway],
            base,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            upstream,
        }
    }

    /// 登录指定镜像用户（同一上游账号），返回 mirror_token。
    async fn login(&self, user: &str) -> String {
        let response = self
            .client
            .post(format!("{}/api/login", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({
                "user_name":user,
                "access_token":format!("synthetic-access-{user}"),
                "authorization":"signature-v1",
                "login_mode":"api",
                "isolated_session":true,
                "mcp_isolation":true,
                "skills_isolation":true,
                "model_isolation":true,
                "daily_quota":20,
                "monthly_quota":100,
                "model_allowed_ids":["fixture-model"],
                "model_rate_limits":{},
                "limits":[],
                "mcp_allowed_ids":[],
                "skills_allowed_ids":[],
                "chatgpt_account_id":"3",
                // 账号导入的 cookie 里刻意不含 oai-did：设备标识只走本批新增的来源。
                "extra_cookies":[{"name":"probe_extra","value":user}],
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        let body: Value = serde_json::from_str(&body).unwrap();
        body["login_url"]
            .as_str()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_owned()
    }

    async fn me(&self, token: &str, device_header: Option<&str>) -> reqwest::Response {
        let mut request = self
            .client
            .get(format!("{}/backend-api/me", self.base))
            .header("x-mirror-token", token);
        if let Some(value) = device_header {
            request = request.header("oai-device-id", value);
        }
        request.send().await.unwrap()
    }

    /// 号池账号行：`extra_cookies` 写明文 JSON（与导入的历史数据同形，解密为透传）。
    fn seed_account_cookies(&self, cookies: Value) {
        let conn = Connection::open(self._dir.path().join("db.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO chatgpt_accounts (chatgpt_username, access_token, extra_cookies) \
             VALUES (?1, 'plain-access', ?2)",
            rusqlite::params![ACCOUNT, cookies.to_string()],
        )
        .unwrap();
    }

    /// 会话 jar 列的密文原文（`upstream_cookies`，本候选新增列）。
    fn session_jar_column(&self, user: &str) -> Option<String> {
        let conn = Connection::open(self._dir.path().join("db.sqlite")).unwrap();
        conn.query_row(
            "SELECT upstream_cookies FROM gateway_sessions WHERE user_name = ?1",
            [user],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn calls(&self, path: &str) -> Vec<Value> {
        self.upstream
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event["path"].as_str() == Some(path))
            .cloned()
            .collect()
    }

    fn clear_calls(&self) {
        self.upstream.events.lock().unwrap().clear();
    }
}

fn last(calls: &[Value]) -> &Value {
    calls.last().expect("夹具应至少记录一次上游调用")
}

/// 浏览器播种：首个请求带 `oai-device-id` 时定型，之后的请求即使不带该头，
/// 上游也继续收到同一个设备标识（Cookie 与请求头同值）。
#[tokio::test]
async fn browser_device_header_seeds_session_and_is_replayed() {
    let fixture = Fixture::new().await;
    let token = fixture.login("alice").await;
    fixture.clear_calls();

    let response = fixture.me(&token, Some(BROWSER_DID)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let calls = fixture.calls("/backend-api/me");
    let seeded = last(&calls);
    assert_eq!(seeded["device_header"], json!(BROWSER_DID));
    assert!(
        seeded["cookie"]
            .as_str()
            .unwrap()
            .contains(&format!("oai-did={BROWSER_DID}")),
        "上游 Cookie 应带播种的设备标识: {seeded}"
    );

    fixture.clear_calls();
    let response = fixture.me(&token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let calls = fixture.calls("/backend-api/me");
    let replayed = last(&calls);
    assert_eq!(
        replayed["device_header"],
        json!(BROWSER_DID),
        "会话已定型后，请求头应复用同一设备标识"
    );
    assert!(
        replayed["cookie"]
            .as_str()
            .unwrap()
            .contains(&format!("oai-did={BROWSER_DID}")),
        "会话已定型后，Cookie 应复用同一设备标识: {replayed}"
    );
    // 落库列必须是加密形态（与凭据列同约定，不存明文设备值）。
    let stored = fixture.session_jar_column("alice").unwrap();
    assert!(
        stored.starts_with("enc:v1:"),
        "设备 Cookie 必须以 enc:v1 密文形态落库: {stored}"
    );
    assert!(
        !stored.contains(BROWSER_DID),
        "密文列不得出现明文设备值: {stored}"
    );
}

/// 上游捕获：`set-cookie: oai-did=…` 在响应交给客户端前落库，下一个请求即带上它。
/// fixture 上游是明文 http，而真实上游形态的 `oai-did` 带 `Secure`，因此回注只体现在
/// `oai-device-id` 头（header 不参与 cookie 作用域）；同一 jar 在 https 上游下的
/// Cookie 回注与作用域判定见 `tests/upstream_cookie_jar.rs`。
#[tokio::test]
async fn upstream_set_cookie_is_captured_and_reused() {
    let fixture = Fixture::new().await;
    let token = fixture.login("alice").await;
    fixture
        .upstream
        .set_device_on_me
        .store(true, Ordering::SeqCst);
    fixture.clear_calls();

    let response = fixture.me(&token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let first = last(&fixture.calls("/backend-api/me")).clone();
    assert!(
        !first["cookie"].as_str().unwrap().contains("oai-did="),
        "捕获前的请求不应凭空出现设备标识: {first}"
    );
    assert_eq!(
        first["device_header"],
        json!(""),
        "捕获前不应有设备头: {first}"
    );

    fixture.clear_calls();
    let response = fixture.me(&token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let second = last(&fixture.calls("/backend-api/me")).clone();
    assert_eq!(second["device_header"], json!(UPSTREAM_DID));
    assert!(
        !second["cookie"].as_str().unwrap().contains("oai-did="),
        "Secure 条目不得发往明文 http 上游（捕获仍应以设备头生效）: {second}"
    );
}

/// 号池恢复与跨镜像用户一致性：同一上游账号的两个镜像用户共享同一个设备标识。
#[tokio::test]
async fn pool_row_device_id_is_shared_across_mirror_users() {
    let fixture = Fixture::new().await;
    fixture.seed_account_cookies(json!([{"name":"oai-did","value":POOL_DID}]));

    for user in ["alice", "bob"] {
        let token = fixture.login(user).await;
        fixture.clear_calls();
        let response = fixture.me(&token, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let call = last(&fixture.calls("/backend-api/me")).clone();
        assert_eq!(
            call["device_header"],
            json!(POOL_DID),
            "{user} 应从号池账号恢复设备标识"
        );
        assert!(
            call["cookie"]
                .as_str()
                .unwrap()
                .contains(&format!("oai-did={POOL_DID}")),
            "{user} 的 Cookie 应带上号池设备标识: {call}"
        );
    }
}

/// 上游轮换设备标识时覆盖号池，其它镜像用户随后跟上同一值。
#[tokio::test]
async fn captured_device_id_replaces_pool_value_for_other_users() {
    let fixture = Fixture::new().await;
    fixture.seed_account_cookies(json!([{"name":"oai-did","value":POOL_DID}]));
    let alice = fixture.login("alice").await;
    fixture
        .upstream
        .set_device_on_me
        .store(true, Ordering::SeqCst);

    // alice 首次请求带号池值；上游同时下发新值，捕获后覆盖号池。
    fixture.clear_calls();
    let response = fixture.me(&alice, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        last(&fixture.calls("/backend-api/me"))["device_header"],
        json!(POOL_DID)
    );

    let bob = fixture.login("bob").await;
    fixture.clear_calls();
    let response = fixture.me(&bob, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        last(&fixture.calls("/backend-api/me"))["device_header"],
        json!(UPSTREAM_DID),
        "号池被上游轮换后，另一镜像用户应拿到新值"
    );
}

/// 生成类路径（创建会话）同样捕获设备 cookie；生成请求本身不重放。
#[tokio::test]
async fn generation_path_captures_device_cookie() {
    let fixture = Fixture::new().await;
    let token = fixture.login("alice").await;
    fixture
        .upstream
        .set_device_on_create
        .store(true, Ordering::SeqCst);
    fixture.clear_calls();

    let response = fixture
        .client
        .post(format!("{}/backend-api/f/conversation", fixture.base))
        .header("x-mirror-token", &token)
        .json(&json!({"model":"fixture-model","messages":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    fixture.clear_calls();
    let response = fixture.me(&token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        last(&fixture.calls("/backend-api/me"))["device_header"],
        json!(UPSTREAM_DID)
    );
}

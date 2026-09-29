//! 缺口 3 的产品接线回归：ACL 判权与登记在真实 HTTP 入口上的行为。
//!
//! 覆盖：访客被拒绝但账号级路径仍可用；项目创建后仅创建者可见；集合列表按受众
//! 过滤并重算 `total`；管理端授予/撤销共享即时生效；生成互斥返回 409；撤权中止
//! 在途流；旧归属一次性回填幂等且不认领访客行。
//! 全部为本机合成回环 fixture，不接触真实 chatgpt.com，也不使用任何真实账号。
use axum::{
    body::to_bytes,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    Router,
};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Notify;

const ADMIN: &str = "acl-wiring-admin-secret";
const KEY: &str = "acl-wiring-encryption-key-0000001";
const CONVERSATION: &str = "6ab350c7-5d3c-83ea-be1f-a87b536c1c6c";
/// 上游清单里存在、但本账号从未登记的第二条会话（仅用于清单差集断言）。
const UNREGISTERED: &str = "22222222-3333-4444-5555-666666666666";
const PROJECT: &str = "proj-0001";
const LEGACY_CONVERSATION: &str = "11111111-2222-3333-4444-555555555555";

type Events = Arc<Mutex<Vec<Value>>>;

#[derive(Default)]
struct Upstream {
    events: Events,
    /// 慢速流：发出首块后等待放行，用于生成互斥与撤权中止。
    release: Arc<Notify>,
    held: AtomicUsize,
    /// 剩余多少次 `/backend-api/conversations` 应答要先返回 CF 挑战。
    challenge: AtomicUsize,
    /// 为真时清单应答缺 `items`/`total`：模拟上游变更信封。
    malformed_list: AtomicBool,
}

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

async fn chat_upstream(state: Arc<Upstream>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.unwrap();
    state.events.lock().unwrap().push(json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "authorization": parts.headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""),
        "cookie": parts.headers.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or(""),
        "device": parts.headers.get("oai-device-id").and_then(|v| v.to_str().ok()).unwrap_or(""),
        "body": String::from_utf8_lossy(&body),
    }));
    let path = parts.uri.path();
    let post = parts.method == axum::http::Method::POST;
    // Cloudflare 挑战：只对清单端点生效，首轮 403 + `cf-mitigated: challenge`。
    if path == "/backend-api/conversations"
        && state
            .challenge
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
            .is_ok()
    {
        return (
            StatusCode::FORBIDDEN,
            [("cf-mitigated", "challenge")],
            "<html>challenge</html>",
        )
            .into_response();
    }
    // 慢速流：首块立即下发，第二块等 fixture 放行——租约与撤权中止都靠它观测。
    if path.starts_with("/realtime/") || (post && path == format!("/backend-api/conversation/{CONVERSATION}")) {
        state.held.fetch_add(1, Ordering::SeqCst);
        let release = state.release.clone();
        let stream = futures_util::stream::unfold(0u8, move |stage| {
            let release = release.clone();
            async move {
                match stage {
                    0 => Some((
                        Ok::<_, std::io::Error>("data: first\n\n".to_owned()),
                        1u8,
                    )),
                    1 => {
                        release.notified().await;
                        Some((Ok("data: second\n\n".to_owned()), 2u8))
                    }
                    _ => None,
                }
            }
        });
        return (
            [("content-type", "text/event-stream")],
            axum::body::Body::from_stream(stream),
        )
            .into_response();
    }
    match (parts.method.as_str(), path) {
        ("POST", "/backend-api/projects") => {
            axum::Json(json!({"project_id": PROJECT})).into_response()
        }
        // 列表对所有会话返回同一条目：过滤与 total 必须由网关按 ACL 重算。
        ("GET", "/backend-api/projects") => {
            axum::Json(json!({"items":[{"project_id":PROJECT,"title":"fixture"}],"total":1}))
                .into_response()
        }
        ("GET", path) if path == format!("/backend-api/projects/{PROJECT}") => {
            axum::Json(json!({"project_id":PROJECT})).into_response()
        }
        ("GET", "/backend-api/me") => {
            axum::Json(json!({"email":"fixture@example.invalid","id":"fixture","name":"Fixture"}))
                .into_response()
        }
        ("POST", "/backend-api/f/conversation") => {
            axum::Json(json!({"conversation_id":CONVERSATION})).into_response()
        }
        // SessionToken 换取：ACL 清单端点在号池账号没有 AccessToken 时走这一条。
        ("GET", "/api/auth/session") => {
            axum::Json(json!({"accessToken":"synthetic-exchange-alice"})).into_response()
        }
        // 上游会话清单：一条已登记、一条未登记，差集必须只留下未登记的。
        ("GET", "/backend-api/conversations") => {
            let envelope = if state.malformed_list.load(Ordering::SeqCst) {
                json!({"limit": 50, "offset": 0})
            } else {
                json!({
                    "items": [
                        {"id": CONVERSATION, "title": "已登记会话", "update_time": 1_700_000_100.0},
                        {"id": UNREGISTERED, "title": "未认领会话", "update_time": 1_700_000_200.0},
                    ],
                    "total": 2,
                    "limit": 50,
                    "offset": 0,
                })
            };
            axum::Json(envelope).into_response()
        }
        _ => axum::Json(json!({"path":path})).into_response(),
    }
}

/// Django 桩：身份字段恒来自本响应；`root` 是管理员，`free_account:*` 是访客。
fn django_router(mapping_calls: Arc<AtomicUsize>, legacy: bool) -> Router {
    Router::new().fallback(move |request: Request| {
        let mapping_calls = mapping_calls.clone();
        async move {
            let path = request.uri().path().to_owned();
            let (_, body) = request.into_parts();
            let body = to_bytes(body, 64 * 1024).await.unwrap();
            if path == "/0x/user/gateway-authorization" {
                let input: Value = serde_json::from_slice(&body).unwrap_or_default();
                let subject = input["subject"].as_str().unwrap_or("").to_owned();
                let visitor = subject.starts_with("free_account:");
                let admin = subject == "root";
                let user_id = match subject.as_str() {
                    "root" => "1",
                    "alice" => "11",
                    "bob" => "12",
                    _ => "2",
                };
                return axum::Json(json!({
                    "active": true,
                    "version": "v1",
                    "user_id": user_id,
                    "is_admin": admin,
                    "principal_kind": if visitor {"visitor"} else {"user"},
                    "subject": subject,
                    "expires_at": 4_102_444_800_i64,
                }))
                .into_response();
            }
            if path == "/0x/user/gateway-acl-mapping" {
                mapping_calls.fetch_add(1, Ordering::SeqCst);
                // 旧归属回填的映射：只有 alice 能唯一映射，访客与未知用户不在表内。
                let users = if legacy { json!([{"username":"alice","user_id":"11","is_admin":false}]) } else { json!([]) };
                let accounts = if legacy {
                    json!([{"chatgpt_username":"fixture@example.invalid","account_id":"3"}])
                } else {
                    json!([])
                };
                return axum::Json(json!({"users":users,"accounts":accounts})).into_response();
            }
            StatusCode::NOT_FOUND.into_response()
        }
    })
}

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    base: String,
    client: reqwest::Client,
    upstream: Arc<Upstream>,
    django: url::Url,
    upstream_url: url::Url,
    database: std::path::PathBuf,
    mapping_calls: Arc<AtomicUsize>,
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
        Self::with_seed(None, false).await
    }

    /// `seed` 非空时先把旧归属行写进网关库，用于断言启动回填的结果。
    /// `cfbypass` 为真时挂一个本地 cfbypass 桩，用于断言挑战刷新后只重放一次。
    async fn with_seed(seed: Option<&[(String, String, String)]>, cfbypass: bool) -> Self {
        let upstream = Arc::new(Upstream::default());
        let chat_url = {
            let state = upstream.clone();
            serve(Router::new().fallback(move |request: Request| {
                chat_upstream(state.clone(), request)
            }))
            .await
        };
        let mapping_calls = Arc::new(AtomicUsize::new(0));
        let django_url = serve(django_router(mapping_calls.clone(), seed.is_some())).await;
        let cfbypass_url = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            // 每次刷新返回不同值：这样才能证明重放用的是刷新后的 CF cookies，
            // 而不是复用启动预热那一份。
            let issued = Arc::new(AtomicUsize::new(0));
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().fallback(move || {
                        let value = format!(
                            "CF-FIXTURE-{}",
                            issued.fetch_add(1, Ordering::SeqCst) + 1
                        );
                        async move {
                            axum::Json(json!({
                                "user_agent": "fixture-agent",
                                "cookies": [{"name":"cf_clearance","value":value}],
                            }))
                        }
                    }),
                )
                .await
                .unwrap()
            });
            (url, task)
        };
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("db.sqlite");
        let django = loopback_url(&django_url.0).unwrap();
        let upstream_url = loopback_url(&chat_url.0).unwrap();
        if let Some(rows) = seed {
            // 直接写旧表：回填只读旧表，不改写它们。
            let db = mirror_gateway::storage::Database::open(&database, KEY).unwrap();
            for (chatgpt_username, conversation_id, user_name) in rows {
                db.conn
                    .execute(
                        "INSERT INTO conversation_owners \
                         (chatgpt_username, conversation_id, user_name, created_at, updated_at) \
                         VALUES (?1, ?2, ?3, ?4, ?4)",
                        rusqlite::params![chatgpt_username, conversation_id, user_name, 1_700_000_000i64],
                    )
                    .unwrap();
            }
        }
        let app = server::router(Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: database.clone(),
            secret: ADMIN.into(),
            key: KEY.into(),
            django: django.clone(),
            upstream: upstream_url.clone(),
            // 这些用例不经过 WS 桥接：给一个不会用到的回环 WS 基址即可。
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            cfbypass: cfbypass.then(|| loopback_url(&cfbypass_url.0).unwrap()),
            timeout: Duration::from_secs(5),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
            admin_public_url: None,
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            _dir: dir,
            tasks: vec![django_url.1, chat_url.1, cfbypass_url.1, gateway],
            base,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            upstream,
            django,
            upstream_url,
            database,
            mapping_calls,
        }
    }

    /// 同一数据库/同一上游的配置：用于断言第二次启动不会重复回填。
    fn config(&self) -> Config {
        Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: self.database.clone(),
            secret: ADMIN.into(),
            key: KEY.into(),
            django: self.django.clone(),
            upstream: self.upstream_url.clone(),
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
        }
    }

    async fn login(&self, user: &str, account_id: &str) -> String {
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
                "chatgpt_account_id":account_id,
                "extra_cookies":[],
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

    fn request(&self, method: &str, token: &str, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.base);
        let builder = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            other => panic!("fixture 不支持的方法 {other}"),
        };
        builder.header("x-mirror-token", token)
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

    /// 管理端 ACL 操作：服务密钥 + 操作者 `authorization`/`subject` + 管理员身份。
    async fn acl(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.base))
            .bearer_auth(ADMIN)
            .header("authorization", "signature-v1")
            .header("subject", "root")
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// 管理端 ACL 只读查询：`subject` 决定 Django 桩返回的管理员身份。
    async fn acl_get(&self, path: &str, subject: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{path}", self.base))
            .bearer_auth(ADMIN)
            .header("authorization", "signature-v1")
            .header("subject", subject)
            .send()
            .await
            .unwrap()
    }

    /// 号池账号行：ACL 管理端清单的凭据来源（`chatgpt_accounts.id` = Django 侧 account_id）。
    fn seed_pool_account(&self, id: i64, access: &str, session: Option<&str>, extra: &str) {
        let db = mirror_gateway::storage::Database::open(&self.database, KEY).unwrap();
        db.conn
            .execute(
                "INSERT INTO chatgpt_accounts(id, chatgpt_username, access_token, session_token, extra_cookies) \
                 VALUES (?1,'fixture@example.invalid',?2,?3,?4)",
                rusqlite::params![id, access, session, extra],
            )
            .unwrap();
    }

    async fn create_project(&self, token: &str) -> reqwest::Response {
        self.request("POST", token, "/backend-api/projects")
            .json(&json!({"name":"fixture"}))
            .send()
            .await
            .unwrap()
    }
}

/// 访客不参与 ACL：作用域与创建路径 403，账号级路径与空集合保持可用。
#[tokio::test]
async fn visitor_is_denied_on_acl_paths_but_keeps_account_level_access() {
    let f = Fixture::new().await;
    let visitor = f.login("free_account:visitor-1", "3").await;
    f.clear_calls();

    for (method, path) in [
        ("GET", format!("/backend-api/conversation/{CONVERSATION}").leak().to_owned()),
        ("POST", "/backend-api/projects".to_owned()),
    ] {
        let request = f.request(method, &visitor, &path);
        let response = if method == "POST" {
            request.json(&json!({"name":"nope"})).send().await.unwrap()
        } else {
            request.send().await.unwrap()
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "acl_visitor_denied", "{path}");
    }
    // 集合读取返回空信封：没有可归属资源，也没有泄露。
    let listed = f
        .request("GET", &visitor, "/backend-api/projects")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let body: Value = listed.json().await.unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert_eq!(body["total"], 0);
    // 账号级路径不受 ACL 影响。
    let models = f
        .request("GET", &visitor, "/backend-api/models")
        .send()
        .await
        .unwrap();
    assert_eq!(models.status(), StatusCode::OK);
    assert!(
        f.upstream.events.lock().unwrap().iter().all(|event| event["path"] != "/backend-api/projects"),
        "访客的 ACL 拒绝不得接触上游"
    );
}

/// 项目创建后只有创建者可见；他人的直读 404 且不触上游；列表按受众过滤并重算 total。
#[tokio::test]
async fn project_creation_is_private_and_lists_are_filtered_per_audience() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    let bob = f.login("bob", "3").await;
    f.clear_calls();

    let created = f.create_project(&alice).await;
    assert_eq!(created.status(), StatusCode::OK);
    assert!(created.text().await.unwrap().contains(PROJECT));

    let scoped = format!("/backend-api/projects/{PROJECT}");
    let read = f.request("GET", &alice, &scoped).send().await.unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(f.calls(&scoped).len(), 1);

    f.clear_calls();
    let denied = f.request("GET", &bob, &scoped).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    let body: Value = denied.json().await.unwrap();
    assert_eq!(body["code"], "acl_not_found");
    assert!(
        f.calls(&scoped).is_empty(),
        "他人资源的拒绝不得接触上游：{:?}",
        f.calls(&scoped)
    );

    // 未登记 id 同样 404 且不触上游。
    let unknown = f
        .request("GET", &alice, "/backend-api/projects/proj-9999")
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert!(f.calls("/backend-api/projects/proj-9999").is_empty());

    // 列表：上游对两边返回同一条目，网关按 ACL 过滤并重算 total。
    for (token, expected) in [(&alice, 1), (&bob, 0)] {
        let listed = f
            .request("GET", token, "/backend-api/projects")
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let body: Value = listed.json().await.unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), expected);
        assert_eq!(body["total"], expected);
    }
}

/// 管理端授予共享后他人立即可读，撤销后立即回到 404；服务密钥本身不是管理员。
#[tokio::test]
async fn admin_grant_and_revoke_take_effect_immediately() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    let bob = f.login("bob", "3").await;
    assert_eq!(f.create_project(&alice).await.status(), StatusCode::OK);
    let scoped = format!("/backend-api/projects/{PROJECT}");
    f.clear_calls();

    // 服务密钥 + 非管理员身份不能执行管理操作。
    let denied = f
        .client
        .post(format!("{}/api/acl/share", f.base))
        .bearer_auth(ADMIN)
        .header("authorization", "signature-v1")
        .header("subject", "bob")
        .json(&json!({"account_id":"3","resource_type":"project","upstream_id":PROJECT,
            "recipient_user_id":"12","granted":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let granted = f
        .acl(
            "/api/acl/share",
            json!({"account_id":"3","resource_type":"project","upstream_id":PROJECT,
                "recipient_user_id":"12","granted":true}),
        )
        .await;
    assert_eq!(granted.status(), StatusCode::OK);
    assert_eq!(
        f.request("GET", &bob, &scoped).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(f.calls(&scoped).len(), 1);

    let revoked = f
        .acl(
            "/api/acl/share",
            json!({"account_id":"3","resource_type":"project","upstream_id":PROJECT,
                "recipient_user_id":"12","granted":false}),
        )
        .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    assert_eq!(
        f.request("GET", &bob, &scoped).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(f.calls(&scoped).len(), 1, "撤销后不得再接触上游");
    // 属主始终可用。
    assert_eq!(
        f.request("GET", &alice, &scoped).send().await.unwrap().status(),
        StatusCode::OK
    );
}

/// 生成互斥：同一会话同时只允许一个在途生成，冲突返回 409 且不排队、不重放。
#[tokio::test]
async fn concurrent_generation_on_one_conversation_returns_busy() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    assert_eq!(
        f.request("POST", &alice, "/backend-api/f/conversation")
            .json(&json!({"messages":[]}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let scoped = format!("/backend-api/conversation/{CONVERSATION}");
    f.clear_calls();

    let first = f
        .request("POST", &alice, &scoped)
        .json(&json!({"messages":[{"role":"user"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    // 首块到达即证明上游请求已进入在途状态（租约已持有）。
    let mut first = first;
    let head = first.chunk().await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&head).contains("first"));

    let second = f
        .request("POST", &alice, &scoped)
        .json(&json!({"messages":[{"role":"user"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body: Value = second.json().await.unwrap();
    assert_eq!(body["code"], "generation_busy");
    assert_eq!(f.calls(&scoped).len(), 1, "冲突不得重放上游请求");

    // 放行首块之后，租约随响应体结束释放。
    f.upstream.release.notify_one();
    while first.chunk().await.unwrap().is_some() {}
    let third = f
        .request("POST", &alice, &scoped)
        .json(&json!({"messages":[{"role":"user"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(third.status(), StatusCode::OK);
    f.upstream.release.notify_one();
    let _ = third.text().await.unwrap();
}

/// 撤权中止在途流：撤权事件送达后，已开始的响应不再把后续内容交给客户端。
#[tokio::test]
async fn revocation_aborts_an_in_flight_stream() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    f.clear_calls();

    let mut response = f
        .request("GET", &alice, "/realtime/session")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let head = response.chunk().await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&head).contains("first"));
    assert_eq!(f.upstream.held.load(Ordering::SeqCst), 1);

    let revoked = f
        .client
        .post(format!("{}/api/revoke-authorization", f.base))
        .bearer_auth(ADMIN)
        .json(&json!({"subject":"alice","version":"v1","include_visitors":false,
            "expires_at": 4_102_444_800_i64}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);

    // 放行第二块：流已被中止，客户端再也读不到它。
    f.upstream.release.notify_one();
    let tail = tokio::time::timeout(Duration::from_secs(5), response.chunk())
        .await
        .expect("撤权后响应流必须结束");
    // 流或被正常关闭（None），或因中止断开（Err）；两者都不得再送来第二块。
    if let Ok(Some(chunk)) = tail {
        assert!(
            !String::from_utf8_lossy(&chunk).contains("second"),
            "撤权后不得下发剩余内容"
        );
    }
    // 撤权后的会话不再可用。
    assert_eq!(
        f.request("GET", &alice, "/backend-api/models")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

/// 旧归属一次性回填：唯一可映射的行被认领，访客行保持未认领，且只做一次。
#[tokio::test]
async fn legacy_ownership_backfill_claims_mappable_rows_once() {
    let rows = vec![
        (
            "fixture@example.invalid".to_owned(),
            LEGACY_CONVERSATION.to_owned(),
            "alice".to_owned(),
        ),
        (
            "fixture@example.invalid".to_owned(),
            "22222222-3333-4444-5555-666666666666".to_owned(),
            "free_account:visitor-1".to_owned(),
        ),
        (
            "fixture@example.invalid".to_owned(),
            "33333333-4444-5555-6666-777777777777".to_owned(),
            "carol".to_owned(),
        ),
    ];
    let f = Fixture::with_seed(Some(&rows), false).await;
    let alice = f.login("alice", "3").await;

    let scoped = format!("/backend-api/conversation/{LEGACY_CONVERSATION}");
    assert_eq!(
        f.request("GET", &alice, &scoped).send().await.unwrap().status(),
        StatusCode::OK,
        "可唯一映射的旧会话必须已被认领"
    );
    // 访客主体与无法映射的用户名都保持未认领：任何人（含 alice）都读不到。
    for unclaimed in [
        "/backend-api/conversation/22222222-3333-4444-5555-666666666666",
        "/backend-api/conversation/33333333-4444-5555-6666-777777777777",
    ] {
        assert_eq!(
            f.request("GET", &alice, unclaimed).send().await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "{unclaimed} 不应被认领"
        );
    }

    // 恰好一行被认领，且回填标记已写入。
    {
        let db = mirror_gateway::storage::Database::open(&f.database, KEY).unwrap();
        let claimed: i64 = db
            .conn
            .query_row("SELECT count(*) FROM acl_resources", [], |row| row.get(0))
            .unwrap();
        assert_eq!(claimed, 1, "只有可唯一映射的旧行能被认领");
        assert!(
            db.get_setting("acl_backfill_v1").unwrap().is_some(),
            "回填标记必须已写入，避免每次启动重新回填"
        );
    }

    // 第二次启动读到标记后不再调用映射端点、也不再写入归属。
    let before = f.mapping_calls.load(Ordering::SeqCst);
    let second = server::router(f.config()).await.unwrap();
    drop(second);
    assert_eq!(
        f.mapping_calls.load(Ordering::SeqCst),
        before,
        "回填只做一次"
    );
    let db = mirror_gateway::storage::Database::open(&f.database, KEY).unwrap();
    let claimed: i64 = db
        .conn
        .query_row("SELECT count(*) FROM acl_resources", [], |row| row.get(0))
        .unwrap();
    assert_eq!(claimed, 1);
}

/// 未登记会话清单：上游清单减去已登记 id；凭据按 chat 路径注入；
/// 首轮命中 CF 挑战时刷新一次并只重放一次（上游计数严格为 2）。
#[tokio::test]
async fn unclaimed_conversation_list_subtracts_registered_ids_and_retries_once() {
    let f = Fixture::with_seed(None, true).await;
    f.seed_pool_account(
        3,
        "synthetic-pool-access",
        None,
        r#"[{"name":"pool_cookie","value":"PV"},{"name":"oai-did","value":"device-fixture"}]"#,
    );
    let _alice = f.login("alice", "3").await;
    let claimed = f
        .acl(
            "/api/acl/claim",
            json!({
                "account_id":"3",
                "resource_type":"conversation",
                "upstream_id":CONVERSATION,
                "owner_user_id":"11",
            }),
        )
        .await;
    assert_eq!(claimed.status(), StatusCode::OK);
    f.clear_calls();
    f.upstream.challenge.store(1, Ordering::SeqCst);

    let response = f
        .acl_get("/api/acl/unclaimed-conversations?account_id=3", "root")
        .await;
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["account_id"], "3");
    assert_eq!(body["page"], 0);
    assert_eq!(body["page_size"], 50);
    assert_eq!(body["upstream_total"], 2);
    assert_eq!(body["has_more"], false);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "已登记的会话必须被差集掉: {body}");
    assert_eq!(items[0]["upstream_id"], UNREGISTERED);
    assert_eq!(items[0]["title"], "未认领会话");

    let calls = f.calls("/backend-api/conversations");
    assert_eq!(calls.len(), 2, "挑战后必须只重放一次: {calls:?}");
    assert_eq!(calls[0]["authorization"], "Bearer synthetic-pool-access");
    let first = calls[0]["cookie"].as_str().unwrap();
    let retried = calls[1]["cookie"].as_str().unwrap();
    assert!(retried.contains("pool_cookie=PV"), "{retried}");
    assert!(first.contains("pool_cookie=PV"), "{first}");
    // 设备身份与会话 chat 路径同形：cookie 与请求头都带同一个 oai-did。
    assert!(retried.contains("oai-did=device-fixture"), "{retried}");
    assert_eq!(calls[0]["device"], "device-fixture", "{}", calls[0]);
    assert_eq!(calls[1]["device"], "device-fixture", "{}", calls[1]);
    // 启动预热下发 CF-FIXTURE-1；挑战后的重放必须换成 cfbypass 新发的那一份。
    assert!(
        first.contains("cf_clearance=CF-FIXTURE-1"),
        "{first}"
    );
    assert!(
        retried.contains("cf_clearance=CF-FIXTURE-2"),
        "重放必须使用刷新后的 CF cookies: {retried}"
    );
}

/// 号池账号只有 SessionToken 时按登录同一条链路换取一次，
/// 并把合成的会话 Cookie 同时发给换取与清单两个上游请求。
#[tokio::test]
async fn unclaimed_conversation_list_exchanges_the_session_token_once() {
    let f = Fixture::with_seed(None, false).await;
    f.seed_pool_account(3, "", Some("synthetic-pool-session"), "[]");

    let response = f
        .acl_get("/api/acl/unclaimed-conversations?account_id=3", "root")
        .await;
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");

    let exchanges = f.calls("/api/auth/session");
    assert_eq!(exchanges.len(), 1, "换取只做一次: {exchanges:?}");
    assert!(
        exchanges[0]["cookie"]
            .as_str()
            .unwrap()
            .contains("__Secure-next-auth.session-token=synthetic-pool-session"),
        "{exchanges:?}"
    );
    let calls = f.calls("/backend-api/conversations");
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0]["authorization"], "Bearer synthetic-exchange-alice");
    assert!(
        calls[0]["cookie"]
            .as_str()
            .unwrap()
            .contains("__Secure-next-auth.session-token=synthetic-pool-session"),
        "{calls:?}"
    );
}

/// 管理端鉴权与输入边界：服务密钥本身不是管理员，越界与未知账号都在本地拒绝，
/// 且这些失败路径一律不接触上游。
#[tokio::test]
async fn unclaimed_conversation_list_is_admin_only_and_bounded() {
    let f = Fixture::with_seed(None, false).await;
    f.seed_pool_account(3, "synthetic-pool-access", None, "[]");
    f.clear_calls();
    let path = "/api/acl/unclaimed-conversations?account_id=3";
    // 服务密钥 + 无操作者身份：中间件放行，管理员判定必须拒绝。
    let anonymous = f
        .client
        .get(format!("{}{path}", f.base))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::FORBIDDEN);
    // 非管理员主体（Django 桩里只有 root 是管理员）。
    let denied = f.acl_get(path, "alice").await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(denied.json::<Value>().await.unwrap()["code"], "acl_admin_required");

    for (query, status, code) in [
        ("account_id=3&page=21", StatusCode::BAD_REQUEST, "acl_invalid_input"),
        ("account_id=abc", StatusCode::BAD_REQUEST, "acl_invalid_input"),
        ("account_id=99", StatusCode::NOT_FOUND, "acl_not_found"),
    ] {
        let response = f
            .acl_get(&format!("/api/acl/unclaimed-conversations?{query}"), "root")
            .await;
        assert_eq!(response.status(), status, "{query}");
        assert_eq!(response.json::<Value>().await.unwrap()["code"], code, "{query}");
    }

    // 上游信封变更（缺 items/total）：必须报错，不能当成「没有未登记会话」。
    f.upstream.malformed_list.store(true, Ordering::SeqCst);
    let response = f.acl_get(path, "root").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.json::<Value>().await.unwrap()["code"],
        "acl_upstream_unavailable"
    );
    f.upstream.malformed_list.store(false, Ordering::SeqCst);
    // 上面这一例是唯一会真的接触上游的失败路径，清空计数再验证凭据缺失分支。
    f.clear_calls();

    // 账号行存在但两种凭据都为空：不得用空凭据去撞上游。
    {
        let db = mirror_gateway::storage::Database::open(&f.database, KEY).unwrap();
        db.conn
            .execute(
                "UPDATE chatgpt_accounts SET access_token='', session_token=NULL WHERE id=3",
                [],
            )
            .unwrap();
    }
    let response = f.acl_get(path, "root").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.json::<Value>().await.unwrap()["code"],
        "acl_account_credentials_invalid"
    );
    assert!(
        f.calls("/backend-api/conversations").is_empty(),
        "所有拒绝路径都不得接触上游"
    );
}

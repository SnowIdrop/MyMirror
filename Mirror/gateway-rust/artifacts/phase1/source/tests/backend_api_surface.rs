//! 缺口 1 的合成回环回归：已登录业务面读写、会话归属登记与隔离、
//! 创建/续聊的方法与重放边界、实时通道的 HTTP 与升级分支。
//! 全部为本机 fixture，不接触真实 chatgpt.com，也不使用任何真实账号。
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
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const ADMIN: &str = "surface-fixture-admin-secret";
const KEY: &str = "surface-fixture-encryption-key-00001";
/// 上游桩返回的会话 id（形态与真实创建响应一致）。
const CONVERSATION: &str = "6ab350c7-5d3c-83ea-be1f-a87b536c1c6c";

type Events = Arc<Mutex<Vec<Value>>>;

/// 镜像用户名 → 稳定 user_id（真实 Django 为 `User.pk`）；两个用户必须不同，
/// 否则 ACL 会把 Bob 当成 Alice。
fn fixture_user_id(subject: &str) -> &'static str {
    match subject {
        "alice" => "11",
        "bob" => "12",
        _ => "13",
    }
}

#[derive(Default)]
struct Upstream {
    events: Events,
    /// 剩余挑战次数：`usize::MAX` 表示一直挑战。
    challenges_left: AtomicUsize,
    fetches: AtomicUsize,
    /// 会话创建响应是否按分块 SSE 返回（覆盖跨块扫描）。
    hold_creation: std::sync::atomic::AtomicBool,
}

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

impl Upstream {
    fn take_challenge(&self) -> bool {
        let left = self.challenges_left.load(Ordering::SeqCst);
        if left == usize::MAX {
            return true;
        }
        if left == 0 {
            return false;
        }
        self.challenges_left.store(left - 1, Ordering::SeqCst);
        true
    }
}

/// 上游聊天桩：记录请求，按路径给出最小可用响应。
async fn chat_upstream(state: Arc<Upstream>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.unwrap();
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
        "query": parts.uri.query(),
        "cookie": header("cookie"),
        "authorization": header("authorization"),
        "upgrade": header("upgrade"),
        "body": String::from_utf8_lossy(&body),
    }));
    if state.take_challenge() {
        return (
            StatusCode::FORBIDDEN,
            [("cf-mitigated", "challenge")],
            "<html>Just a moment...</html>",
        )
            .into_response();
    }
    let path = parts.uri.path();
    if path.ends_with("/conversation") && parts.method == axum::http::Method::POST {
        if state.hold_creation.load(Ordering::SeqCst) {
            // 分块 SSE：会话 id 与后续增量分开到达，覆盖跨块扫描。
            let first = format!("event: delta\ndata: {{\"conversation_id\":\"{}\"}}\n\n", &CONVERSATION[..20]);
            let second = format!(
                "data: {{\"conversation_id\":\"{}\",\"v\":\"done\"}}\n\n",
                CONVERSATION
            );
            let stream = futures_util::stream::iter([
                Ok::<_, std::io::Error>(bytes::Bytes::from(first)),
                Ok(bytes::Bytes::from(second)),
            ]);
            return (
                [("content-type", "text/event-stream")],
                axum::body::Body::from_stream(stream),
            )
                .into_response();
        }
        return axum::Json(json!({"conversation_id":CONVERSATION})).into_response();
    }
    if path == "/backend-api/conversations" {
        return axum::Json(json!({"items":[{"id":CONVERSATION,"title":"fixture"}],"total":1}))
            .into_response();
    }
    if path == "/backend-api/me" {
        return axum::Json(json!({"email":"fixture@example.invalid"})).into_response();
    }
    if path.starts_with("/realtime/") {
        return (
            [("content-type", "text/event-stream")],
            "event: ping\ndata: {}\n\n",
        )
            .into_response();
    }
    axum::Json(json!({"path":path})).into_response()
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
            serve(Router::new().fallback(move |request: Request| {
                chat_upstream(state.clone(), request)
            }))
            .await
        };
        let cfbypass_url = {
            let state = upstream.clone();
            serve(Router::new().fallback(move |_request: Request| {
                let state = state.clone();
                async move {
                    let fetch = state.fetches.fetch_add(1, Ordering::SeqCst) + 1;
                    axum::Json(json!({
                        "user_agent": "fixture-agent",
                        "cookies": [{"name":"cf_clearance","value":format!("CF-{fetch}")}],
                    }))
                    .into_response()
                }
            }))
            .await
        };
        let django_url = {
            serve(Router::new().fallback(|request: Request| async move {
                if request.uri().path() == "/0x/user/gateway-authorization" {
                    // 身份三字段 + subject 恒来自本响应：subject 回显请求里的 subject，
                    // 与真实 Django 的可信响应同形。
                    let (_, body) = request.into_parts();
                    let body = to_bytes(body, 64 * 1024).await.unwrap();
                    let input: Value = serde_json::from_slice(&body).unwrap_or_default();
                    let subject = input["subject"].as_str().unwrap_or("");
                    return axum::Json(json!({
                        "active": true,
                        "version": "v1",
                        // 镜像用户各自的稳定 user_id（真实 Django 为 User.pk）。
                        "user_id": fixture_user_id(subject),
                        "is_admin": false,
                        "principal_kind": "user",
                        "subject": subject,
                        // 固定远期 Unix 秒：fixture 不依赖运行时钟。
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
            // 这些用例不经过 WS 桥接：给一个不会用到的回环 WS 基址即可。
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            cfbypass: Some(loopback_url(&cfbypass_url.0).unwrap()),
            timeout: Duration::from_secs(5),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
        };
        let app = server::router(config).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            _dir: dir,
            tasks: vec![cfbypass_url.1, django_url.1, chat_url.1, gateway],
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

    /// 指定镜像用户登录，返回 mirror_token。
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

    fn request(&self, method: &str, token: &str, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.base);
        let builder = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "DELETE" => self.client.delete(url),
            other => panic!("fixture 不支持的方法 {other}"),
        };
        // 空 token 表示不带镜像会话：显式留空 x-mirror-token 会被父层当成空值。
        if token.is_empty() {
            builder
        } else {
            builder.header("x-mirror-token", token)
        }
    }

    /// 创建会话并返回响应，同时清空事件，便于断言创建之后的上游调用。
    async fn create(&self, token: &str) -> reqwest::Response {
        self.request("POST", token, "/backend-api/f/conversation")
            .json(&json!({"model":"fixture-model","messages":[]}))
            .send()
            .await
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

    fn all_calls(&self) -> Vec<Value> {
        self.upstream.events.lock().unwrap().clone()
    }

    fn clear_calls(&self) {
        self.upstream.events.lock().unwrap().clear();
    }
}

/// 创建会话后，创建者能在列表里看到它；同账号的另一个镜像用户看不到。
#[tokio::test]
async fn created_conversations_are_owned_by_the_creating_mirror_user() {
    let f = Fixture::new().await;
    let alice = f.login("alice").await;
    let bob = f.login("bob").await;
    f.clear_calls();

    let created = f.create(&alice).await;
    assert_eq!(created.status(), StatusCode::OK);
    assert!(created.text().await.unwrap().contains(CONVERSATION));
    assert_eq!(f.calls("/backend-api/f/conversation").len(), 1);

    for (token, expected) in [(&alice, 1), (&bob, 0)] {
        let listed = f
            .request("GET", token, "/backend-api/conversations")
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let body: Value = listed.json().await.unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), expected);
        assert_eq!(body["total"], expected);
    }
}

/// 归属判定在转发前完成：他人会话与未知会话一律 404，且不接触上游。
#[tokio::test]
async fn unowned_and_unknown_conversations_are_refused_without_touching_upstream() {
    let f = Fixture::new().await;
    let alice = f.login("alice").await;
    let bob = f.login("bob").await;
    assert_eq!(f.create(&alice).await.status(), StatusCode::OK);
    f.clear_calls();

    let scoped = format!("/backend-api/conversation/{CONVERSATION}");
    let unowned = "/backend-api/conversation/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    for path in [scoped.as_str(), unowned] {
        let response = f.request("GET", &bob, path).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["message"], "会话不存在或不属于当前用户", "{path}");
    }
    // 续聊请求体里的会话 id 同样先判定归属。
    let continuation = f
        .request("POST", &bob, "/backend-api/conversation")
        .json(&json!({"conversation_id":CONVERSATION,"messages":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(continuation.status(), StatusCode::NOT_FOUND);
    assert!(
        f.all_calls().is_empty(),
        "归属拒绝不得接触上游：{:?}",
        f.all_calls()
    );

    // 创建者本人可以直读与续聊。
    for method in ["GET", "POST"] {
        let request = f.request(method, &alice, &scoped);
        let response = if method == "POST" {
            request.json(&json!({"messages":[]})).send().await.unwrap()
        } else {
            request.send().await.unwrap()
        };
        assert_eq!(response.status(), StatusCode::OK, "{method} {scoped}");
    }
    assert_eq!(f.calls(&scoped).len(), 2);
}

/// 创建响应里的会话 id 跨块到达时，仍必须在把该块交给客户端之前登记归属。
#[tokio::test]
async fn streamed_creation_registers_ownership_before_the_client_sees_the_id() {
    let f = Fixture::new().await;
    let alice = f.login("alice").await;
    f.upstream
        .hold_creation
        .store(true, Ordering::SeqCst);
    f.clear_calls();

    let created = f.create(&alice).await;
    assert_eq!(created.status(), StatusCode::OK);
    let body = created.text().await.unwrap();
    assert!(body.contains(CONVERSATION), "{body}");

    // 客户端已经看到 id，此时直读必须已经通过归属判定（无需等待流结束）。
    let scoped = format!("/backend-api/conversation/{CONVERSATION}");
    let read = f.request("GET", &alice, &scoped).send().await.unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    // 同账号的另一个用户依旧不可见。
    let bob = f.login("bob").await;
    assert_eq!(
        f.request("GET", &bob, &scoped).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

/// 已登录业务面按方法语义转发：POST 生成类请求命中挑战也不重放，
/// GET 读取命中挑战则刷新 CF 并重放一次。
#[tokio::test]
async fn generation_requests_are_never_replayed_while_reads_refresh_cloudflare() {
    let f = Fixture::new().await;
    let alice = f.login("alice").await;

    // POST 创建：首轮挑战，严格一次上游调用。
    f.upstream.challenges_left.store(1, Ordering::SeqCst);
    f.clear_calls();
    let created = f.create(&alice).await;
    assert_eq!(created.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        f.calls("/backend-api/f/conversation").len(),
        1,
        "生成类请求不得重放"
    );

    // GET 读取：首轮挑战后刷新并重放一次。
    let fetches_before = f.upstream.fetches.load(Ordering::SeqCst);
    f.upstream.challenges_left.store(1, Ordering::SeqCst);
    f.clear_calls();
    let read = f
        .request("GET", &alice, "/backend-api/models")
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    let attempts = f.calls("/backend-api/models");
    assert_eq!(attempts.len(), 2, "GET 必须重放一次");
    assert!(f.upstream.fetches.load(Ordering::SeqCst) > fetches_before);
    // 重放沿用会话凭据，CF cookies 在会话 cookies 之后。
    for attempt in &attempts {
        assert_eq!(attempt["authorization"], "Bearer synthetic-access-alice");
        let cookie = attempt["cookie"].as_str().unwrap();
        assert!(cookie.starts_with("probe_extra=alice"), "{cookie}");
    }
    // 上一次 POST 挑战已失效 CF 缓存：重放必须使用刷新后的 cf_clearance。
    let replayed = attempts[1]["cookie"].as_str().unwrap();
    assert!(replayed.contains("cf_clearance="), "{replayed}");
}

/// 实时通道：普通 GET/SSE 走聊天上游并带凭据；WebSocket 升级显式拒绝且不触上游。
#[tokio::test]
async fn realtime_http_is_proxied_and_upgrade_is_refused() {
    let f = Fixture::new().await;
    let alice = f.login("alice").await;
    f.clear_calls();

    let response = f
        .request("GET", &alice, "/realtime/session")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let calls = f.calls("/realtime/session");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["authorization"], "Bearer synthetic-access-alice");
    assert!(calls[0]["cookie"].as_str().unwrap().contains("probe_extra=alice"));

    f.clear_calls();
    let upgrade = f
        .request("GET", &alice, "/realtime/session")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(upgrade.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = upgrade.json().await.unwrap();
    assert_eq!(body["message"], "实时通道升级未开放");
    assert!(f.all_calls().is_empty(), "升级请求不得接触上游");
}

/// `/api/*` 未实现路径保持本地 404，且文案与上游无关。
#[tokio::test]
async fn unimplemented_api_paths_stay_local() {
    let f = Fixture::new().await;
    for path in ["/api/livekit/token", "/api/unknown-thing"] {
        let response = f.client.get(format!("{}{path}", f.base)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["message"], "本地未实现的 /api 路径", "{path}");
    }
    assert!(f.all_calls().is_empty());
}

/// 无镜像会话时已登录业务面继续 401，不泄露上游行为。
#[tokio::test]
async fn backend_api_requires_a_mirror_session() {
    let f = Fixture::new().await;
    for (method, path) in [
        ("GET", "/backend-api/models"),
        ("POST", "/backend-api/f/conversation"),
        ("GET", "/realtime/session"),
    ] {
        let response = f.request(method, "", path).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    assert!(f.all_calls().is_empty());
}

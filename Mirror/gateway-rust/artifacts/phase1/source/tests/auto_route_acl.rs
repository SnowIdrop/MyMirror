//! 未显式分类路径（Auto）的合成回环回归。
//!
//! 上游前端新增路由时不再需要改网关代码：字面量路径直接放行，带资源 id 的路径
//! 按 id 判权，写方法的成功响应按响应 id 登记归属，JSON 正文按受众裁剪。
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
    sync::{Arc, Mutex},
    time::Duration,
};

const ADMIN: &str = "auto-route-admin-secret";
const KEY: &str = "auto-route-encryption-key-0000001";
/// 未登记前缀（`new-surface` 不在账号级前缀表里）：所有用例都走 id 兜底路径。
const SURFACE: &str = "/backend-api/new-surface";
/// alice 通过创建端点登记的会话。
const MINE: &str = "6ab350c7-5d3c-83ea-be1f-a87b536c1c6c";
/// 管理员认领给 bob 的会话：alice 必须看不到，也不得因此接触上游。
const OTHERS: &str = "11111111-2222-3333-4444-555555555555";
/// Auto 路径的写响应返回的新会话：交出正文之前就要登记给调用者。
const CREATED: &str = "22222222-3333-4444-5555-666666666666";
/// 账号下从未登记的 id：保持「未登记资源不可用」。
const UNKNOWN: &str = "33333333-4444-5555-6666-777777777777";
/// Auto JSON 过滤上限（`proxy::ACL_JSON_LIMIT`）之外的正文字节数。
const OVERSIZED: usize = 9 * 1024 * 1024;

type Events = Arc<Mutex<Vec<Value>>>;

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

async fn chat_upstream(events: Events, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.unwrap();
    events.lock().unwrap().push(json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "query": parts.uri.query(),
        "body": String::from_utf8_lossy(&body),
    }));
    match (parts.method.as_str(), parts.uri.path()) {
        ("GET", "/backend-api/me") => {
            axum::Json(json!({"email":"fixture@example.invalid","name":"Fixture"})).into_response()
        }
        // 创建端点：走六族规则登记 MINE，后面的 id 判权才有「自己的会话」。
        ("POST", "/backend-api/f/conversation") => {
            axum::Json(json!({"conversation_id": MINE})).into_response()
        }
        ("GET", "/backend-api/new-surface/literal") => {
            axum::Json(json!({"ok": true})).into_response()
        }
        ("POST", "/backend-api/new-surface/create") => {
            axum::Json(json!({"conversation_id": CREATED})).into_response()
        }
        ("GET", "/backend-api/new-surface/list") => axum::Json(json!({
            "items": [{"conversation_id": MINE}, {"conversation_id": OTHERS}],
            "total": 2,
        }))
        .into_response(),
        ("GET", "/backend-api/new-surface/single") => {
            axum::Json(json!({"conversation_id": OTHERS})).into_response()
        }
        ("GET", "/backend-api/new-surface/huge") => {
            axum::Json(json!({"blob": "x".repeat(OVERSIZED)})).into_response()
        }
        ("GET", "/backend-api/new-surface/stream") => {
            let stream = futures_util::stream::unfold(0u8, |stage| async move {
                match stage {
                    0 => Some((Ok::<_, std::io::Error>("data: first\n\n".to_owned()), 1u8)),
                    1 => Some((Ok("data: second\n\n".to_owned()), 2u8)),
                    _ => None,
                }
            });
            (
                [("content-type", "text/event-stream")],
                axum::body::Body::from_stream(stream),
            )
                .into_response()
        }
        // 其余 `/new-surface/<id>` 形态只回 id 回显，用于断言「谁的会话都能读」。
        _ => axum::Json(json!({"path": parts.uri.path()})).into_response(),
    }
}

/// Django 桩：`root` 是管理员、`free_account:*` 是访客，其余按用户名给稳定 user_id。
fn django_router() -> Router {
    Router::new().fallback(|request: Request| async move {
        let path = request.uri().path().to_owned();
        let (_, body) = request.into_parts();
        let body = to_bytes(body, 64 * 1024).await.unwrap();
        if path == "/0x/user/gateway-authorization" {
            let input: Value = serde_json::from_slice(&body).unwrap_or_default();
            let subject = input["subject"].as_str().unwrap_or("").to_owned();
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
                "is_admin": subject == "root",
                "principal_kind": if subject.starts_with("free_account:") {"visitor"} else {"user"},
                "subject": subject,
                "expires_at": 4_102_444_800_i64,
            }))
            .into_response();
        }
        StatusCode::NOT_FOUND.into_response()
    })
}

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    base: String,
    client: reqwest::Client,
    events: Events,
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
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let chat = {
            let events = events.clone();
            serve(Router::new().fallback(move |request: Request| {
                chat_upstream(events.clone(), request)
            }))
            .await
        };
        let django = serve(django_router()).await;
        let dir = tempfile::tempdir().unwrap();
        let app = server::router(Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: dir.path().join("db.sqlite"),
            secret: ADMIN.into(),
            key: KEY.into(),
            django: loopback_url(&django.0).unwrap(),
            upstream: loopback_url(&chat.0).unwrap(),
            // 这些用例不经过 WS 桥接：给一个不会用到的回环 WS 基址即可。
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            cfbypass: None,
            timeout: Duration::from_secs(20),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        Self {
            _dir: dir,
            tasks: vec![chat.1, django.1, gateway],
            base,
            client,
            events,
        }
    }

    async fn login(&self, user: &str, account_id: &str) -> String {
        let response = self
            .client
            .post(format!("{}/api/login", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({
                "user_name": user,
                "access_token": format!("synthetic-access-{user}"),
                "authorization": "signature-v1",
                "login_mode": "api",
                "isolated_session": true,
                "mcp_isolation": true,
                "skills_isolation": true,
                "model_isolation": true,
                "daily_quota": 20,
                "monthly_quota": 100,
                "model_allowed_ids": ["fixture-model"],
                "model_rate_limits": {},
                "limits": [],
                "mcp_allowed_ids": [],
                "skills_allowed_ids": [],
                "chatgpt_account_id": account_id,
                "extra_cookies": [],
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

    fn calls(&self, path: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event["path"].as_str() == Some(path))
            .count()
    }

    /// 管理端操作：服务密钥 + 操作者 `authorization`/`subject`（`root` 是管理员）。
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

    /// 审计行（管理员只读）：`resource_type = route` 的未分类路径留痕。
    async fn route_audit(&self, path: &str) -> Vec<Value> {
        let response = self
            .client
            .get(format!("{}/api/acl/audit?after_id=0&limit=200", self.base))
            .bearer_auth(ADMIN)
            .header("authorization", "signature-v1")
            .header("subject", "root")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        body["audit"]
            .as_array()
            .expect("审计响应必须有 audit 数组")
            .iter()
            .filter(|row| row["resource_type"] == "route")
            .filter(|row| row["upstream_id"].as_str() == Some(path))
            .cloned()
            .collect()
    }

    /// 让 alice 通过创建端点登记 MINE，并把 OTHERS 认领给 bob（user_id 12）。
    async fn seed(&self, alice: &str) {
        assert_eq!(
            self.request("POST", alice, "/backend-api/f/conversation")
                .json(&json!({"action":"next"}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let claimed = self
            .acl(
                "/api/acl/claim",
                json!({
                    "account_id":"3",
                    "resource_type":"conversation",
                    "upstream_id":OTHERS,
                    "owner_user_id":"12",
                }),
            )
            .await;
        assert_eq!(claimed.status(), StatusCode::OK);
        self.events.lock().unwrap().clear();
    }
}

/// 前端新增的字面量路由直接放行；同一路径重复命中只在第一次写审计。
#[tokio::test]
async fn literal_new_route_passes_and_records_one_audit_row() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    let path = format!("{SURFACE}/literal");
    for _ in 0..2 {
        let response = f.request("GET", &alice, &path).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["ok"], true);
    }
    assert_eq!(f.calls(&path), 2, "放行的路径必须真的转发上游");
    let rows = f.route_audit(&format!("GET {path}")).await;
    assert_eq!(rows.len(), 1, "同一路径只记一次：{rows:?}");
    assert_eq!(rows[0]["action"], "route_auto_pass");
    assert_eq!(rows[0]["account_id"], "3");
}

/// 自己的会话 id 放行；他人会话 404；未登记 id 503；两者都不接触上游。
#[tokio::test]
async fn owned_id_passes_foreign_and_unknown_ids_are_refused_before_upstream() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    f.seed(&alice).await;

    let mine = format!("{SURFACE}/with-id/{MINE}");
    let owned = f.request("GET", &alice, &mine).send().await.unwrap();
    assert_eq!(owned.status(), StatusCode::OK);
    assert_eq!(f.calls(&mine), 1);

    let foreign = format!("{SURFACE}/with-id/{OTHERS}");
    let denied = f.request("GET", &alice, &foreign).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    assert_eq!(denied.json::<Value>().await.unwrap()["code"], "acl_not_found");
    assert_eq!(f.calls(&foreign), 0, "他人资源的拒绝不得接触上游");

    let unknown = format!("{SURFACE}/with-id/{UNKNOWN}");
    let unresolved = f.request("GET", &alice, &unknown).send().await.unwrap();
    assert_eq!(unresolved.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        unresolved.json::<Value>().await.unwrap()["code"],
        "acl_unclassified_id"
    );
    assert_eq!(f.calls(&unknown), 0, "未登记资源同样不接触上游");

    for (path, expected) in [
        (format!("GET {foreign}"), "route_auto_denied"),
        (format!("GET {unknown}"), "route_auto_denied"),
    ] {
        assert_eq!(f.route_audit(&path).await[0]["action"], expected);
    }
}

/// 写方法的成功响应：新资源在正文交给客户端之前就登记给调用者。
#[tokio::test]
async fn write_response_claims_the_new_resource_before_it_is_delivered() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    let bob = f.login("bob", "3").await;
    f.events.lock().unwrap().clear();

    let created = f
        .request("POST", &alice, &format!("{SURFACE}/create"))
        .json(&json!({"prompt":"hi"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    assert!(created.text().await.unwrap().contains(CREATED));

    let scoped = format!("{SURFACE}/with-id/{CREATED}");
    assert_eq!(
        f.request("GET", &alice, &scoped).send().await.unwrap().status(),
        StatusCode::OK,
        "创建者必须立刻可读新资源"
    );
    let before = f.calls(&scoped);
    let denied = f.request("GET", &bob, &scoped).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::NOT_FOUND, "同账号他人不可见");
    assert_eq!(f.calls(&scoped), before, "拒绝不得接触上游");
}

/// 集合响应按受众裁剪并同步 `total`；顶层单对象含他人资源时整体拒绝。
#[tokio::test]
async fn collection_entries_are_filtered_and_foreign_objects_are_refused() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    let bob = f.login("bob", "3").await;
    f.seed(&alice).await;

    let listed = f
        .request("GET", &alice, &format!("{SURFACE}/list"))
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let body: Value = listed.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "他人条目必须被裁掉：{body}");
    assert_eq!(items[0]["conversation_id"], MINE);
    assert_eq!(body["total"], 1, "已知信封的总数必须同步");

    // bob 看不到 OTHERS 之外的东西：他自己是这条会话的属主，列表保留它。
    let bob_listed = f
        .request("GET", &bob, &format!("{SURFACE}/list"))
        .send()
        .await
        .unwrap();
    let bob_body: Value = bob_listed.json().await.unwrap();
    assert_eq!(bob_body["items"].as_array().unwrap().len(), 1);
    assert_eq!(bob_body["items"][0]["conversation_id"], OTHERS);

    let single = f
        .request("GET", &alice, &format!("{SURFACE}/single"))
        .send()
        .await
        .unwrap();
    assert_eq!(single.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        single.json::<Value>().await.unwrap()["code"],
        "acl_foreign_resource_in_response"
    );
}

/// 超过过滤上限的 JSON 不做部分过滤：整体拒绝并给出可行动文案。
#[tokio::test]
async fn oversized_json_is_refused_instead_of_partially_filtered() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    let response = f
        .request("GET", &alice, &format!("{SURFACE}/huge"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "acl_response_too_large");
    assert!(
        body["message"].as_str().unwrap().contains("账号级"),
        "文案必须指出出路：{body}"
    );
}

/// 流式正文无法缓冲：原样透传，不做裁剪（首次命中照常留痕）。
#[tokio::test]
async fn streaming_body_passes_through_unchanged() {
    let f = Fixture::new().await;
    let alice = f.login("alice", "3").await;
    let path = format!("{SURFACE}/stream");
    let response = f.request("GET", &alice, &path).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/event-stream",
        "流式响应的内容类型必须保持"
    );
    assert_eq!(
        response.text().await.unwrap(),
        "data: first\n\ndata: second\n\n"
    );
    assert_eq!(f.route_audit(&format!("GET {path}")).await.len(), 1);
}

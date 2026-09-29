// Author: MingTea. All listeners bind numeric loopback; all credentials are synthetic.
//! 管理端录入上游账号（`POST /api/get-user-info`）的合成回环回归：
//! SessionToken（NextAuth JWE）先换取再校验、AccessToken（JWS）直接校验、
//! 非 JWT 形态沿用原版行为走会话换取，并锁定 Django `ChatgptAccount.save_data`
//! 直接读取的响应信封（`user_info.email` / `plan_type` / `access_token` / `session_token`）。
//! 不使用任何真实账号、令牌或上游数据。
use axum::{
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

const ADMIN: &str = "token-import-fixture-admin-secret-01";
const KEY: &str = "token-import-fixture-encryption-key-1";
/// 真实 AccessToken 是 JWS（3 段）；SessionToken 是 NextAuth 的 JWE（5 段、第 2 段为空）。
/// 这里只保留段数与 `eyJ` 头，内容为合成值。
const ACCESS: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.fixture-signature";
const SESSION: &str =
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..fixture-iv.fixture-ciphertext.fixture-tag";

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

#[derive(Default)]
struct Seen {
    calls: Mutex<Vec<Value>>,
}

/// 上游桩：`/api/auth/session` 只认合成的 SessionToken（其它值回空对象，对应原版
/// 「session_token 无法换取 access_token」），`me` 与 `accounts/check` 固定成功。
async fn upstream(seen: Arc<Seen>, request: Request) -> Response {
    let (parts, _) = request.into_parts();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let cookie = header("cookie");
    seen.calls.lock().unwrap().push(json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "cookie": cookie,
        "authorization": header("authorization"),
    }));
    match parts.uri.path() {
        "/api/auth/session" => {
            if cookie.contains(SESSION) {
                axum::Json(json!({"accessToken": "exchanged-access-token"})).into_response()
            } else {
                axum::Json(json!({})).into_response()
            }
        }
        "/backend-api/me" => axum::Json(
            json!({"email": "fixture@example.invalid", "id": "fixture", "name": "Fixture"}),
        )
        .into_response(),
        "/backend-api/accounts/check/v4-2023-04-27" => axum::Json(
            json!({"accounts": {"default": {"account": {"plan_type": "plus"}}}}),
        )
        .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    base: String,
    client: reqwest::Client,
    seen: Arc<Seen>,
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
        let seen = Arc::new(Seen::default());
        let upstream_url = {
            let seen = seen.clone();
            let router = Router::new().fallback(move |request: Request| upstream(seen.clone(), request));
            serve(router).await
        };
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: dir.path().join("db.sqlite"),
            secret: ADMIN.into(),
            key: KEY.into(),
            django: loopback_url(&upstream_url.0).unwrap(),
            upstream: loopback_url(&upstream_url.0).unwrap(),
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
        };
        let app = server::router(config).await.unwrap();
        let gateway = serve(app).await;
        let base = gateway.0;
        // 启动期的旧归属回填会打同一个桩（`/0x/user/gateway-acl-mapping`）；
        // 清掉它，让断言只覆盖本次录入发出的上游调用。
        seen.calls.lock().unwrap().clear();
        Self {
            _dir: dir,
            tasks: vec![upstream_url.1, gateway.1],
            base,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            seen,
        }
    }

    /// 管理端录入调用：与 Django `/0x/chatgpt` 添加按钮发出的请求一致。
    async fn import(&self, token: &str) -> (StatusCode, Value) {
        let response = self
            .client
            .post(format!("{}/api/get-user-info", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({"chatgpt_token": token}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap())
    }

    fn calls(&self) -> Vec<Value> {
        self.seen.calls.lock().unwrap().clone()
    }

    fn paths(&self) -> Vec<String> {
        self.calls()
            .iter()
            .filter_map(|call| call["path"].as_str().map(str::to_owned))
            .collect()
    }
}

#[tokio::test]
async fn session_token_import_exchanges_then_returns_the_django_envelope() {
    let f = Fixture::new().await;
    let (status, body) = f.import(SESSION).await;
    assert_eq!(status, StatusCode::OK);
    // Django `ChatgptAccount.save_data` 直接读这些键；缺 user_info/access_token 会抛 KeyError。
    assert_eq!(body["user_info"]["email"], json!("fixture@example.invalid"));
    assert_eq!(body["user_info"]["plan_type"], json!("plus"));
    assert_eq!(body["access_token"], json!("exchanged-access-token"));
    assert_eq!(body["session_token"], json!(SESSION));
    assert_eq!(body["access_token_valid"], json!(true));
    assert_eq!(body["session_token_valid"], json!(true));
    assert!(
        body.get("extra_cookies").is_none(),
        "录入路径没有 cookie 文本可解析，回传空数组会清掉已存的官网 Cookie"
    );
    assert_eq!(
        f.paths(),
        vec![
            "/api/auth/session",
            "/backend-api/me",
            "/backend-api/accounts/check/v4-2023-04-27"
        ],
        "SessionToken 必须先换取再校验，最后取计划类型"
    );
    let calls = f.calls();
    assert!(
        calls[0]["cookie"]
            .as_str()
            .unwrap()
            .contains("__Secure-next-auth.session-token="),
        "换取请求必须把提交值当会话 Cookie 发出"
    );
    assert_eq!(
        calls[1]["authorization"],
        json!("Bearer exchanged-access-token")
    );
}

#[tokio::test]
async fn access_token_import_skips_the_session_exchange() {
    let f = Fixture::new().await;
    let (status, body) = f.import(ACCESS).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["access_token"], json!(ACCESS));
    assert_eq!(body["session_token"], Value::Null);
    assert_eq!(body["session_token_valid"], json!(false));
    assert_eq!(
        f.paths(),
        vec!["/backend-api/me", "/backend-api/accounts/check/v4-2023-04-27"],
        "AccessToken 不需要经过 api/auth/session"
    );
    assert_eq!(f.calls()[0]["authorization"], json!(format!("Bearer {ACCESS}")));
}

#[tokio::test]
async fn opaque_token_still_takes_the_session_exchange_path() {
    let f = Fixture::new().await;
    let (status, body) = f.import("synthetic-access-token").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], json!("session_token 无法换取 access_token"));
    assert_eq!(
        f.paths(),
        vec!["/api/auth/session"],
        "非 JWT 形态沿用原版行为（evidence/original-003 的 token-fixture）"
    );
}

#[tokio::test]
async fn refresh_token_import_reports_the_unimplemented_path() {
    let f = Fixture::new().await;
    let response = f
        .client
        .post(format!("{}/api/get-user-info", f.base))
        .bearer_auth(ADMIN)
        .json(&json!({"auth_type": "refresh_token", "client_id": "fixture-client", "refresh_token": "fixture-refresh"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["message"], json!("当前网关未实现 refresh_token 刷新"));
    assert!(f.paths().is_empty(), "未实现的路径不得触上游");
    // 完全空输入仍保持原版文案。
    let empty: Value = f
        .client
        .post(format!("{}/api/get-user-info", f.base))
        .bearer_auth(ADMIN)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(empty["message"], json!("chatgpt_token 不能为空"));
}

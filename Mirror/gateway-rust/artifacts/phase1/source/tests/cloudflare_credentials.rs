//! Cloudflare 加固契约的合成回环回归（本机 fixture，不接触真实 chatgpt.com）：
//! 凭据换取/校验注入提交 cookies 与 CF cookies、命中实测挑战刷新一次并重放一次、
//! 持续拦截按 502 `upstream_blocked` 上报且不回传上游 HTML、生成类请求不重放、
//! 并发挑战只拉起一次 cfbypass。不使用任何真实账号、令牌或上游数据。
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

const ADMIN: &str = "cloudflare-fixture-admin-secret";
const KEY: &str = "cloudflare-fixture-encryption-key-0001";
/// 挑战次数哨兵：一直用实测挑战形态拒绝。
const ALWAYS: usize = usize::MAX;

type Events = Arc<Mutex<Vec<Value>>>;

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

#[derive(Default)]
struct Upstream {
    events: Events,
    challenges_left: AtomicUsize,
    fetches: AtomicUsize,
}

impl Upstream {
    /// 本次上游请求是否按实测挑战形态（403 + cf-mitigated: challenge）拒绝。
    fn take_challenge(&self) -> bool {
        let left = self.challenges_left.load(Ordering::SeqCst);
        if left == ALWAYS {
            return true;
        }
        if left == 0 {
            return false;
        }
        self.challenges_left.store(left - 1, Ordering::SeqCst);
        true
    }
}

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
        "cookie": header("cookie"),
        "authorization": header("authorization"),
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
    match parts.uri.path() {
        "/api/auth/session" => {
            axum::Json(json!({"accessToken":"synthetic-access-token"})).into_response()
        }
        "/backend-api/me" => axum::Json(
            json!({"email":"fixture@example.invalid","id":"fixture","name":"Fixture"}),
        )
        .into_response(),
        "/backend-anon/echo" => axum::Json(json!({"echo":true})).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
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
    async fn new(with_cfbypass: bool, challenges: usize) -> Self {
        let upstream = Arc::new(Upstream::default());
        upstream.challenges_left.store(challenges, Ordering::SeqCst);

        let chat_url = {
            let state = upstream.clone();
            let router = Router::new().fallback(move |request: Request| {
                chat_upstream(state.clone(), request)
            });
            serve(router).await
        };
        // cfbypass 每次返回不同的 cf_clearance，用序号证明重放用的是刷新后的值。
        let cfbypass_url = {
            let state = upstream.clone();
            let router = Router::new().fallback(move |_request: Request| {
                let state = state.clone();
                async move {
                    let fetch = state.fetches.fetch_add(1, Ordering::SeqCst) + 1;
                    axum::Json(json!({
                        "user_agent": "fixture-agent",
                        "cookies": [
                            {"name": "cf_clearance", "value": format!("CF-{fetch}")},
                            {"name": "__cf_bm", "value": "BM-FIXTURE"},
                        ],
                    }))
                    .into_response()
                }
            });
            serve(router).await
        };
        let django_url = {
            let router = Router::new().fallback(|request: Request| async move {
                if request.uri().path() == "/0x/user/gateway-authorization" {
                    return axum::Json(json!({
                        "active": true,
                        "version": "v1",
                        // 固定远期 Unix 秒：fixture 不依赖运行时钟。
                        "expires_at": 4_102_444_800_i64,
                    }))
                    .into_response();
                }
                StatusCode::NOT_FOUND.into_response()
            });
            serve(router).await
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
            cfbypass: with_cfbypass.then(|| loopback_url(&cfbypass_url.0).unwrap()),
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

    /// session_token 登录；提交 cookies 固定为 `probe_extra=EV`。
    async fn session_login(&self) -> reqwest::Response {
        self.client
            .post(format!("{}/api/login", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({
                "user_name":"alice",
                "session_token":"synthetic-session-token",
                "authorization":"signature-v1",
                "login_mode":"web",
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
                "extra_cookies":[{"name":"probe_extra","value":"EV"}],
            }))
            .send()
            .await
            .unwrap()
    }

    /// 登录成功并取出 mirror_token。
    async fn session_token(&self) -> String {
        let response = self.session_login().await;
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap()
                    .strip_prefix("mirror_token=")
                    .map(str::to_owned)
            })
            .expect("登录必须下发 mirror_token")
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

    fn fetches(&self) -> usize {
        self.upstream.fetches.load(Ordering::SeqCst)
    }

    fn always_challenge(&self) {
        self.upstream.challenges_left.store(ALWAYS, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn session_exchange_refreshes_cloudflare_and_replays_once() {
    let f = Fixture::new(true, 1).await;
    let response = f.session_login().await;
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("fixture@example.invalid"), "{body}");
    // 启动预热一次 + 挑战刷新一次。
    assert_eq!(f.fetches(), 2);

    let attempts = f.calls("/api/auth/session");
    assert_eq!(attempts.len(), 2, "首轮挑战后必须重放一次");
    let first = attempts[0]["cookie"].as_str().unwrap();
    let second = attempts[1]["cookie"].as_str().unwrap();
    assert!(
        first.starts_with("__Secure-next-auth.session-token=synthetic-session-token"),
        "{first}"
    );
    assert!(first.contains("probe_extra=EV"), "{first}");
    assert!(first.contains("cf_clearance=CF-1"), "{first}");
    // 重放必须用刷新后的 CF cookies，并保留提交的额外 cookie。
    assert!(second.contains("cf_clearance=CF-2"), "{second}");
    assert!(second.contains("probe_extra=EV"), "{second}");
    // CF cookies 在会话 cookies 之后（观测顺序）。
    assert!(
        second.find("probe_extra=EV").unwrap() < second.find("cf_clearance=CF-2").unwrap(),
        "{second}"
    );

    let me = f.calls("/backend-api/me");
    assert_eq!(me.len(), 1);
    assert_eq!(
        me[0]["authorization"].as_str().unwrap(),
        "Bearer synthetic-access-token"
    );
    assert!(me[0]["cookie"].as_str().unwrap().contains("cf_clearance=CF-2"));
}

#[tokio::test]
async fn sustained_challenge_reports_upstream_blocked_without_upstream_html() {
    let f = Fixture::new(true, ALWAYS).await;
    let response = f.session_login().await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let text = response.text().await.unwrap();
    let value: Value = serde_json::from_str(&text).expect("错误必须是 JSON");
    assert_eq!(value["code"], "upstream_blocked");
    let message = value["message"].as_str().unwrap();
    assert!(message.contains("403"), "{message}");
    assert!(message.contains("已刷新 CF cookies 并重试一次"), "{message}");
    assert!(!text.contains("<html"), "{text}");
    assert!(!text.contains("Just a moment"), "{text}");
    // 持续拦截时只刷新一次：不得每个请求都拉起 cfbypass 浏览器。
    assert_eq!(f.fetches(), 2);
    assert_eq!(f.calls("/api/auth/session").len(), 2);
}

#[tokio::test]
async fn missing_cfbypass_reports_actionable_message_without_replay() {
    let f = Fixture::new(false, ALWAYS).await;
    let response = f.session_login().await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let value: Value = response.json().await.unwrap();
    assert_eq!(value["code"], "upstream_blocked");
    let message = value["message"].as_str().unwrap();
    assert!(message.contains("CF_BYPASS_URL 未配置"), "{message}");
    assert_eq!(f.calls("/api/auth/session").len(), 1, "无法刷新时不得重放");
    assert_eq!(f.fetches(), 0);
}

#[tokio::test]
async fn diagnose_flags_upstream_blocked_and_keeps_submitted_cookies() {
    let f = Fixture::new(true, ALWAYS).await;
    let value: Value = f
        .client
        .post(format!("{}/api/diagnose-chatgpt-auth", f.base))
        .bearer_auth(ADMIN)
        .json(&json!({
            "session_token":"synthetic-session-token",
            "extra_cookies":[{"name":"probe_extra","value":"EV"}],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value["upstream_blocked"], json!(true));
    assert_eq!(value["session_token_valid"], json!(false));
    assert_eq!(value["access_token_valid"], json!(false));
    let error = value["last_error"].as_str().unwrap();
    assert!(error.contains("403"), "{error}");
    assert!(!error.contains("<html"), "{error}");
    let attempt = f.calls("/api/auth/session");
    // 诊断路径与登录路径共用同一封装：刷新一次并重放一次。
    assert_eq!(attempt.len(), 2, "诊断必须刷新一次并重放一次");
    assert!(attempt[0]["cookie"].as_str().unwrap().contains("probe_extra=EV"));
}

#[tokio::test]
async fn generation_requests_are_not_replayed_but_invalidate_clearance() {
    let f = Fixture::new(true, 0).await;
    let token = f.session_token().await;
    f.always_challenge();

    let response = f
        .client
        .post(format!("{}/backend-anon/echo", f.base))
        .header("x-mirror-token", &token)
        .json(&json!({"prompt":"hi"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        f.calls("/backend-anon/echo").len(),
        1,
        "生成类请求不得自动重放"
    );

    // 挑战已失效 CF 缓存：下一次请求必须重新走 cfbypass 才可能通过。
    let before = f.fetches();
    let page = f
        .client
        .get(format!("{}/backend-anon/echo", f.base))
        .header("x-mirror-token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::FORBIDDEN);
    assert!(f.fetches() > before, "失效后必须重新获取 CF cookies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_challenges_share_one_cfbypass_refresh() {
    let f = Fixture::new(true, 0).await;
    let token = f.session_token().await;
    f.always_challenge();
    let before = f.fetches();

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let client = f.client.clone();
        let base = f.base.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(async move {
            client
                .get(format!("{base}/backend-api/me"))
                .header("x-mirror-token", token)
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), StatusCode::FORBIDDEN);
    }
    assert_eq!(
        f.fetches() - before,
        1,
        "并发挑战必须共用一次 cfbypass 刷新"
    );
}

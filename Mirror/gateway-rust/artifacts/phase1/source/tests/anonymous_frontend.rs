//! 本批契约（匿名上游前端反代）的合成回环回归：
//! 登录开关、共享匿名身份、页面注入、被上游拒绝后重新获取 cfbypass 凭据。
//! 全部为本机 fixture，不接触真实 chatgpt.com，也不使用任何真实账号。
use axum::{
    body::to_bytes,
    extract::Request,
    http::StatusCode,
    response::IntoResponse,
    Router,
};
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
    time::Duration,
};

const ADMIN: &str = "anonymous-fixture-admin-secret";
const KEY: &str = "anonymous-fixture-encryption-key-000001";

type Events = Arc<Mutex<Vec<Value>>>;

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    base: String,
    client: reqwest::Client,
    chat_events: Events,
    cfbypass_events: Events,
    reject_anonymous: Arc<AtomicBool>,
    reject_as_challenge: Arc<AtomicBool>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn new(allow_anonymous_session: bool) -> Self {
        let chat_events: Events = Arc::new(Mutex::new(Vec::new()));
        let cfbypass_events: Events = Arc::new(Mutex::new(Vec::new()));
        let reject_anonymous = Arc::new(AtomicBool::new(false));
        let reject_as_challenge = Arc::new(AtomicBool::new(true));

        let cfbypass_url = {
            let events = cfbypass_events.clone();
            let router = Router::new().fallback(move |request: Request| {
                let events = events.clone();
                async move {
                    events.lock().unwrap().push(json!({
                        "method": request.method().as_str(),
                        "path": request.uri().path().to_owned(),
                    }));
                    axum::Json(json!({
                        "user_agent": "fixture-agent",
                        "cookies": [
                            {"name": "cf_clearance", "value": "CF-FIXTURE"},
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
                    // 访客会话：principal_kind=visitor，网关不构造 ACL 身份，
                    // 资源路径一律拒绝，但页面与匿名通道保持可用。
                    let (_, body) = request.into_parts();
                    let body = to_bytes(body, 64 * 1024).await.unwrap();
                    let input: Value = serde_json::from_slice(&body).unwrap_or_default();
                    return axum::Json(json!({
                        "active": true,
                        "version": "v1",
                        "user_id": "21",
                        "is_admin": false,
                        "principal_kind": "visitor",
                        "subject": input["subject"],
                        // 固定远期 Unix 秒：fixture 不依赖运行时钟。
                        "expires_at": 4_102_444_800_i64,
                    }))
                    .into_response();
                }
                StatusCode::NOT_FOUND.into_response()
            });
            serve(router).await
        };

        let chat_url = {
            let events = chat_events.clone();
            let reject = reject_anonymous.clone();
            let as_challenge = reject_as_challenge.clone();
            let router = Router::new().fallback(move |request: Request| {
                let events = events.clone();
                let reject = reject.clone();
                let as_challenge = as_challenge.clone();
                async move {
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
                    events.lock().unwrap().push(json!({
                        "method": parts.method.as_str(),
                        "uri": parts.uri.to_string(),
                        "cookie": header("cookie"),
                        "authorization": header("authorization"),
                        "origin": header("origin"),
                        "referer": header("referer"),
                        "sec-ch-ua": header("sec-ch-ua"),
                        "body": String::from_utf8_lossy(&body),
                    }));
                    if parts.uri.path() == "/"
                        || parts.uri.path().starts_with("/c/")
                        // 任意 SPA 页面路由都用同一段 HTML 应答：网关不维护页面路径清单。
                        || parts.uri.path() == "/projects"
                    {
                        return (
                            [(axum::http::header::CONTENT_TYPE, "text/html")],
                            "<html><head><script src=\"/assets/app.js\"></script></head><body>anon-page</body></html>",
                        )
                            .into_response();
                    }
                    if parts.uri.path().starts_with("/backend-anon/") {
                        if reject.load(Ordering::SeqCst) {
                            return if as_challenge.load(Ordering::SeqCst) {
                                (
                                    StatusCode::FORBIDDEN,
                                    [("cf-mitigated", "challenge")],
                                    "<html>challenge</html>",
                                )
                                    .into_response()
                            } else {
                                (
                                    StatusCode::UNAUTHORIZED,
                                    axum::Json(json!({"detail":{"message":"Unauthorized - Access token is missing"}})),
                                )
                                    .into_response()
                            };
                        }
                        return axum::Json(
                            json!({"anonymous": true, "path": parts.uri.path()}),
                        )
                        .into_response();
                    }
                    StatusCode::IM_A_TEAPOT.into_response()
                }
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
            cfbypass: Some(loopback_url(&cfbypass_url.0).unwrap()),
            timeout: Duration::from_secs(5),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session,
            admin_public_url: None,
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
            chat_events,
            cfbypass_events,
            reject_anonymous,
            reject_as_challenge,
        }
    }

    /// 匿名登录：无上游凭据的 `/api/login`，返回 mirror_token。
    async fn anonymous_login(&self) -> (StatusCode, String, Vec<String>) {
        let response = self
            .client
            .post(format!("{}/api/login", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({
                "user_name":"free_account:visitor-1",
                "authorization":"signature-v1",
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
                "force_chat_mode":true,
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let cookies: Vec<String> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap().to_owned())
            .collect();
        let body = response.text().await.unwrap();
        (status, body, cookies)
    }

    /// 上游 chat 请求的路径部分（去掉查询串）。
    fn upstream_paths(&self) -> Vec<String> {
        self.chat_events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| {
                event["uri"]
                    .as_str()
                    .map(|uri| uri.split('?').next().unwrap_or("").to_owned())
            })
            .collect()
    }

    fn chat_calls(&self, path: &str) -> Vec<Value> {
        self.chat_events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                event["uri"]
                    .as_str()
                    .map(|uri| uri.split('?').next() == Some(path))
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }
}

#[tokio::test]
async fn anonymous_login_requires_the_explicit_switch() {
    let f = Fixture::new(false).await;
    let (status, body, _) = f.anonymous_login().await;
    assert_eq!(status, 400);
    assert!(
        body.contains("至少提供一个"),
        "默认仍是原版空凭据拒绝: {body}"
    );
    assert!(f.chat_calls("/").is_empty());
}

#[tokio::test]
async fn anonymous_session_shares_one_upstream_identity_and_injects_before_head() {
    let f = Fixture::new(true).await;
    let (status, body, cookies) = f.anonymous_login().await;
    assert_eq!(status, 200, "{body}");
    let token = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("mirror_token="))
        .expect("登录必须下发 mirror_token")
        .to_owned();

    let page = f
        .client
        .get(format!("{}/", f.base))
        .header("cookie", format!("mirror_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    let injected = html.find("gateway-user-logout-button").expect("必须注入客户端资源");
    let head_end = html.find("</head>").expect("fixture 含 </head>");
    assert!(injected < head_end, "注入必须位于 </head> 之前");
    // 注入必须位于页面脚本之前，身份覆盖才能先执行。
    assert!(injected < html.find("/assets/app.js").unwrap());

    let upstream = &f.chat_calls("/")[0];
    // 匿名链路以 cookies 为唯一凭据：不发 Authorization，也不转发镜像令牌。
    assert_eq!(upstream["authorization"].as_str().unwrap(), "");
    assert_eq!(
        upstream["cookie"].as_str().unwrap(),
        "cf_clearance=CF-FIXTURE; __cf_bm=BM-FIXTURE"
    );
    // 原版 chat 上游的 origin 固定为 scheme://host（去端口），referer 为其加 `/`。
    assert_eq!(upstream["origin"].as_str().unwrap(), "http://127.0.0.1");
    assert_eq!(upstream["referer"].as_str().unwrap(), "http://127.0.0.1/");
    assert!(!upstream["sec-ch-ua"].as_str().unwrap().is_empty());
    assert!(!upstream["cookie"].as_str().unwrap().contains(&token));

    // 匿名通道复用同一身份，不再触发第二次 cfbypass 获取。
    let cf_before = f.cfbypass_events.lock().unwrap().len();
    let anonymous = f
        .client
        .get(format!("{}/backend-anon/sentinel/chat-requirements", f.base))
        .header("cookie", format!("mirror_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 200);
    assert_eq!(f.cfbypass_events.lock().unwrap().len(), cf_before);
    // accessToken 只属于真实账号登录：匿名链路不得请求 `/api/auth/session`
    //（fixture 对该路径返回 418，一旦请求就会被断言暴露）。
    assert!(
        !f.upstream_paths()
            .iter()
            .any(|path| path == "/api/auth/session"),
        "匿名链路不得尝试换取 accessToken"
    );
}

#[tokio::test]
async fn cloudflare_challenge_reacquires_the_shared_identity() {
    let f = Fixture::new(true).await;
    let (_, _, cookies) = f.anonymous_login().await;
    let token = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("mirror_token="))
        .expect("登录必须下发 mirror_token")
        .to_owned();
    let request = |path: &'static str| {
        f.client
            .get(format!("{}{path}", f.base))
            .header("cookie", format!("mirror_token={token}"))
            .send()
    };

    assert_eq!(request("/backend-anon/me").await.unwrap().status(), 200);
    let cf_after_success = f.cfbypass_events.lock().unwrap().len();

    f.reject_anonymous.store(true, Ordering::SeqCst);
    assert_eq!(request("/backend-anon/me").await.unwrap().status(), 403);
    f.reject_anonymous.store(false, Ordering::SeqCst);
    assert_eq!(request("/backend-anon/me").await.unwrap().status(), 200);
    assert!(
        f.cfbypass_events.lock().unwrap().len() > cf_after_success,
        "被 Cloudflare 挑战后必须重新获取匿名身份"
    );
}

/// 上游对具体请求的业务 4xx 不得清除匿名身份：实测 401 由客户端缺少 oai-* 头导致，
/// 重新获取身份并不能修复，还会为每个请求启动一次浏览器。
#[tokio::test]
async fn unrelated_upstream_4xx_keeps_the_shared_identity() {
    let f = Fixture::new(true).await;
    let (_, _, cookies) = f.anonymous_login().await;
    let token = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("mirror_token="))
        .expect("登录必须下发 mirror_token")
        .to_owned();
    let request = |path: &'static str| {
        f.client
            .get(format!("{}{path}", f.base))
            .header("cookie", format!("mirror_token={token}"))
            .send()
    };
    assert_eq!(request("/backend-anon/me").await.unwrap().status(), 200);
    let cf_before = f.cfbypass_events.lock().unwrap().len();

    f.reject_as_challenge.store(false, Ordering::SeqCst);
    f.reject_anonymous.store(true, Ordering::SeqCst);
    assert_eq!(request("/backend-anon/me").await.unwrap().status(), 401);
    f.reject_anonymous.store(false, Ordering::SeqCst);

    assert_eq!(request("/backend-anon/me").await.unwrap().status(), 200);
    assert_eq!(f.cfbypass_events.lock().unwrap().len(), cf_before);
}

#[tokio::test]
async fn internal_upstream_media_is_allowlisted_and_credential_free() {
    let f = Fixture::new(true).await;
    let (_, _, cookies) = f.anonymous_login().await;
    let token = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("mirror_token="))
        .expect("登录必须下发 mirror_token")
        .to_owned();
    // 非白名单主机在接触上游之前就被拒绝。
    for path in [
        "/internal-upstream/https/evil.example/x.png",
        "/internal-upstream/http/images.openai.com/x.png",
        "/internal-upstream/https/evil-oaiusercontent.com/x.png",
        "/internal-upstream",
    ] {
        let response = f
            .client
            .get(format!("{}{path}", f.base))
            .header("cookie", format!("mirror_token={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503, "{path}");
    }
    // 非读取/上传方法同样在门禁处拒绝，不接触上游。
    let response = f
        .client
        .delete(format!(
            "{}/internal-upstream/https/files.oaiusercontent.com/file-1",
            f.base
        ))
        .header("cookie", format!("mirror_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 405);
    assert_eq!(response.headers()["allow"], "GET, HEAD, PUT");
    assert!(f.chat_calls("/internal-upstream").is_empty());

    // 分片签名主机的 PUT 必须真正转发到上游（实测 files → files09 轮换）。
    let put = f
        .client
        .put(format!(
            "{}/internal-upstream/https/files09.oaiusercontent.com/file-1?se=1&sp=cw&sig=x",
            f.base
        ))
        .header("cookie", format!("mirror_token={token}"))
        .header("x-ms-blob-type", "BlockBlob")
        .body("blob-body")
        .send()
        .await
        .unwrap();
    assert_ne!(put.status(), 503, "分片主机必须命中白名单而不是门禁");
}

/// 页面注入必须容忍头部大小写与缺失的 `</head>`。
#[tokio::test]
async fn injection_handles_missing_or_uppercase_head() {
    let f = Fixture::new(true).await;
    let (_, _, cookies) = f.anonymous_login().await;
    let token = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("mirror_token="))
        .expect("登录必须下发 mirror_token")
        .to_owned();
    // 上游 fixture 只返回固定 HTML；这里直接验证网关对 HTML 的注入位置，
    // 缺失 </head> 的降级分支由 src/server/proxy.rs 的单元测试覆盖。
    let response = f
        .client
        .get(format!("{}/c/conv-1", f.base))
        .header("cookie", format!("mirror_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let html = response.text().await.unwrap();
    assert!(html.ends_with("</head><body>anon-page</body></html>"));
    assert!(
        html.starts_with("<html><head><script id=\"gateway-user-logout-button\">")
    );
    assert!(html.contains("<script src=\"/assets/app.js\"></script>"));
    assert!(
        !f.upstream_paths().iter().any(|path| path.starts_with("/assets/")),
        "页面静态资源必须走 CDN，不是 chat 上游"
    );
    assert_eq!(f.chat_calls("/c/conv-1").len(), 1);
}

/// 读取面用例：`Accept` 取不同值时行为必须一致（2026-09-29 实测同一个 `/projects`
/// 曾因 Accept 不同得到 200 与 503 —— 那次是按 `text/html` 判「页面导航」的后果）。
async fn read_request(path: &str, accept: &str) -> (reqwest::Response, Vec<String>) {
    let f = Fixture::new(true).await;
    let (_, _, cookies) = f.anonymous_login().await;
    let token = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("mirror_token="))
        .expect("登录必须下发 mirror_token")
        .to_owned();
    let response = f
        .client
        .get(format!("{}{path}", f.base))
        .header("cookie", format!("mirror_token={token}"))
        .header("accept", accept)
        .send()
        .await
        .unwrap();
    (response, f.upstream_paths())
}

#[tokio::test]
async fn read_requests_are_forwarded_regardless_of_accept() {
    // 地址栏导航（text/html）与取数请求（*/*）走同一条路径：原版兜底路由本就是
    // `/*path` 全转发，读取面按方法放行，不由 Accept 决定。
    for accept in [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "*/*",
        "application/json",
    ] {
        let (response, paths) = read_request("/projects", accept).await;
        assert_eq!(response.status(), 200, "accept={accept}");
        assert_eq!(
            paths.iter().filter(|path| *path == "/projects").count(),
            1,
            "accept={accept} 必须恰好转发一次"
        );
    }
}

/// 未登录前端自带的 next-auth 客户端在进入对话前会调用这四个端点；缺一个就会
/// 落入 signIn 失败路径并停在错误页（实测见 evidence/anonymous-nextauth-001 与
/// ANONYMOUS_FRONTEND_EVIDENCE.md §7）。它们不校验镜像会话、也不下发任何 cookie。
#[tokio::test]
async fn nextauth_compatibility_endpoints_answer_without_mirror_session() {
    let f = Fixture::new(true).await;

    let providers = f
        .client
        .get(format!("{}/api/auth/providers", f.base))
        .send()
        .await
        .unwrap();
    assert_eq!(providers.status(), 200);
    assert_eq!(
        providers
            .headers()
            .get_all("set-cookie")
            .into_iter()
            .count(),
        0,
        "兼容端点不得下发 cookie"
    );
    let body: Value = providers.json().await.unwrap();
    assert_eq!(body.as_object().unwrap().len(), 4);
    assert_eq!(body["openai"]["type"], "oauth");
    assert_eq!(body["openai"]["signinUrl"], "/api/auth/signin/openai");
    assert_eq!(body["openai"]["callbackUrl"], "/api/auth/callback/openai");
    let text = body.to_string();
    assert!(
        !text.contains("chatgpt.com"),
        "providers 必须同源改写，不能把浏览器带出镜像: {text}"
    );

    let csrf = f
        .client
        .get(format!("{}/api/auth/csrf", f.base))
        .send()
        .await
        .unwrap();
    assert_eq!(csrf.status(), 200);
    let body: Value = csrf.json().await.unwrap();
    let token = body["csrfToken"].as_str().unwrap();
    assert_eq!(token.len(), 64);
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "{token}");

    let log = f
        .client
        .post(format!("{}/api/auth/_log", f.base))
        .json(&json!({"error":"fixture","level":"debug","logger":"fixture"}))
        .send()
        .await
        .unwrap();
    assert_eq!(log.status(), 200);
    assert!(log.text().await.unwrap().is_empty(), "_log 必须返回空正文");

    let error = f
        .client
        .get(format!("{}/api/auth/error?error=Configuration", f.base))
        .send()
        .await
        .unwrap();
    assert_eq!(error.status(), 200);
    assert_eq!(error.headers()["content-type"], "text/html; charset=utf-8");
    let html = error.text().await.unwrap();
    assert!(html.contains("href=\"/\""), "{html}");
    assert!(
        !html.contains("https://"),
        "本地错误页不得引用上游资源: {html}"
    );

    // 兼容面是本地响应：这四个路径一个都不得转发到 chat 上游。
    for path in [
        "/api/auth/providers",
        "/api/auth/csrf",
        "/api/auth/_log",
        "/api/auth/error",
    ] {
        assert!(f.chat_calls(path).is_empty(), "{path} 不得转发上游");
    }
}

/// 兼容面保持最小：只补齐实测的四个端点与各自方法，其余 `/api/auth/*` 继续 404，
/// 因此镜像不会因为这次改动获得任何 OAuth/登录能力。
#[tokio::test]
async fn nextauth_compatibility_surface_stays_minimal() {
    let f = Fixture::new(true).await;

    for (method, path) in [
        ("POST", "/api/auth/providers"),
        ("POST", "/api/auth/csrf"),
        ("GET", "/api/auth/_log"),
        ("POST", "/api/auth/error"),
    ] {
        let url = format!("{}{path}", f.base);
        let response = if method == "GET" {
            f.client.get(url).send().await.unwrap()
        } else {
            f.client.post(url).send().await.unwrap()
        };
        assert_eq!(response.status(), 405, "{method} {path}");
        assert!(
            response.headers().contains_key("allow"),
            "{method} {path} 必须带 allow 头"
        );
    }

    for path in [
        "/api/auth/signin/openai",
        "/api/auth/callback/openai",
        "/api/auth/fixture-unknown",
    ] {
        let response = f
            .client
            .get(format!("{}{path}", f.base))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{path}");
    }
}

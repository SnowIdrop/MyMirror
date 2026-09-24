//! 缺口 2 的合成回环回归：注入脚本改写出去的前缀要么命中固定主机的无凭据反代，
//! 要么拿到按类别区分的可行动文案；两者都不得把请求交给任意目标。
//! 全部为本机 fixture，不接触真实上游。
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
use serde_json::Value;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const ADMIN: &str = "prefix-fixture-admin-secret";
const KEY: &str = "prefix-fixture-encryption-key-000001";

type Events = Arc<Mutex<Vec<Value>>>;

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    base: String,
    client: reqwest::Client,
    events: Events,
    token: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// 记录请求的桩上游：按扩展名给出可接受正文类型，HTML 路径用于验证拒绝。
async fn stub(events: Events, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    events.lock().unwrap().push(serde_json::json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "query": parts.uri.query(),
        "host": header("host"),
        "cookie": header("cookie"),
        "authorization": header("authorization"),
        "x_mirror_token": header("x-mirror-token"),
        "body": String::from_utf8_lossy(&body),
    }));
    let path = parts.uri.path().to_owned();
    // 登录需要上游用户信息；这里给最小可用形状。
    if path == "/backend-api/me" {
        return axum::Json(serde_json::json!({"email":"fixture@example.invalid"}))
            .into_response();
    }
    if path.ends_with("/page.html") {
        return (
            [("content-type", "text/html")],
            "<html>must-not-be-proxied</html>",
        )
            .into_response();
    }
    let content_type = if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "image/png"
    };
    (
        [("content-type", content_type), ("etag", "fixture-etag")],
        "fixture-body",
    )
        .into_response()
}

impl Fixture {
    /// `ab` 为 true 时额外配置 `CHATGPT_AB_BASE_URL`（指向同一个桩）。
    async fn new(with_ab: bool) -> Self {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let upstream_url = {
            let events = events.clone();
            let router = Router::new().fallback(move |request: Request| {
                stub(events.clone(), request)
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            // 任务句柄随后并入 Fixture。
            let _ = &task;
            (url, task)
        };
        let django_url = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().fallback(|request: Request| async move {
                        if request.uri().path() == "/0x/user/gateway-authorization" {
                            return axum::Json(serde_json::json!({
                                "active": true,
                                "version": "v1",
                                "user_id": "7",
                                "is_admin": false,
                                "principal_kind": "user",
                                "subject": "alice",
                                "expires_at": 4_102_444_800_i64,
                            }))
                            .into_response();
                        }
                        StatusCode::NOT_FOUND.into_response()
                    }),
                )
                .await
                .unwrap()
            });
            (url, task)
        };
        let dir = tempfile::tempdir().unwrap();
        let loopback = loopback_url(&upstream_url.0).unwrap();
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: dir.path().join("db.sqlite"),
            secret: ADMIN.into(),
            key: KEY.into(),
            django: loopback_url(&django_url.0).unwrap(),
            upstream: loopback.clone(),
            // 这些用例不经过 WS 桥接：给一个不会用到的回环 WS 基址即可。
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
            cdn_upstream: Some(loopback.clone()),
            ab_upstream: with_ab.then_some(loopback.clone()),
            // 策略表条目指向固定主机；离线回归把它们指到本机桩。
            public_prefix_base: Some(loopback.clone()),
            cfbypass: None,
            timeout: Duration::from_secs(3),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
        };
        let app = server::router(config).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        // 有意不代理的前缀保留既有门禁顺序：未登录先 401，因此用例需要会话。
        let login = client
            .post(format!("{base}/api/login"))
            .bearer_auth(ADMIN)
            .json(&serde_json::json!({
                "user_name":"alice",
                "access_token":"synthetic-access-alice",
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
                "extra_cookies":[{"name":"probe_extra","value":"EV"}],
            }))
            .send()
            .await
            .unwrap();
        let status = login.status();
        let body = login.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        let body: Value = serde_json::from_str(&body).unwrap();
        let token = body["login_url"]
            .as_str()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_owned();
        events.lock().unwrap().clear();
        Self {
            _dir: dir,
            tasks: vec![upstream_url.1, django_url.1, gateway],
            base,
            client,
            events,
            token,
        }
    }

    fn calls(&self, path: &str) -> Vec<Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event["path"].as_str() == Some(path))
            .cloned()
            .collect()
    }

    fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

/// 每个被脚本改写的静态/媒体前缀都必须反代成功，且不带任何凭据。
#[tokio::test]
async fn rewritten_static_prefixes_proxy_without_credentials() {
    let f = Fixture::new(true).await;
    for path in [
        "/common/fonts/a.woff2",
        "/static-rsc-1/a.png",
        "/static-rsc-4/a.png",
        "/images-openai/a.png",
        "/images-app/a.png",
        "/persistent-deep-research/a.png",
        "/files/v1/a.png",
        "/files-southcentral/v1/a.png",
        "/files-north/v1/a.png",
        "/openai-files/a.png",
        "/connector-assets/a.js",
        "/mapbox/styles/v1/oai-data/style.json",
        "/mapbox/tiles/1.png",
        "/google-s2/a.png",
        "/google-avatar/a/abc",
        "/gstatic-t0/a.woff2",
        "/gstatic-t3/a.woff2",
        "/ab/config.json",
    ] {
        f.clear();
        let response = f
            .client
            .get(format!("{}{path}?v=1", f.base))
            .bearer_auth("browser-secret")
            .header("cookie", "mirror_token=invalid")
            .header("x-mirror-token", "invalid")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["etag"], "fixture-etag", "{path}");
        // 断言只看本次请求：上游路径按策略表重写，因此不按本地路径匹配。
        let calls = f.events.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "{path}");
        let call = &calls[0];
        assert_eq!(call["query"], "v=1", "{path}");
        for header in ["cookie", "authorization", "x_mirror_token"] {
            assert_eq!(call[header], "", "{path} 不得携带 {header}");
        }
    }
}

/// 策略表把本地前缀映射到固定上游路径（不是原样透传本地路径）。
#[tokio::test]
async fn upstream_paths_follow_the_prefix_table() {
    let f = Fixture::new(true).await;
    for (local, upstream) in [
        ("/mapbox/tiles/1.png", "/tiles/1.png"),
        ("/persistent-deep-research/a.png", "/deep-research/a.png"),
        ("/openai-files/a.png", "/a.png"),
        ("/connector-assets/a.js", "/assets/a.js"),
        ("/google-s2/a.png", "/s2/a.png"),
        ("/google-avatar/a/abc", "/a/abc"),
        ("/gstatic-t1/a.woff2", "/a.woff2"),
        ("/images-openai/a.png", "/a.png"),
        ("/ab/config.json", "/config.json"),
        ("/common/fonts/a.woff2", "/common/fonts/a.woff2"),
    ] {
        f.clear();
        let response = f.client.get(format!("{}{local}", f.base)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{local}");
        let calls = f.events.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "{local}");
        assert_eq!(calls[0]["path"], upstream, "{local}");
    }
}

/// `/ab/` 未配置时给出可行动文案；配置后按固定上游反代。
#[tokio::test]
async fn ab_prefix_requires_configuration() {
    let f = Fixture::new(false).await;
    let response = f
        .client
        .get(format!("{}/ab/config.json", f.base))
        .header("x-mirror-token", &f.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = response.json().await.unwrap();
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("CHATGPT_AB_BASE_URL"), "{message}");
    assert!(f.calls("/config.json").is_empty());
    // 未登录时保持既有门禁顺序：先 401，不泄露前缀语义。
    let anonymous = f.client.get(format!("{}/ab/config.json", f.base)).send().await.unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
}

/// 有意不代理的前缀：状态码与文案稳定，且一律不接触上游。
#[tokio::test]
async fn refused_prefixes_answer_with_a_stable_category_message() {
    let f = Fixture::new(true).await;
    for (path, expected) in [
        ("/external/https/accounts.google.com/gsi/client", "外链代理尚未开放"),
        ("/vendor-script/gtag/js", "第三方脚本代理"),
        ("/vendor-static", "第三方脚本代理"),
        ("/cloudflare-insights/beacon.min.js", "第三方脚本代理"),
        ("/vendor-batch/collect", "第三方遥测上报"),
        ("/ga/collect", "第三方遥测上报"),
        ("/mapbox-events/events/v2", "地图遥测上报"),
        ("/connector-deep-research/index.html", "沙箱页面尚未开放"),
        ("/v1/chat/completions", "尚未开放"),
    ] {
        let response = f
            .client
            .post(format!("{}{path}", f.base))
            .header("x-mirror-token", &f.token)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let body: Value = response.json().await.unwrap();
        let message = body["message"].as_str().unwrap();
        assert!(message.contains(expected), "{path}: {message}");
        assert!(!message.contains('<'), "{path} 不得回传上游 HTML：{message}");
    }
    assert!(f.events.lock().unwrap().is_empty(), "拒绝路径不得接触上游");
}

/// 公共前缀只允许 GET/HEAD，且 HTML 正文一律拒绝（同源下会变成可执行页面）。
#[tokio::test]
async fn public_prefixes_reject_other_methods_and_html_bodies() {
    let f = Fixture::new(true).await;
    let response = f
        .client
        .post(format!("{}/common/a.png", f.base))
        .body("must-not-be-forwarded")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "GET, HEAD");
    assert!(f.events.lock().unwrap().is_empty());

    let response = f
        .client
        .get(format!("{}/common/page.html", f.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(!response.text().await.unwrap().contains("must-not-be-proxied"));
}

/// 路径余段不能逃出固定主机/路径：`..`、编码分隔符与空段一律拒绝。
#[tokio::test]
async fn path_escapes_never_reach_upstream() {
    let f = Fixture::new(true).await;
    // 编码分隔符不会被 URL 标准归一化，直接命中策略表的余段校验。
    for path in ["/common/%2Fsecret", "/common/a%5Cb.png", "/common/%2e%2e/secret"] {
        let response = f.client.get(format!("{}{path}", f.base)).send().await.unwrap();
        assert!(
            !response.status().is_success(),
            "{path} 不得成为成功响应"
        );
    }
    // 归一化形态（`..`、空段）：客户端或 HTTP 栈归一化后落到未开放路径，
    // 同样不得变成成功响应，也不得被当成已开放前缀转发。
    for path in ["/common/../secret", "/common//a.png"] {
        let response = f.client.get(format!("{}{path}", f.base)).send().await.unwrap();
        assert!(
            !response.status().is_success(),
            "{path} 归一化后不得成功"
        );
    }
    assert!(f.events.lock().unwrap().is_empty(), "逃逸路径不得接触上游");
}

/// 原始 TCP 请求（不经客户端归一化）：`..` 余段必须在接触上游前被拒绝。
#[tokio::test]
async fn raw_requests_with_dot_segments_are_refused_before_upstream() {
    let f = Fixture::new(true).await;
    for target in [
        "/common/../secret",
        "/common/./secret",
        "/common/%2e%2e/secret",
        "/common/%2Fsecret",
    ] {
        let status = raw_get(&f.base, target, &f.token).await;
        assert_eq!(status, 503, "{target}");
    }
    assert!(f.events.lock().unwrap().is_empty(), "逃逸路径不得接触上游");
}

/// 直接写一行 HTTP 请求，返回响应状态码（客户端与 URL 标准都不参与）。
async fn raw_get(base: &str, target: &str, token: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let authority = base.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let request = format!(
        "GET {target} HTTP/1.1\r\nhost: {authority}\r\nx-mirror-token: {token}\r\nconnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let head = String::from_utf8_lossy(&raw);
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("响应无法解析：{head}"))
}

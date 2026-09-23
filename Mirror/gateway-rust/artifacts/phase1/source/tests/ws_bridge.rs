//! WebSocket 路由级回归：镜像会话鉴权、代理出口 fail-closed、上游不可达时的
//! 无正文错误、以及会话凭据（extra_cookies 在前、CF cookies 在后）的注入。
//! 全部为本机 fixture，不接触真实 chatgpt.com。
use axum::{
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
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio_tungstenite::tungstenite;

/// 最小 HTTP 正向代理桩：reqwest 走代理时发绝对形式请求行，这里改写为
/// origin-form 后双向转发。只用于合成回环回归，不接触任何真实主机。
async fn proxy_stub(listener: tokio::net::TcpListener, events: Events) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut client, _)) = listener.accept().await else {
            return;
        };
        let events = events.clone();
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 1024];
            let head_end = loop {
                let read = match client.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => read,
                };
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(index) = find(&buffer, b"\r\n\r\n") {
                    break index;
                }
            };
            let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
            let mut lines = head.split("\r\n");
            let mut request = lines.next().unwrap_or_default().split(' ');
            let method = request.next().unwrap_or_default().to_owned();
            let target = request.next().unwrap_or_default().to_owned();
            let version = request.next().unwrap_or("HTTP/1.1").to_owned();
            let Ok(url) = url::Url::parse(&target) else {
                return;
            };
            let host = url.host_str().unwrap_or("127.0.0.1").to_owned();
            let port = url.port_or_known_default().unwrap_or(80);
            events
                .lock()
                .unwrap()
                .push(json!({"event":"proxy", "target": target}));
            let Ok(mut upstream) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                return;
            };
            let mut forwarded = format!(
                "{method} {} {version}\r\n",
                match url.query() {
                    Some(query) => format!("{}?{query}", url.path()),
                    None => url.path().to_owned(),
                }
            );
            for line in lines {
                if line.to_ascii_lowercase().starts_with("proxy-connection:") {
                    continue;
                }
                forwarded.push_str(line);
                forwarded.push_str("\r\n");
            }
            forwarded.push_str("\r\n");
            if upstream.write_all(forwarded.as_bytes()).await.is_err() {
                return;
            }
            if !buffer[head_end + 4..].is_empty()
                && upstream.write_all(&buffer[head_end + 4..]).await.is_err()
            {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

const ADMIN: &str = "ws-fixture-admin-secret";
const KEY: &str = "ws-fixture-encryption-key-00000001";

type Events = Arc<Mutex<Vec<Value>>>;

/// 只做 WS 握手的桩上游：记录握手头，然后按需要回帧或直接断开。
/// 握手回调的 Err 变体由 tungstenite 的 `Callback` trait 固定为握手响应，
/// 本桩永不拒绝握手，因此这里按 lint 建议收窄不了。
#[allow(clippy::result_large_err)]
async fn ws_upstream(
    events: Events,
    state: Arc<AtomicUsize>,
    listener: tokio::net::TcpListener,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let events = events.clone();
        let state = state.clone();
        tokio::spawn(async move {
            // 用带回调的握手记录上游实际收到的头：凭据注入必须可断言。
            let mut socket = match tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tungstenite::handshake::server::Request, response| {
                    let header = |name: &str| {
                        request
                            .headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("")
                            .to_owned()
                    };
                    events.lock().unwrap().push(json!({
                        "event": "handshake",
                        "path": request.uri().path(),
                        "query": request.uri().query(),
                        "cookie": header("cookie"),
                        "authorization": header("authorization"),
                        "origin": header("origin"),
                        "user_agent": header("user-agent"),
                    }));
                    Ok(response)
                },
            )
            .await
            {
                Ok(socket) => socket,
                Err(cause) => {
                    events
                        .lock()
                        .unwrap()
                        .push(json!({"error": cause.to_string()}));
                    return;
                }
            };
            if state.load(Ordering::SeqCst) == 1 {
                // 模式 1：握手后立刻断开，用于验证桥接收尾不悬住。
                return;
            }
            use futures_util::{SinkExt, StreamExt};
            while let Some(message) = socket.next().await {
                match message {
                    Ok(tungstenite::Message::Text(text)) => {
                        events.lock().unwrap().push(json!({"text":text}));
                        let _ = socket.send(tungstenite::Message::Text(text)).await;
                    }
                    Ok(tungstenite::Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }
        });
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    base: String,
    client: reqwest::Client,
    events: Events,
    handshakes: Arc<AtomicUsize>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    /// `upstream_ws` 为 WS 桩监听地址；`proxy` 为是否把会话出口设为代理。
    async fn new(proxy: bool) -> Self {
        let events: Events = Arc::new(Mutex::new(Vec::new()));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_addr = ws_listener.local_addr().unwrap();
        let ws_task = {
            let events = events.clone();
            let handshakes = handshakes.clone();
            tokio::spawn(ws_upstream(events, handshakes.clone(), ws_listener))
        };
        // HTTP 聊天上游：登录需要 `/backend-api/me`，与 WS 桩分开。
        let chat_url = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().fallback(|request: Request| async move {
                        if request.uri().path() == "/backend-api/me" {
                            return axum::Json(json!({"email":"fixture@example.invalid"}))
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
        // 出口代理：本机正向代理桩，使会话出口真的走「已启用代理」这条绑定。
        let proxy_url = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let events = events.clone();
            let task = tokio::spawn(proxy_stub(listener, events));
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
                            return axum::Json(json!({
                                "active": true,
                                "version": "v1",
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
        let cfbypass_url = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().fallback(|| async {
                        axum::Json(json!({
                            "user_agent": "fixture-agent",
                            "cookies": [{"name":"cf_clearance","value":"CF-FIXTURE"}],
                        }))
                    }),
                )
                .await
                .unwrap()
            });
            (url, task)
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
            // WS 桥接目标指向合成回环 WS 桩。
            ws_upstream: url::Url::parse(&format!("ws://{ws_addr}/")).unwrap(),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            // 出口绑定与 CF 同时配置在 fail-closed 边界内被拒绝（egress::normalized），
            // 因此代理出口用例不配置 cfbypass。
            cfbypass: (!proxy).then(|| loopback_url(&cfbypass_url.0).unwrap()),
            timeout: Duration::from_secs(5),
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
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let fixture = Self {
            _dir: dir,
            tasks: vec![
                ws_task,
                chat_url.1,
                django_url.1,
                cfbypass_url.1,
                proxy_url.1,
                gateway,
            ],
            base,
            client,
            events,
            handshakes,
        };
        if proxy {
            let response = fixture
                .client
                .post(format!("{}/api/mirror-proxy-config", fixture.base))
                .bearer_auth(ADMIN)
                .json(&json!({
                    "enabled": true,
                    "proxy_url": proxy_url.0,
                    "transport_mode": "reqwest",
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        fixture
    }

    async fn login(&self) -> String {
        let response = self
            .client
            .post(format!("{}/api/login", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({
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
                "extra_cookies":[{"name":"probe_extra","value":"EV"}],
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

    fn ws_url(&self, path: &str) -> String {
        format!("{}{path}", self.base.replace("http://", "ws://"))
    }
}

/// 无镜像会话时升级请求必须 401，且不接触上游。
#[tokio::test]
async fn websocket_requires_a_mirror_session() {
    let f = Fixture::new(false).await;
    let response = f
        .client
        .get(format!("{}/ws-chatgpt/v1/threads", f.base))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.handshakes.load(Ordering::SeqCst), 0);
}

/// 代理出口上的 WS 桥接 fail-closed：不静默改走直连。
#[tokio::test]
async fn websocket_fails_closed_on_a_proxied_egress() {
    let f = Fixture::new(true).await;
    let token = f.login().await;
    let response = f
        .client
        .get(format!("{}/ws-chatgpt/v1/threads", f.base))
        .header("x-mirror-token", &token)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["message"], "WebSocket 桥接尚未支持代理出口");
    assert_eq!(f.handshakes.load(Ordering::SeqCst), 0, "不得接触上游");
}

/// 直连出口上的桥接：握手成功、消息双向透传，且凭据按会话注入。
#[tokio::test]
async fn websocket_bridges_messages_with_session_credentials() {
    let f = Fixture::new(false).await;
    let token = f.login().await;
    let url = f.ws_url("/ws-chatgpt/v1/threads?model=fixture");
    let request = url
        .into_client_request_with_token(&token)
        .expect("握手请求构造失败");
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    use futures_util::SinkExt;
    socket
        .send(tungstenite::Message::Text("hello".into()))
        .await
        .unwrap();
    use futures_util::StreamExt;
    let echoed = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("回帧超时")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, tungstenite::Message::Text("hello".into()));
    let events = f.events.lock().unwrap().clone();
    assert!(
        events.iter().any(|event| event["text"] == "hello"),
        "{events:?}"
    );
    // 上游握手头：会话 cookies 在前、CF cookies 在后，且只带会话 access_token。
    let handshake = events
        .iter()
        .find(|event| event["event"] == "handshake")
        .expect("上游必须收到握手");
    assert_eq!(handshake["path"], "/v1/threads", "{handshake}");
    assert_eq!(handshake["query"], "model=fixture", "{handshake}");
    assert_eq!(handshake["authorization"], "Bearer synthetic-access-alice");
    let cookie = handshake["cookie"].as_str().unwrap();
    assert!(cookie.starts_with("probe_extra=EV"), "{cookie}");
    assert!(cookie.contains("cf_clearance=CF-FIXTURE"), "{cookie}");
    assert_eq!(
        handshake["user_agent"],
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    );
    assert!(
        handshake["origin"].as_str().unwrap().starts_with("http://127.0.0.1"),
        "{handshake}"
    );
}

/// 小工具：把镜像 token 放进握手头（`IntoClientRequest` 只认 `http::Request`）。
trait TokenHandshake {
    fn into_client_request_with_token(
        self,
        token: &str,
    ) -> anyhow::Result<tungstenite::handshake::client::Request>;
}

impl TokenHandshake for String {
    fn into_client_request_with_token(
        self,
        token: &str,
    ) -> anyhow::Result<tungstenite::handshake::client::Request> {
        use tungstenite::client::IntoClientRequest;
        let mut request = self.into_client_request()?;
        request.headers_mut().insert(
            "x-mirror-token",
            tungstenite::http::HeaderValue::from_str(token)?,
        );
        Ok(request)
    }
}

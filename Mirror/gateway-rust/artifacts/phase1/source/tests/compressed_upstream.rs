// Author: MingTea. All listeners bind numeric loopback; all identities are synthetic.
//! 上游压缩正文的回归（2026-09-29）。
//!
//! 现场症状：镜像页面提示「无法加载历史记录」。根因是网关向上游声明了
//! `gzip, deflate, br, zstd`，而上游回的是 **br**，网关的流式解码只实现 gzip：
//! 集合 JSON 因此解析失败并**被替换成空信封**，同时把上游的 `content-encoding`
//! 原样留给客户端 —— 浏览器拿 identity 正文去 brotli 解压，前端直接报加载失败。
//!
//! 该 fixture 忠实模拟上游：按请求声明的编码回 br（若声明了 br），否则回 gzip，
//! 并记录网关实际声明的 `accept-encoding`。修复前本用例在集合、创建登记、注入三处
//! 都会失败；修复后网关只声明 gzip 且各分支都能拿到明文。
use axum::{
    extract::Request,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use flate2::{write::GzEncoder, Compression};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use serde_json::{json, Value};
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ADMIN: &str = "compressed-fixture-admin-secret";
const KEY: &str = "compressed-fixture-encryption-key-01";
const CONVERSATION: &str = "3f0c0f5c-1cb0-4b1a-9a6f-0f2a7e1d4c88";

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        writer.write_all(data).unwrap();
    }
    out
}

/// 按请求声明的编码压正文：声明了 br 就回 br（现场形态），否则回 gzip。
fn encode_like_upstream(headers: &HeaderMap, body: &[u8]) -> (&'static str, Vec<u8>) {
    let accept = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if accept.contains("br") {
        ("br", brotli(body))
    } else {
        ("gzip", gzip(body))
    }
}

fn encoded_response(headers: &HeaderMap, content_type: &str, body: Value) -> Response {
    let raw = serde_json::to_vec(&body).unwrap();
    let (encoding, compressed) = encode_like_upstream(headers, &raw);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap()),
            (header::CONTENT_ENCODING, HeaderValue::from_static(encoding)),
        ],
        compressed,
    )
        .into_response()
}

#[derive(Default)]
struct Seen {
    /// `(path, accept-encoding)`：凭据类请求（`/backend-api/me` 等网关自发请求）由
    /// `cloudflare::Answer` 自己解码，声明全量编码是既有行为；需要断言的是**代理路径**。
    accept_encoding: Mutex<Vec<(String, String)>>,
}

async fn upstream(seen: Arc<Seen>, request: Request) -> Response {
    let (parts, _) = request.into_parts();
    let accept = parts
        .headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    seen.accept_encoding
        .lock()
        .unwrap()
        .push((parts.uri.path().to_owned(), accept));
    match (parts.method.as_str(), parts.uri.path()) {
        ("GET", "/backend-api/me") => encoded_response(
            &parts.headers,
            "application/json",
            json!({"email": "fixture@example.invalid", "id": "fixture"}),
        ),
        ("POST", "/backend-api/f/conversation") => encoded_response(
            &parts.headers,
            "application/json",
            json!({"conversation_id": CONVERSATION}),
        ),
        ("GET", path) if path == format!("/backend-api/conversation/{CONVERSATION}") => {
            encoded_response(&parts.headers, "application/json", json!({"id": CONVERSATION}))
        }
        ("GET", "/backend-api/conversations") => encoded_response(
            &parts.headers,
            "application/json",
            json!({"items": [{"id": CONVERSATION, "title": "fixture"}], "total": 1}),
        ),
        ("GET", "/") => {
            let html = b"<html><head><title>fixture</title></head><body>fixture-page</body></html>";
            let (encoding, compressed) = encode_like_upstream(&parts.headers, html);
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static("text/html")),
                    (header::CONTENT_ENCODING, HeaderValue::from_static(encoding)),
                ],
                compressed,
            )
                .into_response()
        }
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}", listener.local_addr().unwrap());
        let state = seen.clone();
        let upstream_task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(move |request: Request| upstream(state.clone(), request)),
            )
            .await
            .unwrap()
        });
        // Django 授权桩：登录需要一份「active」的可信身份。
        let django_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let django_url = format!("http://{}", django_listener.local_addr().unwrap());
        let django_task = tokio::spawn(async move {
            axum::serve(
                django_listener,
                Router::new().route(
                    "/0x/user/gateway-authorization",
                    axum::routing::post(|axum::Json(v): axum::Json<Value>| async move {
                        axum::Json(json!({
                            "active": true, "version": "v1", "user_id": "7", "is_admin": false,
                            "principal_kind": "user", "subject": v["subject"],
                            "expires_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
                        }))
                    }),
                ),
            )
            .await
            .unwrap()
        });

        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            database: dir.path().join("db.sqlite"),
            secret: ADMIN.into(),
            key: KEY.into(),
            django: loopback_url(&django_url).unwrap(),
            upstream: loopback_url(&upstream_url).unwrap(),
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
        let gateway = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", gateway.local_addr().unwrap());
        let gateway_task = tokio::spawn(async move { axum::serve(gateway, app).await.unwrap() });
        Self {
            _dir: dir,
            tasks: vec![upstream_task, django_task, gateway_task],
            base,
            // 刻意不开 reqwest 的自动解压特性：这样断言看到的就是网关真正写出的字节。
            // 默认带浏览器那组 accept-encoding：现场的 br 就是由它触发的。
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .default_headers({
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::ACCEPT_ENCODING,
                        HeaderValue::from_static("gzip, deflate, br, zstd"),
                    );
                    headers
                })
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            seen,
        }
    }

    async fn login(&self) -> String {
        let response = self
            .client
            .post(format!("{}/api/login", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({
                "user_name": "alice",
                "authorization": "signature-v1",
                "access_token": "synthetic-access-alice",
                "chatgpt_account_id": "3",
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
                "extra_cookies": [],
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_str::<Value>(&body).unwrap()["login_url"]
            .as_str()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_owned()
    }

    fn declared_encodings(&self) -> Vec<(String, String)> {
        self.seen.accept_encoding.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn compressed_upstream_bodies_are_decoded_before_inspection() {
    let f = Fixture::new().await;
    let token = f.login().await;

    // 1) 创建响应（含 conversation_id）必须先登记归属，客户端才能读到它。
    let created = f
        .client
        .post(format!("{}/backend-api/f/conversation", f.base))
        .header("x-mirror-token", &token)
        .json(&json!({"messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let scoped = f
        .client
        .get(format!("{}/backend-api/conversation/{CONVERSATION}", f.base))
        .header("x-mirror-token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        scoped.status(),
        StatusCode::OK,
        "创建响应里的 id 必须在交给客户端前完成登记（压缩正文曾让扫描落空）"
    );

    // 2) 集合读：正文必须先是明文才能按 ACL 过滤，且不能再把上游的 content-encoding 留给客户端。
    let list = f
        .client
        .get(format!("{}/backend-api/conversations", f.base))
        .header("x-mirror-token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let encoding = list.headers().get(header::CONTENT_ENCODING).cloned();
    let raw = list.bytes().await.unwrap();
    let payload: Value = serde_json::from_slice(&raw).unwrap_or_else(|cause| {
        panic!(
            "网关写出的集合正文必须是可直接解析的明文（content-encoding={encoding:?}）: {cause}"
        )
    });
    assert_eq!(payload["total"], json!(1));
    assert_eq!(payload["items"].as_array().unwrap().len(), 1);

    // 3) 页面注入同样要作用在明文上，且响应不得保留上游的编码头。
    let page = f
        .client
        .get(format!("{}/", f.base))
        .header("x-mirror-token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(
        page.headers().get(header::CONTENT_ENCODING).is_none(),
        "解码后的正文不能再声明 content-encoding"
    );
    let html = page.text().await.unwrap();
    assert!(html.contains("gateway-user-logout-button"), "{html:.200}");
    assert!(html.contains("fixture-page"));

    // 4) 代理路径只声明网关能解码的 gzip（凭据类自发请求不在此列：它们声明全量
    //    编码并由 `cloudflare::Answer` 自行解码，是既有行为）。
    let proxied: Vec<(String, String)> = f
        .declared_encodings()
        .into_iter()
        .filter(|(path, _)| {
            path == "/" || path.starts_with("/backend-api/conversation") || path == "/backend-api/conversations"
        })
        .collect();
    assert!(!proxied.is_empty(), "代理路径应当被调用过");
    for (path, accept) in proxied {
        assert_eq!(accept, "gzip", "代理路径 {path} 只能声明 gzip");
    }
}

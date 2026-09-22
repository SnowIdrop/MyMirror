use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct Fixture {
    base: String,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn fixture(stub: Router, enable_cdn: bool) -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = loopback_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let stub_task = tokio::spawn(async move { axum::serve(listener, stub).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        database: dir.path().join("fresh.db"),
        secret: "fixture-admin-secret-0001".into(),
        key: "fixture-encryption-key-000000000001".into(),
        django: upstream.clone(),
        upstream: upstream.clone(),
        cdn_upstream: enable_cdn.then_some(upstream),
        cfbypass: None,
        timeout: Duration::from_secs(3),
        mirror_profile: true,
        cookie_secure: false,
    };
    let app = server::router(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Fixture {
        base,
        _dir: dir,
        tasks: vec![task, stub_task],
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

#[tokio::test]
async fn routes_public_assets_without_any_credentials_or_response_cookies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let stub = Router::new().fallback(move |request: Request| {
        let count = count.clone();
        async move {
            count.fetch_add(1, Ordering::SeqCst);
            let path = request.uri().path();
            assert!(matches!(path, "/assets/fixture.js" | "/fixture.css"));
            for header in [
                "authorization",
                "cookie",
                "x-mirror-token",
                "x-api-key",
                "x-forwarded-host",
                "origin",
                "referer",
            ] {
                assert!(!request.headers().contains_key(header), "{header}");
            }
            assert_eq!(request.headers()["if-none-match"], "fixture-etag");
            assert_eq!(
                request.uri().query(),
                Some("v=1&url=https://example.invalid")
            );
            (
                [
                    (
                        "content-type",
                        if path.ends_with(".css") {
                            "text/css"
                        } else {
                            "application/javascript"
                        },
                    ),
                    ("set-cookie", "mirror_token=must-not-escape"),
                    ("etag", "fixture-etag"),
                ],
                "fixture-static",
            )
        }
    });
    let f = fixture(stub, true).await;
    for path in [
        "/assets/fixture.js",
        "/cdn/assets/fixture.js",
        "/cdn/fixture.css",
    ] {
        let response = f
            .client
            .get(format!("{}{path}?v=1&url=https://example.invalid", f.base))
            .bearer_auth("browser-secret")
            .header("cookie", "mirror_token=invalid")
            .header("x-mirror-token", "invalid")
            .header("x-api-key", "private")
            .header("x-forwarded-host", "example.invalid")
            .header("origin", "https://example.invalid")
            .header("referer", "https://example.invalid/private")
            .header("if-none-match", "fixture-etag")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(response.headers()["etag"], "fixture-etag");
        assert_eq!(response.text().await.unwrap(), "fixture-static");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn unknown_paths_methods_and_unconfigured_cdn_never_contact_upstream() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let f = fixture(
        Router::new().fallback(move || {
            count.fetch_add(1, Ordering::SeqCst);
            async { StatusCode::OK }
        }),
        true,
    )
    .await;
    for path in [
        "/assets/private.png",
        "/assets/a.json",
        "/cdn/backend-api/me.js",
        "/cdn//host/a.js",
        "/assets/%2Fsecret.js",
    ] {
        assert_eq!(
            f.client
                .get(format!("{}{path}", f.base))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
    }
    let response = f
        .client
        .post(format!("{}/assets/a.js", f.base))
        .body("must-not-be-forwarded")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 405);
    assert_eq!(response.headers()["allow"], "GET, HEAD");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let f = fixture(Router::new(), false).await;
    assert_eq!(
        f.client
            .get(format!("{}/assets/a.js", f.base))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
}

#[tokio::test]
async fn rejects_redirects_html_and_missing_content_type() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let stub = Router::new()
        .route(
            "/assets/redirect.js",
            get(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/trap")]) }),
        )
        .route(
            "/trap",
            get(move || {
                count.fetch_add(1, Ordering::SeqCst);
                async { "PRIVATE" }
            }),
        )
        .route(
            "/assets/html.js",
            get(|| async {
                (
                    [("content-type", "text/html"), ("set-cookie", "private=1")],
                    "PRIVATE",
                )
            }),
        )
        .route(
            "/assets/missing.js",
            get(|| async { axum::response::Response::new(Body::from("PRIVATE")) }),
        );
    let f = fixture(stub, true).await;
    for name in ["redirect", "html", "missing"] {
        let response = f
            .client
            .get(format!("{}/assets/{name}.js", f.base))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 502);
        assert!(!response.headers().contains_key("location"));
        assert!(!response.headers().contains_key("set-cookie"));
        assert!(!response.text().await.unwrap().contains("PRIVATE"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn preserves_head_cache_and_error_status_without_exposing_error_body() {
    let stub = Router::new()
        .route(
            "/assets/a.js",
            get(|headers: HeaderMap| async move {
                if headers.contains_key("if-none-match") {
                    (StatusCode::NOT_MODIFIED, [("etag", "fixture")]).into_response()
                } else {
                    (
                        [("content-type", "text/javascript; charset=utf-8")],
                        "fixture",
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/assets/error.js",
            get(|| async { (StatusCode::FORBIDDEN, "PRIVATE-ERROR") }),
        );
    let f = fixture(stub, true).await;
    let response = f
        .client
        .head(format!("{}/assets/a.js", f.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.bytes().await.unwrap().is_empty());
    let response = f
        .client
        .get(format!("{}/assets/a.js", f.base))
        .header("if-none-match", "fixture")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 304);
    assert_eq!(response.headers()["etag"], "fixture");
    let response = f
        .client
        .get(format!("{}/assets/error.js", f.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(!response.text().await.unwrap().contains("PRIVATE-ERROR"));
}

#[tokio::test]
async fn forwards_first_chunk_before_upstream_completes() {
    let stub = Router::new().route(
        "/assets/slow.js",
        get(|| async {
            let stream = futures_util::stream::unfold(0, |index| async move {
                match index {
                    0 => Some((Ok::<_, std::io::Error>("first"), 1)),
                    1 => {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Some((Ok("last"), 2))
                    }
                    _ => None,
                }
            });
            (
                [("content-type", "application/javascript")],
                Body::from_stream(stream),
            )
        }),
    );
    let f = fixture(stub, true).await;
    let mut response = tokio::time::timeout(
        Duration::from_secs(1),
        f.client.get(format!("{}/assets/slow.js", f.base)).send(),
    )
    .await
    .unwrap()
    .unwrap();
    let chunk = tokio::time::timeout(Duration::from_secs(1), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(chunk, "first");
}

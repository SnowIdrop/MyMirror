// Author: MingTea. All listeners bind numeric loopback; all credentials are synthetic.
//! 上游连接类失败的回归：部署环境实测存在偶发失败（20 次探测中 4 次在 ~5 秒后失败，
//! 2026-09-29），因此凭据类幂等 GET 必须自动重放一次；持续失败要按
//! `502 upstream_unavailable` 上报，而不是把偶发出网故障说成凭据问题。
//! 用本地 TCP 代理「接受后立刻关闭」模拟该形态，不接触真实上游。
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
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const ADMIN: &str = "upstream-retry-fixture-admin-01";
const KEY: &str = "upstream-retry-fixture-encryption-key-01";
/// NextAuth SessionToken 的形状：JWE、5 段、第 2 段为空（内容为合成值）。
const SESSION: &str =
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..fixture-iv.fixture-ciphertext.fixture-tag";

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

#[derive(Default)]
struct ProxyStats {
    accepted: AtomicUsize,
    dropped: AtomicUsize,
    forwarded: AtomicUsize,
}

/// 迷你 TCP 代理：前 `drop_first` 条连接接受后立即关闭（模拟出网偶发失败），
/// 其余连接原样双向转发到真实上游桩。返回（代理地址，连接统计，任务句柄）。
async fn flaky_proxy(
    target: String,
    drop_first: usize,
) -> (String, Arc<ProxyStats>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stats = Arc::new(ProxyStats::default());
    let counted = stats.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let target = target.clone();
            let stats = counted.clone();
            tokio::spawn(async move {
                if stats.accepted.fetch_add(1, Ordering::SeqCst) < drop_first {
                    // 不发任何字节就关闭：客户端侧表现为传输层失败。
                    stats.dropped.fetch_add(1, Ordering::SeqCst);
                    let _ = inbound.shutdown().await;
                    return;
                }
                let Ok(mut outbound) = tokio::net::TcpStream::connect(&target).await else {
                    return;
                };
                stats.forwarded.fetch_add(1, Ordering::SeqCst);
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    (url, stats, task)
}

/// 上游桩：`api/auth/session` 认合成的 SessionToken，`me` 与 `accounts/check` 固定成功。
async fn upstream(request: Request) -> Response {
    let (parts, _) = request.into_parts();
    match parts.uri.path() {
        "/api/auth/session" => {
            axum::Json(json!({"accessToken": "exchanged-access-token"})).into_response()
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
    stats: Arc<ProxyStats>,
    base: String,
    client: reqwest::Client,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    /// `drop_first` 条上游连接被立即关闭；其余转发到桩。
    async fn new(drop_first: usize) -> Self {
        let upstream_url = serve(Router::new().fallback(upstream)).await;
        // TcpStream 需要裸 host:port（`serve` 返回的是完整 URL）。
        let upstream_addr = upstream_url
            .0
            .trim_start_matches("http://")
            .to_owned();
        let (proxy_url, stats, proxy_task) = flaky_proxy(upstream_addr, drop_first).await;
        let django_url = {
            let router = Router::new().fallback(|request: Request| async move {
                if request.uri().path() == "/0x/user/gateway-acl-mapping" {
                    return axum::Json(json!({"users": [], "accounts": []})).into_response();
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
            // 上游指向「会偶发关闭连接」的代理，桩在它后面。
            upstream: loopback_url(&proxy_url).unwrap(),
            // 这些用例不经过 WS 桥接：给一个不会用到的回环 WS 基址即可。
            ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
            cdn_upstream: None,
            ab_upstream: None,
            public_prefix_base: None,
            cfbypass: None,
            timeout: Duration::from_secs(5),
            mirror_profile: true,
            cookie_secure: false,
            allow_anonymous_session: false,
        };
        let app = server::router(config).await.unwrap();
        let gateway = serve(app).await;
        Self {
            _dir: dir,
            tasks: vec![upstream_url.1, proxy_task, django_url.1, gateway.1],
            stats,
            base: gateway.0,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }

    async fn import(&self) -> (StatusCode, Value) {
        let response = self
            .client
            .post(format!("{}/api/get-user-info", self.base))
            .bearer_auth(ADMIN)
            .json(&json!({"chatgpt_token": SESSION}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap())
    }
}

#[tokio::test]
async fn a_dropped_connection_is_retried_once_and_the_import_succeeds() {
    let f = Fixture::new(1).await;
    let (status, body) = f.import().await;
    assert_eq!(
        status,
        StatusCode::OK,
        "accepted={} dropped={} forwarded={} body={body}",
        f.stats.accepted.load(Ordering::SeqCst),
        f.stats.dropped.load(Ordering::SeqCst),
        f.stats.forwarded.load(Ordering::SeqCst)
    );
    assert_eq!(body["access_token"], json!("exchanged-access-token"));
    assert!(
        f.stats.dropped.load(Ordering::SeqCst) == 1
            && f.stats.forwarded.load(Ordering::SeqCst) >= 1,
        "首条连接被关闭后必须重放一次并成功走通：dropped={} forwarded={}",
        f.stats.dropped.load(Ordering::SeqCst),
        f.stats.forwarded.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn a_persistent_connection_failure_reports_upstream_unavailable() {
    let f = Fixture::new(usize::MAX).await;
    let (status, body) = f.import().await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("上游连接失败"), "{message}");
    assert!(message.contains("已自动重试一次"), "{message}");
    assert!(message.contains("请稍后重试"), "{message}");
    assert!(!message.contains("<html"), "{message}");
    // 连接类失败不能被说成凭据结论。
    assert!(!message.contains("无法换取"), "{message}");
    assert!(!message.contains("校验失败"), "{message}");
    // 首轮 + 重试：正好两次，不做无界重试。
    assert_eq!(f.stats.accepted.load(Ordering::SeqCst), 2);
}

//! 上游 cookie jar 的合成回环回归（本机 fixture，不接触真实 chatgpt.com，不使用任何
//! 真实账号或令牌）：完整 `set-cookie` 捕获与回注、作用域（域 / 安全位 / 路径 / 过期）
//! 过滤、会话列与号池双存储的写入边界，以及 CF 刷新后旧 CF 条目的清理。
use axum::{
    body::to_bytes,
    extract::Request,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use mirror_gateway::{
    config::{loopback_url, Config},
    crypto::Crypto,
    server,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const ADMIN: &str = "upstream-jar-admin-secret";
const KEY: &str = "upstream-jar-fixture-encryption-key-0001";
/// 上游账号名：登录时网关用它作为 `chatgpt_username`（来自 `/backend-api/me` 的 email）。
const ACCOUNT: &str = "fixture@example.invalid";
/// 挑战次数哨兵：一直用实测挑战形态拒绝。
const ALWAYS: usize = usize::MAX;

type Events = Arc<Mutex<Vec<Value>>>;

/// 合成上游：记录每次请求的 cookie 面，并按夹具配置附加 `set-cookie`。
#[derive(Default)]
struct Upstream {
    events: Events,
    set_cookie: Mutex<Vec<String>>,
    challenges_left: AtomicUsize,
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

    fn set_cookie(&self, values: impl IntoIterator<Item = &'static str>) {
        *self.set_cookie.lock().unwrap() = values.into_iter().map(str::to_owned).collect();
    }

    fn clear_set_cookie(&self) {
        self.set_cookie.lock().unwrap().clear();
    }
}

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

async fn chat_upstream(state: Arc<Upstream>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let _ = to_bytes(body, 1024 * 1024).await.unwrap();
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
        "device_header": header("oai-device-id"),
    }));
    if state.take_challenge() {
        return (
            StatusCode::FORBIDDEN,
            [("cf-mitigated", "challenge")],
            "<html>Just a moment...</html>",
        )
            .into_response();
    }
    let mut response = match parts.uri.path() {
        "/backend-api/me" => axum::Json(json!({"email":ACCOUNT})).into_response(),
        path => axum::Json(json!({"path":path})).into_response(),
    };
    for raw in state.set_cookie.lock().unwrap().iter() {
        response
            .headers_mut()
            .append("set-cookie", HeaderValue::from_str(raw).unwrap());
    }
    response
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
    /// `with_cfbypass` 时挂一个固定返回 `cf_clearance=CF-FRESH` 的 cfbypass 桩。
    async fn new(with_cfbypass: bool) -> Self {
        let upstream = Arc::new(Upstream::default());
        let chat_url = {
            let state = upstream.clone();
            serve(
                Router::new()
                    .fallback(move |request: Request| chat_upstream(state.clone(), request)),
            )
            .await
        };
        let cfbypass_url = {
            serve(Router::new().fallback(|| async {
                axum::Json(json!({
                    "user_agent": "fixture-agent",
                    "cookies": [{"name": "cf_clearance", "value": "CF-FRESH"}],
                }))
            }))
            .await
        };
        let django_url = {
            serve(Router::new().fallback(|request: Request| async move {
                if request.uri().path() == "/0x/user/gateway-authorization" {
                    // 身份字段恒来自本响应；subject 回显请求里的 subject，与真实 Django 同形。
                    let (_, body) = request.into_parts();
                    let body = to_bytes(body, 64 * 1024).await.unwrap();
                    let input: Value = serde_json::from_slice(&body).unwrap_or_default();
                    let subject = input["subject"].as_str().unwrap_or("");
                    let user_id = if subject == "alice" { "11" } else { "12" };
                    return axum::Json(json!({
                        "active": true,
                        "version": "v1",
                        "user_id": user_id,
                        "is_admin": false,
                        "principal_kind": "user",
                        "subject": subject,
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
            // 本批用例不经过 WS 桥接：给一个不会用到的回环 WS 基址即可。
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

    /// 登录指定镜像用户（同一上游账号），返回 mirror_token。
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
                // 会话凭据里刻意带一个上游不会下发的名字：它必须留在会话侧，不进号池行。
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

    async fn me(&self, token: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/backend-api/me", self.base))
            .header("x-mirror-token", token)
            .send()
            .await
            .unwrap()
    }

    /// 号池账号行：`extra_cookies` 写明文 JSON（与导入的历史数据同形，解密为透传）。
    fn seed_account_cookies(&self, cookies: Value) {
        let conn = Connection::open(self._dir.path().join("db.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO chatgpt_accounts (chatgpt_username, access_token, extra_cookies) \
             VALUES (?1, 'plain-access', ?2)",
            rusqlite::params![ACCOUNT, cookies.to_string()],
        )
        .unwrap();
    }

    /// 会话 jar 列的密文原文（`upstream_cookies`，本候选新增列）。
    fn session_jar_column(&self, user: &str) -> Option<String> {
        let conn = Connection::open(self._dir.path().join("db.sqlite")).unwrap();
        conn.query_row(
            "SELECT upstream_cookies FROM gateway_sessions WHERE user_name = ?1",
            [user],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// 会话 jar 列解密后的条目。
    fn session_jar(&self, user: &str) -> Vec<Value> {
        let stored = self
            .session_jar_column(user)
            .unwrap_or_else(|| panic!("{user} 的会话应落 jar"));
        let crypto = Crypto::new(KEY).unwrap();
        serde_json::from_str(&crypto.decrypt(&stored).unwrap()).unwrap()
    }

    /// 号池账号行解密后的条目。
    fn account_jar(&self) -> Vec<Value> {
        let conn = Connection::open(self._dir.path().join("db.sqlite")).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT extra_cookies FROM chatgpt_accounts WHERE chatgpt_username = ?1",
                [ACCOUNT],
                |row| row.get(0),
            )
            .unwrap();
        let crypto = Crypto::new(KEY).unwrap();
        serde_json::from_str(&crypto.decrypt(&stored).unwrap()).unwrap()
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

    fn clear_calls(&self) {
        self.upstream.events.lock().unwrap().clear();
    }
}

fn last(calls: &[Value]) -> &Value {
    calls.last().expect("夹具应至少记录一次上游调用")
}

/// 会话列里出现的 cookie 名字（按落库顺序）。
fn names(entries: &[Value]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| entry["name"].as_str().map(str::to_owned))
        .collect()
}

/// 名字表：上游实测会下发的 cookie 全部捕获并按作用域回注；镜像自有与浏览器偏好名字
/// 既不落库也不回注。
#[tokio::test]
async fn captured_name_table_is_replayed_and_excluded_names_are_ignored() {
    let fixture = Fixture::new(false).await;
    let token = fixture.login("alice").await;
    fixture.upstream.set_cookie([
        // 2026-09-24 真实上游实测下发的名字（页面/哨兵给 oai-did、oai-sc，边缘给其余）。
        "oai-did=DID-1; Path=/; HttpOnly; SameSite=None",
        "oai-sc=SC-1; Path=/",
        "__oailb=LB-1; Path=/; HttpOnly",
        "__cf_bm=BM-1; Path=/; HttpOnly",
        "__cflb=LB-2; Path=/; HttpOnly",
        "_cfuvid=UV-1; Path=/",
        // 镜像自有（is_mirror_local）与浏览器偏好名字：绝不能落库或回注。
        "mirror_token=LEAK-1; Path=/",
        "gateway_user_name=LEAK-2; Path=/",
        "oai_consent_analytics=LEAK-3; Path=/",
    ]);
    fixture.clear_calls();

    assert_eq!(fixture.me(&token).await.status(), StatusCode::OK);
    fixture.upstream.clear_set_cookie();
    assert_eq!(fixture.me(&token).await.status(), StatusCode::OK);

    let call = last(&fixture.calls("/backend-api/me")).clone();
    let cookie = call["cookie"].as_str().unwrap();
    for pair in [
        "oai-did=DID-1",
        "oai-sc=SC-1",
        "__oailb=LB-1",
        "__cf_bm=BM-1",
        "__cflb=LB-2",
        "_cfuvid=UV-1",
    ] {
        assert!(cookie.contains(pair), "应回注 {pair}: {call}");
    }
    for leaked in ["LEAK-1", "LEAK-2", "LEAK-3"] {
        assert!(!cookie.contains(leaked), "不得回注被排除的 cookie: {call}");
    }
    assert_eq!(
        call["device_header"],
        json!("DID-1"),
        "设备头取 jar 里的 oai-did: {call}"
    );

    let stored = names(&fixture.session_jar("alice"));
    assert_eq!(
        stored,
        vec!["oai-did", "oai-sc", "__oailb", "__cf_bm", "__cflb", "_cfuvid"],
        "会话列只落实测捕获条目，被排除的名字根本不进 jar"
    );
}

/// 作用域：捕获不看作用域（上游给什么就记住什么），回注严格按域 / 安全位 / 路径 / 过期过滤。
#[tokio::test]
async fn injection_filters_by_domain_secure_path_and_expiry() {
    let fixture = Fixture::new(false).await;
    let token = fixture.login("alice").await;
    fixture.upstream.set_cookie([
        "plain=YES; Path=/",
        "path_ok=YES; Path=/backend-api",
        // 域不属于上游主机：host_only=false 的后缀也不匹配。
        "other_domain=NO; Domain=invalid.example; Path=/",
        // 安全位：fixture 上游是明文 http，不得发送。
        "secure_only=NO; Secure; Path=/",
        // 路径不覆盖本次请求。
        "path_other=NO; Path=/other",
        // Max-Age=0 是删除指令，等价于从未存在。
        "deleted=NO; Path=/; Max-Age=0",
    ]);
    fixture.clear_calls();

    assert_eq!(fixture.me(&token).await.status(), StatusCode::OK);
    fixture.upstream.clear_set_cookie();
    assert_eq!(fixture.me(&token).await.status(), StatusCode::OK);

    let call = last(&fixture.calls("/backend-api/me")).clone();
    let cookie = call["cookie"].as_str().unwrap();
    for pair in ["plain=YES", "path_ok=YES"] {
        assert!(cookie.contains(pair), "应回注 {pair}: {call}");
    }
    for absent in ["other_domain", "secure_only", "path_other", "deleted"] {
        assert!(!cookie.contains(absent), "不得回注 {absent}: {call}");
    }

    // 捕获与回注是两件事：作用域外的条目照样留在 jar 里（换个 https/路径就适用），
    // 只有删除指令不留条目。
    let stored = names(&fixture.session_jar("alice"));
    assert_eq!(
        stored,
        vec![
            "plain",
            "path_ok",
            "other_domain",
            "secure_only",
            "path_other"
        ],
        "删除指令不进 jar"
    );
}

/// 号池一侧只写实测捕获条目：会话凭据留在会话侧，同账号的其它镜像用户拿到的是同一个
/// 账号级 cookie 集合，Django 行内的未知字段原样保留。
#[tokio::test]
async fn account_pool_is_shared_without_taking_session_cookies() {
    let fixture = Fixture::new(false).await;
    fixture.seed_account_cookies(json!([
        {"name":"__oailb","value":"POOL-LB","django_note":"keep-me"}
    ]));
    let alice = fixture.login("alice").await;
    fixture
        .upstream
        .set_cookie(["oai-did=POOL-DID; Path=/; HttpOnly"]);
    fixture.clear_calls();
    assert_eq!(fixture.me(&alice).await.status(), StatusCode::OK);

    let pool = fixture.account_jar();
    let pool_names = names(&pool);
    assert!(
        !pool_names.contains(&"probe_extra".to_owned()),
        "镜像会话凭据不得写进号池行: {pool:?}"
    );
    assert_eq!(pool[0]["value"], json!("POOL-LB"));
    assert_eq!(
        pool[0]["django_note"],
        json!("keep-me"),
        "行内未知字段必须保留: {pool:?}"
    );
    assert!(pool_names.contains(&"oai-did".to_owned()), "{pool:?}");

    // 另一个镜像用户：自己的会话凭据 + 号池同款设备标识。
    fixture.upstream.clear_set_cookie();
    let bob = fixture.login("bob").await;
    fixture.clear_calls();
    assert_eq!(fixture.me(&bob).await.status(), StatusCode::OK);
    let call = last(&fixture.calls("/backend-api/me")).clone();
    let cookie = call["cookie"].as_str().unwrap();
    assert!(cookie.contains("probe_extra=bob"), "{call}");
    assert!(
        !cookie.contains("probe_extra=alice"),
        "不得串用他人会话凭据: {call}"
    );
    assert!(cookie.contains("__oailb=POOL-LB"), "{call}");
    assert!(cookie.contains("oai-did=POOL-DID"), "{call}");
    assert_eq!(call["device_header"], json!("POOL-DID"), "{call}");
    // bob 自己没有捕获任何东西：会话列保持 NULL，不凭空落库。
    assert_eq!(fixture.session_jar_column("bob"), None);
}

/// CF 刷新后必须丢掉 jar 里的旧 CF 条目：jar 在 Cookie 头里排在 CF 缓存之前，
/// 留着旧 `cf_clearance` 会让刷新后的重放继续被判挑战。
#[tokio::test]
async fn cloudflare_refresh_drops_stale_stored_cloudflare_cookies() {
    let fixture = Fixture::new(true).await;
    let token = fixture.login("alice").await;
    fixture
        .upstream
        .set_cookie(["cf_clearance=STALE; Path=/; HttpOnly"]);
    fixture.clear_calls();
    assert_eq!(fixture.me(&token).await.status(), StatusCode::OK);
    fixture.upstream.clear_set_cookie();

    // 持续一次挑战：GET 刷新一次 cfbypass 并重放一次。
    fixture.upstream.challenges_left.store(1, Ordering::SeqCst);
    fixture.clear_calls();
    assert_eq!(fixture.me(&token).await.status(), StatusCode::OK);

    let calls = fixture.calls("/backend-api/me");
    assert_eq!(calls.len(), 2, "首轮挑战后必须重放一次");
    assert!(
        calls[0]["cookie"].as_str().unwrap().contains("STALE"),
        "首轮带的是捕获到的旧值: {}",
        calls[0]
    );
    let replayed = calls[1]["cookie"].as_str().unwrap();
    assert!(replayed.contains("cf_clearance=CF-FRESH"), "{replayed}");
    assert!(
        !replayed.contains("STALE"),
        "刷新后的重放不得再带旧 CF 值: {replayed}"
    );
    assert_eq!(
        names(&fixture.session_jar("alice")),
        Vec::<String>::new(),
        "旧 CF 条目必须从落库 jar 里一并清掉"
    );
}

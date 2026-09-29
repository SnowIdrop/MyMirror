// Author: MingTea. All listeners bind numeric loopback; all identities are synthetic.
//! 注入脚本控制条登出入口（`GET /api/user-logout`）的回归。
//!
//! 该路径来自原版客户端脚本本身（`src/assets/gateway-client.html` 的
//! `_gwSessionLogoutPath`，由 evidence/proxy-v3-original-010 逐字节提取，按钮文案
//! 「返回后台 / 换号」），客户端的用法决定了两条契约：不要求会话有效（`user-blocked-paths`
//! 返回 401 时正是它被调用的场景），并且必须把浏览器交回管理后台。
use axum::{routing::post, Json, Router};
use mirror_gateway::{
    config::{loopback_url, Config},
    server,
};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 管理后台地址是否配置，决定跳转目标是绝对地址（跨源部署）还是原版的 `/admin#/`。
async fn fixture(admin_public_url: Option<&str>) -> (String, tempfile::TempDir, Vec<tokio::task::JoinHandle<()>>) {
    let stub = Router::new()
        .route(
            "/0x/user/gateway-authorization",
            post(|Json(v): Json<Value>| async move {
                Json(json!({
                    "active": true, "version": "v1", "user_id": "7", "is_admin": false,
                    "principal_kind": "user", "subject": v["subject"],
                    "expires_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
                }))
            }),
        )
        // 会话存活探针：由上游桩回 200，网关在会话缺失时改回本地 401。
        // `email` 同时是登录校验读取的字段（缺它会得到 400）。
        .route(
            "/backend-api/me",
            axum::routing::get(|| async {
                Json(json!({"email": "fixture@example.invalid", "id": "fixture"}))
            }),
        );
    let stub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_url = format!("http://{}", stub_listener.local_addr().unwrap());
    let stub_task = tokio::spawn(async move { axum::serve(stub_listener, stub).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        database: dir.path().join("db.sqlite"),
        secret: "logout-fixture-admin-secret-01".into(),
        key: "logout-fixture-encryption-key-00001".into(),
        django: loopback_url(&stub_url).unwrap(),
        upstream: loopback_url(&stub_url).unwrap(),
        ws_upstream: url::Url::parse("ws://127.0.0.1:1/").unwrap(),
        cdn_upstream: None,
        ab_upstream: None,
        public_prefix_base: None,
        cfbypass: None,
        timeout: Duration::from_secs(3),
        mirror_profile: true,
        cookie_secure: false,
        allow_anonymous_session: false,
        admin_public_url: admin_public_url.map(str::to_owned),
    };
    let app = server::router(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let gateway = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, dir, vec![stub_task, gateway])
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// 登录拿 mirror_token（与 Django `/api/login` 同一载荷形状）。
async fn login(base: &str) -> String {
    let body = json!({"user_name":"alice","authorization":"signature-v1","access_token":"synthetic-access-token",
        "login_mode":"api","isolated_session":true,"mcp_isolation":true,"skills_isolation":true,
        "model_isolation":true,"daily_quota":20,"monthly_quota":100,"model_allowed_ids":["fixture-model"],
        "model_rate_limits":{},"limits":[],"mcp_allowed_ids":[],"skills_allowed_ids":[],
        "chatgpt_account_id":"3"});
    let result: Value = client()
        .post(format!("{base}/api/login"))
        .bearer_auth("logout-fixture-admin-secret-01")
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    result["login_url"]
        .as_str()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .to_owned()
}

fn cleared_cookie_names(response: &reqwest::Response) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| value.contains("Max-Age=0"))
        .filter_map(|value| value.split('=').next().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn logout_clears_the_session_and_returns_to_the_configured_admin_origin() {
    let (base, _dir, tasks) = fixture(Some("http://127.0.0.1:40003/admin/")).await;
    let client = client();
    let token = login(&base).await;
    // 登录后会话有效：业务面转发到上游桩。
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("cookie", format!("mirror_token={token}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let response = client
        .get(format!("{base}/api/user-logout"))
        .header("cookie", format!("mirror_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()["location"],
        "http://127.0.0.1:40003/admin/",
        "跨源部署必须把浏览器交回管理后台"
    );
    let cleared = cleared_cookie_names(&response);
    for name in ["mirror_token", "login_mode", "chatgpt_username"] {
        assert!(cleared.contains(&name.to_owned()), "{name} 未清理: {cleared:?}");
    }

    // 会话行已删除：同一个 token 再访问业务面必须是未登录。
    assert_eq!(
        client
            .get(format!("{base}/backend-api/me"))
            .header("cookie", format!("mirror_token={token}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // 重复点击按钮必须仍然可用（客户端在会话失效时也会跳到这里）。
    assert_eq!(
        client
            .get(format!("{base}/api/user-logout"))
            .header("cookie", format!("mirror_token={token}"))
            .send()
            .await
            .unwrap()
            .status(),
        302
    );
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn logout_without_a_config_keeps_the_same_origin_relative_redirect() {
    let (base, _dir, tasks) = fixture(None).await;
    let client = client();
    // 原版单端口部署：网关自己托管 /admin，相对跳转即同源。
    let response = client
        .get(format!("{base}/api/user-logout"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(response.headers()["location"], "/admin#/");
    for task in tasks {
        task.abort();
    }
}

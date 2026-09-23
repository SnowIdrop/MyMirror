//! Fixed server-side read transport. Nodes/impersonation and proxy-bound CF
//! clearance are not verified and fail closed rather than silently going direct.
use super::*;

pub(super) struct Egress {
    pub binding: String,
    pub client: reqwest::Client,
}

pub(super) fn normalized(config: &Config, setting: &Value, node: Option<i64>) -> Result<Value> {
    anyhow::ensure!(node.is_none(), "指定代理节点尚未实现，拒绝回退默认出口");
    let enabled = match setting.get("enabled") {
        None => false,
        Some(value) => value.as_bool().context("代理 enabled 必须是布尔值")?,
    };
    let mode = match setting.get("transport_mode") {
        None => "reqwest",
        Some(value) => value.as_str().context("代理 transport_mode 无效")?,
    };
    anyhow::ensure!(
        mode == "reqwest",
        "指纹传输兼容尚未验证，不允许退化为普通 HTTP"
    );
    if let Some(nodes) = setting.get("nodes") {
        anyhow::ensure!(
            nodes.as_array().is_some_and(Vec::is_empty),
            "代理节点选择尚未实现"
        );
    }
    if !enabled {
        return Ok(json!({"enabled":false,"transport_mode":"reqwest"}));
    }
    anyhow::ensure!(
        config.cfbypass.is_none(),
        "代理出口与 CF 凭据绑定尚未验证，拒绝使用旧 clearance"
    );
    let url = crate::config::loopback_url(setting["proxy_url"].as_str().context("缺少代理地址")?)?;
    anyhow::ensure!(
        url.path() == "/" && url.query().is_none() && url.fragment().is_none(),
        "代理地址不能带路径、查询或片段"
    );
    let mut normalized =
        json!({"enabled":true,"proxy_url":url.as_str(),"transport_mode":"reqwest"});
    for key in ["username", "password"] {
        normalized[key] = match setting.get(key) {
            None | Some(Value::Null) => Value::Null,
            Some(Value::String(value)) if value.is_empty() => Value::Null,
            Some(Value::String(value)) => json!(value),
            _ => anyhow::bail!("代理凭据字段必须是字符串或 null"),
        };
    }
    anyhow::ensure!(
        normalized["password"].is_null() || normalized["username"].is_string(),
        "代理密码需要用户名"
    );
    Ok(normalized)
}

fn definition(db: &Database, config: &Config, node: Option<i64>) -> Result<Value> {
    let setting = db
        .get_setting("mirror_proxy")?
        .unwrap_or_else(default_proxy);
    let profile = normalized(config, &setting, node)?;
    let generation = db
        .get_setting("rust_egress_epoch")?
        .unwrap_or(json!("initial"));
    anyhow::ensure!(
        generation.as_str().is_some_and(|v| !v.is_empty()),
        "出口配置代次无效"
    );
    Ok(
        json!({"generation":generation,"proxy":profile,"upstream":config.upstream.as_str(),
        "cdn":config.cdn_upstream.as_ref().map(url::Url::as_str),"cf":config.cfbypass.as_ref().map(url::Url::as_str),
        "transport_profile":"reqwest-read-v1-no-retry-no-redirect","user_agent":proxy::DEFAULT_USER_AGENT}),
    )
}

pub(super) fn binding(db: &Database, config: &Config, node: Option<i64>) -> Result<String> {
    Ok(sha256_hex(&definition(db, config, node)?.to_string()))
}

/// Call inside the caller's settings/restore transaction, so an old saved epoch
/// cannot reactivate a session after an A -> B -> A profile transition.
pub(super) fn rotate_epoch(conn: &rusqlite::Connection) -> Result<()> {
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let epoch: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    conn.execute("INSERT INTO gateway_settings(key,value,updated_at) VALUES('rust_egress_epoch',?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", params![json!(epoch).to_string(),now()])?;
    Ok(())
}

pub(super) fn client(config: &Config, profile: &Value) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .user_agent(proxy::DEFAULT_USER_AGENT)
        .timeout(config.timeout);
    if profile["enabled"] == true {
        let mut proxy =
            reqwest::Proxy::all(profile["proxy_url"].as_str().context("缺少代理地址")?)?;
        if let Some(user) = profile["username"].as_str() {
            proxy = proxy.basic_auth(user, profile["password"].as_str().unwrap_or(""));
        }
        builder = builder.proxy(proxy);
    }
    builder.build().context("构建固定出口客户端失败")
}

pub(super) fn load(db: &Database, config: &Config, node: Option<i64>) -> Result<Egress> {
    let definition = definition(db, config, node)?;
    Ok(Egress {
        binding: sha256_hex(&definition.to_string()),
        client: client(config, &definition["proxy"])?,
    })
}

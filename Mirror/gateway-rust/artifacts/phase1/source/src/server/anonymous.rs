// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/anonymous.rs
// Created : 2026-09-23
// Summary : 全局共享的匿名上游身份（cfbypass 的 Cloudflare cookies），
//           持久化在 gateway_settings['anonymous_upstream']（整值加密）。
// 证据来源：2026-09-23 本机实测（Windows 出口 + 本地 cfbypass + 真实 chatgpt.com）
//           - 不带 Cloudflare cookies 直连 https://chatgpt.com/ 返回
//             403 + `cf-mitigated: challenge`；
//           - 带 cfbypass cookies 时页面、匿名对话（SSE）与匿名上传全部通过，
//             匿名 `/api/auth/session` 返回 200 但不含 accessToken —— accessToken
//             只属于真实账号登录（产品口径），匿名链路以 cookies 为唯一凭据；
//           - 原版网关把上游视为唯一身份：匿名通道为 /backend-anon/*，
//             多镜像用户共享同一上游身份，隔离由本地归属表负责（报告 03 §7.3）。
// -----------------------------------------------------------------------------

//! 匿名身份不是新的用户系统：它只是一份共享上游 Cookie 缓存。
//! 取不到时按“无凭据匿名请求”继续转发，绝不伪造成功响应或回退到其它账号。

use super::*;

/// settings 键；`is_encrypted_setting_key` 已把它列入整值加密。
pub(super) const SETTING_KEY: &str = "anonymous_upstream";

/// 匿名会话在 `gateway_sessions.chatgpt_username` 使用的保留标签。
/// 不含 `@`，与真实上游邮箱账号不可能冲突。
pub(super) const ACCOUNT: &str = "anonymous";

/// 匿名会话的 `gateway_sessions.login_mode` 取值。
pub(super) const LOGIN_MODE: &str = "anonymous";

#[derive(Clone)]
pub(super) struct Identity {
    /// 上游 Cookie 必须整组下发（`__cf_bm` 与 `cf_clearance` 共同通过 Cloudflare）；
    /// 这与带凭据会话只补 `cf_clearance` 的既有行为不同，调用方见 proxy::send_chat。
    pub cookies: Vec<(String, String)>,
}

fn parse(raw: &Value, context: &str) -> Result<Identity> {
    let cookies = raw["cookies"]
        .as_array()
        .with_context(|| format!("{context}: cookies 必须是数组"))?
        .iter()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?.trim();
            let value = entry.get("value")?.as_str()?;
            (!name.is_empty() && !value.is_empty()).then(|| (name.to_owned(), value.to_owned()))
        })
        .collect::<Vec<_>>();
    Ok(Identity { cookies })
}

/// 读取已保存的匿名身份；未保存或结构损坏都视为“没有可用身份”。
/// 损坏时记录错误并返回 None，由调用方重新获取，而不是让请求 500。
pub(super) async fn load(app: &App) -> Option<Identity> {
    let stored = {
        let db = app.db.lock().await;
        db.get_setting(SETTING_KEY)
    };
    match stored {
        Ok(Some(value)) => match parse(&value, SETTING_KEY) {
            Ok(identity) => Some(identity),
            Err(cause) => {
                tracing::error!(module = "gateway", error = %cause, "匿名上游身份损坏，改为重新获取");
                None
            }
        },
        Ok(None) => None,
        Err(cause) => {
            tracing::error!(module = "gateway", error = %cause, "读取匿名上游身份失败");
            None
        }
    }
}

/// 删除已保存的匿名身份；`proxy::chat_forward` 判定为实测的 Cloudflare 挑战
/// （403 + `cf-mitigated: challenge`）时调用，让下一次请求重新走 cfbypass
/// （本请求不做自动重放）。
pub(super) async fn invalidate(app: &App) {
    let db = app.db.lock().await;
    let result = db.conn.execute(
        "DELETE FROM gateway_settings WHERE key=?1",
        params![SETTING_KEY],
    );
    if let Err(cause) = result {
        tracing::error!(module = "gateway", error = %cause, "清除匿名上游身份失败");
    }
}

/// 重新获取匿名身份：走 cfbypass 并把同一份结果记入共享 CF 状态与 settings。
/// `CF_BYPASS_URL` 缺失由 cfbypass 调用层负责报错，这里不再重复判定。
async fn obtain(app: &App) -> Result<Identity> {
    let cookies = app.cloudflare.force(app).await?;
    Ok(store(app, &cookies).await)
}

/// 把一组 Cloudflare cookies 作为匿名身份持久化。
/// 匿名身份与 CF 状态来自同一份 cfbypass 响应，因此挑战重放可以直接复用刷新结果，
/// 不必再拉起第二次浏览器。
pub(super) async fn store(app: &App, cookies: &[(String, String)]) -> Identity {
    let identity = Identity {
        cookies: cookies.to_vec(),
    };
    let stored = {
        let db = app.db.lock().await;
        db.set_setting(
            SETTING_KEY,
            &json!({
                "cookies": identity.cookies.iter()
                    .map(|(name, value)| json!({"name":name,"value":value}))
                    .collect::<Vec<_>>(),
            }),
        )
    };
    if let Err(cause) = stored {
        tracing::error!(module = "gateway", error = %cause, "匿名上游身份落库失败");
    }
    identity
}

/// 取得可用匿名身份：已有 cookies 直接复用，否则重新获取。
/// 获取失败时返回 None，调用方按无凭据匿名请求转发，由上游给出真实答复。
pub(super) async fn ensure(app: &App) -> Option<Identity> {
    if let Some(identity) = load(app).await {
        if !identity.cookies.is_empty() {
            return Some(identity);
        }
    }
    match obtain(app).await {
        Ok(identity) => Some(identity),
        Err(cause) => {
            tracing::error!(module = "gateway", error = %cause, "匿名上游身份获取失败");
            None
        }
    }
}

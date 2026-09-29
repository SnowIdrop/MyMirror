// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/acl_admin.rs
// Created : 2026-09-23
// Summary : ACL 管理 API 组：资源查询、未登记资源认领、授予/撤销共享、移动到项目、
//           审计游标读取。操作者身份来自固定 Django 源（要求 is_admin），服务密钥
//           本身不代表管理员。证据来源：integrations/acl/CONTRACT_V1.md 的失败语义
//           表与 src/resource_acl.rs 的自由函数契约。
// -----------------------------------------------------------------------------

//! ACL 管理端点（挂载于 `server`，由父模块 `mod acl_admin;` +
//! `require_admin` 中间件接线）。所有入口都先做一次 fresh 管理身份校验，
//! 任何失败都明确拒绝，不用服务密钥补造管理员。

use super::*;
use crate::resource_acl::{AclError, ResourceKey, ResourceKind};
use serde::Deserialize;

/// 管理端返回类型：错误统一走 [`ApiError`]，与文件外其它管理端点的形状一致。
type AclResult = std::result::Result<Json<Value>, ApiError>;

/// 管理端 JSON 错误：状态码稳定、正文只含本地文案。
fn acl_error(cause: AclError) -> ApiError {
    match cause {
        AclError::Unauthorized => error_code(
            StatusCode::UNAUTHORIZED,
            "请求方身份无效或已失效",
            "acl_identity_invalid",
        ),
        AclError::Forbidden => error_code(
            StatusCode::FORBIDDEN,
            "需要管理员身份才能执行该操作",
            "acl_admin_required",
        ),
        AclError::UnknownResource => error_code(
            StatusCode::NOT_FOUND,
            "资源不存在或不属于当前账号",
            "acl_not_found",
        ),
        AclError::InvalidInput => error_code(
            StatusCode::BAD_REQUEST,
            "请求参数无效",
            "acl_invalid_input",
        ),
        AclError::InvalidOperation => error_code(
            StatusCode::BAD_REQUEST,
            "该资源不支持此操作",
            "acl_invalid_operation",
        ),
        AclError::CrossAccount => error_code(
            StatusCode::BAD_REQUEST,
            "资源与目标项目不属于同一上游账号",
            "acl_cross_account",
        ),
        AclError::AlreadyRegistered => error_code(
            StatusCode::CONFLICT,
            "资源已有归属，认领不会覆盖",
            "acl_already_registered",
        ),
        AclError::Sqlite(cause) => {
            tracing::error!(module = "gateway", error = %cause, "ACL 管理操作失败");
            error_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "ACL 存储暂时不可用",
                "acl_storage_unavailable",
            )
        }
    }
}

/// 管理入口的操作者：服务密钥（中间件已校验）+ 请求方 authorization/subject +
/// 固定 Django 源 fresh 校验 + `is_admin`。
async fn operator(app: &App, headers: &HeaderMap) -> std::result::Result<RequestIdentity, ApiError> {
    match request_admin_identity(app, headers).await {
        Ok(Some(identity)) => Ok(identity),
        Ok(None) => Err(error_code(
            StatusCode::FORBIDDEN,
            "请求方不是管理员",
            "acl_admin_required",
        )),
        Err(cause) => Err(cause),
    }
}

/// 资源种类文本 → 枚举；未知取值按输入错误拒绝。
fn parse_kind(value: &str) -> std::result::Result<ResourceKind, ApiError> {
    Ok(match value {
        "conversation" => ResourceKind::Conversation,
        "project" => ResourceKind::Project,
        "file" => ResourceKind::File,
        "image" => ResourceKind::Image,
        "task" => ResourceKind::Task,
        "connector" => ResourceKind::Connector,
        _ => {
            return Err(error_code(
                StatusCode::BAD_REQUEST,
                "资源类型无效",
                "acl_invalid_input",
            ))
        }
    })
}

/// 资源键：account_id + 类型 + 上游 id。缺任一字段都拒绝。
fn parse_key(
    account_id: &str,
    kind: &str,
    upstream_id: &str,
) -> std::result::Result<ResourceKey, ApiError> {
    let kind = parse_kind(kind)?;
    ResourceKey::new(account_id, kind, upstream_id).map_err(|cause| {
        tracing::warn!(module = "gateway", error = %cause, "ACL 资源键无效");
        error_code(
            StatusCode::BAD_REQUEST,
            "资源键无效",
            "acl_invalid_input",
        )
    })
}

// ---------------------------------------------------------------------------
// GET /api/acl/resources —— 资源查询与筛选
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ResourcesQuery {
    account_id: Option<String>,
    resource_type: Option<String>,
    owner_user_id: Option<String>,
    limit: Option<u32>,
}

/// 观测上限：单页最多 1000 条；这是有界分页，不是备份导出。
const DEFAULT_PAGE: u32 = 200;

pub(super) async fn list_resources(
    State(app): State<Shared>,
    Query(query): Query<ResourcesQuery>,
    headers: HeaderMap,
) -> AclResult {
    let operator = operator(&app, &headers).await?;
    let kind = match query.resource_type.as_deref() {
        Some(value) => Some(parse_kind(value)?),
        None => None,
    };
    let db = app.db.lock().await;
    let records = crate::resource_acl::list_resources(
        &db.conn,
        &operator,
        query.account_id.as_deref(),
        kind,
        query.owner_user_id.as_deref(),
        query.limit.unwrap_or(DEFAULT_PAGE),
    )
    .map_err(acl_error)?;
    Ok(Json(json!({
        "resources": records.iter().map(|record| json!({
            "account_id": record.resource.account_id(),
            "resource_type": record.resource.kind().as_str(),
            "upstream_id": record.resource.upstream_id(),
            "owner_user_id": record.owner_user_id,
        })).collect::<Vec<_>>(),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/acl/claim —— 未登记资源认领
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ClaimRequest {
    account_id: String,
    resource_type: String,
    upstream_id: String,
    owner_user_id: String,
}

pub(super) async fn claim(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<ClaimRequest>,
) -> AclResult {
    let operator = operator(&app, &headers).await?;
    let resource = parse_key(&input.account_id, &input.resource_type, &input.upstream_id)?;
    let db = app.db.lock().await;
    let change = crate::resource_acl::claim(
        &db.conn,
        &operator,
        &resource,
        &input.owner_user_id,
    )
    .map_err(acl_error)?;
    Ok(Json(json!({"audit_id": change.audit_id})))
}

// ---------------------------------------------------------------------------
// POST /api/acl/share —— 授予/撤销共享
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ShareRequest {
    account_id: String,
    resource_type: String,
    upstream_id: String,
    recipient_user_id: String,
    granted: bool,
}

pub(super) async fn share(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<ShareRequest>,
) -> AclResult {
    let operator = operator(&app, &headers).await?;
    let resource = parse_key(&input.account_id, &input.resource_type, &input.upstream_id)?;
    let db = app.db.lock().await;
    let change = if input.granted {
        crate::resource_acl::grant(&db.conn, &operator, &resource, &input.recipient_user_id)
    } else {
        crate::resource_acl::revoke(&db.conn, &operator, &resource, &input.recipient_user_id)
    }
    .map_err(acl_error)?;
    Ok(Json(json!({"audit_id": change.audit_id})))
}

// ---------------------------------------------------------------------------
// POST /api/acl/move —— 移动到项目 / 移出项目
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct MoveRequest {
    account_id: String,
    resource_type: String,
    upstream_id: String,
    /// `null` 表示移出项目。
    project_id: Option<String>,
}

pub(super) async fn move_to_project(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<MoveRequest>,
) -> AclResult {
    let operator = operator(&app, &headers).await?;
    let resource = parse_key(&input.account_id, &input.resource_type, &input.upstream_id)?;
    let project = match input.project_id.as_deref() {
        Some(project_id) => Some(parse_key(&input.account_id, "project", project_id)?),
        None => None,
    };
    let db = app.db.lock().await;
    let change = crate::resource_acl::move_to_project(
        &db.conn,
        &operator,
        &resource,
        project.as_ref(),
    )
    .map_err(acl_error)?;
    Ok(Json(json!({"audit_id": change.audit_id})))
}

// ---------------------------------------------------------------------------
// GET /api/acl/audit —— 审计游标
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct AuditQuery {
    after_id: Option<i64>,
    limit: Option<u32>,
}

pub(super) async fn audit(
    State(app): State<Shared>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> AclResult {
    let operator = operator(&app, &headers).await?;
    let db = app.db.lock().await;
    let records = crate::resource_acl::audit_after(
        &db.conn,
        &operator,
        query.after_id.unwrap_or(0),
        query.limit.unwrap_or(DEFAULT_PAGE),
    )
    .map_err(acl_error)?;
    Ok(Json(json!({
        "audit": records.iter().map(|record| json!({
            "id": record.id,
            "occurred_at": record.occurred_at,
            "actor_user_id": record.actor_user_id,
            "authorization_version": record.authorization_version,
            "action": record.action,
            "account_id": record.account_id,
            "resource_type": record.resource_type,
            "upstream_id": record.upstream_id,
            "recipient_user_id": record.recipient_user_id,
            "project_id": record.project_id,
        })).collect::<Vec<_>>(),
    })))
}

// ---------------------------------------------------------------------------
// GET /api/acl/unclaimed-conversations —— 上游会话清单与 ACL 登记的差集
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct UnclaimedQuery {
    account_id: String,
    #[serde(default)]
    page: Option<u32>,
}

/// 上游清单一页的条数：管理端翻页，网关不一次拉完整个账号的会话。
const UNCLAIMED_PAGE_SIZE: u32 = 50;
/// 页数上限：20 页 = 1000 条；再往后翻说明该账号几乎无人认领，应改为人工排查。
const UNCLAIMED_MAX_PAGE: u32 = 20;

/// 通用上游失败：日志记本地原因，响应只给可行动文案，不含上游正文。
fn upstream_unavailable(label: &str, cause: anyhow::Error) -> ApiError {
    tracing::error!(module = "gateway", error = %cause, "ACL 管理端上游请求失败");
    error_code(
        StatusCode::BAD_GATEWAY,
        &format!("{label}: 无法访问上游，请稍后重试"),
        "acl_upstream_unavailable",
    )
}

/// 未登记会话清单：读上游账号的会话列表，减去本账号已登记的会话 id。
/// 只读上游，不改任何归属；登记仍由 [`claim`] 完成。
pub(super) async fn unclaimed_conversations(
    State(app): State<Shared>,
    Query(query): Query<UnclaimedQuery>,
    headers: HeaderMap,
) -> AclResult {
    let operator = operator(&app, &headers).await?;
    let page = query.page.unwrap_or(0);
    if page > UNCLAIMED_MAX_PAGE {
        return Err(error_code(
            StatusCode::BAD_REQUEST,
            "页码超出允许范围",
            "acl_invalid_input",
        ));
    }
    let row_id: i64 = query
        .account_id
        .parse()
        .map_err(|_| error_code(StatusCode::BAD_REQUEST, "账号 ID 无效", "acl_invalid_input"))?;
    // 凭据解密、出口客户端与已登记集合都在同一次持锁内取出，之后按原版规则
    // 不跨上游 IO 持锁；凭据解密失败说明导入材料与库密钥不匹配，按凭据问题上报。
    let (client, access_token, session_token, extra_cookies, registered) = {
        let db = app.db.lock().await;
        let row: Option<(String, Option<String>, Option<String>)> = db
            .conn
            .query_row(
                "SELECT access_token, session_token, extra_cookies FROM chatgpt_accounts WHERE id=?1",
                [row_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|cause| acl_error(AclError::Sqlite(cause)))?;
        let Some((access_token, session_token, extra_cookies)) = row else {
            return Err(error_code(StatusCode::NOT_FOUND, "账号不存在", "acl_not_found"));
        };
        let outbound = egress::load(&db, &app.config, None).map_err(|cause| {
            tracing::error!(module = "gateway", error = %cause, "ACL 清单出口不可用");
            error_code(
                StatusCode::BAD_GATEWAY,
                "网关出口配置不可用，无法访问上游",
                "acl_upstream_unavailable",
            )
        })?;
        let decrypt = |value: &str| {
            db.decrypt(value).map_err(|cause| {
                tracing::error!(module = "gateway", error = %cause, "ACL 清单账号凭据解密失败");
                error_code(
                    StatusCode::BAD_GATEWAY,
                    "账号凭据无法解密，请重新导入该账号凭据",
                    "acl_account_credentials_invalid",
                )
            })
        };
        let access_token = decrypt(&access_token)?;
        let session_token = session_token
            .as_deref()
            .map(&decrypt)
            .transpose()?;
        let extra_cookies = decrypt(extra_cookies.as_deref().unwrap_or("[]"))?;
        let registered = crate::resource_acl::registered_ids(
            &db.conn,
            &operator,
            &query.account_id,
            ResourceKind::Conversation,
        )
        .map_err(acl_error)?;
        (
            outbound.client,
            access_token,
            session_token,
            extra_cookies,
            registered,
        )
    };
    let cookies = proxy::parse_extra_cookies(&extra_cookies);
    // AccessToken 直接可用就不要再换取；只有 SessionToken 时按登录同一条链路换取一次。
    let access_token = if access_token.is_empty() {
        let Some(token) = session_token.as_deref().filter(|value| !value.is_empty()) else {
            return Err(error_code(
                StatusCode::BAD_GATEWAY,
                "账号既没有可用的 AccessToken 也没有 SessionToken，请重新导入该账号凭据",
                "acl_account_credentials_invalid",
            ));
        };
        match exchange_session_with_client(&app, &client, token, &cookies).await {
            Ok(exchanged) => exchanged,
            Err(cause) => {
                if let Some(blocked) = cause.downcast_ref::<cloudflare::UpstreamBlocked>() {
                    return Err(error_code(
                        StatusCode::BAD_GATEWAY,
                        &blocked.to_string(),
                        "upstream_blocked",
                    ));
                }
                return Err(error_code(
                    StatusCode::BAD_GATEWAY,
                    &format!("账号 SessionToken 换取失败（{cause}），请重新导入该账号凭据"),
                    "acl_account_credentials_invalid",
                ));
            }
        }
    } else {
        access_token
    };
    let session = proxy::session_cookie_group(session_token.as_deref(), &cookies, &[]);
    // 设备身份：原版所有服务端上游请求都显式写 `oai-device-id`（与 jar 里的 `oai-did`
    // 同值），会话 chat 路径同样如此。清单走的是同一个上游端点，身份形状保持一致。
    let device = cookies
        .iter()
        .rev()
        .find(|(name, value)| name == upstream_cookies::DEVICE_COOKIE && !value.is_empty())
        .map(|(_, value)| value.clone());
    let url = app.config.upstream.join(&format!(
        "/backend-api/conversations?offset={}&limit={UNCLAIMED_PAGE_SIZE}",
        page * UNCLAIMED_PAGE_SIZE
    ))?;
    let (response, refresh) = cloudflare::get_with_challenge_retry(&app, "读取会话清单失败", |cf| {
        let url = url.clone();
        let client = client.clone();
        let cookies = cookies.clone();
        let session = session.clone();
        let access_token = access_token.clone();
        let device = device.clone();
        async move {
            let mut request = client
                .get(url.as_str())
                .headers(identity::api_baseline(&url, &Method::GET)?)
                .bearer_auth(&access_token);
            if let Some((name, value)) = device.as_deref().and_then(upstream_cookies::device_header) {
                request = request.header(name, value);
            }
            if let Some(cookie) = cloudflare::cookie_header(&[
                cookies.as_slice(),
                session.as_slice(),
                cf.as_slice(),
            ]) {
                request = request.header(
                    "cookie",
                    HeaderValue::from_str(&cookie).context("Cookie 头无效")?,
                );
            }
            request.send().await.context("上游请求失败")
        }
    })
    .await
    .map_err(|cause| upstream_unavailable("读取会话清单失败", cause))?;
    let answer = cloudflare::read(response)
        .await
        .map_err(|cause| upstream_unavailable("读取会话清单失败", cause))?;
    if !answer.status.is_success() {
        if answer.blocked() {
            return Err(error_code(
                StatusCode::BAD_GATEWAY,
                &cloudflare::blocked_error(
                    "会话清单读取失败",
                    "backend-api/conversations",
                    answer.status,
                    refresh.as_ref(),
                )
                .to_string(),
                "upstream_blocked",
            ));
        }
        return Err(error_code(
            StatusCode::BAD_GATEWAY,
            &format!("上游返回状态 {}，未能取得会话清单", answer.status.as_u16()),
            "acl_upstream_unavailable",
        ));
    }
    let value = answer
        .json::<Value>()
        .map_err(|cause| upstream_unavailable("会话清单解析失败", cause))?;
    // 两个键都是真实上游的既有形状（空账号也返回 `total: 0`）。缺任何一个都说明上游
    // 变更了信封：这时不能回退成空清单或伪造页数，那会让管理员以为「没有未登记会话」。
    let invalid = || {
        error_code(
            StatusCode::BAD_GATEWAY,
            "上游返回的会话清单结构不符合预期，暂不能列出未登记会话",
            "acl_upstream_unavailable",
        )
    };
    let items = value["items"].as_array().cloned().ok_or_else(invalid)?;
    let total = value["total"].as_u64().ok_or_else(invalid)?;
    let offset = u64::from(page) * u64::from(UNCLAIMED_PAGE_SIZE);
    let unclaimed: Vec<Value> = items
        .iter()
        .filter_map(|item| {
            let upstream_id = item["conversation_id"]
                .as_str()
                .or_else(|| item["id"].as_str())
                .filter(|value| !value.is_empty())?;
            if registered.contains(upstream_id) {
                return None;
            }
            Some(json!({
                "upstream_id": upstream_id,
                "title": item["title"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .unwrap_or(upstream_id),
                "update_time": item["update_time"],
            }))
        })
        .collect();
    let has_more = offset + (items.len() as u64) < total;
    Ok(Json(json!({
        "account_id": query.account_id,
        "page": page,
        "page_size": UNCLAIMED_PAGE_SIZE,
        "upstream_total": total,
        "has_more": has_more,
        "items": unclaimed,
    })))
}

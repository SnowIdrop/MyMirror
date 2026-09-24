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
// axum handler 的错误分支只能直接返回 `Response`：这里不为通过 lint 去装箱错误值，
// 错误路径不承担额外堆分配，符合框架自身的惯例。
#![allow(clippy::result_large_err)]

use super::*;
use crate::resource_acl::{AclError, ResourceKey, ResourceKind};
use serde::Deserialize;

/// 管理端返回类型：错误以 `Response` 表示，避免把 HTTP 响应再包进 `ApiError`。
type AclResult = std::result::Result<Json<Value>, Response>;

/// 管理端 JSON 错误：状态码稳定、正文只含本地文案。
fn acl_error(cause: AclError) -> Response {
    let (status, message, code) = match cause {
        AclError::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            "请求方身份无效或已失效",
            "acl_identity_invalid",
        ),
        AclError::Forbidden => (
            StatusCode::FORBIDDEN,
            "需要管理员身份才能执行该操作",
            "acl_admin_required",
        ),
        AclError::UnknownResource => (
            StatusCode::NOT_FOUND,
            "资源不存在或不属于当前账号",
            "acl_not_found",
        ),
        AclError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            "请求参数无效",
            "acl_invalid_input",
        ),
        AclError::InvalidOperation => (
            StatusCode::BAD_REQUEST,
            "该资源不支持此操作",
            "acl_invalid_operation",
        ),
        AclError::CrossAccount => (
            StatusCode::BAD_REQUEST,
            "资源与目标项目不属于同一上游账号",
            "acl_cross_account",
        ),
        AclError::AlreadyRegistered => (
            StatusCode::CONFLICT,
            "资源已有归属，认领不会覆盖",
            "acl_already_registered",
        ),
        AclError::Sqlite(cause) => {
            tracing::error!(module = "gateway", error = %cause, "ACL 管理操作失败");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "ACL 存储暂时不可用",
                "acl_storage_unavailable",
            )
        }
    };
    error_code(status, message, code).into_response()
}

/// 管理入口的操作者：服务密钥（中间件已校验）+ 请求方 authorization/subject +
/// 固定 Django 源 fresh 校验 + `is_admin`。
async fn operator(app: &App, headers: &HeaderMap) -> std::result::Result<RequestIdentity, Response> {
    match request_admin_identity(app, headers).await {
        Ok(Some(identity)) => Ok(identity),
        Ok(None) => Err(error_code(
            StatusCode::FORBIDDEN,
            "请求方不是管理员",
            "acl_admin_required",
        )
        .into_response()),
        Err(cause) => Err(cause.into_response()),
    }
}

/// 资源种类文本 → 枚举；未知取值按输入错误拒绝。
fn parse_kind(value: &str) -> std::result::Result<ResourceKind, Response> {
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
            )
            .into_response())
        }
    })
}

/// 资源键：account_id + 类型 + 上游 id。缺任一字段都拒绝。
fn parse_key(account_id: &str, kind: &str, upstream_id: &str) -> std::result::Result<ResourceKey, Response> {
    let kind = parse_kind(kind)?;
    ResourceKey::new(account_id, kind, upstream_id).map_err(|cause| {
        tracing::warn!(module = "gateway", error = %cause, "ACL 资源键无效");
        error_code(
            StatusCode::BAD_REQUEST,
            "资源键无效",
            "acl_invalid_input",
        )
        .into_response()
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

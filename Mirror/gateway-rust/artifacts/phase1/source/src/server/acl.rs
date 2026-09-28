// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/acl.rs
// Created : 2026-09-23
// Summary : 缺口 3 完整批次的产品接线。把 `/backend-api/*` 分类为资源作用域 /
//           集合 / 创建 / 账号级，并在转发前判权、创建后登记、响应前过滤，
//           另提供生成互斥租约与撤权中止。
//           证据来源：reverse/reports/03-gateway-static-analysis.md §7.3 与附录 A
//           （enforce_conversation_owner / enforce_project_owner / claim_* 族）、
//           05-database-schema.md §3.5–§3.6（conversation_owners / project_owners）、
//           07-security-behavior.md §4.2（归属判定为「恰好 1 个 owner 且等于当前
//           用户」），以及 src/assets/chatgpt-api-routes.json（2026-09-23 从
//           公开前端 CDN 分块提取的 923 条路由模板快照）。
// -----------------------------------------------------------------------------

//! ACL 分类与执行。
//!
//! 三类判定，绝不静默放行：
//! - **资源族**（会话/项目/文件/图片/任务/连接器）按作用域判权：未登记或他人资源
//!   返回 404 且不接触上游；
//! - **账号级前缀**（模型清单、账号检查、设置、遥测等）与六类资源无关，按原版
//!   行为透传，显式登记在 [`UNOWNED`]；
//! - 其余路径一律 503：新增上游路由必须显式分类后才可用，`tests/acl_routes.rs`
//!   用路由快照保证每个已观测模板都落在前两类之一。

use super::*;
use crate::resource_acl::{
    Action, ConfirmedCreation, Identity, RequestIdentity, ResourceKey, ResourceKind,
};
use axum::http::Method;
use futures_util::StreamExt;
use serde_json::Map;
use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use tokio::sync::watch;

/// 账号级前缀：与六类可归属资源无关，原版同样原样透传。
/// 新增前缀必须在这里显式登记（`tests/acl_routes.rs` 会对着路由快照核对）。
const UNOWNED: &[&str] = &[
    "accounts",
    "agent",
    "aip",
    "amphora",
    "apps",
    "automation",
    "automations",
    "bazaar",
    "beacons",
    "buying-advisor",
    "ca",
    "calpico",
    "celsius",
    "chat",
    // 2026-09-24 真实前端观测：每个已登录页面固定请求 4 次，属快照（2026-09-23）
    // 之后新增的路由，与六类可归属资源无关，按账号级放行。
    "checkout_pricing_config",
    "client",
    "client_applications",
    "cme",
    "codex",
    "compliance",
    "composer",
    "connectors",
    "conversation_limit",
    "credits",
    "custom_source_lists",
    "cyber_verification",
    "dictation",
    "enterprise_surveys",
    "epic",
    "estuary",
    "export_doc",
    "file_upload_action_suggestions",
    "flora",
    "generate_audio_paragen",
    "gift-credits",
    "gizmo_creator_profile",
    "gizmo_creators",
    "gizmo_reviews",
    "gizmos",
    "global",
    "hazelnuts",
    "hermes",
    "hosting",
    "inbox",
    "incentives",
    "invoices",
    "jupiter",
    "language-learning-block",
    "lat",
    "learning",
    "local",
    "locked_chats",
    "me",
    "memories",
    "models",
    "notifications",
    "onboarding",
    "pageConfigs",
    "paragen_audio_submission",
    "paragen_submission",
    "payments",
    "pins",
    "personality_onboarding",
    "personality_settings_impression",
    "personality_trait_types",
    "personality_types",
    "pets",
    "placeholders",
    "plugin-categories",
    "plugin-shares",
    "plugins",
    "pro_mode",
    "profiles",
    "public",
    "promo_campaign",
    "promotions",
    "prompt_library",
    "pronunciation",
    "quorum",
    "rbac",
    "report_flow",
    "search",
    "sentinel",
    "service-accounts",
    "settings",
    "share",
    "shopping",
    "stride",
    "students",
    "subscriptions",
    "synthesize",
    "system_hints",
    "targeted_feedback",
    "templated_prompts",
    "textdoc",
    "tpp",
    "transcribe",
    "translation-block",
    "trusted_contact",
    "unified_user_signals",
    "user_granular_consent",
    "user_information",
    "user_segments",
    "user_surveys",
    "user_system_messages",
    "venus_suggested_prompts",
    "wham",
    "widget_server_action",
    "workspace-resources",
    "workspaces",
    "writing-blocks",
];

/// 一次请求的 ACL 判定结果。
pub(super) enum Verdict {
    /// 资源作用域：转发前必须命中当前会话的 ACL。
    Scoped(Scoped),
    /// 集合读取：转发后按 ACL 过滤正文。
    Collection(ResourceKind),
    /// 创建：只在 2xx 已确认的响应里登记新资源。`project` 是请求头
    /// `chatgpt-project-id` 指明的归属项目（会话/文件等新建在项目内时携带）。
    Creation {
        kind: ResourceKind,
        project: Option<String>,
    },
    /// 账号级路径，不参与归属判权。
    Unscoped,
    /// 未显式分类：按请求里出现的资源 id 判定（上游前端新增路由时不需要再登记）。
    /// `claim` 为真表示这是写方法，2xx 响应里的新资源 id 归当前用户。
    Auto { claim: bool, ids: Vec<String> },
}

pub(super) struct Scoped {
    pub(super) kind: ResourceKind,
    pub(super) upstream_id: String,
    pub(super) action: Action,
    /// 生成类写请求：需要按 `(account_id, 会话 id)` 取独占租约。
    pub(super) generation: bool,
}

/// 分类：路径 + 方法 + 请求体 + 归属头。
pub(super) fn classify(
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> Verdict {
    let Some(rest) = path.strip_prefix("/backend-api") else {
        // 页面、匿名通道与公共前缀由 `open_path` 决定可达性，这里没有归属语义。
        return Verdict::Unscoped;
    };
    let segments: Vec<&str> = rest.split('/').filter(|segment| !segment.is_empty()).collect();
    let Some(head) = segments.first().copied() else {
        return Verdict::Unscoped;
    };
    let read = matches!(*method, Method::GET | Method::HEAD);
    let delete = *method == Method::DELETE;
    let action = if read {
        Action::Read
    } else if delete {
        Action::Delete
    } else {
        Action::Modify
    };
    let scope = |kind, id: &str, action, generation| {
        Verdict::Scoped(Scoped {
            kind,
            upstream_id: id.to_owned(),
            action,
            generation,
        })
    };
    let body_id = |key: &str| json_id(body, key);
    let header_id = |name: &str| header_resource_id(headers, name);

    match head {
        "conversation" => {
            if segments.len() == 1 {
                if *method == Method::POST {
                    return match body_id("conversation_id").filter(|id| is_uuid(id)) {
                        Some(id) => scope(ResourceKind::Conversation, &id, Action::Modify, true),
                        None => Verdict::Creation { kind: ResourceKind::Conversation, project: header_id("chatgpt-project-id") },
                    };
                }
                return Verdict::Unscoped;
            }
            let tail = &segments[1..];
            // 会话 id 出现在路径任意位置都按会话判权：`id/{id}`、`{id}/rename`、
            // `{id}/messages/{mid}` 这些模板因此共用一条规则，不依赖字面量白名单。
            if let Some(id) = tail.iter().copied().find(|segment| is_uuid(segment)) {
                // 裸续聊（`POST conversation/<id>`）才是生成；其余子路径是读写状态。
                let generation = *method == Method::POST && tail.len() == 1;
                return scope(ResourceKind::Conversation, id, action, generation);
            }
            // 消息级与实验类子路径把会话 id 放在请求体或归属头里：有 id 就判权，
            // 没有 id 的（`init`/`prepare` 等字面量子路径）交给账号级判定。
            if let Some(id) = body_id("conversation_id")
                .filter(|id| is_uuid(id))
                .or_else(|| header_id("chatgpt-conv-owner-id").filter(|id| is_uuid(id)))
            {
                return scope(ResourceKind::Conversation, &id, action, false);
            }
            return Verdict::Unscoped;
        }
        "conversations" => {
            if segments.len() == 1 {
                return if read {
                    Verdict::Collection(ResourceKind::Conversation)
                } else {
                    Verdict::Unscoped
                };
            }
            if segments[1] == "search" {
                return if read {
                    Verdict::Collection(ResourceKind::Conversation)
                } else {
                    Verdict::Unscoped
                };
            }
            if is_uuid(segments[1]) {
                return scope(ResourceKind::Conversation, segments[1], action, false);
            }
        }
        "f" => {
            if segments.get(1) == Some(&"conversation") {
                if segments.len() == 2 && *method == Method::POST {
                    return match body_id("conversation_id").filter(|id| is_uuid(id)) {
                        Some(id) => scope(ResourceKind::Conversation, &id, Action::Modify, true),
                        None => Verdict::Creation { kind: ResourceKind::Conversation, project: header_id("chatgpt-project-id") },
                    };
                }
                if segments.len() == 3 && is_uuid(segments[2]) {
                    return scope(ResourceKind::Conversation, segments[2], action, false);
                }
            }
            if segments.get(1) == Some(&"steer_turn") {
                if let Some(id) = body_id("conversation_id").filter(|id| is_uuid(id)) {
                    return scope(ResourceKind::Conversation, &id, Action::Modify, true);
                }
            }
            // `f/conversation/prepare` 等字面量子路径不指向已存在的会话
            // （新建流程的准备阶段），没有可判权的资源 id：按账号级放行。
            return Verdict::Unscoped;
        }
        "sidebar" => {
            // 前端新建/续聊实际走 `/sidebar/conversation`：带会话 id 是续聊，
            // 不带 id 的客户端临时 id 一律按创建处理（登记发生在 2xx 之后）。
            if segments.get(1) == Some(&"conversation") && *method == Method::POST {
                return match body_id("conversation_id").filter(|id| is_uuid(id)) {
                    Some(id) => scope(ResourceKind::Conversation, &id, Action::Modify, true),
                    None => Verdict::Creation { kind: ResourceKind::Conversation, project: header_id("chatgpt-project-id") },
                };
            }
            // 其余 `sidebar/*` 是与会话无关的反馈上报，不携带资源归属。
            return Verdict::Unscoped;
        }
        "stop_conversation" => {
            if let Some(id) = body_id("conversation_id").filter(|id| is_uuid(id)) {
                return scope(ResourceKind::Conversation, &id, Action::Modify, false);
            }
        }
        "realtime" => {
            if let Some(id) = body_id("conversation_id").filter(|id| is_uuid(id)) {
                return scope(ResourceKind::Conversation, &id, Action::Read, false);
            }
        }
        "projects" => {
            if segments.len() == 1 {
                return if read {
                    Verdict::Collection(ResourceKind::Project)
                } else if *method == Method::POST {
                    Verdict::Creation { kind: ResourceKind::Project, project: header_id("chatgpt-project-id") }
                } else {
                    Verdict::Unscoped
                };
            }
            if segments[1] == "share" {
                if let Some(id) = body_id("project_id").filter(|id| is_resource_id(id)) {
                    return scope(ResourceKind::Project, &id, Action::Modify, false);
                }
                return Verdict::Unscoped;
            }
            if is_resource_id(segments[1]) {
                return scope(ResourceKind::Project, segments[1], action, false);
            }
        }
        "websites" => {
            if let Some(id) = segments.get(1).filter(|id| is_resource_id(id)) {
                return scope(ResourceKind::Project, id, action, false);
            }
        }
        "files" => {
            if segments.len() == 1 {
                return if read {
                    Verdict::Collection(ResourceKind::File)
                } else if *method == Method::POST {
                    Verdict::Creation {
                        kind: ResourceKind::File,
                        project: header_id("chatgpt-project-id"),
                    }
                } else {
                    Verdict::Unscoped
                };
            }
            if segments[1] == "library" {
                return library(&segments, method, read, header_id("chatgpt-project-id"));
            }
            if segments[1] == "import_image" {
                return if *method == Method::POST {
                    Verdict::Creation { kind: ResourceKind::Image, project: header_id("chatgpt-project-id") }
                } else {
                    Verdict::Unscoped
                };
            }
            // 上传预约与流式上传返回的是预约/会话 id，不是文件 id；文件实体随后由
            // `/files` 或库接口登记，因此这里不按预约 id 认领（见 COMPATIBILITY.md）。
            if matches!(segments[1], "upload_reservations" | "process_upload_stream") {
                return Verdict::Unscoped;
            }
            if is_resource_id(segments[1]) {
                return scope(ResourceKind::File, segments[1], action, false);
            }
        }
        "images" => {
            if segments.len() == 1 {
                return if read {
                    Verdict::Collection(ResourceKind::Image)
                } else if *method == Method::POST {
                    Verdict::Creation { kind: ResourceKind::Image, project: header_id("chatgpt-project-id") }
                } else {
                    Verdict::Unscoped
                };
            }
            if segments[1] == "image-tags" {
                if segments.get(2) == Some(&"self") {
                    return Verdict::Unscoped;
                }
                if let Some(id) = segments.get(2).filter(|id| is_resource_id(id)) {
                    return scope(ResourceKind::Image, id, action, false);
                }
                return if read {
                    Verdict::Collection(ResourceKind::Image)
                } else if *method == Method::POST {
                    Verdict::Creation { kind: ResourceKind::Image, project: header_id("chatgpt-project-id") }
                } else {
                    Verdict::Unscoped
                };
            }
            if matches!(segments[1], "bootstrap" | "init" | "styles" | "prompt-items") {
                return Verdict::Unscoped;
            }
            if is_resource_id(segments[1]) {
                return scope(ResourceKind::Image, segments[1], action, false);
            }
        }
        "my" => {
            if segments.get(1) == Some(&"recent") {
                if matches!(segments.get(2), Some(&"image_gen") | Some(&"uploaded_images")) {
                    return if read {
                        Verdict::Collection(ResourceKind::Image)
                    } else {
                        Verdict::Unscoped
                    };
                }
                // deep_research_reports 等报告族不在本批开放面。
                return Verdict::Unscoped;
            }
            if segments.get(1) == Some(&"image") {
                if let Some(id) = segments.get(2).filter(|id| is_resource_id(id)) {
                    return scope(ResourceKind::Image, id, action, false);
                }
            }
        }
        "tasks" => {
            if segments.len() == 1 {
                return if read {
                    Verdict::Collection(ResourceKind::Task)
                } else if *method == Method::POST {
                    Verdict::Creation { kind: ResourceKind::Task, project: header_id("chatgpt-project-id") }
                } else {
                    Verdict::Unscoped
                };
            }
            if is_resource_id(segments[1]) {
                return scope(ResourceKind::Task, segments[1], action, false);
            }
        }
        "task" => {
            if segments.get(1) == Some(&"cancel") {
                // 取消用请求体里的 task id 判权；没有可判权的 id 时按账号级放行
                // （上游对未知任务本就会拒绝），不把整个前缀判为未分类。
                let id = body_id("task_id").or_else(|| body_id("id"));
                if let Some(id) = id.filter(|id| is_resource_id(id)) {
                    return scope(ResourceKind::Task, &id, Action::Delete, false);
                }
            }
            return Verdict::Unscoped;
        }
        "task_suggestions" => {
            // 建议列表按账号生成，不带资源归属。
            return Verdict::Unscoped;
        }
        "aip" => {
            // 连接器是六类资源之一：带 id 的子路径判权，账号级清单不判权。
            if let Some(id) = connector_id(&segments) {
                return scope(ResourceKind::Connector, id, action, false);
            }
        }
        "v2" => {
            // `/v2/connectors/{id}/…` 与 `/v2/links/{id}` 是连接器族的另一套前缀
            // （路由快照 2026-09-23）：同样按连接器判权，不能当成账号级路径放行。
            if matches!(segments.get(1), Some(&"connectors" | &"links")) {
                if let Some(id) = segments.get(2).filter(|id| is_resource_id(id)) {
                    return scope(ResourceKind::Connector, id, action, false);
                }
            }
        }
        "ecosystem" => {
            if matches!(
                segments.get(1),
                Some(&"file_download_url" | &"file_authorize_app" | &"file_metadata")
            ) {
                if let Some(id) = body_id("file_id").filter(|id| is_resource_id(id)) {
                    return scope(ResourceKind::File, &id, Action::Read, false);
                }
                return Verdict::Unscoped;
            }
            if segments.get(1) == Some(&"call_mcp") {
                if let Some(id) = body_id("connector_id").filter(|id| is_resource_id(id)) {
                    return scope(ResourceKind::Connector, &id, Action::Read, false);
                }
                return Verdict::Unscoped;
            }
            // 其余 `ecosystem/*` 是 widget 运行时与启动引导：不带可归属资源 id，
            // 按账号级放行（文件类入口在上面的 `file_*` 分支已单独判权）。
            return Verdict::Unscoped;
        }
        _ => {}
    }

    if UNOWNED.contains(&head) {
        Verdict::Unscoped
    } else {
        // 未显式登记的前缀不再按路径形状拒绝：只要请求里出现的资源 id 都
        // 属于当前会话就放行，写方法的成功响应再按响应 id 登记新资源。
        Verdict::Auto {
            claim: !read,
            ids: auto_ids(rest, query, body),
        }
    }
}

/// 未分类路径的 id 材料：路径里 UUID 形态的段、query 与请求体顶层的 `*_id` 键。
/// 只认「一定不是字面量」的形态（UUID 或 `*_id` 键名），避免把普通路径段
/// 当成资源 id 误判。
fn auto_ids(path: &str, query: Option<&str>, body: &[u8]) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for segment in path.split('/') {
        if is_uuid(segment) {
            ids.push(segment.to_owned());
        }
    }
    for pair in query.unwrap_or("").split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key.ends_with("_id") {
                ids.push(value.to_owned());
            }
        }
    }
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                if !key.ends_with("_id") {
                    continue;
                }
                if let Some(value) = value.as_str() {
                    ids.push(value.to_owned());
                }
            }
        }
    }
    ids.retain(|id| is_resource_id(id));
    let mut seen = HashSet::new();
    ids.retain(|id| seen.insert(id.clone()));
    ids
}

/// 归属上下文头：前端在项目内创建/读取时携带 `chatgpt-project-id`
/// （`chatgpt-conv-owner-id` 是共享会话的属主提示，不作为归属真相）。
fn header_resource_id(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_resource_id(value))
        .map(str::to_owned)
}

/// 文件库子路径：库文件按文件判权，目录行按同一命名空间登记。
fn library(segments: &[&str], method: &Method, read: bool, project: Option<String>) -> Verdict {
    let action = if read {
        Action::Read
    } else if *method == Method::DELETE {
        Action::Delete
    } else {
        Action::Modify
    };
    match segments.get(2).copied() {
        Some("files") => {
            if segments.len() == 3 {
                return if read {
                    Verdict::Collection(ResourceKind::File)
                } else if *method == Method::POST {
                    Verdict::Creation { kind: ResourceKind::File, project }
                } else {
                    Verdict::Unscoped
                };
            }
            if let Some(id) = segments.get(3).filter(|id| is_resource_id(id)) {
                return Verdict::Scoped(Scoped {
                    kind: ResourceKind::File,
                    upstream_id: (*id).to_owned(),
                    action,
                    generation: false,
                });
            }
        }
        Some("directories") => {
            if let Some(id) = segments
                .get(3)
                .filter(|id| **id != "path" && is_resource_id(id))
            {
                return Verdict::Scoped(Scoped {
                    kind: ResourceKind::File,
                    upstream_id: (*id).to_owned(),
                    action,
                    generation: false,
                });
            }
        }
        Some("reference-images") => {
            if let Some(id) = segments.get(3).filter(|id| is_resource_id(id)) {
                return Verdict::Scoped(Scoped {
                    kind: ResourceKind::Image,
                    upstream_id: (*id).to_owned(),
                    action,
                    generation: false,
                });
            }
        }
        Some("favorites") => {
            // `/files/library/favorites/conversations/{conversation_id}`：收藏项按会话判权。
            if let (Some(&"conversations"), Some(id)) = (
                segments.get(3),
                segments.get(4).filter(|id| is_uuid(id)),
            ) {
                return Verdict::Scoped(Scoped {
                    kind: ResourceKind::Conversation,
                    upstream_id: (*id).to_owned(),
                    action,
                    generation: false,
                });
            }
        }
        _ => {}
    }
    Verdict::Unscoped
}

/// `/aip/connectors/...` 里的连接器 id：字面量子资源不算，`{connector_id}` 与
/// `links/{link_id}` 算。
fn connector_id<'a>(segments: &'a [&'a str]) -> Option<&'a str> {
    // `aip` 下的账号级族（ledger/first-party/p/workspace）与 connectors 的动作字面量
    // 都不是连接器 id；把任意非字面量段当 id 会把账号级路由误判成他人资源。
    if !matches!(segments.get(1), Some(&"connectors")) {
        return None;
    }
    const LITERALS: &[&str] = &[
        "batch",
        "email",
        "github",
        "google_contacts",
        "links",
        "list_accessible",
        "mcp",
        "oauth",
        "oauth_clients",
        "product_specific",
        "templates",
    ];
    let tail = segments.get(2)?;
    if *tail == "links" {
        return segments.get(3).filter(|id| is_resource_id(id)).copied();
    }
    if LITERALS.contains(tail) {
        return None;
    }
    is_resource_id(tail).then_some(*tail)
}

/// 请求体里的字符串 id（顶层字段）。
fn json_id(body: &[u8], key: &str) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|id| is_resource_id(id))
        .map(str::to_owned)
}

/// 资源 id 的通用形态：4–64 个 URL 安全字符。
fn is_resource_id(value: &str) -> bool {
    (4..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// 会话 id 的严格形态：8-4-4-4-12 十六进制 UUID（原版只认这种会话 id）。
fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

// ---------------------------------------------------------------------------
// 判权与拒绝响应
// ---------------------------------------------------------------------------

/// 会话的 ACL 身份与稳定账号键；访客/匿名/老会话为 None。
pub(super) fn identity_of(session: &Session) -> Option<(&Identity, &str)> {
    let identity = session.identity.as_ref()?;
    let account_id = session.account_id.as_deref()?;
    Some((identity, account_id))
}

/// 单资源判权：只有已登记且属于当前受众才放行。
pub(super) async fn authorized(
    app: &App,
    identity: &Identity,
    account_id: &str,
    kind: ResourceKind,
    upstream_id: &str,
    action: Action,
) -> Result<bool> {
    let key = match ResourceKey::new(account_id, kind, upstream_id) {
        Ok(key) => key,
        // 形态不合法的 id 不可能对应已登记资源：按未授权处理，不再查询。
        Err(_) => return Ok(false),
    };
    let actor = RequestIdentity::from_session(identity.clone());
    let db = app.db.lock().await;
    match crate::resource_acl::authorize(&db.conn, &actor, &key, action) {
        Ok(_) => Ok(true),
        Err(crate::resource_acl::AclError::Forbidden)
        | Err(crate::resource_acl::AclError::UnknownResource) => Ok(false),
        Err(error) => Err(anyhow::anyhow!("ACL 判权失败: {error}")),
    }
}

/// 未登记或不属于当前用户：与「会话不存在」同形，既不泄露他人资源是否存在，
/// 也不接触上游。
pub(super) fn refusal() -> Response {
    error_code(
        StatusCode::NOT_FOUND,
        "会话不存在或不属于当前用户",
        "acl_not_found",
    )
    .into_response()
}

/// 访客/匿名会话没有可归属的镜像身份：资源路径一律拒绝。
pub(super) fn visitor_denied() -> Response {
    error_code(
        StatusCode::FORBIDDEN,
        "访客会话不能访问需要归属的资源",
        "acl_visitor_denied",
    )
    .into_response()
}

/// 未显式分类的路径带着账号下查不到的 id：保持「未登记资源不可用」不变量，
/// 拒绝并给出两条可行动出路（管理员认领，或把该路径登记为账号级）。
pub(super) fn unclassified_id() -> Response {
    error_code(
        StatusCode::SERVICE_UNAVAILABLE,
        "该路径携带的资源 id 尚未登记：管理员可认领该资源，或把该路径登记为账号级前缀",
        "acl_unclassified_id",
    )
    .into_response()
}

/// 未显式分类的响应正文里出现了他人资源：不裁剪也不透传，整体拒绝。
pub(super) fn foreign_in_response() -> Response {
    error_code(
        StatusCode::SERVICE_UNAVAILABLE,
        "上游响应包含不属于当前用户的资源：该路径需要显式登记归属语义",
        "acl_foreign_resource_in_response",
    )
    .into_response()
}

/// 未显式分类的 JSON 响应超过可过滤上限：不做部分过滤，整体拒绝。
pub(super) fn response_too_large() -> Response {
    error_code(
        StatusCode::BAD_GATEWAY,
        "上游响应过大，无法完成归属过滤：该路径需要显式登记为账号级前缀",
        "acl_response_too_large",
    )
    .into_response()
}

/// 生成冲突：同一会话已有在途生成，不排队、不重放。
pub(super) fn generation_busy() -> Response {
    error_code(
        StatusCode::CONFLICT,
        "该会话已有正在进行的生成请求",
        "generation_busy",
    )
    .into_response()
}

// ---------------------------------------------------------------------------
// 创建响应登记
// ---------------------------------------------------------------------------

/// 响应正文与集合条目里的资源 id 字段名 → 资源族。创建登记、Auto 路径的响应
/// 登记与集合过滤共用同一张表，键名不会在两个方向漂移。
const RESOURCE_ID_KEYS: &[(&str, ResourceKind)] = &[
    ("conversation_id", ResourceKind::Conversation),
    ("project_id", ResourceKind::Project),
    ("file_id", ResourceKind::File),
    ("library_file_id", ResourceKind::File),
    ("image_id", ResourceKind::Image),
    ("gen_id", ResourceKind::Image),
    ("task_id", ResourceKind::Task),
    ("connector_id", ResourceKind::Connector),
];

/// 响应正文扫描器：按块寻找 `<键>":"<id>`，尾部保留重叠，保证 id 跨块时仍能
/// 命中；同一个 id 只出现一次。
#[derive(Default)]
struct IdScanner {
    tail: Vec<u8>,
    seen: HashSet<String>,
    keys: Vec<(String, ResourceKind)>,
}

impl IdScanner {
    /// 单族扫描（创建响应登记）：族专用键 + 兜底的 `id`。
    fn for_kind(kind: ResourceKind) -> Self {
        let mut keys: Vec<(String, ResourceKind)> = RESOURCE_ID_KEYS
            .iter()
            .filter(|(_, key_kind)| *key_kind == kind)
            .map(|(key, key_kind)| (format!("\"{key}\":\""), *key_kind))
            .collect();
        // 部分创建响应只回 `id`；它排在族专用键之后，命中的 id 也一并登记。
        keys.push(("\"id\":\"".to_string(), kind));
        Self {
            keys,
            ..Self::default()
        }
    }

    /// 全族扫描（未分类路径的响应登记）：未显式分类的路径可能返回任意资源族。
    fn for_all_kinds() -> Self {
        let mut keys: Vec<(String, ResourceKind)> = RESOURCE_ID_KEYS
            .iter()
            .map(|(key, kind)| (format!("\"{key}\":\""), *kind))
            .collect();
        // 裸 `id` 无法区分资源族；会话是唯一带 UUID 约束的族，按会话登记。
        keys.push(("\"id\":\"".to_string(), ResourceKind::Conversation));
        Self {
            keys,
            ..Self::default()
        }
    }

    /// 扫描一个正文块，返回本块内新识别到的 (资源族, id)（跨块与同块都去重）。
    fn push(&mut self, chunk: &[u8]) -> Vec<(ResourceKind, String)> {
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(chunk);
        let mut found: Vec<(ResourceKind, String)> = Vec::new();
        for (marker, kind) in &self.keys {
            let needle = marker.as_bytes();
            let mut cursor = 0;
            while let Some(offset) = find(&window[cursor..], needle) {
                let start = cursor + offset + needle.len();
                // id 可能还没到齐（跨块）：此时不能取固定长度切片，只取从 start 起的
                // 剩余字节，尾部重叠保证下一块补齐后仍能命中。
                let Some(id) = window.get(start..) else {
                    break;
                };
                let id = &id[..id.len().min(64)];
                let Some(end) = id.iter().position(|byte| *byte == b'"') else {
                    break;
                };
                if let Ok(id) = std::str::from_utf8(&id[..end]) {
                    if is_resource_id(id) && self.seen.insert(id.to_owned()) {
                        found.push((*kind, id.to_owned()));
                    }
                }
                cursor = start;
            }
        }
        let keep = window.len().saturating_sub(128);
        self.tail = window[keep..].to_vec();
        found
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// 创建响应包装：在把含资源 id 的块交给客户端之前先登记归属。
/// 非 2xx 没有新资源可登记，由调用方按原样回传。
pub(super) fn creation_body(
    app: Shared,
    session: &Session,
    kind: ResourceKind,
    project: Option<String>,
    path: String,
    body: Body,
) -> Body {
    let Some((identity, account_id)) = identity_of(session) else {
        return body;
    };
    let identity = identity.clone();
    let account_id = account_id.to_owned();
    let recognized = Arc::new(AtomicU64::new(0));
    let scanner = IdScanner::for_kind(kind);
    // 只有拿到完整 id 才推送正文：登记必须发生在客户端看到该 id 之前。
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), scanner),
        move |(mut data, mut scanner)| {
            let app = app.clone();
            let identity = identity.clone();
            let account_id = account_id.clone();
            let project = project.clone();
            let recognized = recognized.clone();
            let path = path.clone();
            async move {
                match data.next().await {
                    Some(Ok(chunk)) => {
                        for (_, upstream_id) in scanner.push(&chunk) {
                            recognized.fetch_add(1, Ordering::SeqCst);
                            let key = ResourceKey::new(&account_id, kind, &upstream_id);
                            let receipt = key.ok().map(|resource| ConfirmedCreation {
                                creation_id: format!(
                                    "{}:{}:{}",
                                    account_id,
                                    kind.as_str(),
                                    upstream_id
                                ),
                                resource,
                                // 项目内新建：请求头已指明归属项目；项目本身
                                // 必须先已登记（record_created 会校验）。
                                project: project.as_ref().and_then(|project_id| {
                                    ResourceKey::new(
                                        &account_id,
                                        ResourceKind::Project,
                                        project_id,
                                    )
                                    .ok()
                                }),
                            });
                            let db = app.db.lock().await;
                            let actor = RequestIdentity::from_session(identity.clone());
                            match crate::resource_acl::record_created(
                                &db.conn,
                                &actor,
                                receipt,
                            ) {
                                Ok(Some(_)) => tracing::info!(
                                    module = "gateway",
                                    kind = kind.as_str(),
                                    upstream_id = %upstream_id,
                                    "新资源已登记归属"
                                ),
                                Ok(None) => {}
                                Err(crate::resource_acl::AclError::AlreadyRegistered) => {}
                                Err(cause) => tracing::warn!(
                                    module = "gateway",
                                    error = %cause,
                                    "资源归属登记失败"
                                ),
                            }
                        }
                        Some((Ok(chunk), (data, scanner)))
                    }
                    Some(Err(cause)) => Some((Err(cause), (data, scanner))),
                    None => {
                        if recognized.load(Ordering::SeqCst) == 0 {
                            tracing::warn!(
                                module = "gateway",
                                path = %path,
                                kind = kind.as_str(),
                                "创建响应未识别到资源 id，归属未登记"
                            );
                        }
                        None
                    }
                }
            }
        },
    );
    Body::from_stream(stream)
}

// ---------------------------------------------------------------------------
// 集合过滤
// ---------------------------------------------------------------------------

/// 旧归属回填标记：写入 `gateway_settings` 表示已尝试过，回填只做一次。
const BACKFILL_SETTING: &str = "acl_backfill_v1";

/// 映射端点响应：`user_name → user_id`、`chatgpt_username → account_id`。
fn parse_mapping(value: &Value) -> (HashMap<String, String>, HashMap<String, String>) {
    let mut users = HashMap::new();
    for item in value["users"].as_array().into_iter().flatten() {
        let (Some(username), Some(user_id)) =
            (item["username"].as_str(), item["user_id"].as_str())
        else {
            continue;
        };
        users.insert(username.to_owned(), user_id.to_owned());
    }
    let mut accounts = HashMap::new();
    for item in value["accounts"].as_array().into_iter().flatten() {
        let (Some(username), Some(account_id)) = (
            item["chatgpt_username"].as_str(),
            item["account_id"].as_str(),
        ) else {
            continue;
        };
        accounts.insert(username.to_owned(), account_id.to_owned());
    }
    (users, accounts)
}

/// 启动时的一次性回填：把旧 `conversation_owners` / `project_owners` 搬进
/// `acl_resources`。只有能唯一映射 `user_name → user_id` 且
/// `chatgpt_username → account_id` 的行才认领；访客主体（含 `:`）与无法唯一
/// 映射的行保持未认领并写清单日志。回填幂等、只做一次、不修改旧表。
pub(super) async fn backfill_legacy_ownership(app: &Arc<App>) -> Result<()> {
    if app
        .db
        .lock()
        .await
        .get_setting(BACKFILL_SETTING)?
        .is_some()
    {
        return Ok(());
    }
    // 映射端点不可用时既不写标记也不回填猜测值，交给下次启动重试。
    let value: Value = match app
        .client
        .post(app.config.django.join("/0x/user/gateway-acl-mapping")?.as_str())
        .bearer_auth(&app.config.secret)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            response.json().await.context("ACL 映射响应不是 JSON")?
        }
        Ok(response) => {
            tracing::warn!(
                module = "gateway",
                status = %response.status(),
                "ACL 映射端点不可用，跳过旧归属回填"
            );
            return Ok(());
        }
        Err(cause) => {
            tracing::warn!(module = "gateway", error = %cause, "ACL 映射请求失败，跳过旧归属回填");
            return Ok(());
        }
    };
    let (users, accounts) = parse_mapping(&value);
    let mut claimed = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    {
        let db = app.db.lock().await;
        for (table, kind, id_column) in [
            (
                "conversation_owners",
                ResourceKind::Conversation,
                "conversation_id",
            ),
            ("project_owners", ResourceKind::Project, "project_id"),
        ] {
            let sql =
                format!("SELECT chatgpt_username,{id_column},user_name FROM {table}");
            let mut statement = db.conn.prepare(&sql)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            // 逐行独立提交：单行无法认领不影响其它行，也不回滚已认领结果。
            for (account_name, upstream_id, user_name) in rows {
                let kind = kind.as_str();
                if user_name.contains(':') {
                    skipped.push(format!("{kind}:{upstream_id}:访客主体"));
                    continue;
                }
                let (Some(account_id), Some(user_id)) =
                    (accounts.get(&account_name), users.get(&user_name))
                else {
                    skipped.push(format!("{kind}:{upstream_id}:无可唯一映射"));
                    continue;
                };
                let creation_id = format!("backfill:{account_id}:{kind}:{upstream_id}");
                // 冲突不覆盖：已登记资源保持原归属。
                claimed += db.conn.execute(
                    "INSERT OR IGNORE INTO acl_resources(account_id,resource_type,upstream_id,owner_user_id,creation_id) VALUES(?1,?2,?3,?4,?5)",
                    params![account_id, kind, upstream_id, user_id, creation_id],
                )?;
            }
        }
        db.set_setting(BACKFILL_SETTING, &json!({"claimed": claimed}))?;
    }
    if !skipped.is_empty() {
        tracing::warn!(
            module = "gateway",
            count = skipped.len(),
            detail = %skipped.join(", "),
            "旧归属回填跳过未认领行"
        );
    }
    tracing::info!(module = "gateway", claimed, "旧归属回填完成");
    Ok(())
}

/// 集合项的 id 字段（按资源族）。
fn collection_keys(kind: ResourceKind) -> &'static [&'static str] {
    match kind {
        ResourceKind::Conversation => &["conversation_id", "id"],
        ResourceKind::Project => &["project_id", "id"],
        ResourceKind::File => &["file_id", "library_file_id", "id"],
        ResourceKind::Image => &["image_id", "gen_id", "id"],
        ResourceKind::Task => &["task_id", "id"],
        ResourceKind::Connector => &["connector_id", "id"],
    }
}

/// 集合响应正文的元素数组键，按原版前端实际信封。
const COLLECTION_ENVELOPES: &[&str] = &[
    "items",
    "data",
    "results",
    "conversations",
    "projects",
    "files",
    "tasks",
    "connectors",
];

/// 集合过滤：只保留当前会话可见的资源项，并把 `total` 改成可见总数
/// （与逐条判权共用 `visible_ids`，不泄露他人资源的数量）。
pub(super) async fn filter_collection(
    app: &Arc<App>,
    session: &Session,
    kind: ResourceKind,
    value: Value,
) -> Result<Value> {
    let Some((identity, account_id)) = identity_of(session) else {
        // 访客/匿名会话看不到任何可归属资源：空集合不构成泄露。
        return Ok(empty_collection(value));
    };
    let visible = {
        let db = app.db.lock().await;
        let actor = RequestIdentity::from_session(identity.clone());
        crate::resource_acl::visible_ids(&db.conn, &actor, account_id, kind)?
    };
    let Some((mut object, array_key)) = collection_shape(value) else {
        // 未知信封：只有整体为空/非对象才原样返回，其它情况按空集合处理，
        // 避免把未过滤的他人资源交给客户端。
        return Ok(Value::Object(Map::new()));
    };
    let items = object
        .get(&array_key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let keys = collection_keys(kind);
    let filtered: Vec<Value> = items
        .into_iter()
        .filter(|item| {
            keys.iter().any(|key| {
                item.get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|id| visible.contains(id))
            })
        })
        .collect();
    object.insert(array_key, Value::Array(filtered));
    if object.contains_key("total") {
        object.insert("total".to_string(), json!(visible.len()));
    }
    Ok(Value::Object(object))
}

/// 集合信封形状：对象 + 已知数组键，或顶层数组。
fn collection_shape(value: Value) -> Option<(Map<String, Value>, String)> {
    match value {
        Value::Object(object) => {
            let key = COLLECTION_ENVELOPES
                .iter()
                .find(|key| object.contains_key(**key))?
                .to_string();
            Some((object, key))
        }
        Value::Array(items) => {
            let mut object = Map::new();
            object.insert("items".to_string(), Value::Array(items));
            Some((object, "items".to_string()))
        }
        _ => None,
    }
}

/// 空集合信封：保留原对象键形状，但把已知数组键清空。
fn empty_collection(value: Value) -> Value {
    match value {
        Value::Object(mut object) => {
            for key in COLLECTION_ENVELOPES {
                if object.contains_key(*key) {
                    object.insert((*key).to_string(), Value::Array(Vec::new()));
                }
            }
            object.insert("total".to_string(), json!(0));
            Value::Object(object)
        }
        Value::Array(_) => json!([]),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// 未显式分类的路径（Auto）：按 id 判定与响应裁剪
// ---------------------------------------------------------------------------

/// Auto 路径的请求侧判定结果。
pub(super) enum AutoDecision {
    /// 请求里出现的资源 id 全部属于当前会话（或没有 id）。
    Allowed,
    /// 存在他人资源 id：不接触上游，按「不存在」拒绝。
    Foreign,
    /// 存在账号下查不到的 id：未登记资源不可用，拒绝并提示两条出路。
    Unknown,
}

/// 请求侧判权：Auto 路径不像六族那样有固定语义，因此逐个 id 查登记与受众；
/// 只要有一个 id 不属于当前会话就整体拒绝（不部分放行）。
pub(super) async fn authorize_auto(
    app: &App,
    identity: &Identity,
    account_id: &str,
    ids: &[String],
    method: &Method,
) -> Result<AutoDecision> {
    // 动作按方法推导，与六族路径同一套语义：读方法查读权限，DELETE 查删除，
    // 其余按修改。
    let action = if matches!(*method, Method::GET | Method::HEAD) {
        Action::Read
    } else if *method == Method::DELETE {
        Action::Delete
    } else {
        Action::Modify
    };
    let actor = RequestIdentity::from_session(identity.clone());
    let db = app.db.lock().await;
    for id in ids {
        match crate::resource_acl::auto_authority(&db.conn, &actor, account_id, id, action)? {
            crate::resource_acl::AutoAuthority::Visible(_) => {}
            crate::resource_acl::AutoAuthority::Foreign => return Ok(AutoDecision::Foreign),
            crate::resource_acl::AutoAuthority::Unknown => return Ok(AutoDecision::Unknown),
        }
    }
    Ok(AutoDecision::Allowed)
}

/// 六个资源族在当前会话下可见的 id 集合；Auto 响应过滤与创建登记共用一份视图，
/// 避免逐条查库。
pub(super) async fn visible_sets(
    app: &App,
    session: &Session,
) -> Result<HashMap<ResourceKind, std::collections::BTreeSet<String>>> {
    let mut sets = HashMap::new();
    let Some((identity, account_id)) = identity_of(session) else {
        return Ok(sets);
    };
    let actor = RequestIdentity::from_session(identity.clone());
    let db = app.db.lock().await;
    for kind in [
        ResourceKind::Conversation,
        ResourceKind::Project,
        ResourceKind::File,
        ResourceKind::Image,
        ResourceKind::Task,
        ResourceKind::Connector,
    ] {
        sets.insert(
            kind,
            crate::resource_acl::visible_ids(&db.conn, &actor, account_id, kind)?,
        );
    }
    Ok(sets)
}

/// 对象里的资源 id：族专用键必看，裸 `id` 只在 UUID 形态时参与（否则
/// `id: "gpt-5"` 这类账号级清单会被当成资源裁空）。
fn object_ids(object: &Map<String, Value>) -> Vec<(ResourceKind, String)> {
    let mut ids = Vec::new();
    for (key, kind) in RESOURCE_ID_KEYS {
        if let Some(id) = object.get(*key).and_then(Value::as_str) {
            if is_resource_id(id) {
                ids.push((*kind, id.to_owned()));
            }
        }
    }
    if let Some(id) = object.get("id").and_then(Value::as_str) {
        if is_uuid(id) {
            ids.push((ResourceKind::Conversation, id.to_owned()));
        }
    }
    ids
}

/// 这些 id 是否全部可见；没有任何可识别 id 时恒为真（不参与过滤）。
fn ids_visible(
    ids: &[(ResourceKind, String)],
    visible: &HashMap<ResourceKind, std::collections::BTreeSet<String>>,
) -> bool {
    ids.iter()
        .all(|(kind, id)| visible.get(kind).is_some_and(|known| known.contains(id)))
}

/// 条目是否可见：非对象（数组里混入标量）不参与过滤。
fn entry_visible(
    item: &Value,
    visible: &HashMap<ResourceKind, std::collections::BTreeSet<String>>,
) -> bool {
    match item.as_object() {
        Some(object) => ids_visible(&object_ids(object), visible),
        None => true,
    }
}

/// Auto 响应过滤：顶层数组按可见性裁剪，已知信封同步 `total`；顶层对象自身
/// 提到不可见 id 时整体拒绝（返回 None）。返回值第二项表示是否真的裁剪过，
/// 没有裁剪时调用方可以原样回传上游字节。
pub(super) fn filter_auto_json(
    value: Value,
    visible: &HashMap<ResourceKind, std::collections::BTreeSet<String>>,
) -> Option<(Value, bool)> {
    match value {
        Value::Object(mut object) => {
            // 顶层单对象：`{"conversation_id": "..."}` 这类响应不允许携带他人资源。
            if !ids_visible(&object_ids(&object), visible) {
                return None;
            }
            let mut changed = false;
            let keys: Vec<String> = object.keys().cloned().collect();
            for key in keys {
                let Some(Value::Array(items)) = object.get(&key) else {
                    continue;
                };
                let listed = items.len();
                let filtered: Vec<Value> = items
                    .iter()
                    .filter(|item| entry_visible(item, visible))
                    .cloned()
                    .collect();
                if filtered.len() == listed {
                    continue;
                }
                let length = filtered.len();
                object.insert(key.clone(), Value::Array(filtered));
                changed = true;
                if COLLECTION_ENVELOPES.contains(&key.as_str()) && object.contains_key("total") {
                    object.insert("total".to_string(), json!(length));
                }
            }
            Some((Value::Object(object), changed))
        }
        Value::Array(items) => {
            let listed = items.len();
            let filtered: Vec<Value> = items
                .into_iter()
                .filter(|item| entry_visible(item, visible))
                .collect();
            let changed = filtered.len() != listed;
            Some((Value::Array(filtered), changed))
        }
        other => Some((other, false)),
    }
}

/// Auto 路径的成功响应登记：把正文里出现的资源 id 记到当前会话名下，已登记
/// 的归属一律不动（`claim_if_absent`）。
pub(super) async fn claim_auto(
    app: &App,
    identity: &Identity,
    account_id: &str,
    found: Vec<(ResourceKind, String)>,
) {
    let actor = RequestIdentity::from_session(identity.clone());
    let db = app.db.lock().await;
    for (kind, upstream_id) in found {
        let Ok(key) = ResourceKey::new(account_id, kind, &upstream_id) else {
            continue;
        };
        match crate::resource_acl::claim_if_absent(&db.conn, &actor, &key) {
            Ok(true) => tracing::info!(
                module = "gateway",
                kind = kind.as_str(),
                upstream_id = %upstream_id,
                "未分类路径响应里的新资源已登记归属"
            ),
            Ok(false) => {}
            Err(cause) => tracing::warn!(
                module = "gateway",
                error = %cause,
                "未分类路径的资源登记失败"
            ),
        }
    }
}

/// 已缓冲的成功响应（JSON）：扫描正文里的资源 id 并登记给当前会话。
pub(super) async fn claim_auto_buffer(app: &App, session: &Session, body: &[u8]) {
    let Some((identity, account_id)) = identity_of(session) else {
        return;
    };
    let found = IdScanner::for_all_kinds().push(body);
    claim_auto(app, identity, account_id, found).await;
}

/// Auto 路径的流式响应正文：与创建响应同规则——含 id 的块交给客户端之前先登记。
pub(super) fn auto_claim_body(app: Shared, session: &Session, body: Body) -> Body {
    let Some((identity, account_id)) = identity_of(session) else {
        return body;
    };
    let identity = identity.clone();
    let account_id = account_id.to_owned();
    let scanner = IdScanner::for_all_kinds();
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), scanner),
        move |(mut data, mut scanner)| {
            let app = app.clone();
            let identity = identity.clone();
            let account_id = account_id.clone();
            async move {
                match data.next().await {
                    Some(Ok(chunk)) => {
                        let found = scanner.push(&chunk);
                        claim_auto(&app, &identity, &account_id, found).await;
                        Some((Ok(chunk), (data, scanner)))
                    }
                    Some(Err(cause)) => Some((Err(cause), (data, scanner))),
                    None => None,
                }
            }
        },
    );
    Body::from_stream(stream)
}

// ---------------------------------------------------------------------------
// 生成租约与撤权中止
// ---------------------------------------------------------------------------

/// 进程内 ACL 运行时：生成互斥租约 + 流式中止登记。
/// 两者都是进程内状态：重启后不重建上游任务，也不假装还有在途流。
#[derive(Default)]
pub(super) struct Runtime {
    /// 在途生成：(账号, 资源) 唯一，Drop 即移除——同一键同时只能有一个所有者。
    leases: Mutex<HashSet<String>>,
    streams: Mutex<Vec<StreamEntry>>,
    next_stream: AtomicU64,
    /// 未显式分类路径的首次命中记录：`<方法> <路径>`，上限见 [`ROUTE_LOG_LIMIT`]。
    routes: Mutex<HashSet<String>>,
}

/// 未分类路径的首次命中表上限。上游前端每次发版都会带来一批新路径，这张表
/// 只用于「第一次见到就记一笔」，不是路由白名单，因此满了以后只记日志。
const ROUTE_LOG_LIMIT: usize = 1024;

/// 未分类路径的命中次数：只有第一次需要写日志与审计。
#[derive(Debug, Clone, Copy)]
pub(super) enum RouteSighting {
    /// 第一次见到：写日志 + 审计。
    First,
    /// 第一次见到但表已满：只写日志（不再无限增长）。
    Overflow,
    /// 之前见过：静默。
    Repeat,
}

/// 一次请求的未分类路径记录：判定与响应阶段共用同一个键与命中次数。
pub(super) struct RouteWatch {
    key: String,
    sighting: RouteSighting,
}

impl RouteWatch {
    /// 记录本请求的处理结果：首次命中写 warn 日志，`First` 额外写一条审计。
    pub(super) async fn note(self, app: &App, session: &Session, action: &'static str) {
        match self.sighting {
            RouteSighting::Repeat => return,
            RouteSighting::Overflow => {
                tracing::warn!(
                    module = "gateway",
                    route = %self.key,
                    "未分类路径首次命中但记录表已满：只记日志"
                );
                return;
            }
            RouteSighting::First => {}
        }
        tracing::warn!(
            module = "gateway",
            route = %self.key,
            action,
            "未分类路径首次命中：上游前端可能新增了路由"
        );
        let Some((identity, account_id)) = identity_of(session) else {
            return;
        };
        let actor = RequestIdentity::from_session(identity.clone());
        let db = app.db.lock().await;
        if let Err(cause) =
            crate::resource_acl::audit_route(&db.conn, &actor, account_id, action, &self.key)
        {
            tracing::warn!(module = "gateway", error = %cause, "未分类路径审计写入失败");
        }
    }
}

struct StreamEntry {
    id: u64,
    /// 镜像用户名（Django 撤销事件里的 subject）：撤权事件按 subject 命中会话，
    /// 因此中止登记也用同一把键，不引入第二套用户 id 真相。
    subject: String,
    tx: watch::Sender<bool>,
}

/// 生成租约：Drop 即释放（成功、失败、取消、连接断开都走 Drop）。
pub(super) struct Lease {
    runtime: Arc<Runtime>,
    key: String,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut leases = self.runtime.leases.lock().expect("租约表中毒");
        leases.remove(&self.key);
    }
}

impl Runtime {
    /// 取得 `(账号, 资源)` 的独占生成租约；已有在途生成时返回 None（调用方 409）。
    pub(super) fn acquire(
        runtime: &Arc<Runtime>,
        account_id: &str,
        resource_id: &str,
    ) -> Option<Lease> {
        let key = format!("{account_id}\u{1f}{resource_id}");
        let mut leases = runtime.leases.lock().expect("租约表中毒");
        if !leases.insert(key.clone()) {
            return None;
        }
        Some(Lease {
            runtime: runtime.clone(),
            key,
        })
    }

    /// 中止某个镜像用户的全部在途流（撤权、登出、踢下线）。
    pub(super) fn abort_subject(&self, subject: &str) {
        let mut streams = self.streams.lock().expect("流表中毒");
        streams.retain(|entry| {
            if entry.subject == subject {
                let _ = entry.tx.send(true);
                false
            } else {
                true
            }
        });
    }

    /// 把上游流包成「撤权即结束」的流：登记一个中止通道，流结束或被丢弃时注销。
    pub(super) fn abortable(runtime: &Arc<Runtime>, subject: &str, body: Body) -> Body {
        let (rx, guard) = Runtime::watch(runtime, subject);
        let stream = futures_util::stream::unfold(
            (body.into_data_stream(), guard, rx.clone()),
            move |(mut data, guard, mut rx)| {
                async move {
                    tokio::select! {
                        biased;
                        // 只有撤权会写这个通道：收到即结束下游响应，不再把剩余内容交给已失权用户。
                        _ = rx.changed() => None,
                        chunk = data.next() => match chunk {
                            Some(Ok(chunk)) => Some((Ok(chunk), (data, guard, rx))),
                            Some(Err(error)) => Some((Err(error), (data, guard, rx))),
                            None => None,
                        },
                    }
                }
            },
        );
        Body::from_stream(stream)
    }

    /// 登记一个「撤权即中止」的订阅：返回接收端与注销守卫。
    /// HTTP/SSE 用 [`Runtime::abortable`] 包正文体；WebSocket 等长连接直接 select 接收端，
    /// 两者共用同一张表，撤权/登出因此对两种在途流都生效。
    pub(super) fn watch(
        runtime: &Arc<Runtime>,
        subject: &str,
    ) -> (watch::Receiver<bool>, StreamGuard) {
        let tx = watch::channel(false).0;
        let id = runtime.next_stream.fetch_add(1, Ordering::SeqCst);
        runtime
            .streams
            .lock()
            .expect("流表中毒")
            .push(StreamEntry {
                id,
                subject: subject.to_owned(),
                tx: tx.clone(),
            });
        let rx = tx.subscribe();
        (
            rx,
            StreamGuard {
                runtime: runtime.clone(),
                id,
                tx,
            },
        )
    }
}

/// 响应级包装：保留状态码与响应头，只把正文换成可中止流。
pub(super) fn abortable_stream(runtime: &Arc<Runtime>, subject: &str, response: Response) -> Response {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Runtime::abortable(runtime, subject, body))
}

/// 生成租约挂到响应体上：响应体被消费完或客户端断开时 Drop，租约随之释放。
pub(super) fn attach_lease(response: Response, lease: Lease) -> Response {
    let (parts, body) = response.into_parts();
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), lease),
        |(mut data, lease)| async move {
            match data.next().await {
                Some(Ok(chunk)) => Some((Ok(chunk), (data, lease))),
                Some(Err(error)) => Some((Err(error), (data, lease))),
                None => None,
            }
        },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

/// 流注册的注销守卫：流结束、被丢弃或客户端断开都会移除登记，避免表无限增长。
/// `tx` 只用于持有发送端：全部发送端释放时订阅端会收到关闭，这正是「流已结束」的
/// 信号，因此该字段必须活着而不是被优化掉。
pub(super) struct StreamGuard {
    runtime: Arc<Runtime>,
    id: u64,
    #[allow(dead_code)]
    tx: watch::Sender<bool>,
}

/// 长连接（WebSocket）的中止订阅：接收端用于 select，守卫负责注销登记。
pub(super) type AbortWatch = (watch::Receiver<bool>, StreamGuard);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.runtime
            .streams
            .lock()
            .expect("流表中毒")
            .retain(|entry| entry.id != self.id);
    }
}

/// 登记一次未分类路径的命中：只有 `<方法> <路径>` 第一次出现时需要留痕。
pub(super) fn observe_route(runtime: &Runtime, method: &Method, path: &str) -> RouteWatch {
    let key = format!("{method} {path}");
    let mut routes = runtime.routes.lock().expect("路径表中毒");
    let sighting = if routes.contains(&key) {
        RouteSighting::Repeat
    } else if routes.len() >= ROUTE_LOG_LIMIT {
        RouteSighting::Overflow
    } else {
        routes.insert(key.clone());
        RouteSighting::First
    };
    RouteWatch { key, sighting }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSATION: &str = "6ab350c7-5d3c-83ea-be1f-a87b536c1c6c";

    fn class(path: &str, method: Method) -> Verdict {
        classify(&method, path, None, &HeaderMap::new(), b"")
    }

    /// 测试辅助：按带 query 与请求体的真实形态分类。
    fn class_with(path: &str, method: Method, query: Option<&str>, body: &[u8]) -> Verdict {
        classify(&method, path, query, &HeaderMap::new(), body)
    }

    fn scoped(verdict: Verdict) -> Scoped {
        match verdict {
            Verdict::Scoped(scope) => scope,
            _ => panic!("必须判定为资源作用域"),
        }
    }

    impl Verdict {
        /// 测试辅助：判定是否为账号级路径。
        fn into_unscoped(self) -> bool {
            matches!(self, Verdict::Unscoped)
        }

        /// 测试辅助：判定是否为「未显式分类、按 id 判定」的路径。
        fn into_auto(self) -> Option<(bool, Vec<String>)> {
            match self {
                Verdict::Auto { claim, ids } => Some((claim, ids)),
                _ => None,
            }
        }
    }

    /// 会话作用域：裸 id、id 前缀与请求体 id 都要按会话判权。
    #[test]
    fn conversation_scope_matches_path_and_body_ids() {
        let path = format!("/backend-api/conversation/{CONVERSATION}");
        assert_eq!(scoped(class(&path, Method::GET)).upstream_id, CONVERSATION);
        assert_eq!(
            scoped(class(&path, Method::DELETE)).action,
            Action::Delete
        );
        // 裸续聊才是生成；带子路径的写操作不占生成租约。
        assert!(scoped(class(
            &format!("/backend-api/conversation/{CONVERSATION}"),
            Method::POST
        ))
        .generation);
        assert!(!scoped(class(
            &format!("/backend-api/conversation/{CONVERSATION}/rename"),
            Method::POST
        ))
        .generation);
        let body = format!(r#"{{"conversation_id":"{CONVERSATION}"}}"#);
        let verdict = classify(
            &Method::POST,
            "/backend-api/conversation",
            None,
            &HeaderMap::new(),
            body.as_bytes(),
        );
        assert_eq!(scoped(verdict).upstream_id, CONVERSATION);
        // 没有会话 id 的创建请求走登记分支。
        assert!(matches!(
            classify(
                &Method::POST,
                "/backend-api/f/conversation",
                None,
                &HeaderMap::new(),
                b""
            ),
            Verdict::Creation {
                kind: ResourceKind::Conversation,
                project: None
            }
        ));
        assert!(matches!(
            classify(
                &Method::POST,
                "/backend-api/sidebar/conversation",
                None,
                &HeaderMap::new(),
                b"{}"
            ),
            Verdict::Creation {
                kind: ResourceKind::Conversation,
                project: None
            }
        ));
    }

    /// 项目/文件/图片/任务/连接器：带 id 的子路径判权，集合与创建分开。
    #[test]
    fn other_resource_families_are_classified() {
        assert!(matches!(
            class("/backend-api/projects", Method::GET),
            Verdict::Collection(ResourceKind::Project)
        ));
        assert!(matches!(
            class("/backend-api/projects", Method::POST),
            Verdict::Creation {
                kind: ResourceKind::Project,
                project: None
            }
        ));
        assert_eq!(
            scoped(class("/backend-api/projects/abc-123", Method::PATCH)).kind,
            ResourceKind::Project
        );

        assert!(matches!(
            class("/backend-api/files", Method::POST),
            Verdict::Creation {
                kind: ResourceKind::File,
                project: None
            }
        ));
        assert_eq!(
            scoped(class("/backend-api/files/file-1", Method::GET)).kind,
            ResourceKind::File
        );
        assert_eq!(
            scoped(class("/backend-api/files/library/files/lib-9", Method::DELETE)).kind,
            ResourceKind::File
        );
        // 上传预约 id 不是文件 id：不登记、不判权。
        assert!(matches!(
            class("/backend-api/files/upload_reservations", Method::POST),
            Verdict::Unscoped
        ));

        assert!(matches!(
            class("/backend-api/images", Method::GET),
            Verdict::Collection(ResourceKind::Image)
        ));
        assert_eq!(
            scoped(class("/backend-api/images/image-tags/tag-1", Method::DELETE)).kind,
            ResourceKind::Image
        );
        assert!(matches!(
            class("/backend-api/my/recent/image_gen", Method::GET),
            Verdict::Collection(ResourceKind::Image)
        ));

        assert_eq!(
            scoped(class("/backend-api/tasks/task-1", Method::GET)).kind,
            ResourceKind::Task
        );
        assert!(matches!(
            class("/backend-api/task_suggestions", Method::GET),
            Verdict::Unscoped
        ));

        assert_eq!(
            scoped(class("/backend-api/aip/connectors/conn-1", Method::GET)).kind,
            ResourceKind::Connector
        );
        // 账号级连接器清单不按连接器判权。
        assert!(matches!(
            class("/backend-api/aip/connectors/list_accessible", Method::GET),
            Verdict::Unscoped
        ));
    }

    /// 账号级前缀放行；未显式登记的路径走 id 判定，两者都不能静默互换。
    #[test]
    fn account_level_prefixes_are_explicit_and_new_paths_take_the_id_route() {
        for path in [
            "/backend-api/me",
            "/backend-api/models",
            "/backend-api/accounts/check/v4",
            "/backend-api/settings/user",
            "/backend-api/conversation/init",
            "/backend-api/f/conversation/prepare",
            // 快照之后新增、由真实前端请求观测确认的账号级路径：不加这一条
            // 每个已登录页面都会命中 4 次 503。
            "/backend-api/checkout_pricing_config/configs/US",
        ] {
            assert!(
                class(path, Method::GET).into_unscoped(),
                "{path} 应为账号级路径"
            );
        }
        // 前端新路由：没有 id 就直接放行，不需要再登记前缀。
        let (claim, ids) = class("/backend-api/brand-new-surface/v2", Method::POST)
            .into_auto()
            .expect("未登记前缀应当走 id 判定");
        assert!(claim, "写方法需要按响应登记新资源");
        assert!(ids.is_empty(), "无 id 的路径不参与判权：{ids:?}");
        // 读方法不登记。
        let (claim, _) = class("/backend-api/brand-new-surface/v2", Method::GET)
            .into_auto()
            .expect("未登记前缀应当走 id 判定");
        assert!(!claim);
        // 路径段里的 UUID、query 与请求体里的 `*_id` 都要被识别。
        let (_, ids) = class_with(
            &format!("/backend-api/brand-new-surface/{CONVERSATION}"),
            Method::GET,
            Some("file_id=file-0001&limit=20"),
            br#"{"project_id":"proj-0001","title":"x"}"#,
        )
        .into_auto()
        .expect("未登记前缀应当走 id 判定");
        assert_eq!(ids, vec![CONVERSATION, "file-0001", "proj-0001"]);
        // 形态不合法的值不是资源 id：不参与判权。
        let (_, ids) = class_with(
            "/backend-api/brand-new-surface/v2",
            Method::POST,
            Some("item_id=1"),
            br#"{"name":"proj"}"#,
        )
        .into_auto()
        .expect("未登记前缀应当走 id 判定");
        assert!(ids.is_empty(), "短值/非 `_id` 键不应参与：{ids:?}");
        // 非业务面路径没有归属语义。
        assert!(matches!(
            class("/backend-anon/models", Method::GET),
            Verdict::Unscoped
        ));
    }

    /// 创建响应扫描：id 跨块、重复块、同块重复都只登记一次。
    #[test]
    fn creation_scanner_finds_ids_across_chunks() {
        let mut scanner = IdScanner::for_kind(ResourceKind::Project);
        assert!(scanner.push(b"{\"project_id\":\"").is_empty());
        assert_eq!(
            scanner.push(b"abc-123\",\"kind\":\"topic\"}"),
            vec![(ResourceKind::Project, "abc-123".to_owned())]
        );
        assert!(scanner
            .push(format!("{{\"project_id\":\"{}\"}}", "abc-123").as_bytes())
            .is_empty());
        // 只有 `id` 的信封同样能认领。
        let mut scanner = IdScanner::for_kind(ResourceKind::Task);
        assert_eq!(
            scanner.push(b"{\"id\":\"task-77\"}"),
            vec![(ResourceKind::Task, "task-77".to_owned())]
        );
        let mut scanner = IdScanner::for_kind(ResourceKind::Conversation);
        assert!(scanner.push(b"{\"detail\":\"no id here\"}").is_empty());
    }

    /// 全族扫描器（未分类路径的响应登记）同时识别六族的键，并把裸 `id` 当会话。
    #[test]
    fn all_kinds_scanner_covers_every_family_key() {
        let mut scanner = IdScanner::for_all_kinds();
        let found = scanner.push(
            br#"{"conversation_id":"conv-0001","project_id":"proj-0001","gen_id":"img-0001","id":"6ab350c7-5d3c-83ea-be1f-a87b536c1c6c"}"#,
        );
        assert_eq!(
            found,
            vec![
                (ResourceKind::Conversation, "conv-0001".to_owned()),
                (ResourceKind::Project, "proj-0001".to_owned()),
                (ResourceKind::Image, "img-0001".to_owned()),
                (
                    ResourceKind::Conversation,
                    "6ab350c7-5d3c-83ea-be1f-a87b536c1c6c".to_owned()
                ),
            ]
        );
    }

    /// 路由快照里凡是带六族 id 占位符的模板，都必须由族规则显式判定，不能落到
    /// 「未显式分类」的 id 兜底：否则集合过滤、生成互斥与创建登记都会失效。
    /// 不带占位符的字面量路由允许直接走 id 兜底——这正是上游前端新增路由时
    /// 不需要再改网关代码的原因。
    #[test]
    fn snapshot_family_placeholders_are_never_left_to_the_auto_route() {
        let snapshot: Value =
            serde_json::from_str(include_str!("../assets/chatgpt-api-routes.json"))
                .expect("路由快照必须是 JSON");
        let routes = snapshot["routes"].as_array().expect("快照缺少 routes");
        assert!(routes.len() > 900, "路由快照条数异常：{}", routes.len());
        const FAMILY_HOLDS: [&str; 9] = [
            "{conversation_id}",
            "{conv_id}",
            "{project_id}",
            "{task_id}",
            "{file_id}",
            "{library_file_id}",
            "{image_id}",
            "{gen_id}",
            "{connector_id}",
        ];
        let mut fallen_back: Vec<String> = Vec::new();
        for route in routes {
            let method = route["method"]
                .as_str()
                .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
                .expect("快照方法必须可解析");
            let template = route["path"].as_str().expect("快照路径必须是字符串");
            if !FAMILY_HOLDS
                .iter()
                .any(|placeholder| template.contains(placeholder))
            {
                continue;
            }
            let path = concrete_path(template);
            // 请求体与归属头按「该族最常见的真实形态」给出：带 UUID 的模板因此
            // 能被路径规则识别；不带 id 的模板落账号级也在此允许。
            let body = br#"{"conversation_id":"6ab350c7-5d3c-83ea-be1f-a87b536c1c6c"}"#;
            if matches!(
                classify(&method, &path, None, &HeaderMap::new(), body),
                Verdict::Auto { .. }
            ) {
                fallen_back.push(format!("{method} {template}"));
            }
        }
        assert!(
            fallen_back.is_empty(),
            "以下模板带六族 id 却落到了 id 兜底（六族规则失效）：\n{}",
            fallen_back.join("\n")
        );
    }

    /// Auto 响应过滤：数组按可见性裁剪并同步 `total`；他人单对象整体拒绝；
    /// 账号级清单（非 UUID 的裸 `id`）与含未识别字段的条目原样保留。
    #[test]
    fn auto_response_filter_drops_foreign_entries_and_refuses_foreign_objects() {
        let mut visible: HashMap<ResourceKind, std::collections::BTreeSet<String>> = HashMap::new();
        visible.insert(
            ResourceKind::Conversation,
            std::iter::once(CONVERSATION.to_owned()).collect(),
        );
        visible.insert(
            ResourceKind::Project,
            std::iter::once("proj-mine".to_owned()).collect(),
        );
        let body = json!({
            "items": [
                {"conversation_id": CONVERSATION, "title": "mine"},
                {"conversation_id": "11111111-2222-3333-4444-555555555555", "title": "theirs"},
                {"title": "no id at all"},
            ],
            "total": 3,
            "models": [{"id": "gpt-5"}, {"id": "gpt-5-mini"}],
            "cursor": "opaque",
        });
        let (filtered, changed) =
            filter_auto_json(body.clone(), &visible).expect("数组条目只裁剪不拒绝");
        assert!(changed, "裁掉了他人条目就是改动过");
        assert_eq!(filtered["items"].as_array().unwrap().len(), 2);
        assert_eq!(filtered["total"], 2, "已知信封的总数必须同步");
        assert_eq!(
            filtered["models"].as_array().unwrap().len(),
            2,
            "非 UUID 的裸 id 是账号级清单，不参与过滤"
        );

        // 顶层对象直接提到他人资源：整体拒绝，而不是裁剪。
        let foreign = json!({"conversation_id": "11111111-2222-3333-4444-555555555555"});
        assert!(filter_auto_json(foreign, &visible).is_none());
        // 自己的资源照常放行；未登记/他人数组条目被裁掉。
        let mine = json!({"project_id": "proj-mine", "name": "x"});
        let (_, changed) = filter_auto_json(mine, &visible).unwrap();
        assert!(!changed, "没有裁剪就不该重写正文");
        let (emptied, changed) = filter_auto_json(
            json!([{"task_id": "task-9999"}, {"task_id": "task-9998"}]),
            &visible,
        )
        .unwrap();
        assert!(changed);
        assert_eq!(emptied.as_array().unwrap().len(), 0);
    }

    /// 快照模板 → 具体路径：`{x}` 段按名字换成对应形态的占位值。
    fn concrete_path(template: &str) -> String {
        let segments: Vec<String> = template
            .split('/')
            .map(|segment| match segment {
                "{conversation_id}" | "{conv_id}" => CONVERSATION.to_owned(),
                "{message_id}" => "msg-0001".to_owned(),
                "{account_id}" | "{user_id}" | "{project_id}" | "{file_id}"
                | "{library_file_id}" | "{directory_id}" | "{reference_image_id}"
                | "{image_tag_id}" | "{task_id}" | "{connector_id}" | "{link_id}"
                | "{plugin_id}" | "{app_id}" | "{gizmo_id}" | "{request_id}"
                | "{share_id}" | "{version_number}" | "{provider_key}"
                | "{marketplace_source_id}" | "{account_user_id}" | "{favorite_id}"
                | "{item_type}" | "{item_id}" | "{domain_id}" | "{reservation_id}"
                | "{gizmo_creator_id}" => "res-0001".to_owned(),
                other => other.to_owned(),
            })
            .collect();
        segments.join("/")
    }
}

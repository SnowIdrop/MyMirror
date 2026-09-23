// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/owners.rs
// Created : 2026-09-23
// Summary : 会话归属登记最小核心。创建响应里出现的会话 id 登记给发起用户，
//           会话作用域请求在转发前校验归属，未登记与已属他人一律拒绝。
//           证据来源：MirrorNiXiang/reverse/reports/08-reconstruction-notes.md
//           §3.1-C、§6.1（原版 claim_conversation_owner / conversation_belongs_to_user）；
//           流式创建响应的 conversation_id 形态见
//           evidence/anonymous-nextauth-001/mirror-run-002/conversation-bodies.json。
// -----------------------------------------------------------------------------

//! 缺口 3 的最小接线：只覆盖已登录业务面（`/backend-api/*`）的会话归属。
//!
//! 与「计量 / 配额 / 限流 / 审核 / PoW 为显式非目标」配套：共享账号下剩下的
//! 内容级边界就是归属隔离、撤权与凭据隔离，因此开放 `/backend-api/*` 读写
//! 必须同时落地本模块。项目/分支级归属与整体 ACL 接线仍属缺口 3 的完整批次。

use super::*;
use axum::http::Method;
use futures_util::StreamExt;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// 会话 id 的路径段名（`/backend-api/conversation/<id>`）。
const CONVERSATION_SEGMENT: &str = "conversation";

/// 上游创建响应里的会话 id 字段标记：SSE 增量与普通 JSON 两种形态同名。
const CONVERSATION_ID_MARKER: &[u8] = b"\"conversation_id\":\"";

/// 会话 id 的固定长度（8-4-4-4-12 十六进制 UUID）。
const CONVERSATION_UUID_LEN: usize = 36;

/// 扫描窗口保留的尾部字节数：必须大于标记与 id 长度之和（19 + 36）。
const SCAN_TAIL: usize = 128;

/// 请求与会话归属的关系。只有 `/backend-api/*` 参与判定，其余路径没有归属语义。
pub(super) enum Ownership {
    /// 与会话归属无关（页面、匿名通道、公共前缀、模型清单等）
    Irrelevant,
    /// 创建请求：放行，并在响应正文里登记新会话
    Creation,
    /// 会话作用域请求：转发前必须命中当前用户的登记行
    Existing(String),
}

/// 判定请求与会话归属的关系。`body` 只用于 `POST .../conversation` 的续聊载荷。
pub(super) fn classify(path: &str, method: &Method, body: &[u8]) -> Ownership {
    if !path.starts_with("/backend-api/") {
        return Ownership::Irrelevant;
    }
    if let Some(conversation_id) = conversation_id_from_path(path) {
        return Ownership::Existing(conversation_id.to_owned());
    }
    // 续聊把会话 id 放在请求体里；创建请求没有该字段（客户端临时 id 不是 UUID）。
    if *method == Method::POST && path.ends_with("/conversation") {
        if let Some(conversation_id) = conversation_id_from_body(body) {
            return Ownership::Existing(conversation_id);
        }
        return Ownership::Creation;
    }
    Ownership::Irrelevant
}

/// `/…/conversation/<uuid>` 形态：只认 `conversation` 段之后紧跟的会话 id。
/// `conversations`（列表）、`conversation/init`、`conversation/prepare` 等字面量不算。
fn conversation_id_from_path(path: &str) -> Option<&str> {
    let mut segments = path.split('/');
    while let Some(segment) = segments.next() {
        if segment == CONVERSATION_SEGMENT {
            return segments.next().filter(|next| is_conversation_id(next));
        }
    }
    None
}

/// 请求体里的会话 id：只有合法 UUID 才参与归属判定，临时 id 交给创建分支。
fn conversation_id_from_body(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let raw = value.get("conversation_id")?.as_str()?;
    is_conversation_id(raw).then(|| raw.to_owned())
}

/// 会话 id 形态：8-4-4-4-12 十六进制 UUID。临时/客户端 id 一律不算。
fn is_conversation_id(value: &str) -> bool {
    value.len() == CONVERSATION_UUID_LEN
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// 归属判定：只有「已登记且属于当前用户」为真；未知归属不认领。
pub(super) async fn owned_by(app: &App, session: &Session, conversation_id: &str) -> Result<bool> {
    let db = app.db.lock().await;
    let owned: i64 = db.conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversation_owners WHERE chatgpt_username=?1 AND conversation_id=?2 AND user_name=?3)",
        params![session.account, conversation_id, session.user],
        |row| row.get(0),
    )?;
    Ok(owned != 0)
}

/// 登记归属：同一会话已被登记时保持原行，不改属主（返回值表示本次是否新登记）。
pub(super) async fn claim(
    app: &App,
    account: &str,
    user: &str,
    conversation_id: &str,
) -> Result<bool> {
    let db = app.db.lock().await;
    let stamp = now();
    let inserted = db.conn.execute(
        "INSERT INTO conversation_owners(chatgpt_username,conversation_id,user_name,created_at,updated_at) VALUES(?1,?2,?3,?4,?4) ON CONFLICT(chatgpt_username,conversation_id) DO NOTHING",
        params![account, conversation_id, user, stamp],
    )?;
    Ok(inserted == 1)
}

/// 归属拒绝响应：与「会话不存在」同形，既不泄露他人会话是否存在，也不接触上游。
pub(super) fn refusal() -> Response {
    error(StatusCode::NOT_FOUND, "会话不存在或不属于当前用户").into_response()
}

/// 创建响应扫描器：按块寻找 `"conversation_id":"<uuid>"`，尾部保留重叠，
/// 保证 id 跨块时仍能命中。
#[derive(Default)]
pub(super) struct CreationScanner {
    tail: Vec<u8>,
}

impl CreationScanner {
    /// 扫描一个正文块，返回本块内识别到的会话 id（同块内去重）。
    pub(super) fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(chunk);
        let mut found: Vec<String> = Vec::new();
        let mut cursor = 0;
        while let Some(offset) = find(&window[cursor..], CONVERSATION_ID_MARKER) {
            let start = cursor + offset + CONVERSATION_ID_MARKER.len();
            // id 未完整到达：保留尾窗，等下一块补齐。
            let Some(id) = window.get(start..start + CONVERSATION_UUID_LEN) else {
                break;
            };
            if let Ok(id) = std::str::from_utf8(id) {
                if is_conversation_id(id) && !found.iter().any(|seen| seen == id) {
                    found.push(id.to_owned());
                }
            }
            cursor = start;
        }
        let keep = window.len().saturating_sub(SCAN_TAIL);
        self.tail = window[keep..].to_vec();
        found
    }
}

/// 创建响应的正文包装：在把含会话 id 的块交给客户端之前先登记归属。
/// 非成功响应没有新会话可登记，由调用方按原样回传。
pub(super) fn creation_body(app: Shared, session: &Session, path: String, body: Body) -> Body {
    let user = session.user.clone();
    let account = session.account.clone();
    let recognized = Arc::new(AtomicUsize::new(0));
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), CreationScanner::default()),
        move |(mut data, mut scanner)| {
            let app = app.clone();
            let recognized = recognized.clone();
            let path = path.clone();
            let user = user.clone();
            let account = account.clone();
            async move {
                match data.next().await {
                    Some(Ok(chunk)) => {
                        for conversation_id in scanner.push(&chunk) {
                            recognized.fetch_add(1, Ordering::SeqCst);
                            match claim(&app, &account, &user, &conversation_id).await {
                                Ok(true) => tracing::info!(
                                    module = "gateway",
                                    conversation_id = %conversation_id,
                                    "新会话已登记归属"
                                ),
                                Ok(false) => {}
                                Err(cause) => tracing::warn!(
                                    module = "gateway",
                                    error = %cause,
                                    "会话归属登记失败"
                                ),
                            }
                        }
                        Some((Ok(chunk), (data, scanner)))
                    }
                    Some(Err(cause)) => {
                        Some((Err(std::io::Error::other(cause)), (data, scanner)))
                    }
                    None => {
                        // 2xx 创建响应却认不出会话 id：只记路径与结论，不落正文。
                        if recognized.load(Ordering::SeqCst) == 0 {
                            tracing::warn!(
                                module = "gateway",
                                path = %path,
                                "创建响应未识别到会话 id，归属未登记"
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

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSATION: &str = "6ab350c7-5d3c-83ea-be1f-a87b536c1c6c";

    /// 只有已登录业务面的会话作用域与续聊写路径参与归属判定。
    #[test]
    fn classify_only_gates_the_logged_in_business_surface() {
        let irrelevant = [
            ("/", Method::GET),
            ("/c/6ab350c7-5d3c-83ea-be1f-a87b536c1c6c", Method::GET),
            ("/backend-anon/f/conversation", Method::POST),
            ("/backend-anon/conversation/init", Method::POST),
            ("/backend-api/me", Method::GET),
            ("/backend-api/conversations", Method::GET),
            ("/backend-api/conversation/init", Method::POST),
            ("/backend-api/conversation/prepare", Method::POST),
            ("/backend-api/models", Method::GET),
            ("/backend-api/files", Method::POST),
        ];
        for (path, method) in irrelevant {
            assert!(
                matches!(classify(path, &method, b""), Ownership::Irrelevant),
                "{method} {path}"
            );
        }
        for path in [
            "/backend-api/conversation/6ab350c7-5d3c-83ea-be1f-a87b536c1c6c",
            "/backend-api/conversation/6ab350c7-5d3c-83ea-be1f-a87b536c1c6c/feedback",
            "/backend-api/f/conversation/6ab350c7-5d3c-83ea-be1f-a87b536c1c6c",
        ] {
            match classify(path, &Method::GET, b"") {
                Ownership::Existing(id) => assert_eq!(id, CONVERSATION, "{path}"),
                _ => panic!("{path} 必须按会话作用域判定"),
            }
        }
    }

    /// 创建与续聊靠请求体区分：合法 UUID 走归属判定，缺失/临时 id 走创建登记。
    #[test]
    fn post_conversation_body_decides_between_creation_and_continuation() {
        for path in ["/backend-api/conversation", "/backend-api/f/conversation"] {
            assert!(
                matches!(classify(path, &Method::POST, b""), Ownership::Creation),
                "{path}"
            );
            let continuation = format!(r#"{{"conversation_id":"{CONVERSATION}"}}"#);
            match classify(path, &Method::POST, continuation.as_bytes()) {
                Ownership::Existing(id) => assert_eq!(id, CONVERSATION, "{path}"),
                _ => panic!("{path} 必须按续聊判定"),
            }
            for body in [
                r#"{"conversation_id":"tmp-branch-1"}"#,
                r#"{"conversation_id":null}"#,
                "not-json",
            ] {
                assert!(
                    matches!(classify(path, &Method::POST, body.as_bytes()), Ownership::Creation),
                    "{path} {body}"
                );
            }
        }
    }

    /// 会话 id 必须是完整 UUID：临时 id、截断 id 与其它段都不算。
    #[test]
    fn conversation_ids_require_the_full_uuid_shape() {
        assert!(is_conversation_id(CONVERSATION));
        for value in [
            "",
            "tmp-branch-1",
            "6ab350c7-5d3c-83ea-be1f-a87b536c1c6",
            "6ab350c7-5d3c-83ea-be1f-a87b536c1c6cx",
            "6ab350c75d3c83eabe1fa87b536c1c6c",
            "zzz350c7-5d3c-83ea-be1f-a87b536c1c6c",
        ] {
            assert!(!is_conversation_id(value), "{value}");
        }
    }

    /// 创建响应里的会话 id 跨块时仍要认出来，且重复块不会漏判“未识别到 id”。
    #[test]
    fn creation_scanner_finds_ids_split_across_chunks() {
        let mut scanner = CreationScanner::default();
        assert!(scanner
            .push(b"event: delta\ndata: {\"type\":\"resume\",\"conversation_id\":\"6ab350c7-5d3c-")
            .is_empty());
        assert_eq!(
            scanner.push(b"83ea-be1f-a87b536c1c6c\",\"kind\":\"topic\"}"),
            vec![CONVERSATION.to_owned()]
        );
        // 同一 id 在后续块重复出现：重新识别一次，落库由“不覆盖”语义去重。
        assert_eq!(
            scanner.push(format!("data: {{\"conversation_id\":\"{CONVERSATION}\"}}").as_bytes()),
            vec![CONVERSATION.to_owned()]
        );
        let mut scanner = CreationScanner::default();
        assert!(scanner.push(b"{\"detail\":\"no conversation here\"}").is_empty());
    }
}

// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/chat_ws.rs
// Created : 2026-09-23
// Summary : `/ws-chatgpt[/…]` → `wss://ws.chatgpt.com/…` 的 WebSocket 桥接。
//           证据来源：MirrorNiXiang/reverse/reports/08-reconstruction-notes.md
//           §6.2（路由、`wss://ws.chatgpt.com` 校验、tokio-tungstenite 0.24）、
//           §3.2（`proxy_chatgpt_ws_as_axum` 用 WebSocketUpgrade 提取器）。
//           注入脚本把浏览器 WebSocket 改写到本前缀，见
//           assets/gateway-client.html 的 normalizeWebSocketUrl。
// -----------------------------------------------------------------------------

//! WebSocket 桥接：只连有证据的唯一上游主机，凭据与会话绑定，代理出口未验证时
//! fail-closed。双向透传文本/二进制，任一侧关闭即把关闭帧转交另一侧。

use super::*;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::Uri,
};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use wreq::ws::message::{CloseFrame as WsCloseFrame, Message as WsMessage};

/// 关闭握手的收尾等待：对端不回关闭帧时不能让桥接任务悬住。
const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// 路由入口：鉴权 → 出口判定 → 连接上游 → 升级并双向透传。
pub(super) async fn route(
    State(app): State<Shared>,
    ws: WebSocketUpgrade,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(token) = token_from(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "未登录").into_response();
    };
    // 复用父 session()：镜像 token 只用于本机鉴权，绝不转发上游。
    let session = match session(&app, &token).await {
        Ok(Some(value)) => value,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "未登录").into_response(),
        Err(failure) => {
            return error(StatusCode::BAD_GATEWAY, &failure.to_string()).into_response()
        }
    };
    // 代理出口的 WS 分流尚未验证：宁可拒绝，也不静默改走直连。
    if session.outbound.proxied {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket 桥接尚未支持代理出口",
        )
        .into_response();
    }
    let auth = match proxy::chat_auth(&app, &session).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error(StatusCode::UNAUTHORIZED, "会话或出口绑定已失效").into_response()
        }
        Err(failure) => {
            return error(StatusCode::BAD_GATEWAY, &failure.to_string()).into_response()
        }
    };
    let target = match upstream_url(&app.config.ws_upstream, uri.path(), uri.query()) {
        Ok(value) => value,
        Err(failure) => {
            return error(StatusCode::BAD_REQUEST, &failure.to_string()).into_response()
        }
    };
    let request_headers = match upstream_headers(&app, &auth, &headers).await {
        Ok(value) => value,
        Err(failure) => {
            return error(StatusCode::BAD_GATEWAY, &failure.to_string()).into_response()
        }
    };
    let (upstream, response) =
        match connect(&session.outbound.client, &target, request_headers).await {
        Ok(value) => value,
        Err(failure) => {
            // 握手被 Cloudflare 拒绝时失效缓存，交给下一次请求重新走 cfbypass；
            // 与 HTTP 侧「不可重放的请求只失效缓存」保持一致。
            if failure.status == Some(StatusCode::FORBIDDEN) {
                app.cloudflare.invalidate().await;
                if auth.anonymous {
                    anonymous::invalidate(&app).await;
                }
            }
            let status = failure
                .status
                .map(|status| format!("状态码 {status}"))
                .unwrap_or_else(|| failure.cause.to_string());
            // 只回状态与本地结论，绝不回传上游正文。
            return error(
                StatusCode::BAD_GATEWAY,
                &format!("WebSocket 上游连接失败（{status}）"),
            )
            .into_response();
        }
    };
    // 子协议按上游协商结果回填；客户端争取到的协议必须与上游一致。
    let protocols: Vec<String> = response
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect();
    let upgrade = if protocols.is_empty() {
        ws
    } else {
        ws.protocols(protocols)
    };
    // 撤权/登出中止：与 SSE 共用 ACL 运行时的订阅表，撤权后 WebSocket 立即断开，
    // 不再把后续内容交给已失权用户。匿名与访客没有可中止的镜像身份。
    let abort = session
        .identity
        .as_ref()
        .map(|_| acl::Runtime::watch(&app.acl, &session.user));
    upgrade
        .on_upgrade(move |client| async move {
            if let Err(cause) = pump(client, upstream, abort).await {
                tracing::warn!(module = "gateway", error = %cause, "WebSocket 桥接结束");
            }
        })
        .into_response()
}

/// `/ws-chatgpt/<path>` → `<ws_upstream>/<path>`：主机来自配置（configured 模式
/// 固定 `wss://ws.chatgpt.com/`，原版同样把目标校验为该主机），客户端只选路径。
pub(super) fn upstream_url(base: &url::Url, path: &str, query: Option<&str>) -> Result<url::Url> {
    let rest = path
        .strip_prefix("/ws-chatgpt")
        .context("WebSocket 路径前缀不匹配")?;
    if !rest.is_empty() && !rest.starts_with('/') {
        anyhow::bail!("WebSocket 路径前缀不完整");
    }
    let mut target = base.clone();
    target.set_path(if rest.is_empty() { "/" } else { rest });
    target.set_query(query);
    Ok(target)
}

/// 上游握手头：与会话绑定（会话凭据在前、jar 捕获项其次、CF 白名单在后），
/// origin/referer/UA 按 chat 规则固定，镜像 token 与客户端 cookie 一律不转发。
async fn upstream_headers(
    app: &App,
    auth: &proxy::ChatAuth,
    client: &HeaderMap,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    // 真 Chromium 的 WS 握手头（2026-09-24 服务端实录，顺序 pragma → cache-control →
    // user-agent → accept-language → origin → accept-encoding）：浏览器给的值优先，
    // 缺省时补真实 Chrome 的固定值，这样非浏览器调用方也不会发出残缺握手。
    // 逐跳头（host/connection/upgrade）与 `sec-websocket-key/version/extensions`
    // 一律不转发：由传输层按自己的握手重建。client hints 同理交给身份整组覆盖。
    for (name, fallback) in WS_FORWARDED_HEADERS {
        match (client.get(name), fallback) {
            (Some(value), _) => {
                headers.insert(name, value.clone());
            }
            (None, Some(value)) => {
                headers.insert(name, HeaderValue::from_static(value));
            }
            (None, None) => {}
        }
    }
    let origin = proxy::chat_origin(&app.config.upstream)?;
    headers.insert(
        "origin",
        HeaderValue::from_str(&origin).context("origin 头无效")?,
    );
    headers.insert(
        "referer",
        HeaderValue::from_str(&format!("{origin}/")).context("referer 头无效")?,
    );
    // 上游 WS 是独立连接，必须与 HTTP 侧声称同一个浏览器身份。
    identity::apply_identity(&mut headers);
    // 设备身份：原版 WS 桥显式写 `oai-device-id` 头（错误串 0xD3E785 邻域），
    // 并与 HTTP 侧共用同一个 jar（见 server/upstream_cookies.rs）。
    if let Some(value) = upstream_cookies::device_value(&auth.jar) {
        if let Some((name, value)) = upstream_cookies::device_header(&value) {
            headers.insert(name, value);
        }
    }
    let cf = if auth.anonymous {
        Vec::new()
    } else {
        app.cloudflare.cookies().await
    };
    let jar = upstream_cookies::pairs_for(&auth.jar, &app.config.ws_upstream);
    // 与 HTTP 侧同规则：账号只有 SessionToken 时合成会话 Cookie 再发上游。
    let session = proxy::session_cookie_group(
        auth.session_token.as_deref(),
        auth.cookies.as_slice(),
        jar.as_slice(),
    );
    if let Some(cookie) = cloudflare::cookie_header(&[
        auth.cookies.as_slice(),
        session.as_slice(),
        jar.as_slice(),
        cf.as_slice(),
    ]) {
        headers.insert(
            "cookie",
            HeaderValue::from_str(&cookie).context("Cookie 头无效")?,
        );
    }
    if let Some(token) = auth.access_token.as_deref() {
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).context("上游凭据头无效")?,
        );
    }
    Ok(headers)
}

/// 连接失败：状态码用于判定 Cloudflare 挑战，原因文本不含上游正文。
pub(super) struct ConnectFailure {
    pub status: Option<StatusCode>,
    pub cause: anyhow::Error,
}

/// 连接上游并返回会话与握手响应头（子协议在响应头里）。目标地址由调用方决定，
/// 合成回环回归因此可以直接指向本机 `ws://` fixture。
/// 传输走 [`identity`] 画像化的客户端：WS 握手与 HTTP 必须声称同一个浏览器。
pub(super) async fn connect(
    client: &wreq::Client,
    target: &url::Url,
    headers: HeaderMap,
) -> std::result::Result<(wreq::ws::WebSocket, HeaderMap), ConnectFailure> {
    let response = client
        .websocket(target.as_str())
        .headers(headers)
        .send()
        .await
        .map_err(|cause| ConnectFailure {
            status: cause.status(),
            cause: anyhow::Error::from(cause),
        })?;
    let headers = response.headers().clone();
    let socket = response
        .into_websocket()
        .await
        .map_err(|cause| ConnectFailure {
            status: None,
            cause: anyhow::Error::from(cause),
        })?;
    Ok((socket, headers))
}

/// 转发的浏览器头：真 Chromium 实录里的应用层头加上子协议（由调用方决定）。
/// 逐跳头与握手自有头不在此表内，`origin` 与 `user-agent` 分别由重写与身份组提供。
/// 与证据的绑定由库内单测锁定。
const WS_FORWARDED_HEADERS: [(&str, Option<&str>); 5] = [
    ("pragma", Some("no-cache")),
    ("cache-control", Some("no-cache")),
    ("accept-language", Some("zh-CN,zh;q=0.9,en;q=0.8")),
    ("accept-encoding", Some("gzip, deflate, br, zstd")),
    // 子协议由调用方决定，上游没被要求时不能凭空声明。
    ("sec-websocket-protocol", None),
];

/// 桥接本体：双向透传，任一侧结束即把关闭帧转交另一侧后收尾。
/// `abort` 非空时，撤权/登出会写通道使本次桥接立即结束（不再转发剩余消息）。
pub(super) async fn pump(
    client: WebSocket,
    upstream: wreq::ws::WebSocket,
    abort: Option<acl::AbortWatch>,
) -> Result<()> {
    let (mut abort, _guard) = match abort {
        Some((rx, guard)) => (Some(rx), Some(guard)),
        None => (None, None),
    };
    let (mut client_sink, mut client_stream) = client.split();
    let (mut upstream_sink, mut upstream_stream) = upstream.split();
    let mut relay = Relay {
        client_open: true,
        upstream_open: true,
    };
    // 正常阶段不设超时：对话通道可以长时间空闲。
    let mut revoked = false;
    while relay.client_open && relay.upstream_open {
        match abort.as_mut() {
            Some(rx) => {
                tokio::select! {
                    biased;
                    _ = rx.changed() => {
                        revoked = true;
                        break;
                    }
                    step = relay.step(
                        &mut client_stream,
                        &mut client_sink,
                        &mut upstream_stream,
                        &mut upstream_sink,
                    ) => step?,
                }
            }
            None => {
                relay
                    .step(
                        &mut client_stream,
                        &mut client_sink,
                        &mut upstream_stream,
                        &mut upstream_sink,
                    )
                    .await?;
            }
        }
    }
    // 撤权/登出后不再走关闭握手：握手阶段仍会把上游剩余消息转给客户端，
    // 与「立即停止下发」冲突，因此这里直接结束并让连接被关闭。
    if revoked {
        return Ok(());
    }
    // 收尾阶段把关闭握手走完，语义是「任一侧关闭即关闭另一侧」。
    let _ = tokio::time::timeout(CLOSE_GRACE, async {
        while relay.active() {
            relay
                .step(
                    &mut client_stream,
                    &mut client_sink,
                    &mut upstream_stream,
                    &mut upstream_sink,
                )
                .await?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await;
    Ok(())
}

/// 桥接状态：两侧是否仍在读取。结束的一侧不再被 `select!` 轮询，
/// 因此关闭后不会空转重发关闭帧。
struct Relay {
    client_open: bool,
    upstream_open: bool,
}

impl Relay {
    fn active(&self) -> bool {
        self.client_open || self.upstream_open
    }

    /// 单步转帧：读取先就绪的一侧并转交另一侧；收到关闭帧或读到流末尾时
    /// 标记该侧结束，并把关闭帧转交另一侧。
    async fn step(
        &mut self,
        client_stream: &mut SplitStream<WebSocket>,
        client_sink: &mut SplitSink<WebSocket, Message>,
        upstream_stream: &mut SplitStream<wreq::ws::WebSocket>,
        upstream_sink: &mut SplitSink<wreq::ws::WebSocket, WsMessage>,
    ) -> Result<()> {
        tokio::select! {
            message = client_stream.next(), if self.client_open => match message {
                Some(Ok(message)) => {
                    let closing = matches!(message, Message::Close(_));
                    if let Some(message) = to_upstream(message) {
                        upstream_sink.send(message).await.context("上游 WebSocket 发送失败")?;
                    }
                    if closing {
                        self.client_open = false;
                    }
                }
                Some(Err(cause)) => return Err(anyhow::Error::from(cause)),
                None => {
                    // 客户端连接直接消失：补一个关闭帧给上游，避免上游悬住。
                    self.client_open = false;
                    upstream_sink
                        .send(WsMessage::Close(None))
                        .await
                        .context("上游 WebSocket 发送失败")?;
                }
            },
            message = upstream_stream.next(), if self.upstream_open => match message {
                Some(Ok(message)) => {
                    let closing = matches!(message, WsMessage::Close(_));
                    if let Some(message) = to_client(message) {
                        client_sink.send(message).await.context("客户端 WebSocket 发送失败")?;
                    }
                    if closing {
                        self.upstream_open = false;
                    }
                }
                Some(Err(cause)) => return Err(anyhow::Error::from(cause)),
                None => {
                    // 上游断开：把关闭帧转交客户端，完成关闭握手。
                    self.upstream_open = false;
                    client_sink
                        .send(Message::Close(None))
                        .await
                        .context("客户端 WebSocket 发送失败")?;
                }
            },
        }
        Ok(())
    }
}

/// 客户端消息转上游：Ping/Pong 由协议层自动应答，不再由应用层转发。
fn to_upstream(message: Message) -> Option<WsMessage> {
    match message {
        Message::Text(text) => Some(WsMessage::text(text)),
        Message::Binary(bytes) => Some(WsMessage::binary(bytes)),
        Message::Close(frame) => Some(WsMessage::Close(frame.map(|frame| WsCloseFrame {
            code: wreq::ws::message::CloseCode::from(frame.code),
            reason: frame.reason.to_string().into(),
        }))),
        Message::Ping(_) | Message::Pong(_) => None,
    }
}

/// 上游消息转客户端：控制帧由协议层处理，不进应用层转发。
fn to_client(message: WsMessage) -> Option<Message> {
    match message {
        WsMessage::Text(text) => Some(Message::Text(text.to_string())),
        WsMessage::Binary(bytes) => Some(Message::Binary(bytes.to_vec())),
        WsMessage::Close(frame) => Some(Message::Close(frame.map(|frame| {
            axum::extract::ws::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.to_string().into(),
            }
        }))),
        WsMessage::Ping(_) | WsMessage::Pong(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::sync::{Arc as StdArc, Mutex};

    /// 真 Chromium 的 WS 握手头实录（`evidence/ws-handshake-headers-001.json`）。
    const WS_HANDSHAKE_EVIDENCE: &str =
        include_str!("../../../../../evidence/ws-handshake-headers-001.json");

    /// 转发名单必须覆盖真浏览器发的每个应用层头：漏一个就是可区分的残缺握手，
    /// 将来 Chromium 新增握手头时这条会红。
    #[test]
    fn forwarded_headers_cover_the_recorded_browser_handshake() {
        let evidence: serde_json::Value =
            serde_json::from_str(WS_HANDSHAKE_EVIDENCE).expect("WS 证据 JSON 无效");
        let recorded = evidence["requests"][0]["header_names"]
            .as_array()
            .expect("证据缺少 header_names");
        // 逐跳头与握手自有头由传输层重建；`origin`/`user-agent` 分别由重写与身份组提供。
        let transport_owned = [
            "host",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
        ];
        let rewritten = ["origin", "user-agent"];
        let covered: Vec<&str> = WS_FORWARDED_HEADERS
            .iter()
            .map(|(name, _)| *name)
            .chain(rewritten)
            .collect();
        for name in recorded {
            let name = name.as_str().expect("头名必须是字符串");
            assert!(
                transport_owned.contains(&name) || covered.contains(&name),
                "{name} 既不由传输层重建、也不在转发名单里：浏览器会看到残缺握手"
            );
        }
        // 反向：名单里的代理层头必须在实录里出现过，否则就是凭空发明的头。
        for (name, _) in WS_FORWARDED_HEADERS {
            if name == "sec-websocket-protocol" {
                continue; // 探针没有请求子协议，因此实录里不会出现。
            }
            assert!(
                recorded.iter().any(|value| value.as_str() == Some(name)),
                "{name} 不在浏览器实录里，不应凭猜测发送"
            );
        }
    }

    /// 目标地址只由配置基址与路径决定，客户端不能改主机。
    #[test]
    fn upstream_target_comes_from_config_and_path_only() {
        let base = url::Url::parse("wss://ws.chatgpt.com/").expect("基址无效");
        let target = upstream_url(&base, "/ws-chatgpt/v1/threads", None).expect("目标生成失败");
        assert_eq!(target.as_str(), "wss://ws.chatgpt.com/v1/threads");
        assert_eq!(
            upstream_url(&base, "/ws-chatgpt", Some("model=x"))
                .expect("根路径必须可用")
                .as_str(),
            "wss://ws.chatgpt.com/?model=x"
        );
        assert!(upstream_url(&base, "/realtime/abc", None).is_err());
        assert!(upstream_url(&base, "/ws-chatgptx", None).is_err());
    }

    /// 合成回环 WS 上游：记录收到的消息并原样回显，收到关闭帧后回帧结束。
    async fn echo_upstream(
        seen: StdArc<Mutex<Vec<String>>>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("ws://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(message) = socket.next().await {
                let message = message.unwrap();
                let closing = matches!(message, tokio_tungstenite::tungstenite::Message::Close(_));
                match message {
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        seen.lock().unwrap().push(format!("text:{text}"));
                        socket
                            .send(tokio_tungstenite::tungstenite::Message::Text(text))
                            .await
                            .unwrap();
                    }
                    tokio_tungstenite::tungstenite::Message::Binary(bytes) => {
                        seen.lock().unwrap().push(format!("binary:{}", bytes.len()));
                        socket
                            .send(tokio_tungstenite::tungstenite::Message::Binary(bytes))
                            .await
                            .unwrap();
                    }
                    // 关闭帧由协议层自动回帧，这里记录后 flush 出去即可。
                    tokio_tungstenite::tungstenite::Message::Close(_) => {}
                    _ => {}
                }
                if closing {
                    seen.lock().unwrap().push("close".into());
                    socket.flush().await.unwrap();
                    break;
                }
            }
        });
        (base, task)
    }

    /// 桥接侧：只做升级，桥接本体指向给定的回环目标。
    async fn bridge_endpoint(target: url::Url) -> (String, tokio::task::JoinHandle<()>) {
        let client = identity::client_builder().build().unwrap();
        let router = Router::new().route(
            "/bridge",
            get(move |ws: WebSocketUpgrade| {
                let target = target.clone();
                let client = client.clone();
                async move {
                    let headers = HeaderMap::new();
                    match connect(&client, &target, headers).await {
                        Ok((upstream, _)) => ws
                            .on_upgrade(move |client| async move {
                                let _ = pump(client, upstream, None).await;
                            })
                            .into_response(),
                        Err(failure) => (
                            StatusCode::BAD_GATEWAY,
                            format!("connect failed: {}", failure.cause),
                        )
                            .into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (base, task)
    }

    /// 双向消息必须原样透传，关闭帧必须转交上游。
    #[tokio::test]
    async fn bridge_pumps_messages_both_ways_and_propagates_close() {
        let seen = StdArc::new(Mutex::new(Vec::new()));
        let (upstream_base, upstream_task) = echo_upstream(seen.clone()).await;
        let target = url::Url::parse(&format!("{upstream_base}/chat")).unwrap();
        let (base, bridge_task) = bridge_endpoint(target).await;
        let (mut client, _) =
            tokio_tungstenite::connect_async(format!("{}/bridge", base.replace("http://", "ws://")))
                .await
                .unwrap();
        client
            .send(tokio_tungstenite::tungstenite::Message::Text("hello".into()))
            .await
            .unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            tokio_tungstenite::tungstenite::Message::Text("hello".into())
        );
        client
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![1, 2, 3].into(),
            ))
            .await
            .unwrap();
        match client.next().await.unwrap().unwrap() {
            tokio_tungstenite::tungstenite::Message::Binary(bytes) => {
                assert_eq!(&bytes[..], &[1, 2, 3])
            }
            other => panic!("二进制必须原样回显：{other:?}"),
        }
        // 客户端关闭帧必须转交上游，上游的关闭回帧也要回到客户端。
        client.close(None).await.unwrap();
        for _ in 0..50 {
            if seen.lock().unwrap().iter().any(|event| event == "close") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let seen = seen.lock().unwrap().clone();
        assert!(seen.iter().any(|event| event == "text:hello"), "{seen:?}");
        assert!(seen.iter().any(|event| event == "binary:3"), "{seen:?}");
        assert!(seen.iter().any(|event| event == "close"), "{seen:?}");
        upstream_task.abort();
        bridge_task.abort();
    }
}

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
use tokio_tungstenite::tungstenite;

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
    let (upstream, response) = match connect(&target, request_headers).await {
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
    upgrade
        .on_upgrade(move |client| async move {
            if let Err(cause) = pump(client, upstream).await {
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

/// 上游握手头：与会话绑定（extra_cookies 在前、CF 白名单在后），
/// origin/referer/UA 按 chat 规则固定，镜像 token 与客户端 cookie 一律不转发。
async fn upstream_headers(
    app: &App,
    auth: &proxy::ChatAuth,
    client: &HeaderMap,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    // 浏览器握手自带的协商字段按需透传；凭据类头一律由本模块重建。
    for name in [
        "accept-language",
        "sec-websocket-protocol",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-ch-ua-full-version",
        "sec-ch-ua-full-version-list",
    ] {
        if let Some(value) = client.get(name) {
            headers.insert(name, value.clone());
        }
    }
    headers.insert(
        "user-agent",
        HeaderValue::from_static(proxy::DEFAULT_USER_AGENT),
    );
    let origin = proxy::chat_origin(&app.config.upstream)?;
    headers.insert(
        "origin",
        HeaderValue::from_str(&origin).context("origin 头无效")?,
    );
    headers.insert(
        "referer",
        HeaderValue::from_str(&format!("{origin}/")).context("referer 头无效")?,
    );
    proxy::apply_chrome_146_identity(&mut headers);
    let cf = if auth.anonymous {
        Vec::new()
    } else {
        app.cloudflare.cookies().await
    };
    if let Some(cookie) = cloudflare::cookie_header(&[auth.cookies.as_slice(), cf.as_slice()]) {
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
pub(super) async fn connect(
    target: &url::Url,
    headers: HeaderMap,
) -> std::result::Result<
    (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        HeaderMap,
    ),
    ConnectFailure,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut request = target
        .as_str()
        .into_client_request()
        .map_err(|cause| ConnectFailure {
            status: None,
            cause: anyhow::Error::from(cause),
        })?;
    for (name, value) in headers.iter() {
        request.headers_mut().insert(name.clone(), value.clone());
    }
    match tokio_tungstenite::connect_async(request).await {
        Ok((socket, response)) => Ok((socket, response.headers().clone())),
        Err(tungstenite::Error::Http(response)) => Err(ConnectFailure {
            status: Some(response.status()),
            cause: anyhow::anyhow!("上游 WebSocket 握手被拒绝"),
        }),
        Err(cause) => Err(ConnectFailure {
            status: None,
            cause: anyhow::Error::from(cause),
        }),
    }
}

/// 桥接本体：双向透传，任一侧结束即把关闭帧转交另一侧后收尾。
pub(super) async fn pump(
    client: WebSocket,
    upstream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<()> {
    let (mut client_sink, mut client_stream) = client.split();
    let (mut upstream_sink, mut upstream_stream) = upstream.split();
    let mut relay = Relay {
        client_open: true,
        upstream_open: true,
    };
    // 正常阶段不设超时：对话通道可以长时间空闲。
    while relay.client_open && relay.upstream_open {
        relay
            .step(
                &mut client_stream,
                &mut client_sink,
                &mut upstream_stream,
                &mut upstream_sink,
            )
            .await?;
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

type UpstreamStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

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
        upstream_stream: &mut SplitStream<UpstreamStream>,
        upstream_sink: &mut SplitSink<UpstreamStream, tungstenite::Message>,
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
                        .send(tungstenite::Message::Close(None))
                        .await
                        .context("上游 WebSocket 发送失败")?;
                }
            },
            message = upstream_stream.next(), if self.upstream_open => match message {
                Some(Ok(message)) => {
                    let closing = matches!(message, tungstenite::Message::Close(_));
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
fn to_upstream(message: Message) -> Option<tungstenite::Message> {
    match message {
        Message::Text(text) => Some(tungstenite::Message::Text(text)),
        Message::Binary(bytes) => Some(tungstenite::Message::Binary(bytes)),
        Message::Close(frame) => Some(tungstenite::Message::Close(frame.map(|frame| {
            tungstenite::protocol::CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::from(frame.code),
                reason: frame.reason,
            }
        }))),
        Message::Ping(_) | Message::Pong(_) => None,
    }
}

/// 上游消息转客户端：`Frame` 按 tungstenite 建议忽略。
fn to_client(message: tungstenite::Message) -> Option<Message> {
    match message {
        tungstenite::Message::Text(text) => Some(Message::Text(text)),
        tungstenite::Message::Binary(bytes) => Some(Message::Binary(bytes)),
        tungstenite::Message::Close(frame) => Some(Message::Close(frame.map(|frame| {
            axum::extract::ws::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason,
            }
        }))),
        tungstenite::Message::Ping(_)
        | tungstenite::Message::Pong(_)
        | tungstenite::Message::Frame(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::sync::{Arc as StdArc, Mutex};

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
                let closing = matches!(message, tungstenite::Message::Close(_));
                match message {
                    tungstenite::Message::Text(text) => {
                        seen.lock().unwrap().push(format!("text:{text}"));
                        socket.send(tungstenite::Message::Text(text)).await.unwrap();
                    }
                    tungstenite::Message::Binary(bytes) => {
                        seen.lock().unwrap().push(format!("binary:{}", bytes.len()));
                        socket
                            .send(tungstenite::Message::Binary(bytes))
                            .await
                            .unwrap();
                    }
                    // 关闭帧由协议层自动回帧，这里记录后 flush 出去即可。
                    tungstenite::Message::Close(_) => {}
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
        let router = Router::new().route(
            "/bridge",
            get(move |ws: WebSocketUpgrade| {
                let target = target.clone();
                async move {
                    let headers = HeaderMap::new();
                    match connect(&target, headers).await {
                        Ok((upstream, _)) => ws
                            .on_upgrade(move |client| async move {
                                let _ = pump(client, upstream).await;
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
            .send(tungstenite::Message::Text("hello".into()))
            .await
            .unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            tungstenite::Message::Text("hello".into())
        );
        client
            .send(tungstenite::Message::Binary(vec![1, 2, 3]))
            .await
            .unwrap();
        match client.next().await.unwrap().unwrap() {
            tungstenite::Message::Binary(bytes) => assert_eq!(bytes, vec![1, 2, 3]),
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

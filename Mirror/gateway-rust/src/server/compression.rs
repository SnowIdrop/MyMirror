// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : server/compression.rs
// Created : 2026-09-22
// Summary : 响应压缩统一层：复刻原版压缩层的尺寸阈值、内容类型豁免、vary 追加、
//           Accept-Encoding 协商与 gzip 真正编码（流式，不缓存整段正文）。
// 证据来源：QEMU 无网隔离 guest 的原版运行时观测 evidence/headers-v3-original-006
//           （真实正文长度 29..33 阈值阶梯、内容类型 json/text/html/binary/image/SSE、
//           协商矩阵、管理/用户 401 与 405 层次；004 为同脚本早期轮次）。
// -----------------------------------------------------------------------------

//! 原版压缩层契约（观测见 evidence/headers-v3-original-006/results.json）：
//!
//! - 尺寸阈值：能确定正文长度（content-length 或 body size hint）时，仅当 >= 32 字节才压缩；
//!   长度未知（分块/流式）时一律压缩（观测：8/20/29 字节的流式正文同样被 gzip）。
//! - 内容类型豁免：`image/*`（`image/svg+xml` 除外）、`text/event-stream`、
//!   `application/grpc`（`application/grpc-web` 除外）；已带 `content-encoding` 或
//!   `content-range` 的响应也不压缩。
//! - 只要满足压缩条件就追加 `vary: accept-encoding`（大小写不敏感、子串判重），
//!   与最终是否真正编码无关（观测：identity/未知编码/无 accept-encoding 时仍追加）。
//! - 协商：解析全部 `accept-encoding` 头，忽略未知编码与非法 q 值，按 (q, 偏好) 取最大；
//!   偏好序与 tower-http 的 `Encoding` 枚举一致：identity < deflate < gzip < br < zstd。
//! - 真正编码：原版只有 gzip 生效。q 更高而胜出的 br/deflate/zstd 一律回落 identity，
//!   既不设置 content-encoding 也不移除 content-length（观测 neg-br/deflate/zstd、
//!   all-four、gzip-br 均为 identity）。gzip 生效时移除 content-length 与 accept-ranges
//!   并写入 `content-encoding: gzip`。

use super::*;
use axum::http::header;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use http_body::{Body as HttpBody, Frame};
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};

/// 与 tower-http `DefaultPredicate` 的 `SizeAbove(32)` 同源的阈值（字节）。
const MIN_COMPRESS_SIZE: u64 = 32;

/// 流式 Body / 编码器错误的统一容器（http_body 要求可转 `BoxError`）。
type StreamError = Box<dyn std::error::Error + Send + Sync>;

/// 协商偏好序（与 tower-http `Encoding` 枚举顺序一致，identity 最低）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Encoding {
    Identity,
    Deflate,
    Gzip,
    Brotli,
    Zstd,
}

impl Encoding {
    /// 单 token 解析：未知编码返回 None（忽略该 token）。
    fn parse(token: &str) -> Option<Self> {
        if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
            return Some(Self::Gzip);
        }
        if token.eq_ignore_ascii_case("deflate") {
            return Some(Self::Deflate);
        }
        if token.eq_ignore_ascii_case("br") {
            return Some(Self::Brotli);
        }
        if token.eq_ignore_ascii_case("zstd") {
            return Some(Self::Zstd);
        }
        if token.eq_ignore_ascii_case("identity") {
            return Some(Self::Identity);
        }
        None
    }
}

/// RFC 7231 `q=` 值解析（逐字符复刻 tower-http `QValue::parse`）：0..=1、最多 3 位
/// 小数，表示为 0..=1000 的整数；非法值（含 `q=1.5`、超过 3 位小数）返回 None，
/// 该 token 被忽略（与原版依赖行为一致）。
fn parse_quality(raw: &str) -> Option<u16> {
    let mut chars = raw.chars();
    match chars.next() {
        Some('q' | 'Q') => (),
        _ => return None,
    }
    match chars.next() {
        Some('=') => (),
        _ => return None,
    }
    let mut quality: u16 = match chars.next() {
        Some('0') => 0,
        Some('1') => 1000,
        _ => return None,
    };
    match chars.next() {
        Some('.') => (),
        None => return Some(quality),
        _ => return None,
    }
    let mut factor: u16 = 100;
    loop {
        match chars.next() {
            Some(digit @ '0'..='9') => {
                if factor < 1 {
                    return None;
                }
                quality += factor * u16::from(digit as u8 - b'0');
            }
            None => {
                return if quality <= 1000 { Some(quality) } else { None };
            }
            _ => return None,
        }
        factor /= 10;
    }
}

/// 协商：所有 `accept-encoding` 头按 token 展开，忽略未知编码/非法 q，取 (q, 偏好) 最大。
fn preferred_encoding(headers: &HeaderMap) -> Encoding {
    let mut best: Option<(u16, Encoding)> = None;
    for value in headers.get_all(header::ACCEPT_ENCODING).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            let mut parts = token.splitn(2, ';');
            let Some(encoding) = Encoding::parse(parts.next().unwrap_or_default().trim()) else {
                continue;
            };
            let quality = match parts.next() {
                Some(raw) => match parse_quality(raw.trim()) {
                    Some(quality) if quality > 0 => quality,
                    _ => continue,
                },
                None => 1000,
            };
            let candidate = (quality, encoding);
            if best.map(|current| candidate > current).unwrap_or(true) {
                best = Some(candidate);
            }
        }
    }
    best.map(|(_, encoding)| encoding)
        .unwrap_or(Encoding::Identity)
}

/// 内容类型豁免：image（svg 除外）、SSE、gRPC（grpc-web 除外）。
fn excluded_content_type(headers: &HeaderMap) -> bool {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if content_type.starts_with("text/event-stream") {
        return true;
    }
    if content_type.starts_with("application/grpc-web") {
        return false;
    }
    if content_type.starts_with("application/grpc") {
        return true;
    }
    if content_type.starts_with("image/svg+xml") {
        return false;
    }
    content_type.starts_with("image/")
}

/// 可确定的正文长度：优先 body size hint，其次 content-length。
fn known_body_size(response: &Response) -> Option<u64> {
    response.body().size_hint().exact().or_else(|| {
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    })
}

/// 压缩判定（复刻 tower-http `DefaultPredicate` + 既有编码/范围豁免）。
fn should_compress(response: &Response) -> bool {
    if response.headers().contains_key(header::CONTENT_ENCODING)
        || response.headers().contains_key(header::CONTENT_RANGE)
        || excluded_content_type(response.headers())
    {
        return false;
    }
    match known_body_size(response) {
        Some(size) => size >= MIN_COMPRESS_SIZE,
        None => true,
    }
}

/// 既有 vary 是否已含 accept-encoding（大小写不敏感子串，与 tower-http 判重一致）。
fn vary_has_accept_encoding(headers: &HeaderMap) -> bool {
    headers.get_all(header::VARY).iter().any(|value| {
        value
            .to_str()
            .map(|text| text.to_ascii_lowercase().contains("accept-encoding"))
            .unwrap_or(false)
    })
}

/// 压缩中间件：需注册在 `private_headers` 之外（响应方向最后执行），
/// 以便按 header 层写入的 vary 判重后再追加 accept-encoding。
pub(super) async fn compress(request: Request, next: Next) -> Response {
    let encoding = preferred_encoding(request.headers());
    let mut response = next.run(request).await;
    if !should_compress(&response) {
        return response;
    }
    if !vary_has_accept_encoding(response.headers()) {
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    // 原版只有 gzip 编码器生效；其余胜出编码回落 identity，正文与 content-length 原样保留。
    if encoding != Encoding::Gzip {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(header::ACCEPT_RANGES);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    Response::from_parts(parts, Body::new(GzipBody::new(body)))
}

/// 流式 gzip 正文：逐帧喂入编码器并发出已生成的压缩字节，不缓存完整正文。
struct GzipBody {
    inner: Body,
    encoder: Option<GzEncoder<Vec<u8>>>,
    pending: Option<Bytes>,
    pending_trailers: Option<HeaderMap>,
    source_done: bool,
    needs_flush: bool,
}

impl GzipBody {
    fn new(inner: Body) -> Self {
        Self {
            inner,
            encoder: Some(GzEncoder::new(Vec::new(), Compression::default())),
            pending: None,
            pending_trailers: None,
            source_done: false,
            needs_flush: false,
        }
    }

    /// 取出编码器已生成的压缩字节（同步 flush 后调用，保证当前输入可解码）。
    fn take_encoded(&mut self) -> Option<Bytes> {
        let encoder = self.encoder.as_mut().expect("取出编码数据时编码器仍在运行");
        let buffer = encoder.get_mut();
        if buffer.is_empty() {
            None
        } else {
            Some(Bytes::from(std::mem::take(buffer)))
        }
    }

    /// 写入 gzip 尾帧（CRC 与长度），并保留最后一段输出。
    fn finish_encoder(&mut self) -> Result<(), StreamError> {
        let mut encoder = self
            .encoder
            .take()
            .expect("未结束的 gzip 正文必须持有编码器");
        encoder.try_finish()?;
        let buffer = std::mem::take(encoder.get_mut());
        if !buffer.is_empty() {
            self.pending = Some(Bytes::from(buffer));
        }
        Ok(())
    }
}

impl HttpBody for GzipBody {
    type Data = Bytes;
    type Error = StreamError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            // 先发出编码器累积的压缩字节，保证数据帧顺序。
            if let Some(bytes) = this.pending.take() {
                return Poll::Ready(Some(Ok(Frame::data(bytes))));
            }
            if this.source_done {
                if let Some(trailers) = this.pending_trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        let encoder = this
                            .encoder
                            .as_mut()
                            .expect("未结束的 gzip 正文必须持有编码器");
                        if let Err(error) = encoder.write_all(&data) {
                            this.source_done = true;
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }
                        this.needs_flush = true;
                        this.pending = this.take_encoded();
                    }
                    Err(frame) => {
                        // 尾帧：先收尾编码器，尾帧在压缩数据之后发出。
                        if let Err(error) = this.finish_encoder() {
                            return Poll::Ready(Some(Err(error)));
                        }
                        if let Ok(trailers) = frame.into_trailers() {
                            this.pending_trailers = Some(trailers);
                        }
                        this.source_done = true;
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    this.source_done = true;
                    return Poll::Ready(Some(Err(Box::new(error))));
                }
                Poll::Ready(None) => {
                    if let Err(error) = this.finish_encoder() {
                        return Poll::Ready(Some(Err(error)));
                    }
                    this.source_done = true;
                }
                Poll::Pending => {
                    // 上游暂停时才刷新已输入的数据；防止每个小帧强制刷新改变压缩表示，
                    // 也防止反复 poll 无新输入时产生无限空压缩帧。
                    if this.needs_flush {
                        this.needs_flush = false;
                        if let Err(error) = this.encoder.as_mut().expect("编码器仍在运行").flush()
                        {
                            this.source_done = true;
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }
                        if let Some(bytes) = this.take_encoded() {
                            return Poll::Ready(Some(Ok(Frame::data(bytes))));
                        }
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

/// 普通 HTTP 适配器显式解码上游 gzip，再按下游协商重新编码；不复制失效的长度头。
pub(super) fn decode_upstream(body: Body, headers: &mut HeaderMap) -> Body {
    if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| value == "gzip")
    {
        headers.remove(header::CONTENT_ENCODING);
        headers.remove(header::CONTENT_LENGTH);
        Body::new(GunzipBody {
            inner: body,
            decoder: flate2::write::GzDecoder::new(Vec::new()),
            done: false,
            trailers: None,
        })
    } else {
        body
    }
}

struct GunzipBody {
    inner: Body,
    decoder: flate2::write::GzDecoder<Vec<u8>>,
    done: bool,
    trailers: Option<HeaderMap>,
}

impl HttpBody for GunzipBody {
    type Data = Bytes;
    type Error = StreamError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, StreamError>>> {
        let this = self.get_mut();
        loop {
            if !this.decoder.get_ref().is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from(std::mem::take(
                    this.decoder.get_mut(),
                ))))));
            }
            if this.done {
                return Poll::Ready(
                    this.trailers
                        .take()
                        .map(|trailers| Ok(Frame::trailers(trailers))),
                );
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if let Err(cause) = this.decoder.write_all(&data) {
                            this.done = true;
                            return Poll::Ready(Some(Err(Box::new(cause))));
                        }
                    }
                    Err(frame) => {
                        this.trailers = frame.into_trailers().ok();
                        this.done = true;
                        if let Err(cause) = this.decoder.try_finish() {
                            return Poll::Ready(Some(Err(Box::new(cause))));
                        }
                    }
                },
                Poll::Ready(None) => {
                    this.done = true;
                    if let Err(cause) = this.decoder.try_finish() {
                        return Poll::Ready(Some(Err(Box::new(cause))));
                    }
                }
                Poll::Ready(Some(Err(cause))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(Box::new(cause))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;

    #[tokio::test]
    async fn gzip_encodes_multiple_frames_and_propagates_stream_failure() {
        use std::io::Read;
        let input = vec![Bytes::from(vec![b'a'; 32]), Bytes::from(vec![b'b'; 80])];
        let body = Body::from_stream(futures_util::stream::iter(
            input.into_iter().map(Ok::<_, std::io::Error>),
        ));
        let encoded = to_bytes(Body::new(GzipBody::new(body)), 1024)
            .await
            .unwrap();
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(encoded.as_ref())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, [vec![b'a'; 32], vec![b'b'; 80]].concat());
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&encoded.len().to_string()).unwrap(),
        );
        let decoded_body = decode_upstream(Body::from(encoded), &mut headers);
        assert!(!headers.contains_key(header::CONTENT_ENCODING));
        assert!(!headers.contains_key(header::CONTENT_LENGTH));
        assert_eq!(
            to_bytes(decoded_body, 1024).await.unwrap().as_ref(),
            decoded.as_slice()
        );
        let broken = Body::from_stream(futures_util::stream::iter([Err::<Bytes, _>(
            std::io::Error::other("upstream closed"),
        )]));
        assert!(to_bytes(Body::new(GzipBody::new(broken)), 1024)
            .await
            .is_err());
    }

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("头名无效"),
                HeaderValue::from_str(value).expect("头值无效"),
            );
        }
        headers
    }

    #[test]
    fn negotiation_prefers_quality_then_encoding_order() {
        let cases = [
            ("gzip", Encoding::Gzip),
            ("GZIP", Encoding::Gzip),
            ("x-gzip", Encoding::Gzip),
            ("deflate,x-gzip", Encoding::Gzip),
            ("gzip, br", Encoding::Brotli),
            ("zstd,gzip,deflate,br", Encoding::Zstd),
            ("gzip;q=1.0, zstd;q=0.1", Encoding::Gzip),
            ("identity;q=1.0, gzip", Encoding::Gzip),
            ("identity;q=0.9, gzip;q=0.5", Encoding::Identity),
            ("identity;q=0", Encoding::Identity),
            ("gzip;q=0, br;q=0", Encoding::Identity),
            ("gzip;q=abc", Encoding::Identity),
            ("*", Encoding::Identity),
            ("", Encoding::Identity),
            ("br;q=1.0, gzip;q=0.9", Encoding::Brotli),
        ];
        for (value, expected) in cases {
            let headers = header_map(&[("accept-encoding", value)]);
            assert_eq!(
                preferred_encoding(&headers),
                expected,
                "accept-encoding={value}"
            );
        }
    }

    #[test]
    fn predicate_uses_size_type_and_existing_encoding() {
        let mut short = Response::new(Body::from(vec![b'a'; 31]));
        short.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!should_compress(&short));
        let mut exact = Response::new(Body::from(vec![b'a'; 32]));
        exact.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(should_compress(&exact));
        let streamed = Response::new(Body::from_stream(futures_util::stream::empty::<
            Result<Bytes, std::io::Error>,
        >()));
        assert!(should_compress(&streamed));
        let mut encoded = Response::new(Body::from(vec![b'a'; 64]));
        encoded
            .headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!should_compress(&encoded));
        for content_type in ["image/png", "text/event-stream", "application/grpc"] {
            let mut response = Response::new(Body::from(vec![b'a'; 64]));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(content_type).expect("头值无效"),
            );
            assert!(!should_compress(&response), "content-type={content_type}");
        }
        for content_type in ["image/svg+xml", "application/grpc-web"] {
            let mut response = Response::new(Body::from(vec![b'a'; 64]));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(content_type).expect("头值无效"),
            );
            assert!(should_compress(&response), "content-type={content_type}");
        }
    }

    #[test]
    fn vary_detection_is_case_insensitive_substring() {
        let mut headers = HeaderMap::new();
        assert!(!vary_has_accept_encoding(&headers));
        headers.append(
            header::VARY,
            HeaderValue::from_static("accept-encoding, Cookie, Authorization"),
        );
        assert!(vary_has_accept_encoding(&headers));
        let mut upper = HeaderMap::new();
        upper.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        assert!(vary_has_accept_encoding(&upper));
    }
}

// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : tests/identity_fingerprint.rs
// Created : 2026-09-24
// Summary : 传输身份回归锁。三段断言：ClientHello（**保留原始顺序**与 GREASE 位置）、
//           HTTP/2 首帧（SETTINGS 顺序、连接窗口增量、伪头顺序）、身份相关依赖的
//           精确版本。任何一环漂移都会让测试变红，避免「UA 说 Chrome146、TLS/H2
//           却是别的」这类不一致静默上线。
// 证据来源：真 Chrome 的对照由 `probe/probe_reference_identity.py`（CfT 146）与
//           `probe/probe_tls_identity.py`（系统 Chromium）采集，结论写在
//           `evidence/tls-identity-reference.json` 与 COMPATIBILITY 的对应章节。
// -----------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use mirror_gateway::server::identity;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// ClientHello 归一化指纹（**顺序敏感**）。改了画像、平台或依赖版本就必须重新
/// 采集，同步更新本常量、`evidence/tls-identity-reference.json` 与 COMPATIBILITY。
const EXPECTED_HELLO_SHA256: &str =
    "01e7ace0ac3f2658990a6e8c956cdbd371586b161acc205abfea8d70d52adebb";
/// SNI 场景的 ClientHello 归一化指纹：只有 SNI 与公钥不同，其余字段必须一致。
const EXPECTED_HELLO_SNI_SHA256: &str =
    "15d917f30e1b8f90de104dd5b5fad3d7fc7337a83adb146efb91d8186f18703b";
/// HTTP/2 首帧归一化指纹（preface + SETTINGS 顺序 + 窗口增量 + 伪头顺序 +
/// HEADERS 帧标志位）。2026-09-29 因为归一化结构新增 `headers_frame_flags` 而重算：
/// 标志位本身已由
/// `candidate_http2_first_frame_matches_the_chrome146_reference` 对着参照逐项比过
///（`END_STREAM`/`END_HEADERS`/`PRIORITY`），这里只是把新字段纳入摘要。
const EXPECTED_H2_SHA256: &str =
    "797c2ef2f61a428076dec3c1400ee573dbefe31bc792c5141eda9d6a347a5aab";

/// 身份相关依赖的锁定版本：真实指纹由这些 crate 决定，`cargo update` 必须让这里变红。
const IDENTITY_CRATES: [(&str, &str); 7] = [
    ("wreq", "6.0.0-rc.31"),
    ("wreq-util", "3.0.0-rc.14"),
    ("wreq-proto", "0.2.6"),
    ("btls", "0.5.6"),
    ("btls-sys", "0.5.6"),
    ("tokio-btls", "0.5.6"),
    ("http2", "0.5.20"),
];

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 抓一条完整 ClientHello：按 TLS 记录逐条读，直到握手消息读满。
async fn capture_client_hello(listener: TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.expect("候选客户端未建立 TCP 连接");
    let mut handshake = Vec::new();
    for _ in 0..8 {
        let mut header = [0u8; 5];
        socket.read_exact(&mut header).await.expect("TLS 记录头读取失败");
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; length];
        socket.read_exact(&mut payload).await.expect("TLS 记录体读取失败");
        if header[0] != 0x16 {
            continue;
        }
        handshake.extend_from_slice(&payload);
        if handshake.len() >= 4 {
            let declared = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if handshake.len() >= declared + 4 {
                handshake.truncate(declared + 4);
                return handshake;
            }
        }
    }
    panic!("TLS 记录里没有完整的 ClientHello");
}

/// 用 `identity::client_builder()` 向回环监听发一次请求并抓 ClientHello。
async fn hello_for(host: &str) -> Value {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听失败");
    let port = listener.local_addr().expect("地址失败").port();
    let capture = tokio::spawn(capture_client_hello(listener));
    let client = identity::client_builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("客户端构造失败");
    // 回环上没有可信证书，握手必然失败；这里只要 ClientHello。
    let _ = client
        .get(format!("https://{host}:{port}/"))
        .send()
        .await;
    let handshake = capture.await.expect("抓包任务失败");
    parse_client_hello(&handshake)
}

/// 读大端游标。
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> &'a [u8] {
        let end = self.offset + length;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        slice
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().expect("两个字节"))
    }
}

/// GREASE 值形如 0x?a?a：低两字节相同、低半字节固定为 a。
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

/// 指纹里的 u16 序列：**保留原始顺序**，剔除 GREASE（Chrome 每条连接都会
/// 重新随机 GREASE 值及其位置，因此位置本身不是稳定指纹，个数才是）。
fn hex16(values: &[u16]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !is_grease(**value))
        .map(|value| format!("{value:04x}"))
        .collect()
}

fn grease_count(values: &[u16]) -> usize {
    values.iter().filter(|value| is_grease(**value)).count()
}

/// 剔除 GREASE 后按字面值排序：只用于**顺序本身随机**的字段（扩展）。
fn sorted_hex16(values: &[u16]) -> Vec<String> {
    let mut names = hex16(values);
    names.sort();
    names
}

/// 解析 ClientHello：保留套件、扩展、支持组与 GREASE 的**原始顺序**。
/// 只丢弃每条连接都会变的 random、会话 id 与公钥字节。
fn parse_client_hello(handshake: &[u8]) -> Value {
    assert_eq!(handshake[0], 0x01, "握手消息必须是 ClientHello");
    let declared = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | handshake[3] as usize;
    assert_eq!(declared + 4, handshake.len(), "ClientHello 长度自洽");

    let mut cursor = Cursor {
        bytes: handshake,
        offset: 4,
    };
    let legacy_version = cursor.u16();
    cursor.take(32); // random
    let session_id_length = cursor.u8() as usize;
    cursor.take(session_id_length);

    let suites = {
        let length = cursor.u16() as usize;
        let mut suites = Vec::with_capacity(length / 2);
        for _ in 0..length / 2 {
            suites.push(cursor.u16());
        }
        suites
    };
    let compression_length = cursor.u8() as usize;
    let compression = cursor.take(compression_length).to_vec();

    let mut extensions: Vec<(u16, &[u8])> = Vec::new();
    if cursor.offset < handshake.len() {
        let total = cursor.u16() as usize;
        let end = cursor.offset + total;
        while cursor.offset < end {
            let kind = cursor.u16();
            let length = cursor.u16() as usize;
            extensions.push((kind, cursor.take(length)));
        }
    }

    let find = |kind: u16| {
        extensions
            .iter()
            .find(|(candidate, _)| *candidate == kind)
            .map(|(_, data)| *data)
    };
    let vector = |kind: u16| -> Vec<u16> {
        find(kind).map_or_else(Vec::new, |data| {
            let length = u16::from_be_bytes([data[0], data[1]]) as usize;
            (0..length / 2)
                .map(|index| u16::from_be_bytes([data[2 + index * 2], data[3 + index * 2]]))
                .collect()
        })
    };
    let alpn = find(0x0010).map_or_else(Vec::new, |data| {
        let mut cursor = Cursor { bytes: data, offset: 2 };
        let mut names = Vec::new();
        while cursor.offset < data.len() {
            let length = cursor.u8() as usize;
            names.push(String::from_utf8_lossy(cursor.take(length)).into_owned());
        }
        names
    });
    let key_share = find(0x0033).map_or_else(Vec::new, |data| {
        // RFC 8446：`client_shares` 是**长度前缀**的向量，不是条目计数。
        let total = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut cursor = Cursor { bytes: data, offset: 2 };
        let end = 2 + total;
        let mut groups = Vec::new();
        while cursor.offset < end {
            groups.push(cursor.u16());
            let length = cursor.u16() as usize;
            cursor.take(length); // 公钥每次连接都不同，只留组号
        }
        groups
    });
    // ClientHello 里的 supported_versions 是**单字节**长度前缀（RFC 8446 §4.2.1），
    // 与 supported_groups / signature_algorithms 的两字节前缀不同。
    let supported_versions = find(0x002b).map_or_else(Vec::new, |data| {
        let length = data[0] as usize;
        (0..length / 2)
            .map(|index| u16::from_be_bytes([data[1 + index * 2], data[2 + index * 2]]))
            .collect()
    });

    json!({
        "legacy_version": format!("{legacy_version:04x}"),
        "session_id_bytes": session_id_length,
        "cipher_suites": hex16(&suites),
        "grease_cipher_suites": grease_count(&suites),
        "compression_methods": compression.iter().map(|value| format!("{value:02x}")).collect::<Vec<_>>(),
        // 扩展**顺序逐连接随机**（Chrome 的 `permute_extensions`，见下方专门的行为断言），
        // 因此这里只比较集合；套件/分组/签名算法/版本/ALPN 的顺序仍然被比较。
        "extension_types_sorted": sorted_hex16(&extensions.iter().map(|(kind, _)| *kind).collect::<Vec<_>>()),
        // 原始顺序只用于断言「确实被重排」，不参与指纹哈希。
        "extension_order": hex16(&extensions.iter().map(|(kind, _)| *kind).collect::<Vec<_>>()),
        "grease_extensions": grease_count(&extensions.iter().map(|(kind, _)| *kind).collect::<Vec<_>>()),
        "alpn": alpn,
        "supported_groups": hex16(&vector(0x000a)),
        "key_share_groups": hex16(&key_share),
        "signature_algorithms": hex16(&vector(0x000d)),
        "supported_versions": hex16(&supported_versions),
        "has_sni": extensions.iter().any(|(kind, _)| *kind == 0x0000),
        "has_status_request": extensions.iter().any(|(kind, _)| *kind == 0x0005),
        "has_sct": extensions.iter().any(|(kind, _)| *kind == 0x0012),
        "has_certificate_compression": extensions.iter().any(|(kind, _)| *kind == 0x001b),
        "has_alps": extensions.iter().any(|(kind, _)| *kind == 0x44cd),
        "has_encrypted_client_hello": extensions.iter().any(|(kind, _)| *kind == 0xfe0d),
    })
}

/// 自签测试证书：只用于让本测试在本地完成一次 TLS 握手以抓 HTTP/2 首帧。
const TEST_CERT_PEM: &str = include_str!("fixtures/localhost-test-cert.pem");
const TEST_KEY_PEM: &str = include_str!("fixtures/localhost-test-key.pem");

/// 从 PEM 里取出第一个 DER 块（测试自带证书，够用即可，不引入 PEM 解析依赖）。
fn pem_der(pem: &str, label: &str) -> Vec<u8> {
    use base64::Engine;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem
        .split_once(&begin)
        .unwrap_or_else(|| panic!("缺少 {begin}"))
        .1
        .split_once(&end)
        .expect("证书 PEM 缺少结尾标记")
        .0;
    base64::engine::general_purpose::STANDARD
        .decode(body.split_whitespace().collect::<String>())
        .expect("PEM 正文不是合法 base64")
}

/// 抓客户端发来的 HTTP/2 首帧：完成 TLS（ALPN=h2）后读取到出现 HEADERS 为止。
async fn capture_h2_frames(listener: TcpListener) -> Vec<u8> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert = CertificateDer::from(pem_der(TEST_CERT_PEM, "CERTIFICATE"));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_der(TEST_KEY_PEM, "PRIVATE KEY")));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("测试证书必须可用");
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let (stream, _) = listener.accept().await.expect("客户端未建立 TCP 连接");
    let mut stream = acceptor.accept(stream).await.expect("TLS 握手失败");
    let mut first = Some((
        // 服务端 SETTINGS（空负载）+ 对客户端 SETTINGS 的 ACK：正常服务器行为，
        // 也是让客户端把请求头发出来的必要条件。
        vec![0u8; 9],
        vec![0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00],
    ));
    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        if let Some((settings, ack)) = first.take() {
            stream.write_all(&settings).await.expect("SETTINGS 发送失败");
            stream.write_all(&ack).await.expect("SETTINGS ACK 发送失败");
            stream.flush().await.expect("flush 失败");
        }
        let read = tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await;
        match read {
            Ok(Ok(0)) => break,
            Ok(Ok(count)) => {
                received.extend_from_slice(&buffer[..count]);
                if let Some(frames) = h2_frames(&received) {
                    if frames.iter().any(|frame| frame.kind == 0x01) {
                        break; // 已经拿到 HEADERS
                    }
                }
            }
            Ok(Err(cause)) => panic!("读取失败：{cause}"),
            Err(_) => break, // 超时：用已有字节做断言
        }
    }
    received
}

struct H2Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// 解析已完成 preface 的帧序列；preface 未到齐时返回 `None`。
fn h2_frames(bytes: &[u8]) -> Option<Vec<H2Frame>> {
    if bytes.len() < H2_PREFACE.len() {
        return None;
    }
    assert_eq!(&bytes[..H2_PREFACE.len()], H2_PREFACE, "客户端 preface 不符");
    let mut offset = H2_PREFACE.len();
    let mut frames = Vec::new();
    while offset + 9 <= bytes.len() {
        let length =
            ((bytes[offset] as usize) << 16) | ((bytes[offset + 1] as usize) << 8) | bytes[offset + 2] as usize;
        if offset + 9 + length > bytes.len() {
            break;
        }
        frames.push(H2Frame {
            kind: bytes[offset + 3],
            flags: bytes[offset + 4],
            stream: u32::from_be_bytes(bytes[offset + 5..offset + 9].try_into().expect("4 字节")),
            payload: bytes[offset + 9..offset + 9 + length].to_vec(),
        });
        offset += 9 + length;
    }
    Some(frames)
}

/// SETTINGS 里的标识名，取值与 Chrome 的语义一致即可比对。
fn setting_name(id: u16) -> &'static str {
    match id {
        0x01 => "header_table_size",
        0x02 => "enable_push",
        0x03 => "max_concurrent_streams",
        0x04 => "initial_window_size",
        0x05 => "max_frame_size",
        0x06 => "max_header_list_size",
        0x08 => "enable_connect_protocol",
        _ => "unknown",
    }
}

/// HPACK 静态表里本节需要的名字（伪头与常见头）。
fn static_name(index: usize) -> &'static str {
    match index {
        1 => ":authority",
        2 | 3 => ":method",
        4 | 5 => ":path",
        6 | 7 => ":scheme",
        8..=14 => ":status",
        16 | 17 => "accept-encoding",
        19 | 20 => "accept",
        31 => "content-type",
        32 => "cookie",
        58 => "user-agent",
        _ => "other",
    }
}

/// 只按名字解 HEADERS 的 HPACK 块：字符串值（可能 Huffman）一律跳过，
/// 伪头顺序因此可读。
fn hpack_names(block: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut offset = 0;
    while offset < block.len() {
        let byte = block[offset];
        if byte & 0x80 != 0 {
            names.push(static_name((byte & 0x7f) as usize).to_owned());
            offset += 1;
            continue;
        }
        let prefix_mask = if byte & 0xc0 == 0x40 {
            0x3f
        } else if byte & 0xe0 == 0x20 {
            // 动态表大小更新：没有名字，跳过整数。
            offset += 1;
            while offset < block.len() && block[offset] & 0x80 != 0 {
                offset += 1;
            }
            offset += 1;
            continue;
        } else {
            0x0f
        };
        let mut value = (byte & prefix_mask) as usize;
        offset += 1;
        if value == prefix_mask as usize {
            // 整数续字节。
            let mut shift = 0;
            while offset < block.len() && block[offset] & 0x80 != 0 {
                value += ((block[offset] & 0x7f) as usize) << shift;
                shift += 7;
                offset += 1;
            }
            if offset < block.len() {
                value += (block[offset] as usize) << shift;
                offset += 1;
            }
        }
        if value == 0 {
            // 字面名字：长度前缀（可能带 Huffman 标记），跳过。
            if offset >= block.len() {
                break;
            }
            let huffman = block[offset] & 0x80 != 0;
            let mut length = (block[offset] & 0x7f) as usize;
            offset += 1;
            if length == 0x7f {
                let mut shift = 0;
                while offset < block.len() && block[offset] & 0x80 != 0 {
                    length += ((block[offset] & 0x7f) as usize) << shift;
                    shift += 7;
                    offset += 1;
                }
                if offset < block.len() {
                    length += (block[offset] as usize) << shift;
                    offset += 1;
                }
            }
            let raw = block.get(offset..offset + length).unwrap_or_default();
            names.push(if huffman {
                "huffman-name".to_owned()
            } else {
                String::from_utf8_lossy(raw).into_owned()
            });
            offset += length;
        } else {
            names.push(static_name(value).to_owned());
        }
        // 跳过值：长度前缀（可能 Huffman）。
        if offset >= block.len() {
            break;
        }
        let mut length = (block[offset] & 0x7f) as usize;
        let huffman = block[offset] & 0x80 != 0;
        offset += 1;
        if length == 0x7f {
            let mut shift = 0;
            while offset < block.len() && block[offset] & 0x80 != 0 {
                length += ((block[offset] & 0x7f) as usize) << shift;
                shift += 7;
                offset += 1;
            }
            if offset < block.len() {
                length += (block[offset] as usize) << shift;
                offset += 1;
            }
        }
        let _ = huffman; // 值的内容与指纹无关，只消费长度。
        offset += length;
    }
    names
}

/// 归一化 HTTP/2 首帧：preface、SETTINGS 条目**顺序**、连接窗口增量、伪头顺序。
fn parse_h2_first_frames(bytes: &[u8]) -> Value {
    let frames = h2_frames(bytes).expect("preface 未到齐");
    let mut settings = Vec::new();
    let mut window_update = None;
    let mut pseudo_order: Vec<String> = Vec::new();
    let mut headers_flags: Vec<&str> = Vec::new();
    for frame in &frames {
        match frame.kind {
            0x04 if frame.flags & 0x01 == 0 => {
                for entry in frame.payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([entry[0], entry[1]]);
                    let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
                    settings.push(json!({"name": setting_name(id), "id": id, "value": value}));
                }
            }
            0x08 if frame.stream == 0 => {
                window_update = Some(u32::from_be_bytes([
                    frame.payload[0],
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]) & 0x7fff_ffff);
            }
            0x01 => {
                // RFC 7540 §6.2：顺序是 Pad Length（0x08）→ Priority（0x20）→ 头块 → Padding。
                let mut block = frame.payload.as_slice();
                let padding = if frame.flags & 0x08 != 0 {
                    let padding = block[0] as usize;
                    block = &block[1..];
                    padding
                } else {
                    0
                };
                // HEADERS 的标志位本身就是指纹的一部分：真 Chrome146 的首个
                // HEADERS 是 `END_STREAM|END_HEADERS|PRIORITY`（参照记的是
                // `flags: "25"`），带 PRIORITY 就意味着帧里多 5 字节优先级字段。
                // 此前这里只是把那 5 字节跳过去，标志位从不入摘要、也从不与参照
                // 对照——候选少发 PRIORITY 或改了优先级都不会被这套锁发现。
                for (bit, name) in [
                    (0x01, "END_STREAM"),
                    (0x04, "END_HEADERS"),
                    (0x08, "PADDED"),
                    (0x20, "PRIORITY"),
                ] {
                    if frame.flags & bit != 0 {
                        headers_flags.push(name);
                    }
                }
                if frame.flags & 0x20 != 0 {
                    block = &block[5..];
                }
                block = &block[..block.len() - padding];
                pseudo_order = hpack_names(block);
            }
            _ => {}
        }
    }
    json!({
        "preface": String::from_utf8_lossy(&bytes[..H2_PREFACE.len()]),
        "frame_kinds": frames
            .iter()
            .map(|frame| match frame.kind {
                0x00 => "data",
                0x01 => "headers",
                0x02 => "priority",
                0x03 => "rst_stream",
                0x04 => "settings",
                0x06 => "ping",
                0x07 => "goaway",
                0x08 => "window_update",
                0x09 => "continuation",
                _ => "unknown",
            })
            .collect::<Vec<_>>(),
        "settings": settings,
        "connection_window_update": window_update,
        "request_header_names": pseudo_order,
        "headers_frame_flags": headers_flags,
    })
}

/// 从 `Cargo.lock` 读身份相关依赖的实际版本。
fn lockfile_versions() -> BTreeMap<String, String> {
    let lock = include_str!("../Cargo.lock");
    let mut versions = BTreeMap::new();
    let mut lines = lock.lines().peekable();
    let mut current: Option<String> = None;
    for line in lines.by_ref() {
        if let Some(name) = line.strip_prefix("name = \"") {
            current = Some(name.trim_end_matches('"').to_owned());
            continue;
        }
        if let Some(version) = line.strip_prefix("version = \"") {
            if let Some(name) = current.take() {
                versions.entry(name).or_insert_with(|| version.trim_end_matches('"').to_owned());
            }
        }
    }
    versions
}

fn hex_sha256(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_string(value).expect("序列化失败").as_bytes())
    )
}

/// 指纹哈希用的稳定视图：去掉逐连接随机、只用于行为断言的字段。
fn stable_fingerprint(value: &Value) -> String {
    let mut stable = value.clone();
    stable.as_object_mut().expect("指纹必须是对象").remove("extension_order");
    hex_sha256(&stable)
}

#[tokio::test]
async fn candidate_client_hello_matches_chrome_shape() {
    let hello = hello_for("127.0.0.1").await;
    println!("候选 ClientHello（IP 字面量，无 SNI）：{}\n{}",
        stable_fingerprint(&hello),
        serde_json::to_string(&hello).expect("序列化失败"));

    // Chrome 家族不变式：GREASE 必须在原位置出现，TLS1.3 + h2 必须被声明，
    // 密钥共享必须是现代曲线；缺任何一条都说明画像被换掉了。
    assert_eq!(hello["legacy_version"], "0303");
    assert_eq!(hello["session_id_bytes"], 32);
    assert_eq!(hello["grease_cipher_suites"], json!(1), "必须带一个 GREASE 密码套件");
    assert_eq!(hello["grease_extensions"], json!(2), "必须带两个 GREASE 扩展");
    assert!(
        hello["supported_versions"].as_array().expect("版本列表").iter().any(|value| value == "0304"),
        "必须声明 TLS1.3"
    );
    assert!(
        hello["cipher_suites"].as_array().expect("套件列表").iter().any(|value| value == "1301"),
        "必须包含 TLS_AES_128_GCM_SHA256"
    );
    assert!(hello["alpn"].as_array().expect("ALPN").iter().any(|value| value == "h2"));
    for group in ["11ec", "001d"] {
        assert!(
            hello["key_share_groups"].as_array().expect("key_share").iter().any(|value| value == group),
            "key_share 缺少 {group}"
        );
    }
    assert_eq!(hello["has_sni"], json!(false), "IP 字面量不发送 SNI");
    assert_eq!(stable_fingerprint(&hello), EXPECTED_HELLO_SHA256, "ClientHello 指纹变了：确认为有意升级后更新本常量与证据");

    // 扩展顺序必须逐连接重排（Chrome 的 `permute_extensions`）：抓两条比较。
    // 若上游实现改成固定顺序，这里会红——固定顺序本身就是一个可区分特征。
    let second = hello_for("127.0.0.1").await;
    assert_eq!(
        second["extension_types_sorted"], hello["extension_types_sorted"],
        "扩展集合必须稳定"
    );
    assert_ne!(
        second["extension_order"], hello["extension_order"],
        "扩展顺序必须逐连接重排（permute_extensions）"
    );
    assert_eq!(
        second["cipher_suites"], hello["cipher_suites"],
        "密码套件顺序必须稳定（Chrome 不重排套件）"
    );

    // 同一画像在 SNI 场景下必须只有 SNI 不同：`localhost` 会解析到回环。
    let hello_sni = hello_for("localhost").await;
    assert_eq!(hello_sni["has_sni"], json!(true), "localhost 场景必须发送 SNI");
    for field in ["cipher_suites", "supported_groups", "key_share_groups", "signature_algorithms",
                  "supported_versions", "alpn", "legacy_version", "session_id_bytes",
                  "compression_methods", "grease_cipher_suites", "grease_extensions"] {
        assert_eq!(hello_sni[field], hello[field], "SNI 场景的 {field} 必须与 IP 场景一致");
    }
    // SNI 场景多出 `server_name`(0x0000) 扩展，正好是两者唯二的区别（另一处是 has_sni）。
    let mut sni_extensions: Vec<String> = hello_sni["extension_types_sorted"]
        .as_array()
        .expect("扩展集合")
        .iter()
        .map(|value| value.as_str().expect("扩展号").to_owned())
        .filter(|kind| kind != "0000")
        .collect();
    sni_extensions.sort();
    assert_eq!(
        sni_extensions,
        hello["extension_types_sorted"]
            .as_array()
            .expect("扩展集合")
            .iter()
            .map(|value| value.as_str().expect("扩展号").to_owned())
            .collect::<Vec<_>>(),
        "除 server_name 外扩展集合必须一致"
    );
    assert_eq!(stable_fingerprint(&hello_sni), EXPECTED_HELLO_SNI_SHA256, "SNI 场景指纹变了");
}

#[tokio::test]
async fn candidate_http2_first_frame_matches_chrome_shape() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听失败");
    let port = listener.local_addr().expect("地址失败").port();
    let capture = tokio::spawn(capture_h2_frames(listener));
    let client = identity::client_builder()
        .tls_cert_verification(false)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("客户端构造失败");
    // 测试证书是自签的，因此关闭校验；这里只看客户端发出的首帧。
    let _ = client.get(format!("https://127.0.0.1:{port}/")).send().await;
    let bytes = capture.await.expect("抓帧任务失败");
    let h2 = parse_h2_first_frames(&bytes);
    println!(
        "候选 HTTP/2 首帧：\n{}",
        serde_json::to_string_pretty(&h2).expect("序列化失败")
    );

    let settings = h2["settings"].as_array().expect("SETTINGS 列表");
    let setting = |name: &str| {
        settings
            .iter()
            .find(|entry| entry["name"] == name)
            .map(|entry| entry["value"].as_u64().expect("设置值必须是整数"))
    };
    // 真 Chrome146 的 SETTINGS 逐项（证据 reference-chrome146-001）：
    // 只有这四项，**不含** `MAX_CONCURRENT_STREAMS`——补上它反而会偏离参照。
    assert_eq!(setting("header_table_size"), Some(65536), "{h2}");
    assert_eq!(setting("enable_push"), Some(0), "{h2}");
    assert_eq!(setting("initial_window_size"), Some(6291456), "{h2}");
    assert_eq!(setting("max_header_list_size"), Some(262144), "{h2}");
    assert_eq!(settings.len(), 4, "SETTINGS 只能有参照里的四项：{h2}");
    let ids: Vec<u64> = settings
        .iter()
        .map(|entry| entry["id"].as_u64().expect("设置 id"))
        .collect();
    assert_eq!(ids, vec![1, 2, 4, 6], "SETTINGS 的 id 顺序必须与参照一致：{h2}");
    assert_eq!(
        h2["connection_window_update"], json!(15663105),
        "连接级窗口增量必须与 Chrome 一致"
    );
    assert_eq!(
        h2["frame_kinds"], json!(["settings", "window_update", "headers"]),
        "首帧序列必须与参照一致（SETTINGS → WINDOW_UPDATE → HEADERS）"
    );
    let names: Vec<String> = h2["request_header_names"]
        .as_array()
        .expect("头名列表")
        .iter()
        .map(|value| value.as_str().expect("头名").to_owned())
        .collect();
    let pseudo: Vec<String> = names
        .iter()
        .filter(|name| name.starts_with(':'))
        .cloned()
        .collect();
    assert_eq!(
        pseudo,
        vec![":method", ":authority", ":scheme", ":path"],
        "伪头顺序必须与 Chrome 一致：{names:?}"
    );
    assert_eq!(hex_sha256(&h2), EXPECTED_H2_SHA256, "HTTP/2 首帧指纹变了：确认后更新本常量与证据");
}

/// 真实指纹由这些 crate 的字节决定；直接依赖锁了版本还不够，底座换了同样会漂。
#[test]
fn identity_crates_are_pinned_in_the_lockfile() {
    let versions = lockfile_versions();
    for (name, expected) in IDENTITY_CRATES {
        assert_eq!(
            versions.get(name).map(String::as_str),
            Some(expected),
            "{name} 的锁定版本漂了：指纹必须重新采集并更新证据"
        );
    }
}

/// 外部参照：Chrome for Testing **146.0.7680.165** 的三段实测（`probe/probe_reference_identity.py`）。
/// 自锁常量只证明「候选没变」，这里证明「候选与同版本真 Chrome 一致」。
const REFERENCE_HELLO: &str =
    include_str!("../../../../evidence/reference-chrome146-001/01-clienthello.json");
const REFERENCE_H2: &str =
    include_str!("../../../../evidence/reference-chrome146-001/02-h2-first-frames.json");

/// 参照里 `has_sni` 对应的那条采集。
fn reference_capture(document: &Value, has_sni: bool) -> Value {
    document["captures"]
        .as_array()
        .expect("captures 必须是数组")
        .iter()
        .find(|capture| capture["rust_normalized"]["has_sni"] == json!(has_sni))
        .unwrap_or_else(|| panic!("参照缺少 has_sni={has_sni} 的采集"))
        .clone()
}

#[tokio::test]
async fn candidate_client_hello_matches_the_chrome146_reference() {
    let reference: Value = serde_json::from_str(REFERENCE_HELLO).expect("参照 JSON 无效");
    assert_eq!(reference["browser_version"], "146.0.7680.165");

    for (has_sni, host) in [(false, "127.0.0.1"), (true, "localhost")] {
        let expected = reference_capture(&reference, has_sni);
        let expected = &expected["rust_normalized"];
        let hello = hello_for(host).await;

        // 逐字段对照：只有「候选是否排序」这一项的表示不同，比较前统一排序。
        assert_eq!(hello["legacy_version"], expected["legacy_version"], "{host}");
        assert_eq!(hello["session_id_bytes"], expected["session_id_bytes"], "{host}");
        assert_eq!(hello["compression_methods"], expected["compression_methods"], "{host}");
        assert_eq!(hello["grease_cipher_suites"], expected["grease_cipher_suites"], "{host}");
        assert_eq!(hello["grease_extensions"], expected["grease_extensions"], "{host}");
        assert_eq!(hello["alpn"], expected["alpn"], "{host}");
        assert_eq!(hello["supported_groups"], expected["supported_groups"], "{host}");
        assert_eq!(hello["key_share_groups"], expected["key_share_groups"], "{host}");
        assert_eq!(
            hello["signature_algorithms"], expected["signature_algorithms"],
            "{host}：签名算法必须与 146 参照一致（含 ML-DSA 差异的结论由此闭合）"
        );
        assert_eq!(hello["supported_versions"], expected["supported_versions"], "{host}");
        assert_eq!(hello["extension_types_sorted"], expected["extension_types_sorted"], "{host}");
        assert_eq!(hello["has_sni"], expected["has_sni"], "{host}");
        for field in [
            "has_status_request",
            "has_sct",
            "has_certificate_compression",
            "has_alps",
            "has_encrypted_client_hello",
        ] {
            assert_eq!(hello[field], expected[field], "{host} 的 {field}");
        }
        // 套件：**按顺序**比对。密码套件的排列本身就是 TLS 指纹的一部分，
        // 只比集合等于放过「同一批套件、不同顺序」这种整类漂移。
        // `rust_normalized` 只有排序视图，但原始顺序一直躺在同一份参照的
        // `raw.cipher_suites` 里（GREASE 在首位，值每次握手随机，因此剔除后比较）。
        let raw_capture = reference_capture(&reference, has_sni);
        let expected_suites: Vec<String> = raw_capture["raw"]["cipher_suites"]
            .as_array()
            .expect("参照原始套件顺序")
            .iter()
            .map(|value| value.as_str().expect("套件号").to_owned())
            .filter(|value| {
                u16::from_str_radix(value, 16).is_ok_and(|value| !is_grease(value))
            })
            .collect();
        // 候选侧由 `hex16` 产出，GREASE 已经剔除过。
        let suites: Vec<String> = hello["cipher_suites"]
            .as_array()
            .expect("套件列表")
            .iter()
            .map(|value| value.as_str().expect("套件号").to_owned())
            .collect();
        assert_eq!(suites, expected_suites, "{host} 的密码套件顺序");
    }
}

#[tokio::test]
async fn candidate_http2_first_frame_matches_the_chrome146_reference() {
    let reference: Value = serde_json::from_str(REFERENCE_H2).expect("参照 JSON 无效");
    let capture = &reference["capture"];
    assert_eq!(reference["browser_version"], "146.0.7680.165");
    assert_eq!(capture["preface_ok"], json!(true), "参照 preface 必须正确");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听失败");
    let port = listener.local_addr().expect("地址失败").port();
    let task = tokio::spawn(capture_h2_frames(listener));
    let client = identity::client_builder()
        .tls_cert_verification(false)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("客户端构造失败");
    let _ = client.get(format!("https://127.0.0.1:{port}/")).send().await;
    let h2 = parse_h2_first_frames(&task.await.expect("抓帧任务失败"));

    // SETTINGS：id 与值都按参照顺序逐项比对。
    let ours: Vec<(u64, u64)> = h2["settings"]
        .as_array()
        .expect("SETTINGS")
        .iter()
        .map(|entry| {
            (
                entry["id"].as_u64().expect("设置 id"),
                entry["value"].as_u64().expect("设置值"),
            )
        })
        .collect();
    let expected: Vec<(u64, u64)> = capture["settings_pairs"]
        .as_array()
        .expect("参照 SETTINGS")
        .iter()
        .map(|entry| {
            (
                u64::from_str_radix(entry["id"].as_str().expect("参照 id"), 16).expect("十六进制"),
                entry["value"].as_u64().expect("参照设置值"),
            )
        })
        .collect();
    assert_eq!(ours, expected, "SETTINGS 必须与 146 参照逐项一致");

    assert_eq!(
        h2["connection_window_update"].as_u64(),
        capture["window_update"]["increment"].as_u64(),
        "连接级 WINDOW_UPDATE 必须与参照一致"
    );
    assert_eq!(
        h2["frame_kinds"],
        json!(["settings", "window_update", "headers"]),
        "首帧序列必须与参照一致（参照 {}）",
        capture["frame_type_sequence"]
    );
    let pseudo: Vec<String> = h2["request_header_names"]
        .as_array()
        .expect("头名列表")
        .iter()
        .filter(|value| value.as_str().is_some_and(|name| name.starts_with(':')))
        .map(|value| value.as_str().expect("头名").to_owned())
        .collect();
    let expected_pseudo: Vec<String> = capture["first_headers"]["pseudo_header_order"]
        .as_array()
        .expect("参照伪头顺序")
        .iter()
        .map(|value| value.as_str().expect("伪头名").to_owned())
        .collect();
    assert_eq!(pseudo, expected_pseudo, "伪头顺序必须与参照一致");
    assert_eq!(
        h2["headers_frame_flags"],
        capture["first_headers"]["flags_names"],
        "HEADERS 帧标志位必须与 146 参照一致（PRIORITY 在不在，本身就是指纹）"
    );
}

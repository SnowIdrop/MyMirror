// -----------------------------------------------------------------------------
// Author  : MingTea
// File    : tests/identity_fingerprint.rs
// Created : 2026-09-24
// Summary : 传输身份回归锁。用裸 TCP 监听抓候选自己发出的 ClientHello，归一化后
//           锁定指纹，并断言 Chrome 家族不变式（GREASE、TLS1.3、h2 ALPN、X25519 等）。
//           库升级或画像误换会让这条测试变红，避免「UA 说 Chrome146、TLS 却是别的」
//           这类不一致静默上线。
// 证据来源：真 Chromium 的对照由 `probe/probe_tls_identity.py` 采集，结论写在
//           `source/COMPATIBILITY.md` 的「传输身份统一」章节。
// -----------------------------------------------------------------------------

use std::time::Duration;

use mirror_gateway::server::identity;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// 归一化指纹的 sha256。改了画像（或改了 `identity::emulation()` 的平台/开关）
/// 就必须重新采集并更新这个值，同时更新 COMPATIBILITY.md 的对照结论。
const EXPECTED_FINGERPRINT_SHA256: &str =
    "01425d3fe0c24e404839d678bca29b881e52bcd05b37efdc795aac02f703c3cb";

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

/// 读大端 u16 游标。
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

fn hex16(values: &[u16]) -> Vec<String> {
    values.iter().map(|value| format!("{value:04x}")).collect()
}

/// 解析 ClientHello 并归一化：去掉随机、会话 id、GREASE 位置与扩展顺序这些
/// 每条连接都会变的部分，只留可比较的画像。
fn normalize_client_hello(handshake: &[u8]) -> Value {
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
    let session_id = cursor.take(session_id_length).to_vec();

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
    let list = |kind: u16| -> Vec<u16> {
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
        let mut versions: Vec<u16> = (0..length / 2)
            .map(|index| u16::from_be_bytes([data[1 + index * 2], data[2 + index * 2]]))
            .collect();
        versions.retain(|version| !is_grease(*version));
        versions
    });

    let mut suite_no_grease: Vec<u16> = suites
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect();
    let mut extension_types: Vec<u16> = extensions
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| !is_grease(*kind))
        .collect();
    extension_types.sort_unstable();
    let mut groups = list(0x000a);
    groups.retain(|group| !is_grease(*group));
    let mut key_share_groups = key_share;
    key_share_groups.retain(|group| !is_grease(*group));
    suite_no_grease.sort_unstable();

    json!({
        "legacy_version": format!("{legacy_version:04x}"),
        "session_id_bytes": session_id.len(),
        "cipher_suites_sorted": hex16(&suite_no_grease),
        "grease_cipher_suites": suites.len() - suite_no_grease.len(),
        "grease_extensions": extensions.len() - extension_types.len(),
        "compression_methods": compression.iter().map(|value| format!("{value:02x}")).collect::<Vec<_>>(),
        "extension_types_sorted": hex16(&extension_types),
        "alpn": alpn,
        "supported_groups": hex16(&groups),
        "key_share_groups": hex16(&key_share_groups),
        "signature_algorithms": hex16(&list(0x000d)),
        "supported_versions": hex16(&supported_versions),
        "has_sni": extensions.iter().any(|(kind, _)| *kind == 0x0000),
        "has_status_request": extensions.iter().any(|(kind, _)| *kind == 0x0005),
        "has_sct": extensions.iter().any(|(kind, _)| *kind == 0x0012),
        "has_certificate_compression": extensions.iter().any(|(kind, _)| *kind == 0x001b),
        "has_alps": extensions.iter().any(|(kind, _)| *kind == 0x44cd),
        "has_encrypted_client_hello": extensions.iter().any(|(kind, _)| *kind == 0xfe0d),
    })
}

#[tokio::test]
async fn candidate_transport_identity_stays_chrome_shaped() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听失败");
    let port = listener.local_addr().expect("地址失败").port();
    let capture = tokio::spawn(capture_client_hello(listener));

    let client = identity::client_builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("客户端构造失败");
    // 回环上没有证书，握手必然失败；这里的目的是让客户端发出 ClientHello。
    let _ = client.get(format!("https://127.0.0.1:{port}/")).send().await;

    let handshake = capture.await.expect("抓包任务失败");
    let fingerprint = normalize_client_hello(&handshake);
    println!(
        "候选 ClientHello 归一化指纹：\n{}",
        serde_json::to_string_pretty(&fingerprint).expect("序列化失败")
    );

    // Chrome 家族不变式：GREASE 必须存在，TLS1.3 + h2 必须被声明，
    // 密钥交换必须走现代曲线；缺任何一条都说明画像被换掉了。
    let extension = |kind: &str| {
        fingerprint["extension_types_sorted"]
            .as_array()
            .expect("扩展列表")
            .iter()
            .any(|value| value == kind)
    };
    assert!(fingerprint["grease_cipher_suites"].as_u64().unwrap_or(0) > 0, "缺少 GREASE 密码套件");
    assert!(fingerprint["grease_extensions"].as_u64().unwrap_or(0) > 0, "缺少 GREASE 扩展");
    assert_eq!(fingerprint["legacy_version"], "0303", "legacy_version 必须是 TLS1.2");
    assert!(
        fingerprint["supported_versions"].as_array().expect("版本列表")
            .iter()
            .any(|value| value == "0304"),
        "必须声明 TLS1.3"
    );
    assert!(
        fingerprint["cipher_suites_sorted"].as_array().expect("套件列表")
            .iter()
            .any(|value| value == "1301"),
        "必须包含 TLS_AES_128_GCM_SHA256"
    );
    assert!(
        fingerprint["alpn"].as_array().expect("ALPN 列表")
            .iter()
            .any(|value| value == "h2"),
        "必须声明 h2"
    );
    for kind in ["000a", "000d", "002b", "0033"] {
        assert!(extension(kind), "缺少扩展 {kind}");
    }
    // 密钥共享只发「够快」的组，secp256r1 只在 supported_groups 里宣告。
    for (field, group) in [
        ("key_share_groups", "001d"),
        ("key_share_groups", "11ec"),
        ("supported_groups", "0017"),
    ] {
        assert!(
            fingerprint[field].as_array().expect("组列表")
                .iter()
                .any(|value| value == group),
            "{field} 缺少 {group}"
        );
    }

    let canonical = serde_json::to_string(&fingerprint).expect("序列化失败");
    let digest = format!("{:x}", Sha256::digest(canonical.as_bytes()));
    println!("归一化指纹 sha256：{digest}");
    assert_eq!(
        digest, EXPECTED_FINGERPRINT_SHA256,
        "归一化指纹变了：确认是有意升级后更新本常量与 COMPATIBILITY.md 的对照结论"
    );
}

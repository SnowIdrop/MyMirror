# -*- coding: utf-8 -*-
r"""版本匹配的 Chrome 146 参照身份采集（ClientHello / HTTP-2 首帧 / 请求头三段）。

背景：候选网关声称 Chrome146/Linux（wreq-util 的 `Profile::Chrome146`），而此前
`probe_tls_identity.py` 的对照浏览器是 Playwright 自带 Chromium 151，版本不匹配。
本探针驱动 Chrome for Testing **146**（`--chrome` 指向它的 chrome.exe），在同一台机器
上采三份参照证据：

1. ClientHello：裸 TCP 监听，只读 ClientHello、**不完成握手**，分别让浏览器访问
   `https://127.0.0.1:<port>/`（无 SNI）与 `https://localhost:<port>/`（有 SNI）。
   `rust_normalized` 与 `source/tests/identity_fingerprint.rs` 的归一化逐字段一致
   （去 random、会话 id、GREASE 值与扩展顺序），`raw` 保留**未排序**的密码套件与
   扩展顺序——顺序本身是证据，不排序。
2. HTTP/2 首帧：本地 TLS 服务（openssl 现生成自签证书，只落临时目录）协商 `h2`，
   完成握手后只读客户端首批发来的帧：preface、SETTINGS（id 与顺序）、WINDOW_UPDATE、
   第一条 HEADERS 的伪头顺序。HPACK 只按静态表索引判名字，值只在非 Huffman 时给出，
   遇到字面名如实标注「未解码」，不猜。
3. 请求头全量：本地 HTTP 服务（导航响应带 `Accept-CH`），同一 Chrome 加载页面并触发
   同源 `fetch`（GET/POST 各一次），在**服务端**记录完整头的顺序与值。

边界：三段全部只打本机回环，不接触任何上游；页面不写 Cookie，证据里也不落任何
Cookie/Authorization 的值。脚本不写死任何期望值——只记录实测值。

依赖：本机 Python 3.11+ 与可选依赖 `playwright`；Chrome for Testing 146 需先落临时目录
（不入库、不进 evidence）：

    $tmp = "$env:TEMP\cft-146"
    New-Item -ItemType Directory -Force -Path $tmp
    curl.exe -L --fail -o "$tmp\chrome-win64.zip" `
      "https://storage.googleapis.com/chrome-for-testing-public/146.0.7680.165/win64/chrome-win64.zip"
    Expand-Archive -LiteralPath "$tmp\chrome-win64.zip" -DestinationPath $tmp -Force

运行（PowerShell；本机 `python` 是 Microsoft Store 占位程序，用 `py -3` 或解释器绝对路径）：

    py -3 probe_reference_identity.py `
      --chrome "$env:TEMP\cft-146\chrome-win64\chrome.exe" `
      --openssl "C:\Program Files\Git\usr\bin\openssl.exe" `
      --evidence "../../evidence/reference-chrome146-001"
"""

import argparse
import hashlib
import json
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

# --------------------------------------------------------------------------------------
# 通用工具
# --------------------------------------------------------------------------------------

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# 证据里不落任何凭据类头的值：本探针的页面不发这些头，出现即说明来源不可控。
CREDENTIAL_HEADERS = {"cookie", "authorization", "proxy-authorization", "set-cookie"}


def hex16(values) -> list:
    return [f"{value:04x}" for value in values]


def hex8(values) -> list:
    return [f"{value:02x}" for value in values]


def is_grease(value: int) -> bool:
    """与 `identity_fingerprint.rs` 的 `is_grease` 同一判据：0x?a?a 且高低字节相同。"""
    return value & 0x0F0F == 0x0A0A and (value >> 8) == (value & 0xFF)


# --------------------------------------------------------------------------------------
# 第一段：ClientHello
# --------------------------------------------------------------------------------------


def read_client_hello(conn: socket.socket) -> bytes:
    """按 TLS 记录逐条读到一条完整握手消息。"""
    handshake = b""
    for _ in range(8):
        header = b""
        while len(header) < 5:
            chunk = conn.recv(5 - len(header))
            if not chunk:
                return handshake
            header += chunk
        length = int.from_bytes(header[3:5], "big")
        payload = b""
        while len(payload) < length:
            chunk = conn.recv(length - len(payload))
            if not chunk:
                return handshake
            payload += chunk
        if header[0] != 0x16:
            continue
        handshake += payload
        if len(handshake) >= 4:
            declared = int.from_bytes(handshake[1:4], "big")
            if len(handshake) >= declared + 4:
                return handshake[: declared + 4]
    return handshake


def parse_client_hello(handshake: bytes) -> dict:
    """解析 ClientHello。

    `raw` 保留原始顺序（含 GREASE 位置），`rust_normalized` 与
    `identity_fingerprint.rs::normalize_client_hello` 逐字段、逐顺序一致，可直接与该
    测试锁定的 sha256 对照。
    """
    if not handshake or handshake[0] != 0x01:
        raise ValueError("握手消息不是 ClientHello")
    declared = int.from_bytes(handshake[1:4], "big")
    if declared + 4 != len(handshake):
        raise ValueError("ClientHello 长度不自洽")

    offset = 4
    legacy_version = int.from_bytes(handshake[offset:offset + 2], "big")
    offset += 2
    offset += 32  # random：每条连接都不同，归一化里被去掉
    session_id_length = handshake[offset]
    offset += 1
    session_id = handshake[offset:offset + session_id_length]
    offset += session_id_length

    suites_length = int.from_bytes(handshake[offset:offset + 2], "big")
    offset += 2
    suites = [
        int.from_bytes(handshake[offset + index * 2:offset + index * 2 + 2], "big")
        for index in range(suites_length // 2)
    ]
    offset += suites_length
    compression_length = handshake[offset]
    offset += 1
    compression = list(handshake[offset:offset + compression_length])
    offset += compression_length

    extensions = []
    if offset < len(handshake):
        total = int.from_bytes(handshake[offset:offset + 2], "big")
        offset += 2
        end = offset + total
        while offset < end:
            kind = int.from_bytes(handshake[offset:offset + 2], "big")
            length = int.from_bytes(handshake[offset + 2:offset + 4], "big")
            extensions.append((kind, handshake[offset + 4:offset + 4 + length]))
            offset += 4 + length

    def find(kind: int):
        for candidate, data in extensions:
            if candidate == kind:
                return data
        return None

    def vector(kind: int, prefix: int) -> list:
        data = find(kind)
        if data is None:
            return []
        length = int.from_bytes(data[:prefix], "big")
        return [
            int.from_bytes(data[prefix + index * 2:prefix + index * 2 + 2], "big")
            for index in range(length // 2)
        ]

    alpn = []
    alpn_data = find(0x0010)
    if alpn_data is not None:
        cursor = 2
        while cursor < len(alpn_data):
            length = alpn_data[cursor]
            alpn.append(alpn_data[cursor + 1:cursor + 1 + length].decode("utf-8", errors="replace"))
            cursor += 1 + length

    key_share_groups = []
    key_share_data = find(0x0033)
    if key_share_data is not None:
        # RFC 8446：client_shares 是长度前缀的向量，公钥每次连接都不同，只留组号。
        cursor = 2
        end = 2 + int.from_bytes(key_share_data[:2], "big")
        while cursor < end:
            group = int.from_bytes(key_share_data[cursor:cursor + 2], "big")
            length = int.from_bytes(key_share_data[cursor + 2:cursor + 4], "big")
            key_share_groups.append(group)
            cursor += 4 + length

    supported_groups = vector(0x000A, 2)
    signature_algorithms = vector(0x000D, 2)
    # supported_versions 是单字节长度前缀（RFC 8446 §4.2.1）。
    supported_versions = []
    versions_data = find(0x002B)
    if versions_data is not None:
        length = versions_data[0]
        supported_versions = [
            int.from_bytes(versions_data[1 + index * 2:2 + index * 2 + 1], "big")
            for index in range(length // 2)
        ]

    sni_host = None
    sni_data = find(0x0000)
    if sni_data is not None and len(sni_data) >= 5:
        name_type = sni_data[2]
        name_length = int.from_bytes(sni_data[3:5], "big")
        if name_type == 0:
            sni_host = sni_data[5:5 + name_length].decode("ascii", errors="replace")

    raw = {
        "legacy_version": f"{legacy_version:04x}",
        "session_id_hex": session_id.hex(),
        "session_id_bytes": session_id_length,
        "cipher_suites": hex16(suites),
        "grease_cipher_suites": sum(1 for value in suites if is_grease(value)),
        "compression_methods": hex8(compression),
        "extensions": [
            {"type": f"{kind:04x}", "length": len(data), "grease": is_grease(kind)}
            for kind, data in extensions
        ],
        "grease_extensions": sum(1 for kind, _ in extensions if is_grease(kind)),
        "alpn": alpn,
        "supported_groups": hex16(supported_groups),
        "key_share_groups": hex16(key_share_groups),
        "signature_algorithms": hex16(signature_algorithms),
        "supported_versions": hex16(supported_versions),
        "sni_host": sni_host,
        "has_sni": sni_data is not None,
        "has_status_request": find(0x0005) is not None,
        "has_sct": find(0x0012) is not None,
        "has_certificate_compression": find(0x001B) is not None,
        "has_alps": find(0x44CD) is not None,
        "has_encrypted_client_hello": find(0xFE0D) is not None,
    }

    suites_no_grease = sorted(value for value in suites if not is_grease(value))
    extension_types = sorted(kind for kind, _ in extensions if not is_grease(kind))
    groups_no_grease = [value for value in supported_groups if not is_grease(value)]
    key_share_no_grease = [value for value in key_share_groups if not is_grease(value)]
    versions_no_grease = [value for value in supported_versions if not is_grease(value)]
    # 字段书写顺序与 Rust 侧 json! 宏一致（便于逐行对照）。
    rust_normalized = {
        "legacy_version": f"{legacy_version:04x}",
        "session_id_bytes": len(session_id),
        "cipher_suites_sorted": hex16(suites_no_grease),
        "grease_cipher_suites": len(suites) - len(suites_no_grease),
        "grease_extensions": len(extensions) - len(extension_types),
        "compression_methods": hex8(compression),
        "extension_types_sorted": hex16(extension_types),
        "alpn": alpn,
        "supported_groups": hex16(groups_no_grease),
        "key_share_groups": hex16(key_share_no_grease),
        "signature_algorithms": hex16(signature_algorithms),
        "supported_versions": hex16(versions_no_grease),
        "has_sni": sni_data is not None,
        "has_status_request": find(0x0005) is not None,
        "has_sct": find(0x0012) is not None,
        "has_certificate_compression": find(0x001B) is not None,
        "has_alps": find(0x44CD) is not None,
        "has_encrypted_client_hello": find(0xFE0D) is not None,
    }
    # serde_json 默认把 json! 建出来的对象存成 BTreeMap，序列化时按**键名排序**；
    # 这里必须跟着排序，sha256 才能与 identity_fingerprint.rs 的常量逐位对照。
    canonical = json.dumps(rust_normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "handshake_bytes": len(handshake),
        "raw": raw,
        "rust_normalized": rust_normalized,
        "rust_normalized_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "rust_normalized_json": canonical,
    }


def sniff_client_hello(hostname: str, timeout: float) -> dict:
    """起一个只读 ClientHello 的监听（不完成握手），返回可让浏览器访问的 fixture。"""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    captured = {"hostname": hostname, "port": port}

    def serve():
        listener.settimeout(timeout)
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(timeout)
                captured["handshake"] = read_client_hello(conn)
        except OSError as cause:  # 超时或对端先关：如实记录，不造数据
            captured["error"] = str(cause)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return {
        "url": f"https://{hostname}:{port}/",
        "captured": captured,
        "join": lambda wait: thread.join(wait),
    }


def collect_client_hello(context, hostname: str, timeout: float) -> dict:
    fixture = sniff_client_hello(hostname, timeout)
    page = context.new_page()
    entry = {"hostname": hostname, "url": fixture["url"]}
    try:
        page.goto(fixture["url"], wait_until="commit", timeout=8000)
    except Exception as error:  # 监听端不完成握手，导航必然失败；指纹已经抓到
        entry["navigation_error"] = str(error).splitlines()[0]
    finally:
        page.close()
    fixture["join"](timeout)
    captured = fixture["captured"]
    handshake = captured.pop("handshake", b"")
    if handshake:
        entry.update(parse_client_hello(handshake))
    else:
        entry["error"] = captured.get("error", "没有收到 ClientHello")
    return entry


# --------------------------------------------------------------------------------------
# 第二段：HTTP/2 首帧
# --------------------------------------------------------------------------------------

FRAME_TYPES = {
    0x00: "DATA",
    0x01: "HEADERS",
    0x02: "PRIORITY",
    0x03: "RST_STREAM",
    0x04: "SETTINGS",
    0x05: "PUSH_PROMISE",
    0x06: "PING",
    0x07: "GOAWAY",
    0x08: "WINDOW_UPDATE",
    0x09: "CONTINUATION",
}

FRAME_FLAGS = {
    0x01: {0x01: "END_STREAM", 0x04: "END_HEADERS", 0x08: "PADDED", 0x20: "PRIORITY"},
    0x04: {0x01: "ACK"},
    0x06: {0x01: "ACK"},
    0x09: {0x04: "END_HEADERS"},
}

SETTINGS_NAMES = {
    0x01: "HEADER_TABLE_SIZE",
    0x02: "ENABLE_PUSH",
    0x03: "MAX_CONCURRENT_STREAMS",
    0x04: "INITIAL_WINDOW_SIZE",
    0x05: "MAX_FRAME_SIZE",
    0x06: "MAX_HEADER_LIST_SIZE",
}

# RFC 7541 附录 A 的静态表（1 起）。只用来判名字，值只在静态表里才有意义。
HPACK_STATIC_TABLE = [
    None,
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]


def hpack_read_int(block: bytes, index: int, prefix_bits: int):
    """RFC 7541 §5.1 的整数字节串。返回 (值, 新下标)。"""
    mask = (1 << prefix_bits) - 1
    value = block[index] & mask
    index += 1
    if value < mask:
        return value, index
    shift = 0
    while index < len(block):
        byte = block[index]
        index += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return value, index


def hpack_read_string(block: bytes, index: int):
    """读一个被长度前缀的字节串。返回 (原始十六进制, 可读值或 None, 新下标)。

    Huffman 位为 1 时**不猜**内容：本探针不内置 Huffman 表，值留 None 并在证据里标注。
    """
    if index >= len(block):
        return "", None, len(block)
    huffman = bool(block[index] & 0x80)
    length, index = hpack_read_int(block, index, 7)
    raw = block[index:index + length]
    index += length
    if huffman:
        return raw.hex(), None, index
    text = raw.decode("latin1") if raw and all(0x20 <= byte < 0x7F for byte in raw) else None
    return raw.hex(), text, index


def hpack_decode(block: bytes) -> dict:
    """按静态表解出头部块里的**名字顺序**；值能确定就给出，否则标注未解码。"""
    fields = []
    events = []
    index = 0
    while index < len(block):
        byte = block[index]
        if byte & 0x80:
            name_index, index = hpack_read_int(block, index, 7)
            entry = HPACK_STATIC_TABLE[name_index] if name_index < len(HPACK_STATIC_TABLE) else None
            name = entry[0] if entry else None
            value = entry[1] if entry else None
            fields.append({
                "ordinal": len(fields) + 1,
                "mode": "indexed",
                "name_index": name_index,
                "name": name,
                "name_note": None if name else f"未解码（表外索引 {name_index}）",
                "value": value or None,
                "value_decoded": bool(value),
            })
            continue
        if byte & 0x40:
            prefix, mode = 6, "literal_incremental_indexing"
        elif byte & 0x20:
            size, index = hpack_read_int(block, index, 5)
            events.append({"kind": "dynamic_table_size_update", "size": size})
            continue
        elif byte & 0x10:
            prefix, mode = 4, "literal_never_indexed"
        else:
            prefix, mode = 4, "literal_without_indexing"

        name_index, index = hpack_read_int(block, index, prefix)
        if name_index == 0:
            name_raw, name_text, index = hpack_read_string(block, index)
            name, name_note = name_text, None if name_text else f"未解码（字面名 {name_raw}）"
        else:
            name_raw = None
            entry = HPACK_STATIC_TABLE[name_index] if name_index < len(HPACK_STATIC_TABLE) else None
            name = entry[0] if entry else None
            name_note = None if name else f"未解码（表外索引 {name_index}）"
        value_raw, value_text, index = hpack_read_string(block, index)
        fields.append({
            "ordinal": len(fields) + 1,
            "mode": mode,
            "name_index": name_index,
            "name": name,
            "name_note": name_note,
            "name_raw_hex": name_raw,
            "value": value_text,
            "value_raw_hex": value_raw,
            "value_decoded": value_text is not None,
        })
    return {"fields": fields, "events": events}


def describe_frame(type_id: int, flags: int, stream_id: int, payload: bytes) -> dict:
    entry = {
        "type": FRAME_TYPES.get(type_id, f"UNKNOWN({type_id:#04x})"),
        "type_hex": f"{type_id:02x}",
        "flags": f"{flags:02x}",
        "flags_names": [
            name for bit, name in FRAME_FLAGS.get(type_id, {}).items() if flags & bit
        ],
        "stream_id": stream_id,
        "length": len(payload),
    }
    if type_id == 0x04 and not flags & 0x01:
        # 每条设置是 2 字节 id + 4 字节值；id/值的顺序原样保留。
        entry["payload_hex"] = payload.hex()
        entry["settings"] = [
            {
                "id": f"{int.from_bytes(payload[i:i + 2], 'big'):04x}",
                "name": SETTINGS_NAMES.get(int.from_bytes(payload[i:i + 2], "big")),
                "value": int.from_bytes(payload[i + 2:i + 6], "big"),
            }
            for i in range(0, len(payload) - (len(payload) % 6), 6)
        ]
    elif type_id == 0x08:
        entry["increment"] = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
    elif type_id == 0x01:
        cursor = 0
        if flags & 0x08:
            entry["padding"] = payload[0]
            cursor = 1
        if flags & 0x20:
            entry["priority"] = {
                "exclusive": bool(payload[cursor] & 0x80),
                "stream_dependency": int.from_bytes(payload[cursor:cursor + 4], "big") & 0x7FFFFFFF,
                "weight": payload[cursor + 4],
            }
            cursor += 5
        entry["header_block_hex"] = payload[cursor:].hex()
    return entry


def parse_h2_first_bytes(data: bytes) -> dict:
    """解析客户端首批发来的字节：preface + 帧序列 + 第一条 HEADERS 的头部块。"""
    result = {
        "bytes_received": len(data),
        "preface_ok": data.startswith(H2_PREFACE),
        "preface_text": H2_PREFACE.decode("ascii"),
    }
    if not result["preface_ok"]:
        result["raw_head_hex"] = data[:64].hex()
        return result

    body = data[len(H2_PREFACE):]
    raw_frames = []
    offset = 0
    while offset + 9 <= len(body):
        length = int.from_bytes(body[offset:offset + 3], "big")
        if offset + 9 + length > len(body):
            raw_frames.append(("incomplete", body[offset:offset + 3].hex(), 0, b""))
            break
        raw_frames.append((
            body[offset + 3],
            body[offset + 4],
            int.from_bytes(body[offset + 5:offset + 9], "big") & 0x7FFFFFFF,
            body[offset + 9:offset + 9 + length],
        ))
        offset += 9 + length
    result["trailing_bytes_hex"] = body[offset:].hex()

    frames = []
    index = 0
    while index < len(raw_frames):
        type_id, flags, stream_id, payload = raw_frames[index]
        if type_id == "incomplete":
            frames.append({"index": len(frames) + 1, "incomplete": True, "length_prefix_hex": flags})
            break
        entry = describe_frame(type_id, flags, stream_id, payload)
        if type_id == 0x01:
            block = bytes.fromhex(entry.pop("header_block_hex"))
            cursor = index + 1
            continuation_lengths = []
            while not flags & 0x04 and cursor < len(raw_frames):
                next_type, _, next_stream, next_payload = raw_frames[cursor]
                if next_type != 0x09 or next_stream != stream_id:
                    break
                continuation_lengths.append(len(next_payload))
                block += next_payload
                cursor += 1
            entry["continuation_lengths"] = continuation_lengths
            entry["header_block_hex"] = block.hex()
            entry["hpack"] = hpack_decode(block)
            entry["header_name_order"] = [
                field["name"] or "未解码" for field in entry["hpack"]["fields"]
            ]
            entry["pseudo_header_order"] = [
                field["name"] for field in entry["hpack"]["fields"]
                if field["name"] and field["name"].startswith(":")
            ]
            index = cursor - 1
        frames.append(entry)
        index += 1

    result["frames"] = frames
    result["frame_type_sequence"] = [frame["type"] for frame in frames]
    settings = next(
        (frame for frame in frames if frame["type"] == "SETTINGS" and frame.get("settings")),
        None,
    )
    result["settings_id_sequence"] = [
        item["id"] for item in (settings["settings"] if settings else [])
    ]
    result["settings_pairs"] = settings["settings"] if settings else []
    window_update = next((frame for frame in frames if frame["type"] == "WINDOW_UPDATE"), None)
    result["window_update"] = None if window_update is None else {
        "stream_id": window_update["stream_id"],
        "increment": window_update["increment"],
    }
    headers = next((frame for frame in frames if frame["type"] == "HEADERS"), None)
    result["first_headers"] = None if headers is None else {
        "stream_id": headers["stream_id"],
        "flags_names": headers["flags_names"],
        "pseudo_header_order": headers["pseudo_header_order"],
        "header_name_order": headers["header_name_order"],
    }
    return result


def make_certificate(temp_dir: Path, openssl: str) -> dict:
    """openssl 现生成自签证书，只落临时目录（不入库、不进 evidence）。"""
    cert = temp_dir / "h2-probe-cert.pem"
    key = temp_dir / "h2-probe-key.pem"
    info = {
        "openssl": openssl,
        "cert": str(cert),
        "key": str(key),
        "reused_existing": cert.exists() and key.exists(),
    }
    if not info["reused_existing"]:
        command = [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "2",
            "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        info["command"] = subprocess.list2cmdline(command)
        if completed.returncode != 0:
            raise RuntimeError(f"openssl 生成自签证书失败：{completed.stderr.strip()}")
    fingerprint = subprocess.run(
        [openssl, "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"],
        capture_output=True, text=True,
    )
    info["fingerprint_sha256"] = fingerprint.stdout.strip()
    return info


def start_h2_server(cert: dict, timeout: float) -> dict:
    """本地 TLS 服务：协商 h2，完成握手后只读客户端首批帧。"""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert["cert"], cert["key"])
    context.set_alpn_protocols(["h2"])
    captured = {"port": port, "url": f"https://localhost:{port}/"}

    def serve():
        listener.settimeout(timeout)
        try:
            conn, _ = listener.accept()
        except OSError as cause:
            captured["error"] = f"没有收到连接：{cause}"
            listener.close()
            return
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                captured["alpn"] = tls.selected_alpn_protocol()
                captured["tls_version"] = tls.version()
                captured["cipher"] = tls.cipher()[0] if tls.cipher() else None
                # 先发本机 SETTINGS（空表）：服务端该发的照发，之后只读不写。
                tls.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
                tls.settimeout(timeout)
                data = b""
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline and len(data) < 65536:
                    try:
                        chunk = tls.recv(4096)
                    except socket.timeout:
                        break
                    except OSError as cause:
                        captured["read_error"] = str(cause)
                        break
                    if not chunk:
                        break
                    data += chunk
                    if data.startswith(H2_PREFACE) and first_headers_complete(data):
                        break
                captured["bytes"] = data
        except ssl.SSLError as cause:  # 证书或 ALPN 协商失败：如实记录
            captured["tls_error"] = str(cause)
        except OSError as cause:
            captured["error"] = str(cause)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return {"url": captured["url"], "captured": captured, "join": lambda wait: thread.join(wait)}


def first_headers_complete(data: bytes) -> bool:
    """首批数据里是否已经有读完的第一条 HEADERS（含 CONTINUATION）。"""
    body = data[len(H2_PREFACE):]
    offset = 0
    while offset + 9 <= len(body):
        length = int.from_bytes(body[offset:offset + 3], "big")
        if offset + 9 + length > len(body):
            return False
        type_id = body[offset + 3]
        flags = body[offset + 4]
        offset += 9 + length
        if type_id == 0x09 and flags & 0x04:
            return True
        if type_id == 0x01 and flags & 0x04:
            return True
    return False


def collect_h2_first_frames(context, cert: dict, timeout: float) -> dict:
    fixture = start_h2_server(cert, timeout)
    entry = {"url": fixture["url"]}
    page = context.new_page()
    try:
        page.goto(fixture["url"], wait_until="commit", timeout=int(timeout * 1000))
    except Exception as error:  # 服务端只读首批帧就关连接，导航必然失败
        entry["navigation_error"] = str(error).splitlines()[0]
    finally:
        page.close()
    fixture["join"](timeout)
    captured = fixture["captured"]
    entry["port"] = captured["port"]
    for key in ("alpn", "tls_version", "cipher", "error", "tls_error", "read_error"):
        if key in captured:
            entry[key] = captured[key]
    data = captured.get("bytes", b"")
    if data:
        entry.update(parse_h2_first_bytes(data))
    else:
        entry.setdefault("error", "没有收到任何连接字节")
    return entry


# --------------------------------------------------------------------------------------
# 第三段：请求头全量
# --------------------------------------------------------------------------------------

ACCEPT_CH = (
    "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version, "
    "sec-ch-ua-full-version-list, sec-ch-ua-model, sec-ch-ua-platform-version"
)

HIGH_ENTROPY_HINTS = (
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-model",
)

PAGE_HTML = """<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>chrome146 reference probe</title></head>
<body>reference probe
<script>
(async () => {
  try {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const get = await fetch("/probe-get", {cache: "no-store"});
    const post = await fetch("/probe-post", {
      method: "POST",
      cache: "no-store",
      headers: {"content-type": "application/json"},
      body: JSON.stringify({probe: "chrome146"}),
    });
    window.__probeDone = {get: get.status, post: post.status};
  } catch (error) {
    window.__probeError = String(error);
  }
})();
</script>
</body>
</html>
"""


def parse_http_head(head: bytes) -> dict:
    """按收到的字节顺序解析请求行与头，重复头保留多条。"""
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin1", errors="replace")
    parts = request_line.split(" ")
    headers = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        name_text = name.decode("latin1").strip()
        if name_text.lower() in CREDENTIAL_HEADERS:
            headers.append({"name": name_text, "value": None, "redacted": True})
            continue
        headers.append({"name": name_text, "value": value.decode("latin1").strip()})
    return {
        "request_line": request_line,
        "method": parts[0] if parts else None,
        "target": parts[1] if len(parts) > 1 else None,
        "http_version": parts[2] if len(parts) > 2 else None,
        "headers": headers,
        "header_name_order": [item["name"] for item in headers],
        "credential_headers_present": [
            item["name"] for item in headers if item["name"].lower() in CREDENTIAL_HEADERS
        ],
    }


def start_header_server(timeout: float, tls_context=None, scheme: str = "http") -> dict:
    """本地 HTTP(S) 服务：导航响应带 Accept-CH，服务端按顺序记录收到的头。"""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]
    requests = []
    stop = threading.Event()

    def respond(body: bytes, content_type: str, extra: list) -> bytes:
        lines = [
            "HTTP/1.1 200 OK",
            f"content-type: {content_type}",
            f"content-length: {len(body)}",
            "cache-control: no-store",
            "connection: close",
        ]
        lines.extend(f"{name}: {value}" for name, value in extra)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body

    def handle(conn: socket.socket) -> None:
        with conn:
            conn.settimeout(timeout)
            data = b""
            try:
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError as cause:
                requests.append({"read_error": str(cause)})
                return
            head, _, rest = data.partition(b"\r\n\r\n")
            if not head:
                return
            record = parse_http_head(head)
            length_header = next(
                (item["value"] for item in record["headers"]
                 if item["name"].lower() == "content-length"),
                None,
            )
            body_length = int(length_header) if length_header and length_header.isdigit() else 0
            while len(rest) < body_length:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                rest += chunk
            record["body_bytes"] = len(rest)
            record["scheme"] = scheme
            requests.append(record)
            target = (record["target"] or "").split("?")[0]
            if target == "/":
                conn.sendall(respond(
                    PAGE_HTML.encode("utf-8"),
                    "text/html; charset=utf-8",
                    [("accept-ch", ACCEPT_CH)],
                ))
            elif target == "/favicon.ico":
                conn.sendall(respond(b"", "image/x-icon", []))
            else:
                conn.sendall(respond(b'{"ok":true}', "application/json", []))

    def serve():
        while not stop.is_set():
            try:
                listener.settimeout(0.5)
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if tls_context is not None:
                try:
                    conn = tls_context.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError) as cause:
                    requests.append({"read_error": f"TLS 握手失败：{cause}"})
                    conn.close()
                    continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def stop_server():
        stop.set()
        thread.join(timeout)

    return {"url": f"{scheme}://localhost:{port}/", "port": port,
            "requests": requests, "stop": stop_server}


def run_header_stage(context, timeout: float, cert=None, scheme: str = "http") -> dict:
    tls_context = None
    if scheme == "https":
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(cert["cert"], cert["key"])
        tls_context.set_alpn_protocols(["http/1.1"])
    server = start_header_server(timeout, tls_context, scheme)
    entry = {"url": server["url"], "scheme": scheme}
    page = context.new_page()
    try:
        page.goto(server["url"], wait_until="load", timeout=int(timeout * 1000))
        page.wait_for_function("() => window.__probeDone || window.__probeError", timeout=15000)
        entry["page_result"] = page.evaluate(
            "() => window.__probeDone || {error: window.__probeError}"
        )
    except Exception as error:
        entry["page_error"] = str(error).splitlines()[0]
    finally:
        page.close()
    server["stop"]()
    entry["requests"] = server["requests"]
    return entry


def header_stage_digest(requests: list) -> list:
    """给每条请求留一份压平记录：头顺序 + 高熵 hints 是否补发。"""
    digest = []
    for record in requests:
        names = record.get("header_name_order", [])
        digest.append({
            "method": record.get("method"),
            "target": record.get("target"),
            "header_name_order": names,
            "high_entropy_hints": {
                name: next(
                    (item["value"] for item in record.get("headers", [])
                     if item["name"].lower() == name),
                    None,
                )
                for name in HIGH_ENTROPY_HINTS
            },
            "client_hint_names": [
                name for name in names if name.lower().startswith("sec-ch-ua")
            ],
        })
    return digest


# --------------------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------------------


def write_evidence(directory: Path, name: str, payload: dict) -> Path:
    destination = directory / name
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return destination


def chrome_file_version(chrome: Path):
    completed = subprocess.run(
        [
            "powershell", "-NoProfile", "-Command",
            f"(Get-Item -LiteralPath '{chrome}').VersionInfo.ProductVersion",
        ],
        capture_output=True, text=True,
    )
    return completed.stdout.strip() or None


def file_sha256(path: Path):
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Chrome 146 版本匹配参照身份采集")
    parser.add_argument("--chrome", required=True, help="Chrome for Testing 146 的 chrome.exe 路径")
    parser.add_argument(
        "--openssl",
        default=r"C:\Program Files\Git\usr\bin\openssl.exe",
        help="用于现生成自签证书的 openssl（只落临时目录）",
    )
    parser.add_argument("--evidence", required=True, help="证据输出目录")
    parser.add_argument("--temp", default=None, help="临时目录（默认 %TEMP%\\cft-146）")
    parser.add_argument("--timeout", type=float, default=20.0, help="每段的等待上限（秒）")
    parser.add_argument("--only", default=None, help="只跑某一段：clienthello / h2 / headers")
    args = parser.parse_args()

    if args.only is not None and args.only not in ("clienthello", "h2", "headers"):
        parser.error("--only 只支持 clienthello / h2 / headers")
    chrome = Path(args.chrome)
    if not chrome.exists():
        print(f"找不到 Chrome：{chrome}")
        return 2
    evidence_dir = Path(args.evidence).resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = (
        Path(args.temp) if args.temp
        else Path.home() / "AppData" / "Local" / "Temp" / "cft-146"
    )
    temp_dir.mkdir(parents=True, exist_ok=True)
    stages = ["clienthello", "h2", "headers"] if args.only is None else [args.only]

    run = {
        "probe": "reference-chrome146-identity",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "script": str(Path(__file__).resolve()),
        "stages": stages,
        "evidence_directory": str(evidence_dir),
        "chrome_executable": str(chrome),
        "chrome_file_version": chrome_file_version(chrome),
        "chrome_exe_sha256": file_sha256(chrome),
        "chrome_zip_sha256": file_sha256(temp_dir / "chrome-win64.zip"),
        "temp_directory": str(temp_dir),
        "notes": [
            "三段全部只打本机回环，不接触任何上游。",
            "浏览器是 Chrome for Testing 146（与候选声称的版本同版本），不是 Playwright 自带的 Chromium。",
            "脚本不写死期望值：所有字段都是本次实测。",
            "Windows 版 chrome.exe 的 `--version` 不回显版本，本脚本为此不启动该命令"
            "（实测见证据目录 SUMMARY.md）；版本以 VersionInfo 与 CDP Browser.getVersion 为准。",
        ],
    }

    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(chrome),
            args=["--ignore-certificate-errors"],
        )
        try:
            run["browser_version"] = browser.version
            run["launch_args"] = ["--ignore-certificate-errors"]
            run["context_options"] = {"locale": "zh-CN", "ignore_https_errors": True}
            context = browser.new_context(locale="zh-CN", ignore_https_errors=True)

            if "clienthello" in stages:
                captures = [
                    collect_client_hello(context, hostname, args.timeout)
                    for hostname in ("127.0.0.1", "localhost")
                ]
                write_evidence(evidence_dir, "01-clienthello.json", {
                    "stage": "clienthello",
                    "browser_version": browser.version,
                    "captures": captures,
                    "notes": [
                        "监听端只读 ClientHello、不完成握手：不接触上游、不产生 HTTP 层数据。",
                        "raw 段保留密码套件与扩展的原始顺序（含 GREASE 位置）；"
                        "rust_normalized 段与 source/tests/identity_fingerprint.rs 的归一化逐字段一致。",
                        "rust_normalized_sha256 是对 rust_normalized 按 serde_json 的键名排序紧凑"
                        "序列化后的 sha256，可与该测试的 EXPECTED_FINGERPRINT_SHA256 直接对照。",
                    ],
                })

            cert = None
            if "h2" in stages or "headers" in stages:
                cert = make_certificate(temp_dir, args.openssl)
                run["certificate"] = {
                    "openssl": cert["openssl"],
                    "command": cert.get("command"),
                    "reused_existing": cert["reused_existing"],
                    "fingerprint_sha256": cert["fingerprint_sha256"],
                    "note": "证书与私钥只落临时目录，不入库、不进 evidence。",
                }

            if "h2" in stages:
                entry = collect_h2_first_frames(context, cert, args.timeout)
                write_evidence(evidence_dir, "02-h2-first-frames.json", {
                    "stage": "h2",
                    "browser_version": browser.version,
                    "capture": entry,
                    "notes": [
                        "本地 TLS 服务只协商 h2，完成握手后读客户端首批帧，随后主动关闭连接。",
                        "HPACK 只按静态表索引判名字；Huffman 编码的值与字面名如实标注未解码，不猜。",
                    ],
                })

            if "headers" in stages:
                http_entry = run_header_stage(context, args.timeout, cert, "http")
                variants = [http_entry]
                missing = not any(
                    item["high_entropy_hints"]["sec-ch-ua-platform-version"]
                    for item in header_stage_digest(http_entry["requests"])
                )
                # 高熵 hints 只在服务端声明后补发：http 段没拿到就用同一页面在 https 段复采。
                if missing:
                    https_entry = run_header_stage(context, args.timeout, cert, "https")
                    https_entry["fallback_reason"] = "http 段没有拿到 sec-ch-ua-platform-version"
                    variants.append(https_entry)
                write_evidence(evidence_dir, "03-request-headers.json", {
                    "stage": "headers",
                    "browser_version": browser.version,
                    "accept_ch": ACCEPT_CH,
                    "variants": [
                        {
                            "url": variant["url"],
                            "scheme": variant["scheme"],
                            "page_result": variant.get("page_result"),
                            "page_error": variant.get("page_error"),
                            "fallback_reason": variant.get("fallback_reason"),
                            "requests": variant["requests"],
                            "digest": header_stage_digest(variant["requests"]),
                        }
                        for variant in variants
                    ],
                    "notes": [
                        "页面只做同源 fetch（GET 一次、POST 一次，POST 由页面显式设"
                        " content-type: application/json）。",
                        "头顺序是服务端按收到的原始字节记录的；证据里 Cookie/Authorization 只记名字不记值。",
                    ],
                })
        finally:
            browser.close()

    run["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    write_evidence(evidence_dir, "00-run.json", run)
    print(f"证据已写入 {evidence_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

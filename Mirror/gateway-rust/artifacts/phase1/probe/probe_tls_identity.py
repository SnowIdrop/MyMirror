# -*- coding: utf-8 -*-
"""抓真实 Chromium 的 ClientHello，用来与候选网关自己的传输画像对照。

只打本机回环：起一个不完成 TLS 握手的裸 TCP 监听，让浏览器连上去，
把 ClientHello 原始字节抓下来，再按与 `tests/identity_fingerprint.rs`
完全相同的规则归一化（去掉 random、会话 id、GREASE 值与扩展顺序），
这样两边的归一化结果可以逐字段对照。

不做的事情：不完成握手、不发任何真实上游请求、不写 Cookie 或凭据。
"""

import argparse
import json
import socket
import struct
import threading
import time
from pathlib import Path

GREASE = {0xA0A + i * 0x1010 for i in range(16)}


def is_grease(value: int) -> bool:
    """GREASE 值形如 0x?a?a：低两字节相同、低半字节固定为 a。"""
    return value in GREASE


def read_client_hello(conn: socket.socket) -> bytes:
    """按 TLS 记录读到一条完整握手消息。"""
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


def normalize_client_hello(handshake: bytes) -> dict:
    """与 Rust 侧同一套归一化规则。"""
    if not handshake or handshake[0] != 0x01:
        raise ValueError("不是 ClientHello")
    offset = 4
    legacy_version = int.from_bytes(handshake[offset:offset + 2], "big")
    offset += 2 + 32
    session_id_length = handshake[offset]
    offset += 1 + session_id_length
    suites_length = int.from_bytes(handshake[offset:offset + 2], "big")
    offset += 2
    suites = [
        int.from_bytes(handshake[offset + i * 2:offset + i * 2 + 2], "big")
        for i in range(suites_length // 2)
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
            int.from_bytes(data[prefix + i * 2:prefix + i * 2 + 2], "big")
            for i in range(length // 2)
        ]

    alpn_data = find(0x0010)
    alpn = []
    if alpn_data is not None:
        cursor = 2
        while cursor < len(alpn_data):
            length = alpn_data[cursor]
            alpn.append(alpn_data[cursor + 1:cursor + 1 + length].decode("latin1"))
            cursor += 1 + length
    key_share_groups = []
    key_share_data = find(0x0033)
    if key_share_data is not None:
        cursor = 2
        end = 2 + int.from_bytes(key_share_data[:2], "big")
        while cursor < end:
            group = int.from_bytes(key_share_data[cursor:cursor + 2], "big")
            length = int.from_bytes(key_share_data[cursor + 2:cursor + 4], "big")
            key_share_groups.append(group)
            cursor += 4 + length

    suites_sorted = sorted(value for value in suites if not is_grease(value))
    extension_types = sorted(kind for kind, _ in extensions if not is_grease(kind))
    supported_groups = [value for value in vector(0x000A, 2) if not is_grease(value)]
    key_share_groups = [value for value in key_share_groups if not is_grease(value)]
    supported_versions = [value for value in vector(0x002B, 1) if not is_grease(value)]
    return {
        "legacy_version": f"{legacy_version:04x}",
        "session_id_bytes": session_id_length,
        "cipher_suites_sorted": [f"{value:04x}" for value in suites_sorted],
        "grease_cipher_suites": len(suites) - len(suites_sorted),
        "grease_extensions": len(extensions) - len(extension_types),
        "compression_methods": [f"{value:02x}" for value in compression],
        "extension_types_sorted": [f"{kind:04x}" for kind in extension_types],
        "alpn": alpn,
        "supported_groups": [f"{value:04x}" for value in supported_groups],
        "key_share_groups": [f"{value:04x}" for value in key_share_groups],
        "signature_algorithms": [f"{value:04x}" for value in vector(0x000D, 2)],
        "supported_versions": [f"{value:04x}" for value in supported_versions],
        "has_sni": any(kind == 0x0000 for kind, _ in extensions),
        "has_status_request": any(kind == 0x0005 for kind, _ in extensions),
        "has_sct": any(kind == 0x0012 for kind, _ in extensions),
        "has_certificate_compression": any(kind == 0x001B for kind, _ in extensions),
        "has_alps": any(kind == 0x44CD for kind, _ in extensions),
        "has_encrypted_client_hello": any(kind == 0xFE0D for kind, _ in extensions),
    }


def sniff(hostname: str, timeout: float) -> dict:
    """起一个只读 ClientHello 的监听，让浏览器连一次。"""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    captured: dict = {"hostname": hostname, "port": port}

    def serve():
        listener.settimeout(timeout)
        try:
            conn, _ = listener.accept()
            with conn:
                captured["handshake"] = read_client_hello(conn)
        except OSError as cause:  # 超时：浏览器没连上
            captured["error"] = str(cause)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return {"port": port, "url": f"https://{hostname}:{port}/", "join": thread.join, "captured": captured}


def main() -> int:
    parser = argparse.ArgumentParser(description="抓真实 Chromium 的 ClientHello 指纹")
    parser.add_argument("--evidence", default=None, help="证据输出路径（默认写到 probe/evidence/）")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chromium")
        try:
            context = browser.new_context(locale="zh-CN", ignore_https_errors=True)
            version = browser.version
            for hostname in ("127.0.0.1", "localhost"):
                fixture = sniff(hostname, args.timeout)
                page = context.new_page()
                try:
                    page.goto(fixture["url"], wait_until="commit", timeout=8000)
                except Exception:
                    # 监听端不完成握手，导航必然失败；指纹已经抓到。
                    pass
                finally:
                    page.close()
                fixture["join"](args.timeout)
                captured = fixture["captured"]
                handshake = captured.pop("handshake", b"")
                entry = {
                    "hostname": hostname,
                    "url_host": fixture["url"].split("/")[2].split(":")[0],
                    "handshake_bytes": len(handshake),
                }
                if handshake:
                    entry["fingerprint"] = normalize_client_hello(handshake)
                else:
                    entry["error"] = captured.get("error", "没有收到 ClientHello")
                results.append(entry)
        finally:
            browser.close()

    evidence = {
        "probe": "browser-tls-identity",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "browser_channel": "chromium",
        "browser_version": version,
        "captures": results,
        "notes": [
            "只打本机回环，不接触任何真实上游；证据不含凭据。",
            "监听端故意不完成 TLS 握手，因此没有 HTTP/2 首帧；H2 层对照见 COMPATIBILITY.md 的残余差异。",
            "归一化规则与 tests/identity_fingerprint.rs 一致：去掉 random、会话 id、GREASE 与扩展顺序。",
        ],
    }
    destination = Path(args.evidence) if args.evidence else (
        Path(__file__).resolve().parent / "evidence" /
        f"tls-identity-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"证据已写入 {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

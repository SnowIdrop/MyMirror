"""cfbypass 容器内的只读身份探针。

用途：把这一跳的传输层身份采成可逐字段比对的 JSON，供掌握 Docker 的环境与网关的
wreq/btls Chrome146 仿真对照（ClientHello 归一化摘要 + HTTP/2 首帧摘要）。

做法：
- 用 openssl 现场生成一次性自签证书到临时目录，退出即删，不入库；
- 用同一个系统 chromium（CF_BYPASS_BROWSER_PATH，默认 /usr/bin/chromium）打两回
  127.0.0.1 上的临时回环监听：
  1. 第一回只收 ClientHello，随后断开（浏览器握手失败属预期）；
  2. 第二回完成自签 TLS 握手（ALPN 只要 h2），收 HTTP/2 连接前言、客户端帧顺序、
     SETTINGS 顺序与首个请求的伪头顺序；
- 结果写 stdout，或用 --out 落 JSON 文件。

边界：
- 不新开对外端口、不加 HTTP 接口：两次监听都绑 127.0.0.1 的临时端口，采集完即关；
- 只做只读采集，不读数据库、不落 Cookie/令牌，也不访问本机以外的地址；
- 需要镜像内存在 openssl 与系统 chromium（见 Dockerfile）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

DEFAULT_BROWSER_PATH = "/usr/bin/chromium"

# 首帧摘要最多看的客户端帧数：SETTINGS/WINDOW_UPDATE/HEADERS 足够刻画首帧形状。
FRAME_LIMIT = 8

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_NAMES = {
    0x0: "DATA",
    0x1: "HEADERS",
    0x2: "PRIORITY",
    0x3: "RST_STREAM",
    0x4: "SETTINGS",
    0x5: "PUSH_PROMISE",
    0x6: "PING",
    0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE",
    0x9: "CONTINUATION",
}

SETTINGS_NAMES = {
    0x1: "HEADER_TABLE_SIZE",
    0x2: "ENABLE_PUSH",
    0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE",
    0x5: "MAX_FRAME_SIZE",
    0x6: "MAX_HEADER_LIST_SIZE",
    0x8: "ENABLE_CONNECT_PROTOCOL",
    0x9: "NO_RFC7540_PRIORITIES",
}

# HPACK 静态表里可以确定名字的条目（1-61）；只用来给头字段名字定位，不解值。
STATIC_NAMES = {
    1: ":authority",
    2: ":method",
    3: ":method",
    4: ":path",
    5: ":path",
    6: ":scheme",
    7: ":scheme",
    8: ":status",
    9: ":status",
    10: ":status",
    11: ":status",
    12: ":status",
    13: ":status",
    14: ":status",
    15: "accept-charset",
    16: "accept-encoding",
    17: "accept-language",
    18: "accept-ranges",
    19: "accept",
    20: "access-control-allow-origin",
    21: "age",
    22: "allow",
    23: "authorization",
    24: "cache-control",
    25: "content-disposition",
    26: "content-encoding",
    27: "content-language",
    28: "content-length",
    29: "content-location",
    30: "content-range",
    31: "content-type",
    32: "cookie",
    33: "date",
    34: "etag",
    35: "expect",
    36: "expires",
    37: "from",
    38: "host",
    39: "if-match",
    40: "if-modified-since",
    41: "if-none-match",
    42: "if-range",
    43: "if-unmodified-since",
    44: "last-modified",
    45: "link",
    46: "location",
    47: "max-forwards",
    48: "proxy-authenticate",
    49: "proxy-authorization",
    50: "range",
    51: "referer",
    52: "refresh",
    53: "retry-after",
    54: "server",
    55: "set-cookie",
    56: "strict-transport-security",
    57: "transfer-encoding",
    58: "user-agent",
    59: "vary",
    60: "via",
    61: "www-authenticate",
}

SETTINGS_FRAME = 0x4
HEADERS_FRAME = 0x1
WINDOW_UPDATE_FRAME = 0x8
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4


class ProbeError(RuntimeError):
    """采集或解析失败：探针如实上报，不猜测缺失字段。"""


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE 值：两个字节相同且低半字节为 0xa。"""
    return (value & 0x0F0F) == 0x0A0A


def read_exact(stream, size: int, timeout: float) -> bytes:
    """按字节读满；对端提前关闭或超时都如实报错。"""
    stream.settimeout(timeout)
    data = b""
    deadline = time.monotonic() + timeout
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError(f"读取 {size} 字节超时（已收到 {len(data)} 字节）")
        stream.settimeout(remaining)
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise ProbeError(f"连接提前关闭（需要 {size} 字节，已收到 {len(data)} 字节）")
        data += chunk
    return data


def client_hello_body(raw: bytes) -> bytes:
    """从原始 TLS 记录里取出 ClientHello 握手体（允许跨记录分片）。"""
    messages = b""
    index = 0
    while index + 5 <= len(raw):
        record_type = raw[index]
        length = int.from_bytes(raw[index + 3 : index + 5], "big")
        payload = raw[index + 5 : index + 5 + length]
        if len(payload) < length:
            raise ProbeError("ClientHello 的 TLS 记录不完整")
        if record_type == 0x16:
            messages += payload
        index += 5 + length
    if len(messages) < 4 or messages[0] != 0x01:
        raise ProbeError("没有采到 ClientHello 握手消息")
    handshake_len = int.from_bytes(messages[1:4], "big")
    body = messages[4 : 4 + handshake_len]
    if len(body) < handshake_len:
        raise ProbeError("ClientHello 握手消息被截断")
    return body


def hello_complete(raw: bytes) -> bool:
    try:
        client_hello_body(raw)
    except ProbeError:
        return False
    return True


def parse_client_hello(raw: bytes) -> dict[str, object]:
    """把 ClientHello 归一化成摘要：套件与扩展保留原始顺序，记录 GREASE 位置。"""
    body = client_hello_body(raw)
    legacy_version = int.from_bytes(body[0:2], "big")
    offset = 34  # legacy_version(2) + random(32)
    session_id_len = body[offset]
    offset += 1 + session_id_len
    cipher_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    cipher_suites = [
        int.from_bytes(body[index : index + 2], "big") for index in range(offset, offset + cipher_len, 2)
    ]
    offset += cipher_len
    compression_len = body[offset]
    offset += 1
    compression_methods = list(body[offset : offset + compression_len])
    offset += compression_len
    extensions_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    extension_end = offset + extensions_len

    extension_types: list[int] = []
    extension_payloads: dict[int, bytes] = {}
    while offset < extension_end:
        extension_type = int.from_bytes(body[offset : offset + 2], "big")
        extension_size = int.from_bytes(body[offset + 2 : offset + 4], "big")
        payload = body[offset + 4 : offset + 4 + extension_size]
        if len(payload) < extension_size:
            raise ProbeError(f"扩展 0x{extension_type:04x} 被截断")
        extension_types.append(extension_type)
        extension_payloads[extension_type] = payload
        offset += 4 + extension_size

    supported_versions = parse_version_list(extension_payloads.get(43, b""))
    supported_groups = parse_u16_list(extension_payloads.get(10, b""))
    signature_algorithms = parse_u16_list(extension_payloads.get(13, b""))
    alpn = parse_alpn(extension_payloads.get(16, b""))
    key_share_groups = parse_key_share_groups(extension_payloads.get(51, b""))

    summary: dict[str, object] = {
        "legacy_version": hex16(legacy_version),
        "session_id_len": session_id_len,
        "cipher_suites": [hex16(value) for value in cipher_suites],
        "compression_methods": compression_methods,
        "extensions": [hex16(value) for value in extension_types],
        "extension_lengths": {hex16(value): len(extension_payloads[value]) for value in extension_types},
        "supported_versions": [hex16(value) for value in supported_versions],
        "tls13": 0x0304 in supported_versions,
        "supported_groups": [hex16(value) for value in supported_groups],
        "key_share_groups": [hex16(value) for value in key_share_groups],
        "signature_algorithms": [hex16(value) for value in signature_algorithms],
        "alpn": alpn,
        "grease_positions": {
            "cipher_suites": positions(cipher_suites),
            "extensions": positions(extension_types),
            "supported_versions": positions(supported_versions),
            "supported_groups": positions(supported_groups),
            "signature_algorithms": positions(signature_algorithms),
            "key_share_groups": positions(key_share_groups),
        },
    }
    return with_summary_hash(summary)


def parse_u16_list(payload: bytes) -> list[int]:
    if len(payload) < 2:
        return []
    length = int.from_bytes(payload[0:2], "big")
    return [int.from_bytes(payload[index : index + 2], "big") for index in range(2, min(2 + length, len(payload)), 2)]


def parse_version_list(payload: bytes) -> list[int]:
    """`supported_versions`（43）的向量长度是 1 字节，与其它 u16 列表不同。"""
    if len(payload) < 1:
        return []
    length = payload[0]
    return [int.from_bytes(payload[index : index + 2], "big") for index in range(1, min(1 + length, len(payload)), 2)]


def parse_alpn(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    length = int.from_bytes(payload[0:2], "big")
    protocols: list[str] = []
    index = 2
    end = min(2 + length, len(payload))
    while index < end:
        size = payload[index]
        index += 1
        protocols.append(payload[index : index + size].decode("ascii", "replace"))
        index += size
    return protocols


def parse_key_share_groups(payload: bytes) -> list[int]:
    if len(payload) < 2:
        return []
    length = int.from_bytes(payload[0:2], "big")
    groups: list[int] = []
    index = 2
    end = min(2 + length, len(payload))
    while index + 4 <= end:
        groups.append(int.from_bytes(payload[index : index + 2], "big"))
        key_len = int.from_bytes(payload[index + 2 : index + 4], "big")
        index += 4 + key_len
    return groups


def positions(values: list[int]) -> list[int]:
    return [index for index, value in enumerate(values) if is_grease(value)]


def hex16(value: int) -> str:
    return f"0x{value:04x}"


def with_summary_hash(summary: dict[str, object]) -> dict[str, object]:
    """附一个归一化摘要的 sha256，便于与网关侧参照一键比对。"""
    canonical = json.dumps(summary, sort_keys=True, ensure_ascii=False)
    summary["summary_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return summary


def hpack_int(block: bytes, index: int, prefix_bits: int) -> tuple[int, int]:
    mask = 0xFF >> (8 - prefix_bits)
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


def hpack_skip_string(block: bytes, index: int) -> int:
    """跳过字符串字面量：长度前缀不受 Huffman 编码影响，因此不需要 Huffman 表。"""
    length, index = hpack_int(block, index, 7)
    return index + length


def hpack_name(index: int) -> str:
    if index == 0:
        return "<literal-name>"
    return STATIC_NAMES.get(index, f"<dynamic:{index}>")


def decode_hpack_names(block: bytes) -> list[str]:
    """只解出头字段名字，值的字节按长度跳过。

    首帧摘要只要伪头顺序，而伪头名字必然来自静态表（HTTP/2 禁止把伪头写进动态表），
    所以这里不需要 Huffman 表；普通头的字面量名字记成 <literal-name>。
    """
    names: list[str] = []
    index = 0
    while index < len(block):
        first = block[index]
        if first & 0x80:
            value, index = hpack_int(block, index, 7)
            names.append(hpack_name(value))
            continue
        if first & 0x40:
            value, index = hpack_int(block, index, 6)
        elif first & 0x20:
            _, index = hpack_int(block, index, 5)
            continue
        else:
            value, index = hpack_int(block, index, 4)
        names.append(hpack_name(value))
        if value == 0:
            index = hpack_skip_string(block, index)
        index = hpack_skip_string(block, index)
    return names


def parse_settings(payload: bytes) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for index in range(0, len(payload) - 5, 6):
        setting_id = int.from_bytes(payload[index : index + 2], "big")
        entries.append(
            {
                "id": hex16(setting_id),
                "name": SETTINGS_NAMES.get(setting_id, "UNKNOWN"),
                "value": int.from_bytes(payload[index + 2 : index + 6], "big"),
            }
        )
    return entries


def capture_client_hello(conn: socket.socket, timeout: float) -> dict[str, object]:
    conn.settimeout(timeout)
    raw = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        raw += chunk
        if hello_complete(raw):
            break
    return parse_client_hello(raw)


def capture_http2(conn: socket.socket, ssl_context: ssl.SSLContext, timeout: float) -> dict[str, object]:
    conn.settimeout(timeout)  # 握手在 wrap_socket 内完成，同样受 --timeout 约束
    tls = ssl_context.wrap_socket(conn, server_side=True)
    result: dict[str, object] = {
        "alpn_selected": tls.selected_alpn_protocol(),
        "frame_sequence": [],
        "frames": [],
        "settings": [],
        "request_pseudo_header_order": [],
        "request_header_names_resolved": [],
    }
    frames: list[dict[str, object]] = []
    try:
        # 先发一个空 SETTINGS，让对端按正常 HTTP/2 时序继续发请求帧。
        tls.sendall(b"\x00\x00\x00" + bytes([SETTINGS_FRAME]) + b"\x00\x00\x00\x00\x00")
        preface = read_exact(tls, len(H2_PREFACE), timeout)
        if preface != H2_PREFACE:
            raise ProbeError(f"收到的不是 HTTP/2 连接前言: {preface!r}")
        while len(frames) < FRAME_LIMIT:
            header = read_exact(tls, 9, timeout)
            length = int.from_bytes(header[0:3], "big")
            frame_type = header[3]
            flags = header[4]
            stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            payload = read_exact(tls, length, timeout) if length else b""
            entry: dict[str, object] = {
                "type": FRAME_NAMES.get(frame_type, f"0x{frame_type:02x}"),
                "flags": flags,
                "length": length,
                "stream_id": stream_id,
            }
            if frame_type == SETTINGS_FRAME and not flags & FLAG_ACK:
                result["settings"] = parse_settings(payload)
            elif frame_type == WINDOW_UPDATE_FRAME and length == 4:
                entry["increment"] = int.from_bytes(payload, "big") & 0x7FFFFFFF
            frames.append(entry)
            if frame_type == HEADERS_FRAME:
                entry["end_headers"] = bool(flags & FLAG_END_HEADERS)
                # 头块被 CONTINUATION 拆开时这一帧只是片段，解出来的名字没有意义。
                if flags & FLAG_END_HEADERS:
                    names = decode_hpack_names(payload)
                    result["request_pseudo_header_order"] = [name for name in names if name.startswith(":")]
                    result["request_header_names_resolved"] = names
                break
    except ProbeError as error:
        result["error"] = str(error)
    finally:
        tls.close()
    result["frames"] = frames
    result["frame_sequence"] = [frame["type"] for frame in frames]
    return result


class LoopbackProbe:
    """127.0.0.1 上的临时监听：只接浏览器自己的连接，采集完立即关闭。"""

    def __init__(self, handler: Callable[[socket.socket], dict[str, object]], timeout: float) -> None:
        self._handler = handler
        self._timeout = timeout
        self._result: dict[str, object] | None = None
        self._error: str | None = None
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, name="cfbypass-probe", daemon=True)

    @property
    def port(self) -> int:
        return int(self._listener.getsockname()[1])

    def __enter__(self) -> LoopbackProbe:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _serve(self) -> None:
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline and self._result is None:
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                try:
                    self._result = self._handler(conn)
                except Exception as error:  # 采集失败要如实上报，不能中断整个探针
                    self._error = f"{type(error).__name__}: {error}"

    def wait(self) -> dict[str, object]:
        self._thread.join(self._timeout + 1.0)
        if self._result is not None:
            return self._result
        return {"error": self._error or f"{self._timeout:.1f}s 内没有采到浏览器连接"}

    def close(self) -> None:
        self._listener.close()


def generate_certificate(directory: Path) -> tuple[Path, Path]:
    """用 openssl 现场生成一次性自签证书（临时目录，进程退出即删）。"""
    key_path = directory / "probe-key.pem"
    cert_path = directory / "probe-cert.pem"
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as error:
        raise ProbeError(f"openssl 生成证书失败: {error.stderr.decode('utf-8', 'replace').strip()}") from error
    return cert_path, key_path


def request_loopback(page, url: str, timeout: float) -> None:
    """让 chromium 去连回环探针；探针不回响应，页面加载失败属于预期结果。"""
    try:
        page.goto(url, timeout=timeout * 1000, wait_until="commit")
    except PlaywrightError:
        pass


def probe_client_hello(page, timeout: float) -> dict[str, object]:
    """第一回：只收 ClientHello，浏览器随后必然握手失败。"""

    def handler(conn: socket.socket) -> dict[str, object]:
        return capture_client_hello(conn, timeout)

    with LoopbackProbe(handler, timeout) as probe:
        request_loopback(page, f"https://127.0.0.1:{probe.port}/", timeout)
        return probe.wait()


def probe_http2(page, cert_path: Path, key_path: Path, timeout: float) -> dict[str, object]:
    """第二回：完成自签 TLS 握手（ALPN 只留 h2），收 HTTP/2 首帧。"""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ssl_context.set_alpn_protocols(["h2"])

    def handler(conn: socket.socket) -> dict[str, object]:
        return capture_http2(conn, ssl_context, timeout)

    with LoopbackProbe(handler, timeout) as probe:
        request_loopback(page, f"https://127.0.0.1:{probe.port}/", timeout)
        return probe.wait()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="cfbypass 容器内只读身份探针（ClientHello + HTTP/2 首帧）")
    parser.add_argument(
        "--browser-path",
        default=os.getenv("CF_BYPASS_BROWSER_PATH") or DEFAULT_BROWSER_PATH,
        help=f"系统 chromium 可执行文件（默认取 CF_BYPASS_BROWSER_PATH，否则 {DEFAULT_BROWSER_PATH}）",
    )
    parser.add_argument("--out", default="", help="JSON 输出路径；缺省写 stdout")
    parser.add_argument("--timeout", type=float, default=5.0, help="单次采集的等待上限（秒，默认 5）")
    return parser.parse_args(argv)


def collect(browser_path: str, timeout: float) -> dict[str, object]:
    result: dict[str, object] = {"probe": "cfbypass-identity", "browser_path": browser_path}
    with tempfile.TemporaryDirectory(prefix="cfbypass-probe-") as tmp_dir:
        cert_path, key_path = generate_certificate(Path(tmp_dir))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=browser_path,
                headless=True,
                chromium_sandbox=False,
            )
            try:
                result["browser_version"] = browser.version()
                # 自签证书不参与身份比对，这里显式忽略证书错误以便完成握手。
                context = browser.new_context(ignore_https_errors=True, locale="zh-CN")
                page = context.new_page()
                result["client_hello"] = probe_client_hello(page, timeout)
                result["http2"] = probe_http2(page, cert_path, key_path, timeout)
            finally:
                browser.close()
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = collect(args.browser_path, args.timeout)
    except ProbeError as error:
        print(f"探针失败: {error}", file=sys.stderr)
        return 1
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
        print(f"探针结果已写入 {args.out}")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())

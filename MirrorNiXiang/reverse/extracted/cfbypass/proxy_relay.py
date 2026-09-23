from __future__ import annotations

import base64
import ipaddress
import select
import socket
import socketserver
import ssl
import struct
import threading
from urllib.parse import unquote, urlparse


CONNECT_TIMEOUT_SECONDS = 10
HEADER_LIMIT_BYTES = 64 * 1024


class ProxyRelayError(RuntimeError):
    pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ProxyRelayError("代理连接意外关闭")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProxyRelayError("代理请求头不完整")
        data.extend(chunk)
        if len(data) > HEADER_LIMIT_BYTES:
            raise ProxyRelayError("代理请求头过大")
    end = data.index(b"\r\n\r\n") + 4
    return bytes(data[:end]), bytes(data[end:])


def _parse_connect_authority(authority: str) -> tuple[str, int]:
    value = authority.strip()
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or closing + 2 > len(value) or value[closing + 1] != ":":
            raise ProxyRelayError("CONNECT IPv6 地址格式无效")
        host = value[1:closing]
        port_text = value[closing + 2 :]
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            raise ProxyRelayError("CONNECT 地址缺少端口")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ProxyRelayError("CONNECT 端口无效") from error
    if not host or not 1 <= port <= 65535:
        raise ProxyRelayError("CONNECT 地址无效")
    return host, port


class _RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.relay.handle_client(self.request)  # type: ignore[attr-defined]


class AuthenticatedProxyRelay:
    """Expose an unauthenticated loopback HTTP CONNECT proxy for Chromium."""

    def __init__(self, upstream_proxy_url: str):
        parsed = urlparse(upstream_proxy_url)
        if parsed.scheme not in {"http", "https", "socks5", "socks5h"}:
            raise ProxyRelayError("不支持的上游代理协议")
        if not parsed.hostname:
            raise ProxyRelayError("上游代理缺少主机名")

        default_ports = {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080}
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or default_ports[parsed.scheme]
        self.username = unquote(parsed.username or "")
        self.password = unquote(parsed.password or "")
        self._server: _RelayServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def proxy_url(self) -> str:
        if self._server is None:
            raise ProxyRelayError("本地代理转发器尚未启动")
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> None:
        if self._server is not None:
            return
        server = _RelayServer(("127.0.0.1", 0), _RelayHandler)
        server.relay = self  # type: ignore[attr-defined]
        thread = threading.Thread(
            target=server.serve_forever,
            name="cfbypass-proxy-relay",
            daemon=True,
        )
        thread.start()
        self._server = server
        self._thread = thread

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2)

    def handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        response_started = False
        try:
            client.settimeout(CONNECT_TIMEOUT_SECONDS)
            request_head, buffered = _read_headers(client)
            request_line = request_head.split(b"\r\n", 1)[0].decode(
                "latin1", errors="replace"
            )
            parts = request_line.split()
            if len(parts) != 3 or parts[0].upper() != "CONNECT":
                client.sendall(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return
            target_host, target_port = _parse_connect_authority(parts[1])
            upstream = self._connect_upstream(target_host, target_port)
            client.sendall(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: cfbypass-relay\r\n\r\n"
            )
            response_started = True
            if buffered:
                upstream.sendall(buffered)
            client.settimeout(None)
            upstream.settimeout(None)
            self._tunnel(client, upstream)
        except (OSError, ProxyRelayError):
            if not response_started:
                try:
                    client.sendall(
                        b"HTTP/1.1 502 Bad Gateway\r\n"
                        b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                except OSError:
                    pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    def _connect_upstream(self, target_host: str, target_port: int) -> socket.socket:
        if self.scheme in {"http", "https"}:
            return self._connect_http_proxy(target_host, target_port)
        return self._connect_socks5_proxy(target_host, target_port)

    def _connect_http_proxy(self, target_host: str, target_port: int) -> socket.socket:
        upstream = socket.create_connection(
            (self.host, self.port), timeout=CONNECT_TIMEOUT_SECONDS
        )
        try:
            if self.scheme == "https":
                upstream = ssl.create_default_context().wrap_socket(
                    upstream, server_hostname=self.host
                )
            authority_host = f"[{target_host}]" if ":" in target_host else target_host
            authority = f"{authority_host}:{target_port}"
            headers = [
                f"CONNECT {authority} HTTP/1.1",
                f"Host: {authority}",
                "Proxy-Connection: keep-alive",
            ]
            if self.username or self.password:
                credentials = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode("ascii")
                headers.append(f"Proxy-Authorization: Basic {credentials}")
            upstream.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("latin1"))
            response_head, _buffered = _read_headers(upstream)
            status_line = response_head.split(b"\r\n", 1)[0].decode(
                "latin1", errors="replace"
            )
            status_parts = status_line.split()
            if len(status_parts) < 2 or not status_parts[1].isdigit():
                raise ProxyRelayError("HTTP 代理返回了无效响应")
            if not 200 <= int(status_parts[1]) < 300:
                raise ProxyRelayError("HTTP 代理拒绝 CONNECT 请求")
            return upstream
        except Exception:
            upstream.close()
            raise

    def _connect_socks5_proxy(self, target_host: str, target_port: int) -> socket.socket:
        upstream = socket.create_connection(
            (self.host, self.port), timeout=CONNECT_TIMEOUT_SECONDS
        )
        try:
            requires_auth = bool(self.username or self.password)
            methods = b"\x02" if requires_auth else b"\x00"
            upstream.sendall(b"\x05\x01" + methods)
            version, method = _recv_exact(upstream, 2)
            if version != 5 or method == 0xFF:
                raise ProxyRelayError("SOCKS5 代理没有可用认证方式")
            if method == 0x02:
                username = self.username.encode()
                password = self.password.encode()
                if len(username) > 255 or len(password) > 255:
                    raise ProxyRelayError("SOCKS5 用户名或密码过长")
                upstream.sendall(
                    b"\x01"
                    + bytes([len(username)])
                    + username
                    + bytes([len(password)])
                    + password
                )
                auth_version, auth_status = _recv_exact(upstream, 2)
                if auth_version != 1 or auth_status != 0:
                    raise ProxyRelayError("SOCKS5 用户名密码认证失败")
            elif method != 0x00:
                raise ProxyRelayError("SOCKS5 代理选择了未知认证方式")

            address = self._encode_socks_target(target_host, target_port)
            upstream.sendall(b"\x05\x01\x00" + address)
            version, reply, _reserved, address_type = _recv_exact(upstream, 4)
            if version != 5 or reply != 0:
                raise ProxyRelayError("SOCKS5 代理连接目标失败")
            if address_type == 1:
                _recv_exact(upstream, 4)
            elif address_type == 3:
                _recv_exact(upstream, _recv_exact(upstream, 1)[0])
            elif address_type == 4:
                _recv_exact(upstream, 16)
            else:
                raise ProxyRelayError("SOCKS5 代理返回未知地址类型")
            _recv_exact(upstream, 2)
            return upstream
        except Exception:
            upstream.close()
            raise

    def _encode_socks_target(self, target_host: str, target_port: int) -> bytes:
        if self.scheme == "socks5h":
            host = target_host.encode("idna")
            if len(host) > 255:
                raise ProxyRelayError("SOCKS5H 目标主机名过长")
            return b"\x03" + bytes([len(host)]) + host + struct.pack("!H", target_port)

        try:
            address = ipaddress.ip_address(target_host)
        except ValueError:
            records = socket.getaddrinfo(
                target_host,
                target_port,
                type=socket.SOCK_STREAM,
            )
            if not records:
                raise ProxyRelayError("SOCKS5 目标主机解析失败")
            target_host = records[0][4][0]
            address = ipaddress.ip_address(target_host)
        address_type = b"\x01" if address.version == 4 else b"\x04"
        return address_type + address.packed + struct.pack("!H", target_port)

    @staticmethod
    def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        while True:
            readable, _, _ = select.select(sockets, [], [], 30)
            if not readable:
                continue
            for source in readable:
                data = source.recv(64 * 1024)
                if not data:
                    return
                destination = upstream if source is client else client
                destination.sendall(data)

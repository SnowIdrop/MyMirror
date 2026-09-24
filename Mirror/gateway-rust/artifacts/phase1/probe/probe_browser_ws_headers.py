# -*- coding: utf-8 -*-
"""抓真实 Chromium 发起同源 WebSocket 握手时的完整请求头（只打本机回环）。

用途：`server/chat_ws.rs` 的 `upstream_headers` 目前只转发
`accept-language`/`sec-websocket-protocol`，真浏览器实际还会带
`accept-encoding`/`cache-control`/`pragma` 等头。要按证据补齐而不是猜，
就需要在服务端记录浏览器真实发出的握手头。

只读：本地回环 echo 上游，不接触任何真实上游，不写 Cookie 或凭据。
"""

import argparse
import base64
import hashlib
import http.server
import json
import socket
import socketserver
import threading
import time
from pathlib import Path

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>ws header probe</title></head>
<body>
<script>
window.runProbe = () => new Promise((resolve) => {
  const socket = new WebSocket('ws://' + location.host + '/ws');
  socket.onopen = () => { window.__wsState = 'open'; };
  socket.onclose = () => { window.__wsState = 'closed'; resolve(true); };
  socket.onerror = () => { window.__wsState = 'error'; resolve(true); };
  setTimeout(() => resolve(true), 3000);
});
</script>
</body></html>
"""

RECORDED = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        """静音默认访问日志。"""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
        if self.path == "/":
            payload = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/ws" and self.headers.get("upgrade", "").lower() == "websocket":
            RECORDED.append({
                "handshake": {
                    "request_line": f"{self.command} {self.path} {self.request_version}",
                    "headers": [
                        [name.lower(), value]
                        for name, value in self.headers.items()
                        if name.lower() not in ("cookie", "authorization")
                    ],
                    "header_names": [name.lower() for name, _ in self.headers.items()],
                },
            })
            key = self.headers.get("sec-websocket-key", "")
            accept = base64.b64encode(
                hashlib.sha1((key + WS_GUID).encode()).digest()
            ).decode()
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            # 回一帧关闭帧后断开，避免探针悬住。
            try:
                self.connection.sendall(b"\x88\x00")
            except OSError:
                pass
            self.close_connection = True
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser(description="抓真 Chromium 的 WebSocket 握手头")
    parser.add_argument("--evidence", default=None, help="证据输出路径")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    state = None
    user_agent = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chromium")
            try:
                context = browser.new_context(locale="zh-CN")
                page = context.new_page()
                page.goto(base + "/", wait_until="domcontentloaded", timeout=15000)
                page.evaluate("() => window.runProbe()")
                page.wait_for_timeout(1500)
                state = page.evaluate("() => window.__wsState")
                user_agent = page.evaluate("() => navigator.userAgent")
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()

    evidence = {
        "probe": "browser-websocket-handshake-headers",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "origin": base,
        "browser_user_agent": user_agent,
        "socket_state": state,
        "handshakes": RECORDED,
        "notes": [
            "只打本机回环，不接触真实上游；证据不含 Cookie/Authorization。",
            "header_names 保持服务端收到请求头的原始顺序。",
            "回环是 ws://；wss:// 除 scheme 外握手头相同（真浏览器经候选网关的 WS 见 accept 探针）。",
        ],
    }
    destination = Path(args.evidence) if args.evidence else (
        Path(__file__).resolve().parent / "evidence" /
        f"ws-headers-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"证据已写入 {destination}")
    for entry in RECORDED:
        print(entry["handshake"]["header_names"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

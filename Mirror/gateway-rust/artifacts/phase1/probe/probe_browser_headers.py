# -*- coding: utf-8 -*-
"""抓真实 Chromium 对同源 XHR 的完整请求头（离线，只打本机回环）。

用途：`server/identity.rs` 的 `api_baseline()` 需要知道真 Chrome 在
「同源 fetch」这一形态下到底发哪些头（`sec-fetch-*`、`priority`、
`accept`、`accept-language`、`accept-encoding` 与 client hints 全族）。
页面自带的 `request.headers` 不含浏览器自动头，所以这里直接在**服务端**记录
收到的原始头，取值不经过浏览器侧过滤。

第一步先给一个不带 Accept-CH 的响应，第二步带 Accept-CH，用来区分
「默认只发低熵 hints」与「服务端声明后补发高熵 hints」两种形态。
"""

import argparse
import http.server
import json
import socket
import socketserver
import threading
import time
from pathlib import Path

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>header probe</title></head>
<body>
<script>
window.runProbe = async () => {
  await fetch('/api/low', {method: 'GET'});
  await fetch('/api/high', {method: 'GET'});
  await fetch('/api/post', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({hello: 'world'}),
  });
  await new Promise((r) => setTimeout(r, 300));
  return true;
};
</script>
</body></html>
"""

# 高熵 hints 必须由服务端用 Accept-CH 显式声明，Chrome 才会在后续请求补发。
ACCEPT_CH = (
    "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version, "
    "sec-ch-ua-full-version-list, sec-ch-ua-model, sec-ch-ua-platform-version"
)

RECORDED = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        """静音默认访问日志，避免污染输出。"""

    def _record(self, body: bytes) -> None:
        RECORDED.append({
            "method": self.command,
            "path": self.path,
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body_bytes": len(body),
        })

    def _send(self, status: int, payload: bytes, content_type: str, extra=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
        if self.path == "/":
            self._record(b"")
            # Accept-CH 只在**导航响应**上被 Chrome 采纳；放在 XHR 响应上会被忽略。
            self._send(
                200,
                PAGE.encode(),
                "text/html; charset=utf-8",
                {"Accept-CH": ACCEPT_CH},
            )
            return
        if self.path == "/api/low":
            self._record(b"")
            self._send(200, b'{"ok":true}', "application/json")
            return
        if self.path == "/api/high":
            self._record(b"")
            self._send(
                200,
                b'{"ok":true}',
                "application/json",
                {"Accept-CH": ACCEPT_CH, "Vary": "sec-ch-ua-arch, sec-ch-ua-bitness"},
            )
            return
        self._send(404, b'{"error":"not found"}', "application/json")

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        self._record(body)
        self._send(200, b'{"ok":true}', "application/json")


def serve() -> tuple[socketserver.ThreadingTCPServer, str]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def main() -> int:
    parser = argparse.ArgumentParser(description="抓真实 Chromium 的同源 XHR 请求头")
    parser.add_argument("--evidence", default=None, help="证据输出路径（默认写到 probe/evidence/）")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    server, base = serve()
    captured = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chromium")
            try:
                context = browser.new_context(locale="zh-CN")
                page = context.new_page()
                page.set_default_timeout(args.timeout * 1000)
                page.goto(base + "/", wait_until="domcontentloaded", timeout=15000)
                page.evaluate("() => window.runProbe()")
                time.sleep(0.5)
                captured = {
                    "user_agent_via_js": page.evaluate("() => navigator.userAgent"),
                    "brands_via_js": page.evaluate("() => navigator.userAgentData && navigator.userAgentData.brands"),
                    "platform_via_js": page.evaluate("() => navigator.userAgentData && navigator.userAgentData.platform"),
                }
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()

    evidence = {
        "probe": "browser-request-headers",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "origin": base,
        "browser": captured,
        "requests": RECORDED,
        "notes": [
            "只打本机回环，不接触任何真实上游；证据不含凭据。",
            "第一步 /api/low 在服务端声明 Accept-CH 之前，用于观察默认 hints。",
            "第二步起由 /api/high 的 Accept-CH 触发高熵 hints。",
        ],
    }
    destination = Path(args.evidence) if args.evidence else (
        Path(__file__).resolve().parent / "evidence" /
        f"browser-headers-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"证据已写入 {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

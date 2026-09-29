#!/usr/bin/env python3
"""真 Chromium146 的**请求头顺序**采集：导航（低熵/高熵）、子资源、WS 握手。

为什么要这一份：`identity::NAVIGATION_HEADER_ORDER` 与 `chat_ws` 的握手形状原先
只有两份间接证据——

  * `evidence/reference-chrome146-001`：只有**首次**（低熵）导航，没有高熵导航；
  * `evidence/ws-handshake-headers-001.json`：采自 Playwright 自带的
    **HeadlessChrome/151 on Windows**，与我们声称的 Chrome146/Linux 不是同一个
    浏览器，因此「146 到底发不发 `sec-ch-ua*`」这类问题它答不了。

这个脚本用 cfbypass 镜像里那套系统 chromium（146.0.7680.177，与身份表声称的
完整版本号同源）在回环上采集，服务端按**收到的原始顺序**记录头名：

  * 第一次导航 → 低熵提示（可与 reference-chrome146-001 交叉核对）；
  * 响应带 `Accept-CH` → 第二次导航为高熵导航（原先缺的那一例）；
  * 页内 `<a>` 点击导航 → 拿到导航形态下 `referer` 的槽位；
  * 页内子资源（favicon）→ 交叉核对 `REQUEST_HEADER_ORDER`；
  * 页内 `new WebSocket` → 握手形状（146 版本的那一份）。

`--accept-lang` 走命令行语言偏好而不是 Playwright 的 `locale=`：后者经
`Emulation.setUserAgentOverride` 注入，会把 `accept-language` 挪到覆盖机制自己的
槽位上（实测子资源里从表尾挪到第 3 位）。cfbypass 用的正是该覆盖，
`reference-chrome146-001` 也呈现同一特征，因此**顺序表以覆盖形态为准**；这里
两种机制都跑一遍，用来区分「版本差异」与「覆盖机制自带的偏移」。

无网络运行（镜像内置 chromium + playwright）：

    docker run --rm --network none \\
      -v "$PWD/probe/capture_header_order.py:/probe.py:ro" \\
      --entrypoint python3 mirror-cfbypass:phase1 /probe.py

加 `--json` 只输出机器可读结果，供写入 `evidence/`。
"""

import base64
import hashlib
import json
import socket
import sys
import threading
import time

from playwright.sync_api import sync_playwright

PORT = 48351
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# 与 chatgpt.com 下发的那一组一致（reference-chrome146-001 的 accept_ch 字段）。
ACCEPT_CH = (
    "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version, "
    "sec-ch-ua-full-version-list, sec-ch-ua-model, sec-ch-ua-platform-version"
)
PAGE = (
    '<html><head></head><body><a id="go" href="/nav-from-link">go</a><script>'
    "window.openWs = function() { return new Promise(function(done) {"
    '  var ws = new WebSocket("ws://127.0.0.1:%d/ws");'
    '  ws.onopen = function() { done("open"); };'
    '  ws.onerror = function() { done("error"); };'
    '  setTimeout(function() { done("timeout"); }, 3000);'
    "}); };</script></body></html>"
) % PORT

captured: dict[str, dict] = {}
lock = threading.Lock()


def serve() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(32)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def handle(conn: socket.socket) -> None:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            conn.close()
            return
        data += chunk
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    path = head[0].split(" ")[1]
    pairs = [tuple(line.split(": ", 1)) for line in head[1:] if ": " in line]
    fields = dict(pairs)
    tag = path.strip("/").split("/")[0] or "root"
    with lock:
        captured.setdefault(
            tag,
            {
                # 顺序即证据：按服务端收到的原始顺序，不排序、不归一化。
                "header_names": [name.lower() for name, _ in pairs],
                "accept_language": fields.get("Accept-Language"),
                "accept_encoding": fields.get("Accept-Encoding"),
                "referer": fields.get("Referer"),
                "client_hints": [
                    n.lower() for n, _ in pairs if n.lower().startswith("sec-ch-ua")
                ],
            },
        )
    if "Sec-WebSocket-Key" in fields:
        accept = base64.b64encode(
            hashlib.sha1((fields["Sec-WebSocket-Key"] + WS_GUID).encode()).digest()
        ).decode()
        conn.sendall(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode()
        )
        time.sleep(0.5)
        conn.close()
        return
    body = PAGE.encode()
    conn.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nAccept-CH: "
        + ACCEPT_CH.encode()
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )
    conn.close()


def run(pw, *, override_language: bool) -> dict:
    """采集一轮。`override_language=True` 用 CDP 覆盖，False 用命令行偏好。"""
    args = ["--no-sandbox"]
    if not override_language:
        args += ["--lang=zh-CN", "--accept-lang=zh-CN,zh;q=0.9,en;q=0.8"]
    browser = pw.chromium.launch(
        executable_path="/usr/bin/chromium", chromium_sandbox=False, args=args
    )
    context = browser.new_context(**({"locale": "zh-CN"} if override_language else {}))
    page = context.new_page()
    prefix = "override" if override_language else "cmdline"
    page.goto(f"http://127.0.0.1:{PORT}/{prefix}-first", wait_until="domcontentloaded")
    page.goto(f"http://127.0.0.1:{PORT}/{prefix}-second", wait_until="domcontentloaded")
    ws_state = page.evaluate("() => window.openWs()")
    page.click("#go")
    page.wait_for_load_state("domcontentloaded")
    version = browser.version
    browser.close()
    with lock:
        rows = dict(captured)
        captured.clear()
    return {"browser_version": version, "ws_state": ws_state, "requests": rows}


def main() -> int:
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.3)
    with sync_playwright() as pw:
        # 覆盖形态在前：顺序表以它为准（见模块文档）。
        result = {
            "probe": "browser-header-order",
            "capture": "本机回环 HTTP/1.1 + ws:// 服务端按收到顺序记录头名",
            "language_via_cdp_override": run(pw, override_language=True),
            "language_via_command_line": run(pw, override_language=False),
        }
    if "--json" in sys.argv:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    for mode in ("language_via_cdp_override", "language_via_command_line"):
        run_result = result[mode]
        print(
            f"== {mode}  chromium={run_result['browser_version']}  ws={run_result['ws_state']}"
        )
        for tag in sorted(run_result["requests"]):
            row = run_result["requests"][tag]
            print(f"  {tag}: AL={row['accept_language']!r} REF={row['referer']!r}")
            print("     " + " | ".join(row["header_names"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

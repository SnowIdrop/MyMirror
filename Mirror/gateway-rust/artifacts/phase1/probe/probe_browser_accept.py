#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Author  : MingTea
# File    : probe/probe_browser_accept.py
# Created : 2026-09-24
# Summary : 真实浏览器端到端验收。覆盖「发送消息 → 流式回复在页面渲染 → 停止生成 →
#           重命名 → 重新加载后历史可见 → 另一镜像用户越权读取被拒 → 删除」整条链路，
#           并观察页面是否真的打开 WebSocket。
#           复用 probe.py 的授权桩/进程/登录与 probe_browser_create.py 的会话登录。
#           网络记录只落 method/路径/状态/content-type 与长度；消息正文、回复正文、
#           标题、Cookie 与令牌一律不落盘（正文只落长度与 sha256）。
# -----------------------------------------------------------------------------

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

PROBE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROBE_DIR))

import probe  # noqa: E402
import probe_browser_create as browser_probe  # noqa: E402

# 合成提示词：不是用户内容。回复正文只落长度与 sha256。
PROMPT = "Reply with exactly: probe-ok"
RENAME_TITLE = "probe-acceptance-renamed"
# 浏览器侧播放的等待上限：真实生成可能排队，给足余量。
REPLY_TIMEOUT_MS = 180_000


def text_digest(text: str) -> dict:
    encoded = text.encode("utf-8")
    return {
        "chars": len(text),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "has_expected_token": "probe-ok" in text,
    }


def run_acceptance(
    args: argparse.Namespace, base: str, login_url: str, secret: str
) -> tuple[dict, str | None, str | None]:
    """返回 (证据, 交接后的 mirror_token, 会话 id)。会话 id 只留在内存里供清理。"""
    from playwright.sync_api import sync_playwright

    result: dict = {
        "handoff_status": None,
        "page_title": None,
        "html_mentions_access_token": None,
        "composer_found": False,
        "create": None,
        "reply": None,
        "stop": None,
        "rename": None,
        "history_after_reload": None,
        "delete": None,
        "websockets": [],
        "console_errors": 0,
        "notes": [],
    }
    conversation_id: str | None = None
    pending: dict[object, dict] = {}
    order: list[dict] = []
    handoff_token: str | None = None

    def api_status(response) -> dict:
        return {
            "status": response.status,
            "content_type": (response.headers.get("content-type") or "").split(";")[0],
        }

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chromium", headless=True)
        context = browser.new_context()
        page = context.new_page()

        def on_request(request) -> None:
            if not request.url.startswith(base):
                return
            entry = {
                "method": request.method,
                "path": request.url[len(base):].split("?", 1)[0],
                "status": None,
            }
            pending[request] = entry
            order.append(entry)

        def on_response(response) -> None:
            entry = pending.get(response.request)
            if entry is None:
                return
            entry["status"] = response.status
            entry["content_type"] = (
                response.headers.get("content-type") or ""
            ).split(";")[0]

        def on_failed(request) -> None:
            entry = pending.get(request)
            if entry is not None:
                entry["transport_error"] = request.failure

        def on_console(message) -> None:
            if message.type == "error":
                result["console_errors"] += 1

        def on_websocket(socket) -> None:
            entry = {
                "url": socket.url,
                "frames_sent": 0,
                "frames_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "closed": False,
            }
            result["websockets"].append(entry)

            def count(key: str, payload) -> None:
                entry[key] += 1
                entry["bytes_sent" if key == "frames_sent" else "bytes_received"] += len(payload)

            socket.on("framesent", lambda payload: count("frames_sent", payload))
            socket.on("framereceived", lambda payload: count("frames_received", payload))
            socket.on("close", lambda *_: entry.__setitem__("closed", True))

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", on_failed)
        page.on("console", on_console)
        page.on("websocket", on_websocket)

        def create_capture(response) -> None:
            nonlocal conversation_id
            # 精确匹配创建端点：`/f/conversation/prepare` 是同前缀的另一条路由。
            if response.url[len(base):].split("?", 1)[0] != "/backend-api/f/conversation":
                return
            body = b""
            try:
                body = response.body()
            except Exception as cause:
                result["notes"].append(f"创建响应正文读取失败：{type(cause).__name__}")
            found = browser_probe.CONVERSATION_ID_PATTERN.search(body)
            result["create"] = {
                **api_status(response),
                "bytes": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
            }
            if found:
                conversation_id = found.group(1).decode("ascii")
                result["create"]["conversation_id_sha256"] = hashlib.sha256(
                    found.group(1)
                ).hexdigest()

        page.on("response", create_capture)

        # 1) 登录交接（会轮换 mirror_token：交接后的值才是本次会话的凭据）。
        handoff = page.goto(
            base + login_url, wait_until="domcontentloaded", timeout=args.timeout * 1000
        )
        result["handoff_status"] = handoff.status if handoff else None
        handoff_token = next(
            (
                cookie["value"]
                for cookie in context.cookies(base)
                if cookie["name"] == "mirror_token"
            ),
            None,
        )
        page.wait_for_load_state("domcontentloaded", timeout=args.timeout * 1000)
        page.wait_for_timeout(args.settle_ms)
        result["page_title"] = page.title()
        try:
            result["html_mentions_access_token"] = "accessToken" in page.content()
        except Exception as cause:
            result["notes"].append(f"读取页面 HTML 失败：{type(cause).__name__}")

        composer = page.locator("#prompt-textarea, div[contenteditable='true']").first
        result["composer_found"] = composer.count() > 0
        if not result["composer_found"]:
            result["notes"].append("页面没有输入框：后续验收未执行。")
            result["requests"] = order
            context.close()
            browser.close()
            return result, handoff_token, conversation_id

        if args.no_write:
            # 只观察：页面加载到这里已经完成 WS 握手与 sentinel 预取，不再发消息。
            page.wait_for_timeout(5000)
            result["notes"].append("--no-write：只观察页面与 WebSocket，未发送任何消息。")
            result["requests"] = order
            context.close()
            browser.close()
            return result, handoff_token, conversation_id

        # 2) 发送一条消息，等助手回复真正渲染到页面（流式回复的端到端证据）。
        composer.click()
        composer.type(PROMPT, delay=20)
        page.keyboard.press("Enter")
        deadline = time.monotonic() + REPLY_TIMEOUT_MS / 1000
        reply_text = ""
        while time.monotonic() < deadline:
            try:
                candidates = page.locator('[data-message-author-role="assistant"]')
                if candidates.count() > 0:
                    reply_text = candidates.last.inner_text()
                    if "probe-ok" in reply_text:
                        break
            except Exception:
                pass
            page.wait_for_timeout(500)
        result["reply"] = {
            "rendered": bool(reply_text),
            "is_streaming_settled": "probe-ok" in reply_text,
            **text_digest(reply_text),
        }
        if not reply_text:
            result["notes"].append("未观察到助手回复渲染：流式渲染未闭环。")

        # 3) 停止生成（尽力而为）：第二轮消息发出后立刻点停止按钮。
        time.sleep(args.pause_seconds)
        try:
            composer.click()
            composer.type(PROMPT, delay=20)
            page.keyboard.press("Enter")
            stop_button = page.locator(
                '[data-testid="stop-button"], button[aria-label*="Stop"], button[aria-label*="停止"]'
            ).first
            stop_button.wait_for(state="visible", timeout=20_000)
            stop_button.click()
            page.wait_for_timeout(3000)
            still_streaming = page.locator(
                '[data-testid="stop-button"], button[aria-label*="Stop"], button[aria-label*="停止"]'
            ).count()
            result["stop"] = {
                "stop_button_found": True,
                "stop_button_present_after_click": still_streaming > 0,
            }
        except Exception as cause:
            result["stop"] = {"stop_button_found": False, "cause": type(cause).__name__}
            result["notes"].append(
                f"停止生成未演练（{type(cause).__name__}）：不影响其余验收结论。"
            )

        # 4) 重命名：走页面自身的同源路由（与前端工具栏同一个请求）。
        if conversation_id:
            time.sleep(args.pause_seconds)
            renamed = page.evaluate(
                """async ({id, title}) => {
                    const response = await fetch(
                        `/backend-api/conversation/id/${id}/rename`,
                        {
                            method: 'POST',
                            credentials: 'include',
                            headers: {'content-type': 'application/json'},
                            body: JSON.stringify({title}),
                        },
                    );
                    return {status: response.status, bytes: (await response.text()).length};
                }""",
                {"id": conversation_id, "title": RENAME_TITLE},
            )
            result["rename"] = renamed

        # 5) 历史加载：重新加载页面，确认该会话仍在（列表接口 + 侧栏链接）。
        if conversation_id:
            # 页面内查询只作旁证：重载后 frame 可能正在导航，失败不影响结论。
            try:
                page.reload(wait_until="domcontentloaded", timeout=args.timeout * 1000)
                page.wait_for_timeout(args.settle_ms)
                sidebar = page.locator(f'a[href="/c/{conversation_id}"]').count()
                result["history_after_reload"] = {
                    "page_url": page.url,
                    "sidebar_links": sidebar,
                }
            except Exception as cause:
                result["history_after_reload"] = {"error": type(cause).__name__}
                result["notes"].append(
                    f"重载后页面内历史检查未完成（{type(cause).__name__}）：以 Python 侧的网关列表为准。"
                )

        result["requests"] = order
        context.close()
        browser.close()
    return result, handoff_token, conversation_id


def cross_user_check(
    opener: urllib.request.OpenerDirector,
    base: str,
    account_id: str,
    secret: str,
    conversation_id: str,
    timeout: float,
) -> dict:
    """同账号的第二个镜像用户读取该会话：必须被 ACL 拒绝，且拒绝发生在接触上游之前。"""
    _, token = browser_probe.login_with_session_token(
        opener, base, "probe-bob", account_id, secret, False, timeout
    )
    if token is None:
        return {"login_status": "failed"}
    entry = probe.http_request(
        opener,
        "GET",
        f"{base}/backend-api/conversation/{conversation_id}",
        None,
        {"x-mirror-token": token},
        timeout,
    )
    return {
        "status": entry.get("status"),
        "code": entry.get("code"),
        "local_message": entry.get("local_message"),
        "upstream_blocked": entry.get("upstream_blocked"),
    }


def upstream_list_check(secret: str, conversation_id: str, timeout: float) -> dict:
    """绕过网关直连上游查一次会话列表，用来区分「ACL 过滤掉了」与「上游列表本身为空」。

    先用会话 cookie 换 accessToken，再取列表；两者都只在本进程内存里，令牌不进 argv。
    Cloudflare 对纯 Python TLS 会挑战，因此走 curl（与清理脚本同一条通道）。
    """
    import os
    import subprocess
    import tempfile

    ua = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    )
    common = [
        f'header = "user-agent: {ua}"',
        'header = "accept: */*"',
        'header = "accept-language: en-US,en;q=0.9"',
        r'header = "sec-ch-ua: \"Chromium\";v=\"146\", \"Not_A Brand\";v=\"99\""',
        'header = "sec-ch-ua-mobile: ?0"',
        r'header = "sec-ch-ua-platform: \"Linux\""',
        'header = "origin: https://chatgpt.com"',
        'header = "referer: https://chatgpt.com/"',
        f'header = "cookie: __Secure-next-auth.session-token={secret}"',
    ]

    def curl(lines: list[str], url: str) -> tuple[str, bytes]:
        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False, encoding="utf-8") as fh:
            fh.write("silent\nshow-error\nmax-time = 60\n" + "\n".join(lines) + "\n")
            cfg = fh.name
        out = cfg + ".out"
        try:
            proc = subprocess.run(
                ["curl.exe", "--config", cfg, "-o", out, "-w", "%{http_code}", url],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            body = Path(out).read_bytes() if os.path.exists(out) else b""
            return proc.stdout.strip() or "?", body
        finally:
            for path in (cfg, out):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    code, body = curl(common, "https://chatgpt.com/api/auth/session")
    try:
        access = json.loads(body.decode()).get("accessToken")
    except Exception:
        access = None
    if not access:
        return {"exchange_status": code, "access_token": False}
    auth = common + [f'header = "authorization: Bearer {access}"']
    code, body = curl(auth, "https://chatgpt.com/backend-api/conversations?offset=0&limit=50")
    try:
        payload = json.loads(body.decode())
        items = payload.get("items") or []
        return {
            "exchange_status": "200",
            "access_token": True,
            "list_status": code,
            "top_keys": sorted(payload.keys())[:8] if isinstance(payload, dict) else [],
            "count": len(items),
            "contains_target": any(
                isinstance(item, dict) and item.get("id") == conversation_id for item in items
            ),
        }
    except Exception as cause:
        return {
            "exchange_status": "200",
            "access_token": True,
            "list_status": code,
            "bytes": len(body),
            "parse_error": type(cause).__name__,
        }


def gateway_list_check(
    opener: urllib.request.OpenerDirector,
    base: str,
    token: str,
    conversation_id: str,
    timeout: float,
) -> dict:
    """经网关读一次会话列表（与页面侧栏同一个请求）。

    记录状态、信封字段名与可见条数；本条与 `upstream_list_check` 的同一份列表对比，
    用于区分「ACL 过滤掉了」与「上游列表本身为空」。
    """
    entry = probe.http_request(
        opener,
        "GET",
        f"{base}/backend-api/conversations?offset=0&limit=50",
        None,
        {"x-mirror-token": token},
        timeout,
    )
    return {
        "status": entry.get("status"),
        "bytes": entry.get("body_bytes"),
        "top_keys": entry.get("json_top_keys"),
        "item_count": entry.get("item_count"),
        "code": entry.get("code"),
        "html_like": entry.get("html_like"),
        "conversation_id": conversation_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="真实浏览器端到端验收")
    parser.add_argument("--session-token-file", type=Path, default=PROBE_DIR / "session-token.txt")
    parser.add_argument("--evidence-dir", type=Path, default=probe.EVIDENCE_DIR)
    parser.add_argument(
        "--binary",
        type=Path,
        default=PROBE_DIR.parent / "source" / "target" / "debug" / probe.BINARY_NAME,
    )
    parser.add_argument("--chatgpt-base", default="https://chatgpt.com")
    parser.add_argument("--cdn-base", default="https://cdn.oaistatic.com")
    parser.add_argument("--account-id", default="1")
    parser.add_argument("--user", default="probe-accept")
    parser.add_argument("--timeout", type=float, default=150.0)
    parser.add_argument("--startup-seconds", type=float, default=20.0)
    parser.add_argument("--settle-ms", type=int, default=12000)
    # 真实写入之间的随机间隔，避免被上游当成爬虫脚本。
    parser.add_argument("--pause-seconds", type=float, default=10.0)
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="只加载页面并观察 WebSocket，不发送消息、不重命名、不删除（纯只读）",
    )
    args = parser.parse_args()

    secret = browser_probe.read_field(args.session_token_file, "session_token")
    if not args.binary.exists():
        raise SystemExit(f"未找到候选二进制 {args.binary}：先在 source/ 下执行 cargo build。")

    evidence: dict = {
        "probe": "browser-driven-acceptance",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "credential": "session_token",
        "credential_sha256": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        "network": None,
        "cross_user": None,
        "cleanup": None,
        "notes": [],
    }

    authority = probe.AuthorityServer(("127.0.0.1", 0), probe.ADMIN_SECRET)
    threading.Thread(target=authority.serve_forever, daemon=True).start()
    host = "127.0.0.1"
    port = probe.free_port()
    base = f"http://{host}:{port}"
    opener = urllib.request.build_opener(probe.NoRedirect)
    log: list[str] = []
    process = None
    conversation_id: str | None = None
    handoff_token: str | None = None
    try:
        gateway_args = SimpleNamespace(
            chatgpt_base=args.chatgpt_base,
            cdn_base=args.cdn_base,
            cf_bypass_url=None,
            timeout=args.timeout,
        )
        env = probe.gateway_env(gateway_args, host, port, authority.server_address[1])
        process = probe.start_gateway(args.binary, env, secret, log)
        if not probe.wait_for_listening(process, host, port, args.startup_seconds):
            evidence["notes"].append("网关未在超时内监听：未发出任何上游请求。")
            return finish(evidence, args)

        login_entry, mirror_token = browser_probe.login_with_session_token(
            opener, base, args.user, args.account_id, secret, False, args.timeout
        )
        evidence["login"] = login_entry
        if mirror_token is None:
            evidence["notes"].append("登录未成功：验收未执行。")
            return finish(evidence, args)

        # 清理放在 finally 里：验收任何一步失败都必须在真实账号里删掉这次写入。
        try:
            network, handoff_token, conversation_id = run_acceptance(
                args, base, f"/api/not-login?user_gateway_token={mirror_token}", secret
            )
            evidence["network"] = network
            evidence["notes"].extend(network.pop("notes", []))

            if conversation_id:
                evidence["cross_user"] = cross_user_check(
                    opener, base, args.account_id, secret, conversation_id, args.timeout
                )
                # 经网关的列表：页面侧栏走的就是这条请求，Python 侧发起可避免 frame 竞态。
                evidence["gateway_list"] = gateway_list_check(
                    opener, base, handoff_token or mirror_token, conversation_id, args.timeout
                )
                # 直连上游查同一份列表：区分「ACL 过滤掉了」与「上游列表本身为空」。
                evidence["upstream_list"] = upstream_list_check(
                    secret, conversation_id, args.timeout
                )
        except Exception as cause:
            evidence["notes"].append(
                f"验收流程异常，已执行清理：{type(cause).__name__}: {cause}"
            )
        finally:
            # 删除：经网关的同源作用域路径（同时验收 ACL 的 Delete 判权）。
            if conversation_id and handoff_token:
                time.sleep(args.pause_seconds)
                entry = probe.http_request(
                    opener,
                    "DELETE",
                    f"{base}/backend-api/conversation/id/{conversation_id}",
                    None,
                    {"x-mirror-token": handoff_token},
                    args.timeout,
                )
                evidence["cleanup"] = {
                    "status": entry.get("status"),
                    "code": entry.get("code"),
                }
                status = entry.get("status")
                if not (isinstance(status, int) and 200 <= status < 300):
                    evidence["notes"].append(
                        f"删除未返回 2xx（{status}）：请在网页端确认账号没有残留会话。"
                    )
        return finish(evidence, args)
    finally:
        probe.stop_process(process)
        authority.shutdown()
        authority.server_close()
        evidence["gateway_log_lines"] = len(log)
        # 只挑与 WS / 传输失败相关的行做样本：足以判定桥接是否连上上游，
        # 又不把整段日志搬进证据（网关不打印凭据，这里仍按最小面收集）。
        evidence["gateway_log_samples"] = [
            line
            for line in log
            if any(
                keyword in line
                for keyword in ("WebSocket", "websocket", "ws-", "upstream failed", "请求失败")
            )
        ][:20]
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()


def finish(evidence: dict, args: argparse.Namespace) -> int:
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    out = args.evidence_dir / f"accept-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    network = evidence.get("network") or {}
    print("\n真实浏览器验收结果")
    print(f"  页面标题={network.get('page_title')!r} 首屏含 accessToken={network.get('html_mentions_access_token')}")
    print(f"  创建={json.dumps(network.get('create'), ensure_ascii=False)}")
    print(f"  流式回复={json.dumps(network.get('reply'), ensure_ascii=False)}")
    print(f"  停止生成={json.dumps(network.get('stop'), ensure_ascii=False)}")
    print(f"  重命名={json.dumps(network.get('rename'), ensure_ascii=False)}")
    print(f"  重载后历史={json.dumps(network.get('history_after_reload'), ensure_ascii=False)}")
    print(f"  经网关列表={json.dumps(evidence.get('gateway_list'), ensure_ascii=False)}")
    print(f"  跨用户读取={json.dumps(evidence.get('cross_user'), ensure_ascii=False)}")
    print(f"  直连上游列表={json.dumps(evidence.get('upstream_list'), ensure_ascii=False)}")
    print(f"  WebSocket={json.dumps(network.get('websockets'), ensure_ascii=False)}")
    print(f"  删除（经网关）={json.dumps(evidence.get('cleanup'), ensure_ascii=False)}")
    for sample in evidence.get("gateway_log_samples") or []:
        print(f"  gateway: {sample}")
    for note in evidence["notes"]:
        print(f"  ! {note}")
    print(f"\n证据写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

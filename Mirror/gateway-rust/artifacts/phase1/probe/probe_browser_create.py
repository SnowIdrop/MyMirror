#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Author  : MingTea
# File    : probe/probe_browser_create.py
# Created : 2026-09-24
# Summary : 真实浏览器驱动验收。用系统 Playwright 的 Chromium 经候选网关打开 ChatGPT
#           页面，让页面自己完成 sentinel 握手，并在显式开启时发出恰好一次真实新建
#           会话与其删除。
#           复用同目录 probe.py 的授权桩、网关进程管理与登录流程。
#           网络记录只落 method/路径/头名/状态/content-type 与少量安全头值；Cookie、
#           Authorization、发送方令牌、响应正文与消息内容一律不落盘、不打印。
# -----------------------------------------------------------------------------

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

PROBE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROBE_DIR))

import probe  # noqa: E402  （同目录探针的进程/授权桩复用）

# 只记录这些头的**值**：它们不含凭据，且是判定「浏览器材料是否到达上游」的关键证据。
SAFE_HEADER_VALUES = (
    "content-type",
    "accept",
    "accept-language",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
)
# 创建会话端点与其 sentinel 握手端点（前端分块取证确认的路径）。
CREATE_PATH = "/backend-api/f/conversation"
SENTINEL_PATHS = (
    "/backend-api/sentinel/chat-requirements/prepare",
    "/backend-api/sentinel/chat-requirements/finalize",
    "/backend-api/sentinel/heartbeat",
)
# 探测消息是合成文本，不是用户内容；长度仍然只记长度。
PROBE_MESSAGE = "probe-browser-acceptance"
# 会话 id 只以 sha256 进证据：足以核对两次运行指同一会话，又不泄露内容引用。
CONVERSATION_ID_PATTERN = re.compile(rb'"conversation_id"\s*:\s*"([0-9a-fA-F-]{36})"')


def read_field(path: Path, field: str) -> str:
    """读取凭据草稿里的指定赋值行；只返回值，不打印任何内容。"""
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip() != field:
            continue
        value = value.strip().strip("'\"")
        if len(value) < 32 or any(char.isspace() for char in value):
            raise SystemExit(f"{path} 里的 {field} 仍是占位符或未填完整。")
        return value
    raise SystemExit(f"{path} 里没有找到 `{field} = <值>` 赋值行。")


def login_with_session_token(
    opener: urllib.request.OpenerDirector,
    base: str,
    user: str,
    account_id: str,
    session_token: str,
    as_extra_cookie: bool,
    timeout: float,
) -> tuple[dict, str | None]:
    """用 SessionToken 登录。

    `as_extra_cookie=False` 走「只给 session_token 字段」的 A 轮，用于复现候选
    不给上游带会话 cookie 的现状；`True` 时把同一个值额外放进 extra_cookies，
    走 B 轮（等价于管理面导入过会话 cookie 的账号）。
    """
    payload = {
        "user_name": user,
        "authorization": "probe-signature-v1",
        "session_token": session_token,
        "chatgpt_account_id": account_id,
        "login_mode": "web",
        "isolated_session": True,
        "mcp_isolation": False,
        "skills_isolation": False,
        "model_isolation": False,
        "daily_quota": 0,
        "monthly_quota": 0,
        "model_allowed_ids": [],
        "model_rate_limits": {},
        "limits": [],
        "mcp_allowed_ids": [],
        "skills_allowed_ids": [],
        "extra_cookies": (
            [{"name": "__Secure-next-auth.session-token", "value": session_token}]
            if as_extra_cookie
            else []
        ),
    }
    request = probe.build_request(
        "POST",
        f"{base}/api/login",
        payload,
        {"authorization": f"Bearer {probe.ADMIN_SECRET}"},
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(probe.MAX_BODY + 1)
            entry = probe.describe(
                response.status, response.headers, raw, time.monotonic() - started
            )
            mirror_token = probe.extract_mirror_token(raw) if response.status == 200 else None
    except urllib.error.HTTPError as error:
        entry = probe.describe(
            error.code, error.headers, error.read(probe.MAX_BODY + 1), time.monotonic() - started
        )
        mirror_token = None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        entry = probe.transport_failure(error, time.monotonic() - started)
        mirror_token = None
    entry.update({"label": f"login:{user}", "route": "/api/login", "method": "POST"})
    return entry, mirror_token


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: headers[name] for name in SAFE_HEADER_VALUES if name in headers}


def body_digest(body: bytes) -> dict:
    return {
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "html_like": body.lstrip()[:1] == b"<",
    }


def run_browser(
    args: argparse.Namespace, base: str, login_url: str, token: str
) -> tuple[dict, str | None]:
    """浏览器阶段：登录交接 → 页面加载 →（可选）发送一条消息 → 记录结论。

    `login_url` 是网关下发的 `/api/not-login?user_gateway_token=…`；浏览器访问它会
    换到新的 mirror_token 并 302 回 `/`，与产品里 Django 登录后跳转的路径一致。
    返回 (证据, 交接后的 mirror_token)：后者只留在内存里供删除步骤使用——交接会
    轮换 token，用交接前的值删除会被判未登录。
    """
    from playwright.sync_api import sync_playwright

    result: dict = {
        "page_url": None,
        "page_title": None,
        "handoff_status": None,
        "session_probe": None,
        "html_mentions_access_token": None,
        "composer_found": False,
        "console_errors": 0,
        "console_error_samples": [],
        "requests": [],
        "create": None,
        "notes": [],
    }
    # 以 Request 对象本身为键：它被本字典强引用，Python 不会回收后复用 id。
    pending: dict[object, dict] = {}
    order: list[dict] = []

    with sync_playwright() as playwright:
        # channel="chromium" 用完整 Chromium 的 new headless：headless shell 与
        # Cloudflare 的浏览器判定不同，这里取保真度更高的一侧。
        browser = playwright.chromium.launch(channel="chromium", headless=True)
        context = browser.new_context()
        page = context.new_page()

        def on_request(request) -> None:
            if not request.url.startswith(base):
                return
            entry = {
                "method": request.method,
                "path": request.url[len(base):].split("?", 1)[0],
                "resource_type": request.resource_type,
                "header_names": sorted(name.lower() for name in request.headers),
                "safe_headers": safe_headers(request.headers),
                "status": None,
            }
            pending[request] = entry
            order.append(entry)

        def on_response(response) -> None:
            entry = pending.get(response.request)
            if entry is None:
                return
            headers = response.headers
            entry["status"] = response.status
            entry["content_type"] = (headers.get("content-type") or "").split(";")[0].strip()
            entry["content_length"] = headers.get("content-length")
            entry["cf_mitigated"] = bool(headers.get("cf-mitigated"))

        def on_failed(request) -> None:
            entry = pending.get(request)
            if entry is not None:
                entry["transport_error"] = request.failure

        def on_console(message) -> None:
            if message.type == "error":
                result["console_errors"] += 1
                if len(result["console_error_samples"]) < 5:
                    # 控制台错误可能带 URL，但不会带凭据；仍然按探针约定脱敏并截断。
                    text = probe.scrub(message.text, token)[:160]
                    result["console_error_samples"].append(text)

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", on_failed)
        page.on("console", on_console)

        # 1) 登录交接：拿到 mirror_token 会话 cookie（令牌本身不进证据）。
        handoff = page.goto(base + login_url, wait_until="domcontentloaded", timeout=args.timeout * 1000)
        result["handoff_status"] = handoff.status if handoff else None
        handoff_token = next(
            (
                cookie["value"]
                for cookie in context.cookies(base)
                if cookie["name"] == "mirror_token"
            ),
            None,
        )
        # 交接是 302 → `/`：这一次导航本身就是页面加载，不再重复导航，避免丢掉
        # 首个文档上的请求（那正是前端判定登录态的地方）。
        page.wait_for_load_state("domcontentloaded", timeout=args.timeout * 1000)
        page.wait_for_timeout(args.settle_ms)
        result["page_url"] = page.url
        result["page_title"] = page.title()

        # 2) 前端是否把「已登录」写进首屏 HTML：只看布尔，不落任何值。
        try:
            html = page.content()
            result["html_mentions_access_token"] = "accessToken" in html
        except Exception as cause:
            result["notes"].append(f"读取页面 HTML 失败：{type(cause).__name__}")

        # 3) 直接在页面里问会话端点：判定镜像的 `/api/auth/session` 对浏览器是否可用。
        try:
            probe_result = page.evaluate(
                """async () => {
                    const response = await fetch('/api/auth/session', {credentials: 'include'});
                    const text = await response.text();
                    let keys = [];
                    try { const parsed = JSON.parse(text); if (parsed && typeof parsed === 'object') keys = Object.keys(parsed).sort(); } catch (error) {}
                    return {status: response.status, bytes: text.length, keys};
                }"""
            )
            result["session_probe"] = probe_result
        except Exception as cause:
            result["notes"].append(f"会话端点探测失败：{type(cause).__name__}")

        composer = page.locator("#prompt-textarea, div[contenteditable='true']").first
        result["composer_found"] = composer.count() > 0

        if not args.allow_real_write:
            result["notes"].append(
                "未传 --allow-real-write：只加载页面并记录逐跳状态，未发送任何消息。"
            )
        elif not result["composer_found"]:
            result["notes"].append("页面没有找到输入框：未发送消息，写路径未执行。")
        else:
            create_entry: dict | None = None

            def on_create_response(response) -> None:
                nonlocal create_entry
                if not response.url[len(base):].startswith(CREATE_PATH):
                    return
                try:
                    body = response.body()
                except Exception as cause:  # 流式响应读取失败不影响状态码结论
                    body = b""
                    result["notes"].append(f"创建响应正文读取失败：{type(cause).__name__}")
                digest = body_digest(body)
                create_entry = {
                    "status": response.status,
                    "content_type": (response.headers.get("content-type") or "").split(";")[0],
                    "body": digest,
                }
                found = CONVERSATION_ID_PATTERN.search(body)
                if found:
                    # 原文只留在内存里供删除调用，证据里只落摘要。
                    create_entry["conversation_id"] = found.group(1).decode("ascii")
                    create_entry["conversation_id_sha256"] = hashlib.sha256(
                        found.group(1)
                    ).hexdigest()

            page.on("response", on_create_response)
            composer.click()
            composer.type(PROBE_MESSAGE, delay=20)
            page.keyboard.press("Enter")
            deadline = time.monotonic() + args.timeout
            while create_entry is None and time.monotonic() < deadline:
                page.wait_for_timeout(250)
            result["create"] = create_entry
            if create_entry is None:
                result["notes"].append("未观察到创建请求：写路径未闭环。")

        result["requests"] = order
        context.close()
        browser.close()
    return result, handoff_token


def main() -> int:
    parser = argparse.ArgumentParser(description="真实浏览器驱动的新建会话验收（默认只读）")
    parser.add_argument("--token-file", type=Path, default=probe.TOKEN_FILE)
    parser.add_argument(
        "--session-token-file",
        type=Path,
        default=PROBE_DIR / "session-token.txt",
        help="改用 SessionToken 登录（默认用 access-token.txt 里的 AccessToken）",
    )
    parser.add_argument(
        "--use-session-token",
        action="store_true",
        help="从 --session-token-file 读取 SessionToken 而不是 AccessToken",
    )
    parser.add_argument(
        "--session-token-as-extra-cookie",
        action="store_true",
        help="把同一个 SessionToken 额外放进 extra_cookies（B 轮：等价于已导入会话 cookie 的账号）",
    )
    parser.add_argument("--evidence-dir", type=Path, default=probe.EVIDENCE_DIR)
    parser.add_argument(
        "--binary",
        type=Path,
        default=PROBE_DIR.parent / "source" / "target" / "debug" / probe.BINARY_NAME,
    )
    parser.add_argument("--chatgpt-base", default="https://chatgpt.com")
    parser.add_argument("--cdn-base", default="https://cdn.oaistatic.com")
    parser.add_argument("--account-id", default="1")
    parser.add_argument("--user", default="probe-browser")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--startup-seconds", type=float, default=20.0)
    # 页面加载后等前端挂载完成的静置时间；sentinel 握手发生在这段窗口内。
    parser.add_argument("--settle-ms", type=int, default=8000)
    parser.add_argument(
        "--allow-real-write",
        action="store_true",
        help="在页面里发送一条消息（= 恰好一次真实新建会话）；默认不发送",
    )
    args = parser.parse_args()

    if args.use_session_token:
        secret = read_field(args.session_token_file, "session_token")
        credential = "session_token"
    else:
        secret = probe.read_token(args.token_file)
        credential = "access_token"
    if not args.binary.exists():
        raise SystemExit(f"未找到候选二进制 {args.binary}：先在 source/ 下执行 cargo build。")

    evidence: dict = {
        "probe": "browser-driven-create",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "credential": credential,
        "session_token_as_extra_cookie": bool(args.session_token_as_extra_cookie),
        "credential_sha256": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        "real_write_allowed": bool(args.allow_real_write),
        "network": None,
        "notes": [],
    }

    authority = probe.AuthorityServer(("127.0.0.1", 0), probe.ADMIN_SECRET)
    import threading

    threading.Thread(target=authority.serve_forever, daemon=True).start()
    host = "127.0.0.1"
    port = probe.free_port()
    base = f"http://{host}:{port}"
    opener = urllib.request.build_opener(probe.NoRedirect)
    log: list[str] = []
    process = None
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

        if args.use_session_token:
            login_entry, mirror_token = login_with_session_token(
                opener,
                base,
                args.user,
                args.account_id,
                secret,
                args.session_token_as_extra_cookie,
                args.timeout,
            )
        else:
            login_entry, mirror_token = probe.login(
                opener, base, args.user, args.account_id, secret, args.timeout
            )
        evidence["login"] = login_entry
        if mirror_token is None:
            evidence["notes"].append(
                "登录未成功：后续浏览器流程未执行（按该步状态码判定，可能是凭据失效或上游拦截）。"
            )
            return finish(evidence, args)
        login_url = f"/api/not-login?user_gateway_token={mirror_token}"

        network, handoff_token = run_browser(args, base, login_url, secret)
        evidence["network"] = network
        evidence["notes"].extend(network.pop("notes"))

        if args.allow_real_write:
            if handoff_token is None:
                evidence["notes"].append("交接后没有拿到 mirror_token：跳过删除，请人工确认。")
            else:
                cleanup(evidence, opener, base, handoff_token, args)
        return finish(evidence, args)
    finally:
        probe.stop_process(process)
        authority.shutdown()
        authority.server_close()
        evidence["authority_calls"] = authority.calls
        evidence["gateway_log_lines"] = len(log)
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()


def cleanup(
    evidence: dict,
    opener: urllib.request.OpenerDirector,
    base: str,
    mirror_token: str,
    args: argparse.Namespace,
) -> None:
    """删除本次真实写入的会话；删除失败只如实登记，不重试、不猜第二个端点。"""
    create = evidence.get("network", {}).get("create") or {}
    conversation_id = create.pop("conversation_id", None)
    if not conversation_id:
        evidence["notes"].append(
            "创建响应里没有会话 id：无法自动删除，请在网页端确认后手动处理。"
        )
        return
    entry = probe.http_request(
        opener,
        "DELETE",
        f"{base}/backend-api/conversation/id/{conversation_id}",
        None,
        {"x-mirror-token": mirror_token},
        args.timeout,
    )
    entry.update({"label": "delete_conversation", "method": "DELETE"})
    evidence["delete"] = entry
    ok = entry.get("status") is not None and 200 <= int(entry["status"]) < 300
    evidence["notes"].append(
        "删除成功：本次真实写入已清除。"
        if ok
        else "删除未返回 2xx：会话可能仍在账号里，请手动删除，不要重复运行本探针。"
    )


def finish(evidence: dict, args: argparse.Namespace) -> int:
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    out = args.evidence_dir / f"browser-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    network = evidence.get("network") or {}
    print("\n浏览器验收结果")
    print(f"  交接状态={network.get('handoff_status')} 页面标题={network.get('page_title')!r}")
    print(f"  找到输入框={network.get('composer_found')} 控制台错误={network.get('console_errors')}")
    print(f"  首屏 HTML 含 accessToken={network.get('html_mentions_access_token')}")
    print(f"  页面内 /api/auth/session={network.get('session_probe')}")
    for sample in network.get("console_error_samples") or []:
        print(f"    console: {sample}")
    print("  --- sentinel 与创建相关 ---")
    for entry in network.get("requests") or []:
        path = entry["path"]
        if path in SENTINEL_PATHS or path.endswith(CREATE_PATH) or path.startswith("/backend"):
            if entry.get("status") is not None:
                print(
                    f"  {entry['method']:6} {path:52} {entry['status']} "
                    f"{entry.get('content_type','')}"
                )
    print("  --- 非 2xx ---")
    counts: dict[str, int] = {}
    for entry in network.get("requests") or []:
        status = entry.get("status")
        if status is None or 200 <= int(status) < 300:
            continue
        key = f"{entry['method']} {entry['path']} -> {entry['status']}"
        counts[key] = counts.get(key, 0) + 1
    for key, count in sorted(counts.items()):
        print(f"  {key}  x{count}")
    for note in evidence["notes"]:
        print(f"  ! {note}")
    print(f"\n证据写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

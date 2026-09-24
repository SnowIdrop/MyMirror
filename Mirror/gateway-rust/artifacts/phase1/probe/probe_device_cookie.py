#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Author  : MingTea
# File    : probe/probe_device_cookie.py
# Created : 2026-09-24
# Summary : 设备 Cookie（`oai-did`）的真实上游探针。相对 probe.py 的差异：
#           1) 使用**文件**数据库，跑完可用标准库 sqlite3 只读检查
#              `gateway_sessions.upstream_cookies` 是否被捕获（不解密，只看存在性）；
#           2) 记录每一跳上游响应里 `set-cookie` 的**名字**，判断真实上游是否下发
#              `oai-did`（值一律不落盘、不打印）；
#           3) 每个触及上游的请求之间随机停 8–12 秒，避免被上游当成爬虫脚本；
#           4) 真实写入沿用 probe.py 的边界：恰好一次新建会话 + 一次删除。
#           复用同目录 probe.py 的授权桩、网关进程管理与响应压缩实现。
#           令牌、Cookie 值、会话 id 原文、响应正文一律不落盘。
# -----------------------------------------------------------------------------

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

import probe as base

PROBE_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = PROBE_DIR / "evidence"

# 请求间隔：上游风控容忍度未知，取 8–12 秒随机，既不像脚本又有确定性上限。
PAUSE_MIN_SECONDS = 8.0
PAUSE_MAX_SECONDS = 12.0

# 本机没有 cfbypass（2026-09-24 复查 127.0.0.1:18001/18083 均未监听），
# 因此不注入 CF cookie；命中挑战即按 probe.py 的边界记录后停止。

# 只读扫描目标：设备标识最可能出现在页面与会话引导路径上，而 2026-09-24 的
# `/backend-api/me` 观测显示 API 响应只下发 `__oailb/__cf_bm/__cflb/_cfuvid`。
# 全部为读取或会话引导（sentinel 不创建任何资源），不含写入。
SCAN_TARGETS = [
    ("page_root", "GET", "/", None),
    ("sentinel_frame", "GET", "/backend-api/sentinel/frame.html", None),
    ("sentinel_sdk", "GET", "/sentinel/20260423af3c/sdk.js", None),
    ("chat_requirements_prepare", "POST", "/backend-api/sentinel/chat-requirements/prepare", {}),
]


def set_cookie_names(headers) -> list[str]:
    """`set-cookie` 只取名字段；值可能是会话凭据，一律不进证据。"""
    names = []
    for raw in headers.get_all("set-cookie") or []:
        name = raw.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def describe_with_cookies(
    status: int, headers, raw: bytes, elapsed: float, stopped_early: bool = False
) -> dict:
    entry = base.describe(status, headers, raw, elapsed, stopped_early)
    names = set_cookie_names(headers)
    entry["set_cookie_names"] = names
    entry["oai_did_set_cookie"] = "oai-did" in names
    return entry


def request(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    payload: dict | None,
    headers: dict[str, str] | None,
    timeout: float,
) -> dict:
    http_request = base.build_request(method, url, payload, headers)
    started = time.monotonic()
    try:
        with opener.open(http_request, timeout=timeout) as response:
            raw = response.read(base.MAX_BODY + 1)
            return describe_with_cookies(
                response.status, response.headers, raw, time.monotonic() - started
            )
    except urllib.error.HTTPError as error:
        return describe_with_cookies(
            error.code, error.headers, error.read(base.MAX_BODY + 1), time.monotonic() - started
        )
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return base.transport_failure(error, time.monotonic() - started)


def login(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    user: str,
    account_id: str,
    token: str,
    timeout: float,
) -> tuple[dict, str | None]:
    payload = base.login_payload(user, account_id, token)
    http_request = base.build_request(
        "POST",
        f"{base_url}/api/login",
        payload,
        {"authorization": f"Bearer {base.ADMIN_SECRET}"},
    )
    started = time.monotonic()
    mirror_token = None
    try:
        with opener.open(http_request, timeout=timeout) as response:
            raw = response.read(base.MAX_BODY + 1)
            entry = describe_with_cookies(
                response.status, response.headers, raw, time.monotonic() - started
            )
            if response.status == 200:
                mirror_token = base.extract_mirror_token(raw)
    except urllib.error.HTTPError as error:
        entry = describe_with_cookies(
            error.code, error.headers, error.read(base.MAX_BODY + 1), time.monotonic() - started
        )
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        entry = base.transport_failure(error, time.monotonic() - started)
    entry.update({"label": f"login:{user}", "route": "/api/login", "method": "POST"})
    return entry, mirror_token


def db_snapshot(db_path: Path) -> dict:
    """只读检查上游 cookie 落库：只看列是否存在、有多少行非空，不解密、不取值。"""
    snapshot = {"readable": False}
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as error:
        snapshot["error"] = type(error).__name__
        return snapshot
    try:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(gateway_sessions)")]
        snapshot["upstream_cookies_column"] = "upstream_cookies" in columns
        if snapshot["upstream_cookies_column"]:
            snapshot["sessions"] = connection.execute(
                "SELECT COUNT(*) FROM gateway_sessions"
            ).fetchone()[0]
            snapshot["sessions_with_upstream_cookies"] = connection.execute(
                "SELECT COUNT(*) FROM gateway_sessions WHERE upstream_cookies IS NOT NULL"
            ).fetchone()[0]
        snapshot["readable"] = True
    except sqlite3.Error as error:
        snapshot["error"] = type(error).__name__
    finally:
        connection.close()
    return snapshot


def create_conversation(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    headers: dict[str, str],
    timeout: float,
) -> tuple[dict, str | None]:
    """与 probe.py 同边界的一次真实新建：只读到出现会话 id 的块就断开。

    本函数额外记录响应 `set-cookie` 的名字（probe.py 的同名函数不记）。
    """
    body = json.loads(json.dumps(base.CREATE_BODY))
    body["messages"][0]["id"] = str(uuid.uuid4())
    http_request = base.build_request("POST", f"{base_url}{base.CREATE_ROUTE}", body, headers)
    started = time.monotonic()
    raw = bytearray()
    conversation_id: str | None = None
    stopped_early = False
    try:
        with opener.open(http_request, timeout=timeout) as response:
            while True:
                chunk = response.read(2048)
                if not chunk:
                    break
                raw.extend(chunk)
                found = base.CONVERSATION_ID_PATTERN.search(bytes(raw))
                if found:
                    conversation_id = found.group(1).decode("ascii")
                    stopped_early = True
                    break
                if len(raw) >= base.MAX_BODY or time.monotonic() - started > timeout:
                    stopped_early = True
                    break
            entry = describe_with_cookies(
                response.status,
                response.headers,
                bytes(raw),
                time.monotonic() - started,
                stopped_early,
            )
    except urllib.error.HTTPError as error:
        entry = describe_with_cookies(
            error.code, error.headers, error.read(base.MAX_BODY + 1), time.monotonic() - started
        )
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        entry = base.transport_failure(error, time.monotonic() - started)
    entry.update(
        {
            "label": "create_conversation",
            "route": base.CREATE_ROUTE,
            "method": "POST",
            "request_field_names": sorted(body.keys()),
            "conversation_id_found": conversation_id is not None,
            "device_header_sent_sha256": hashlib.sha256(
                headers.get("oai-device-id", "").encode("utf-8")
            ).hexdigest(),
        }
    )
    return entry, conversation_id


def write_evidence(path: Path, evidence: dict) -> None:
    path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def pause(
    rng: random.Random, evidence: dict, after: str, allow_pause: bool
) -> None:
    """上游请求之间的随机间隔；写进证据便于复核实际节奏。"""
    if not allow_pause:
        return
    seconds = round(rng.uniform(PAUSE_MIN_SECONDS, PAUSE_MAX_SECONDS), 1)
    evidence["pauses"].append({"after": after, "seconds": seconds})
    print(f"[probe] 随机间隔 {seconds}s（{after} 之后）", flush=True)
    time.sleep(seconds)


def gateway_env(
    args: argparse.Namespace, host: str, port: int, django_port: int, database: Path
) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "GATEWAY_UPSTREAM_MODE": "configured",
            "GATEWAY_COMPAT_PROFILE": "mirror",
            "HOST": host,
            "PORT": str(port),
            # 文件库：跑完用 sqlite3 只读检查设备 cookie 是否落库。
            "DATABASE_PATH": str(database),
            "GATEWAY_ADMIN_SECRET": base.ADMIN_SECRET,
            "CREDENTIAL_ENCRYPTION_KEY": base.ENCRYPTION_KEY,
            "DJANGO_UPSTREAM": f"http://127.0.0.1:{django_port}",
            "CHATGPT_BASE_URL": args.chatgpt_base,
            "CHATGPT_CDN_BASE_URL": args.cdn_base,
            "COOKIE_SECURE": "false",
            "REQUEST_TIMEOUT_SECS": str(int(args.timeout)),
            "GATEWAY_ALLOW_ANONYMOUS_SESSION": "false",
        }
    )
    if args.cf_bypass_url:
        env["CF_BYPASS_URL"] = args.cf_bypass_url
    return env


def run_probe(args: argparse.Namespace, token: str, out_path: Path, rng: random.Random) -> dict:
    browser_device_id = str(uuid.uuid4())
    workdir = Path(tempfile.mkdtemp(prefix="mirror-device-probe-"))
    database = workdir / "db.sqlite"
    evidence: dict = {
        "probe": "device-cookie-real-upstream",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "token_file": str(args.token_file),
        "access_token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "browser_device_id_sha256": hashlib.sha256(browser_device_id.encode("utf-8")).hexdigest(),
        "gateway": {
            "mode": "configured",
            "binary": str(args.binary),
            "database": "temp-file",
            "chatgpt_base": args.chatgpt_base,
            "cdn_base": args.cdn_base,
            "cf_bypass_configured": bool(args.cf_bypass_url),
            "request_timeout_secs": args.timeout,
            "real_write_allowed": bool(args.allow_real_write),
            "pause_seconds_range": [PAUSE_MIN_SECONDS, PAUSE_MAX_SECONDS],
        },
        "steps": [],
        "pauses": [],
        "db_snapshots": [],
        "notes": [],
    }
    steps = evidence["steps"]
    notes = evidence["notes"]
    allow_pause = not args.no_pause

    def snapshot(label: str) -> None:
        entry = db_snapshot(database)
        entry["label"] = label
        evidence["db_snapshots"].append(entry)
        write_evidence(out_path, evidence)

    authority = base.AuthorityServer(("127.0.0.1", 0), base.ADMIN_SECRET)
    threading.Thread(target=authority.serve_forever, daemon=True).start()
    host = "127.0.0.1"
    port = base.free_port()
    base_url = f"http://{host}:{port}"
    opener = urllib.request.build_opener(base.NoRedirect)
    log: list[str] = []
    process: subprocess.Popen | None = None
    try:
        process = base.start_gateway(
            args.binary,
            gateway_env(args, host, port, authority.server_address[1], database),
            token,
            log,
        )
        if not base.wait_for_listening(process, host, port, args.startup_seconds):
            notes.append("网关未在超时内监听：探针未发出任何上游请求。")
            return evidence

        # 1) 登录（触及上游：凭据换取 + me 校验）
        login_entry, mirror_token = login(
            opener, base_url, args.user, args.account_id, token, args.timeout
        )
        steps.append(login_entry)
        write_evidence(out_path, evidence)
        if mirror_token is None:
            notes.append("登录未成功：后续步骤未执行；按该步状态码判定原因。")
            return evidence
        session_headers = {"x-mirror-token": mirror_token}
        if login_entry.get("upstream_blocked"):
            notes.append("登录阶段即被 Cloudflare 拦截：按边界停止，不做任何写入。")
            return evidence

        # 2) 基线 `/backend-api/me`：不携带 oai-device-id，观察上游是否主动下发 oai-did。
        pause(rng, evidence, "login", allow_pause)
        me_entry = request(
            opener, "GET", f"{base_url}/backend-api/me", None, session_headers, args.timeout
        )
        me_entry.update({"label": "me_without_device_id", "route": "/backend-api/me", "method": "GET"})
        steps.append(me_entry)
        write_evidence(out_path, evidence)
        snapshot("after_me_without_device_id")
        if me_entry.get("upstream_blocked"):
            notes.append("基线 me 被 Cloudflare 拦截：按边界停止，不做任何写入。")
            return evidence
        if me_entry.get("oai_did_set_cookie"):
            notes.append("上游在未携带设备标识的请求上下发了 oai-did，捕获应已落到会话列。")
        else:
            notes.append("上游未在该响应下发 oai-did：设备标识只能来自浏览器请求头。")

        # 3) 浏览器播种：与真实浏览器一致，首个业务请求带 oai-device-id。
        #    `--skip-seed` 时不播种，用于验证「上游页面下发的 oai-did 能被捕获」这条独立路径。
        if not args.skip_seed and not args.capture_first:
            pause(rng, evidence, "me_without_device_id", allow_pause)
            seeded = request(
                opener,
                "GET",
                f"{base_url}/backend-api/me",
                None,
                {**session_headers, "oai-device-id": browser_device_id},
                args.timeout,
            )
            seeded.update(
                {
                    "label": "me_with_browser_device_id",
                    "route": "/backend-api/me",
                    "method": "GET",
                    "device_header_sent_sha256": hashlib.sha256(
                        browser_device_id.encode("utf-8")
                    ).hexdigest(),
                }
            )
            steps.append(seeded)
            write_evidence(out_path, evidence)
            snapshot("after_browser_device_id")
            if seeded.get("upstream_blocked"):
                notes.append("播种请求被 Cloudflare 拦截：按边界停止，不做任何写入。")
                return evidence
        else:
            reason = "--capture-first（生产顺序）" if args.capture_first else "--skip-seed"
            notes.append(f"{reason}：未发送浏览器设备标识，设备 cookie 只能来自上游响应。")

        # 只读扫描：设备标识是否出现在页面/SDK/会话引导路径上。
        # `--capture-first` 时这段同时也是「先让上游下发 oai-did，再发起写请求」的生产顺序。
        if args.scan_only or args.capture_first:
            for label, method, route, payload in SCAN_TARGETS:
                pause(rng, evidence, f"scan:{label}", allow_pause)
                entry = request(
                    opener, method, f"{base_url}{route}", payload, session_headers, args.timeout
                )
                entry.update({"label": label, "route": route, "method": method})
                steps.append(entry)
                write_evidence(out_path, evidence)
                snapshot(f"after_scan:{label}")
                if entry.get("upstream_blocked"):
                    notes.append(f"{label} 被 Cloudflare 拦截：该路径未取得真实证据。")
            scanned = [
                step for step in steps if step["label"] in {item[0] for item in SCAN_TARGETS}
            ]
            if any(step.get("oai_did_set_cookie") for step in scanned):
                notes.append("只读扫描命中 oai-did：真实上游确实下发该设备 cookie。")
            else:
                notes.append(
                    "只读扫描未命中 oai-did：本批观测到的上游 cookie 只有 __oailb/__cf_bm/__cflb/_cfuvid。"
                )

        if args.scan_only:
            notes.append("--scan-only：扫描完成，未发出任何写请求。")
            return evidence

        if not args.allow_real_write:
            notes.append("未传入 --allow-real-write：真实新建会话与其删除未执行。")
            return evidence

        # 4) 唯一一次真实写入：新建会话（带浏览器设备标识，模拟真实前端）。
        pause(rng, evidence, "before_create_conversation", allow_pause)
        create_entry, conversation_id = create_conversation(
            opener,
            base_url,
            {**session_headers, "oai-device-id": browser_device_id},
            args.timeout,
        )
        steps.append(create_entry)
        write_evidence(out_path, evidence)
        snapshot("after_create_conversation")
        if conversation_id is None:
            notes.append(
                "新建会话未返回会话 id：不猜第二个端点、不重试；"
                "若上游已在账号里留下会话，请在网页端手动删除。"
            )
            return evidence

        # 5) 属主直读：会话存在期间确认登记已完成。
        pause(rng, evidence, "create_conversation", allow_pause)
        owner_read = request(
            opener,
            "GET",
            f"{base_url}/backend-api/conversation/{conversation_id}",
            None,
            session_headers,
            args.timeout,
        )
        owner_read.update(
            {
                "label": "owner_read",
                "route": "/backend-api/conversation/{conversation_id}",
                "method": "GET",
                "conversation_id_sha256": base.conversation_id_digest(conversation_id),
            }
        )
        steps.append(owner_read)
        write_evidence(out_path, evidence)
        notes.append(
            "属主直读 200：登记在会话 id 下发之前完成。"
            if owner_read.get("status") == 200
            else f"属主直读得到 {owner_read.get('status')}：需人工确认。"
        )

        # 6) 第二个镜像用户：同一上游账号、不同镜像身份（该读在转发前被拒，不触上游）。
        pause(rng, evidence, "owner_read", allow_pause)
        second_entry, second_token = login(
            opener, base_url, args.user + "-b", args.account_id, token, args.timeout
        )
        steps.append(second_entry)
        write_evidence(out_path, evidence)
        if second_token:
            entry = request(
                opener,
                "GET",
                f"{base_url}/backend-api/conversation/{conversation_id}",
                None,
                {"x-mirror-token": second_token},
                args.timeout,
            )
            entry.update(
                {
                    "label": "second_user_read",
                    "route": "/backend-api/conversation/{conversation_id}",
                    "method": "GET",
                    "conversation_id_sha256": base.conversation_id_digest(conversation_id),
                }
            )
            steps.append(entry)
            notes.append(
                "第二个镜像用户在会话仍存在时读到 404 acl_not_found（判权在转发前返回）。"
                if entry.get("status") == 404 and entry.get("code") == "acl_not_found"
                else "第二个镜像用户未得到预期的 404 acl_not_found，需人工确认。"
            )
        else:
            notes.append("第二个镜像用户登录失败：跨用户隔离未取得真实证据。")
        write_evidence(out_path, evidence)

        # 7) 删除：唯一一次真实写入的收尾。
        pause(rng, evidence, "second_user_read", allow_pause)
        delete_route = base.DELETE_ROUTE_TEMPLATE.format(conversation_id=conversation_id)
        delete_entry = request(
            opener, "DELETE", f"{base_url}{delete_route}", None, session_headers, args.timeout
        )
        delete_entry.update(
            {
                "label": "delete_conversation",
                "route": base.DELETE_ROUTE_TEMPLATE,
                "method": "DELETE",
                "conversation_id_sha256": base.conversation_id_digest(conversation_id),
            }
        )
        steps.append(delete_entry)
        write_evidence(out_path, evidence)
        delete_ok = delete_entry.get("status") is not None and 200 <= int(delete_entry["status"]) < 300
        notes.append(
            "删除成功：会话归属判权在删除前已生效。"
            if delete_ok
            else "删除未返回 2xx：会话可能仍留在账号里，请在网页端手动删除；不要重复运行本探针。"
        )

        # 8) 删除后回到列表：确认账号里没有留下这次真实写入。
        pause(rng, evidence, "delete_conversation", allow_pause)
        listed = request(
            opener,
            "GET",
            f"{base_url}/backend-api/conversations?offset=0&limit=20",
            None,
            session_headers,
            args.timeout,
        )
        listed.update(
            {
                "label": "conversations_after_delete",
                "route": "/backend-api/conversations",
                "method": "GET",
                "query": "offset=0&limit=20",
            }
        )
        steps.append(listed)
        remaining = listed.get("item_count")
        notes.append(
            "删除后本镜像用户可见条目为 0。注意该视图是 ACL 过滤后的结果，"
            "不能证明账号里原本为空。"
            if remaining == 0
            else f"删除后列表仍有 {remaining} 条可见：请人工确认，不要重复运行本探针。"
        )
        return evidence
    finally:
        write_evidence(out_path, evidence)
        base.stop_process(process)
        authority.shutdown()
        authority.server_close()
        evidence["authority_calls"] = authority.calls
        evidence["gateway_log_lines"] = len(log)
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_evidence(out_path, evidence)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="设备 Cookie（oai-did）真实上游探针：文件库 + set-cookie 名字 + 随机间隔"
    )
    parser.add_argument("--token-file", type=Path, default=base.TOKEN_FILE)
    parser.add_argument("--evidence-dir", type=Path, default=EVIDENCE_DIR)
    parser.add_argument(
        "--binary",
        type=Path,
        default=PROBE_DIR.parent / "source" / "target" / "debug" / base.BINARY_NAME,
    )
    parser.add_argument("--chatgpt-base", default="https://chatgpt.com")
    parser.add_argument("--cdn-base", default="https://cdn.oaistatic.com")
    parser.add_argument("--cf-bypass-url", default=None)
    parser.add_argument("--account-id", default="1")
    parser.add_argument("--user", default="probe-alice")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--startup-seconds", type=float, default=20.0)
    parser.add_argument("--seed", type=int, default=None, help="随机间隔种子（复现用）")
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="关闭随机间隔（仅用于本地调试；真实运行必须保留间隔）",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="只跑只读扫描（页面/SDK/sentinel 引导）后停止，不发出任何写请求",
    )
    parser.add_argument(
        "--skip-seed",
        action="store_true",
        help="不发送浏览器 oai-device-id，用于单独验证上游 oai-did 的捕获路径",
    )
    parser.add_argument(
        "--capture-first",
        action="store_true",
        help="先跑只读扫描让上游下发 oai-did（生产顺序），再执行写流程；不发送伪造设备标识",
    )
    parser.add_argument(
        "--allow-real-write",
        action="store_true",
        help="执行恰好一次真实新建会话与其删除；默认不发出任何写请求",
    )
    args = parser.parse_args()

    token = base.read_token(args.token_file)
    if not args.binary.exists():
        raise SystemExit(
            f"未找到候选二进制 {args.binary}：先在 source/ 下执行 "
            "cargo build --locked --offline，或用 --binary 指定路径。"
        )
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.evidence_dir / f"device-cookie-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    rng = random.Random(args.seed)
    evidence = run_probe(args, token, out_path, rng)
    write_evidence(out_path, evidence)

    print("\n探针结果（证据文件只含状态码/响应头名/sha256，不含正文与令牌）")
    for step in evidence["steps"]:
        status = step.get("status")
        detail = (
            f"status={status}" if status is not None else f"transport={step.get('transport_error')}"
        )
        code = f" code={step['code']}" if "code" in step else ""
        device = " oai-did_set_cookie" if step.get("oai_did_set_cookie") else ""
        cookies = (
            f" set-cookie={','.join(step['set_cookie_names'])}"
            if step.get("set_cookie_names")
            else ""
        )
        print(f"  {step['method']:6} {step['route']:52} {detail}{code}{device}{cookies}")
    for entry in evidence["db_snapshots"]:
        print(
            f"  db[{entry['label']}] sessions={entry.get('sessions')} "
            f"with_upstream_cookies={entry.get('sessions_with_upstream_cookies')}"
        )
    for note in evidence["notes"]:
        print(f"  ! {note}")
    print(f"\n证据写入 {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

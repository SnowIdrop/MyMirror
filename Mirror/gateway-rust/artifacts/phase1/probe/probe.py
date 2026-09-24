#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Author  : MingTea
# File    : probe/probe.py
# Created : 2026-09-24
# Summary : 缺口 3 的真实上游探针。以 configured 模式启动候选网关（内存库、无常驻
#           改动），用 accessToken 换取镜像会话，只发已分类的读请求，并在显式开启
#           时执行恰好一次真实新建会话与其删除。
#           证据只落状态码、路由模板、字段名与 sha256；令牌、Cookie、响应正文与
#           标题一律不落盘、不打印、不进入命令行参数或环境变量。
#           边界见同目录 README.md；凭据草稿见 access-token.txt。
# -----------------------------------------------------------------------------

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROBE_DIR = Path(__file__).resolve().parent
TOKEN_FILE = PROBE_DIR / "access-token.txt"
EVIDENCE_DIR = PROBE_DIR / "evidence"
BINARY_NAME = "mirror-gateway.exe" if sys.platform == "win32" else "mirror-gateway"

# 占位符远短于真实令牌：用最小长度拒绝「忘记替换」比字符串比对更稳。
TOKEN_MIN_LENGTH = 32
# 上限内的正文只用于算 sha256、判断是否 HTML、提取 id；正文本身不进入证据。
MAX_BODY = 64 * 1024
ADMIN_SECRET = "probe-gateway-admin-secret-0001"
ENCRYPTION_KEY = "probe-credential-encryption-key-0000000001"

# 只读路径：全部来自 src/assets/chatgpt-api-routes.json 的路由快照，且已在
# server/acl.rs 中分类（集合或账号级）。没有任何写语义。
READ_PROBES = [
    ("me", "/backend-api/me"),
    ("accounts_check", "/backend-api/accounts/check/v4-2023-04-27"),
    ("conversations", "/backend-api/conversations?offset=0&limit=1"),
    ("projects", "/backend-api/projects"),
    ("files_library", "/backend-api/files/library/nodes"),
    ("tasks", "/backend-api/tasks"),
    ("task_suggestions", "/backend-api/task_suggestions"),
]

### 唯一一次写：新建会话与删除
CREATE_ROUTE = "/backend-api/f/conversation"
DELETE_ROUTE_TEMPLATE = "/backend-api/conversation/id/{conversation_id}"
# 新建会话的请求体形状**没有实测证据**（逆向材料只有路由模板与函数名），这里是按
# 公开前端常见字段写的最小载荷。上游若拒绝，探针只记录状态码后停止：不猜第二个
# 端点、不重试、不改写请求。
CREATE_BODY = {
    "action": "next",
    "messages": [
        {
            "id": None,  # 运行时填入随机 UUID
            "author": {"role": "user"},
            "content": {"content_type": "text", "parts": ["probe"]},
            "metadata": {},
        }
    ],
    "model": "auto",
    "parent_message_id": "probe-root",
    "conversation_mode": {"kind": "primary_assistant"},
    "timezone_offset_min": 480,
    "history_and_training_disabled": False,
}

# 只回传本候选自己定义的错误码，不搬运上游错误字段与文案。
LOCAL_CODES = {
    "acl_not_found",
    "acl_visitor_denied",
    "acl_unclassified_route",
    "generation_busy",
    "upstream_blocked",
}
# 本候选自己的错误文案（逐字取自 source/src/server*，随源码更新）。
# 只有与这张表逐字相同的 `message` 才会写进证据：这样「网关在发送阶段就失败」与
# 「上游答复了 502」可以区分，而上游正文、上游错误文案仍然只留 sha256。
LOCAL_MESSAGES = (
    "上游请求失败",
    "上游响应读取失败",
    "上游会话刷新失败",
    "上游用户信息缺少 email",
    "会话或出口绑定已失效",
    "未登录",
    "登录已失效，请重新登录",
    "本地未实现的 /api 路径",
    "该路径不支持此方法",
    "实时通道升级未开放",
    "WebSocket 桥接尚未支持代理出口",
    "集合响应读取失败",
    "集合响应序列化失败",
    "请求体读取失败",
    "静态资源上游不可用",
    "静态资源上游类型不匹配",
    "静态资源上游重定向未开放",
)
COLLECTION_KEYS = (
    "items",
    "data",
    "results",
    "conversations",
    "projects",
    "files",
    "tasks",
    "connectors",
)
CONVERSATION_ID_PATTERN = re.compile(rb'"conversation_id"\s*:\s*"([0-9a-fA-F-]{36})"')


def conversation_id_digest(conversation_id: str) -> str:
    """会话 id 只以 sha256 进证据：它足以核对两次运行指同一会话，又不泄露内容引用。"""
    return hashlib.sha256(conversation_id.encode("utf-8")).hexdigest()


def scrub(text: str, token: str) -> str:
    """打印网关子进程输出前抹掉令牌与 Bearer 值。

    网关自身不打印凭据，这里是最后一道保险：任何意外的凭据外泄都不得出现在终端或
    证据里，代价只有一次字符串替换。
    """
    if token:
        text = text.replace(token, "***")
    head, separator, _ = text.partition("Bearer ")
    return head + "Bearer ***" if separator else text


def read_token(path: Path) -> str:
    """读取凭据草稿里的 access_token 赋值行；只返回值，不打印任何内容。"""
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip() != "access_token":
            continue
        value = value.strip().strip("'\"")
        if len(value) < TOKEN_MIN_LENGTH or any(char.isspace() for char in value):
            raise SystemExit(
                f"{path} 里的 access_token 仍是占位符或未填完整："
                "请把 PASTE_ACCESS_TOKEN_HERE 替换成完整 AccessToken 后重试。"
            )
        return value
    raise SystemExit(f"{path} 里没有找到 `access_token = <值>` 赋值行。")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class AuthorityHandler(http.server.BaseHTTPRequestHandler):
    """本地 Django 授权桩：只回签名授权的身份字段，不接触真实 Django。"""

    server_version = "probe-authority/1"

    def log_message(self, *args) -> None:
        # 探针按调用次数汇总，不需要逐条访问日志。
        pass

    def do_POST(self) -> None:
        server = self.server
        server.calls += 1
        if self.headers.get("authorization", "") != "Bearer " + server.secret:
            self.send_response(401)
            self.end_headers()
            return
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            payload = {}
        if self.path == "/0x/user/gateway-acl-mapping":
            # 旧归属回填：探针用内存库，没有旧行可搬，回空表即可。
            body = {"users": [], "accounts": []}
        elif self.path == "/0x/user/gateway-authorization":
            subject = str(payload.get("subject") or "")
            digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
            body = {
                "active": True,
                "version": "probe-v1",
                "expires_at": int(time.time()) + 3600,
                "user_id": str(1000 + int(digest[:6], 16) % 8000),
                "is_admin": False,
                "subject": subject,
                "principal_kind": "user",
            }
        else:
            self.send_response(404)
            self.end_headers()
            return
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class AuthorityServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, secret: str):
        super().__init__(address, AuthorityHandler)
        self.secret = secret
        self.calls = 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：重定向目标不是本次探针的证据面。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def describe(status: int, headers, raw: bytes, elapsed: float, stopped_early: bool = False) -> dict:
    """把响应压成可入库的形状：状态、类型、长度、sha256、字段名，不含正文。"""
    body = raw[:MAX_BODY]
    content_type = (headers.get("content-type") or "").split(";")[0].strip().lower()
    entry = {
        "status": status,
        "content_type": content_type,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_truncated": len(raw) > MAX_BODY or stopped_early,
        "elapsed_ms": int(elapsed * 1000),
    }
    html_like = content_type == "text/html" or body.lstrip()[:1] == b"<"
    entry["html_like"] = html_like
    # Cloudflare 拦截判定：挑战头，或 403/502 加 HTML 正文（正文本身不落盘）。
    entry["upstream_blocked"] = bool(headers.get("cf-mitigated")) or (
        status in (403, 502) and html_like
    )
    if content_type == "application/json":
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = None
        if isinstance(payload, dict):
            entry["json_top_keys"] = sorted(payload.keys())[:32]
            for key in COLLECTION_KEYS:
                if isinstance(payload.get(key), list):
                    entry["item_count"] = len(payload[key])
                    break
            if isinstance(payload.get("total"), int):
                entry["total"] = payload["total"]
            if payload.get("code") in LOCAL_CODES:
                entry["code"] = payload["code"]
            if payload.get("message") in LOCAL_MESSAGES:
                entry["local_message"] = payload["message"]
    return entry


def transport_failure(error: Exception, elapsed: float) -> dict:
    """网络失败是探针的正常结果之一（真实上游可能拦截或超时），按结论记录。"""
    return {
        "status": None,
        "transport_error": type(error).__name__,
        "elapsed_ms": int(elapsed * 1000),
    }


def http_request(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> dict:
    request = build_request(method, url, payload, headers)
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_BODY + 1)
            return describe(response.status, response.headers, raw, time.monotonic() - started)
    except urllib.error.HTTPError as error:
        raw = error.read(MAX_BODY + 1)
        return describe(error.code, error.headers, raw, time.monotonic() - started)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return transport_failure(error, time.monotonic() - started)


def build_request(
    method: str,
    url: str,
    payload: dict | None,
    headers: dict[str, str] | None,
) -> urllib.request.Request:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("accept", "application/json")
    if data is not None:
        request.add_header("content-type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    return request


def login_payload(user: str, account_id: str, token: str) -> dict:
    """镜像登录载荷：身份字段由本地授权桩回填，凭据只有 accessToken。"""
    return {
        "user_name": user,
        "authorization": "probe-signature-v1",
        "access_token": token,
        "chatgpt_account_id": account_id,
        "login_mode": "api",
        "isolated_session": True,
        # 隔离开关是产品策略面，不是本次探针对象：全部关闭，避免策略拦掉验收路径。
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
        "extra_cookies": [],
    }


def login(
    opener: urllib.request.OpenerDirector,
    base: str,
    user: str,
    account_id: str,
    token: str,
    timeout: float,
) -> tuple[dict, str | None]:
    """登录并取回镜像会话 token；响应正文只用于取本地 token，不进入证据。"""
    request = build_request(
        "POST",
        f"{base}/api/login",
        login_payload(user, account_id, token),
        {"authorization": f"Bearer {ADMIN_SECRET}"},
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_BODY + 1)
            entry = describe(response.status, response.headers, raw, time.monotonic() - started)
            mirror_token = extract_mirror_token(raw) if response.status == 200 else None
    except urllib.error.HTTPError as error:
        entry = describe(error.code, error.headers, error.read(MAX_BODY + 1), time.monotonic() - started)
        mirror_token = None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        entry = transport_failure(error, time.monotonic() - started)
        mirror_token = None
    entry.update({"label": f"login:{user}", "route": "/api/login", "method": "POST"})
    return entry, mirror_token


def extract_mirror_token(raw: bytes) -> str | None:
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    login_url = str(body.get("login_url") or "")
    if "user_gateway_token=" not in login_url:
        return None
    return login_url.split("user_gateway_token=", 1)[1].split("&", 1)[0]


def create_conversation(
    opener: urllib.request.OpenerDirector,
    base: str,
    headers: dict[str, str],
    timeout: float,
) -> tuple[dict, str | None]:
    """恰好一次真实新建会话。

    只读到出现会话 id 的那个块就断开：上游的实际生成不必跑完，网关的归属登记发生
    在含 id 的块下发之前，所以断开前登记已经完成。断流本身也是「生成类请求不重放」
    之外的一次真实观测。
    """
    body = json.loads(json.dumps(CREATE_BODY))
    body["messages"][0]["id"] = str(uuid.uuid4())
    request = build_request("POST", f"{base}{CREATE_ROUTE}", body, headers)
    started = time.monotonic()
    raw = bytearray()
    conversation_id: str | None = None
    stopped_early = False
    try:
        with opener.open(request, timeout=timeout) as response:
            while True:
                chunk = response.read(2048)
                if not chunk:
                    break
                raw.extend(chunk)
                found = CONVERSATION_ID_PATTERN.search(bytes(raw))
                if found:
                    conversation_id = found.group(1).decode("ascii")
                    stopped_early = True
                    break
                if len(raw) >= MAX_BODY or time.monotonic() - started > timeout:
                    stopped_early = True
                    break
            entry = describe(
                response.status,
                response.headers,
                bytes(raw),
                time.monotonic() - started,
                stopped_early,
            )
    except urllib.error.HTTPError as error:
        entry = describe(
            error.code, error.headers, error.read(MAX_BODY + 1), time.monotonic() - started
        )
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        entry = transport_failure(error, time.monotonic() - started)
    entry.update(
        {
            "label": "create_conversation",
            "route": CREATE_ROUTE,
            "method": "POST",
            "request_field_names": sorted(body.keys()),
            "conversation_id_found": conversation_id is not None,
        }
    )
    return entry, conversation_id


def wait_for_listening(process: subprocess.Popen, host: str, port: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.2)
    return False


def start_gateway(
    binary: Path, env: dict[str, str], token: str, log: list[str]
) -> subprocess.Popen:
    process = subprocess.Popen(
        [str(binary)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    def pump() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line = scrub(line.rstrip("\n"), token)
            log.append(line)
            print(f"[gateway] {line}", flush=True)

    threading.Thread(target=pump, daemon=True).start()
    return process


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def gateway_env(args: argparse.Namespace, host: str, port: int, django_port: int) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "GATEWAY_UPSTREAM_MODE": "configured",
            "GATEWAY_COMPAT_PROFILE": "mirror",
            "HOST": host,
            "PORT": str(port),
            # 内存库：探针不落任何本地状态，进程退出即清空。
            "DATABASE_PATH": ":memory:",
            "GATEWAY_ADMIN_SECRET": ADMIN_SECRET,
            "CREDENTIAL_ENCRYPTION_KEY": ENCRYPTION_KEY,
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


def run_probe(args: argparse.Namespace, token: str) -> dict:
    evidence: dict = {
        "probe": "gap3-real-upstream",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "token_file": str(args.token_file),
        "access_token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "gateway": {
            "mode": "configured",
            "binary": str(args.binary),
            "database": ":memory:",
            "chatgpt_base": args.chatgpt_base,
            "cdn_base": args.cdn_base,
            "cf_bypass_configured": bool(args.cf_bypass_url),
            "request_timeout_secs": args.timeout,
            "real_write_allowed": bool(args.allow_real_write),
        },
        "steps": [],
        "notes": [],
    }
    steps = evidence["steps"]
    notes = evidence["notes"]

    authority = AuthorityServer(("127.0.0.1", 0), ADMIN_SECRET)
    threading.Thread(target=authority.serve_forever, daemon=True).start()
    host = "127.0.0.1"
    port = free_port()
    base = f"http://{host}:{port}"
    opener = urllib.request.build_opener(NoRedirect)
    log: list[str] = []
    process: subprocess.Popen | None = None
    try:
        process = start_gateway(
            args.binary, gateway_env(args, host, port, authority.server_address[1]), token, log
        )
        if not wait_for_listening(process, host, port, args.startup_seconds):
            notes.append("网关未在超时内监听：探针未发出任何上游请求。")
            return evidence

        login_entry, mirror_token = login(
            opener, base, args.user, args.account_id, token, args.timeout
        )
        steps.append(login_entry)
        if mirror_token is None:
            notes.append(
                "登录未成功，后续业务请求未发出：可能是令牌失效、用户名与授权桩不匹配，"
                "或上游被拦截；按该步状态码判定。"
            )
            return evidence
        session_headers = {"x-mirror-token": mirror_token}

        blocked_any = False
        for label, route in READ_PROBES:
            path, _, query = route.partition("?")
            entry = http_request(opener, "GET", f"{base}{route}", None, session_headers, args.timeout)
            entry.update({"label": label, "route": path, "method": "GET"})
            if query:
                entry["query"] = query
            steps.append(entry)
            if entry.get("upstream_blocked"):
                blocked_any = True
                notes.append(
                    f"{label} 被 Cloudflare 拦截："
                    + (
                        "已配置 CF_BYPASS_URL，刷新并重放一次后仍被拦。"
                        if args.cf_bypass_url
                        else "未配置 CF_BYPASS_URL，网关无法刷新，该路径未取得真实证据。"
                    )
                )
            elif entry.get("status") is None:
                notes.append(
                    f"{label} 传输失败（{entry['transport_error']}），该路径未取得真实证据。"
                )
            elif not 200 <= int(entry["status"]) < 300:
                notes.append(f"{label} 返回非 2xx，按实际状态记录，未重试。")

        if blocked_any:
            notes.append("读路径已出现拦截：按既定边界停止，写路径未执行。")
            return evidence

        if not args.allow_real_write:
            notes.append(
                "未传入 --allow-real-write：本次只跑读路径，真实新建会话与其删除未执行。"
            )
            return evidence

        create_entry, conversation_id = create_conversation(
            opener, base, session_headers, args.timeout
        )
        steps.append(create_entry)
        if conversation_id is None:
            notes.append(
                "新建会话未返回会话 id：不猜测第二个端点、不重试；"
                "若上游已在账号里留下会话，请在网页端手动删除。"
            )
            return evidence

        # 属主直读：能拿到 200 说明创建时已登记归属，且登记发生在客户端拿到 id 之前。
        owner_read = http_request(
            opener,
            "GET",
            f"{base}/backend-api/conversation/{conversation_id}",
            None,
            session_headers,
            args.timeout,
        )
        owner_read.update(
            {
                "label": "owner_read",
                "route": "/backend-api/conversation/{conversation_id}",
                "method": "GET",
                "conversation_id_sha256": conversation_id_digest(conversation_id),
            }
        )
        steps.append(owner_read)
        notes.append(
            "属主直读新建会话 200：登记在 id 下发之前已完成。"
            if owner_read.get("status") == 200
            else f"属主直读得到 {owner_read.get('status')}：登记或上游读取存在偏差，需人工确认。"
        )

        # 第二个镜像用户：同一上游账号、不同镜像身份。必须在**会话仍存在**时判定，
        # 否则 404 也可能只是「已被删除」，证明不了归属隔离。
        second_entry, second_token = login(
            opener, base, args.user + "-b", args.account_id, token, args.timeout
        )
        steps.append(second_entry)
        if second_token:
            entry = http_request(
                opener,
                "GET",
                f"{base}/backend-api/conversation/{conversation_id}",
                None,
                {"x-mirror-token": second_token},
                args.timeout,
            )
            entry.update(
                {
                    "label": "second_user_read",
                    "route": "/backend-api/conversation/{conversation_id}",
                    "method": "GET",
                    "conversation_id_sha256": conversation_id_digest(conversation_id),
                }
            )
            steps.append(entry)
            notes.append(
                "第二个镜像用户在会话仍存在时读到 404 acl_not_found（该分支在转发前返回，"
                "不接触上游；上游调用计数为 0 由合成回环用例保证）。"
                if entry.get("status") == 404 and entry.get("code") == "acl_not_found"
                else "第二个镜像用户未得到预期的 404 acl_not_found，需人工确认。"
            )
        else:
            notes.append("第二个镜像用户登录失败：跨用户隔离未取得真实证据。")

        delete_route = DELETE_ROUTE_TEMPLATE.format(conversation_id=conversation_id)
        delete_entry = http_request(
            opener, "DELETE", f"{base}{delete_route}", None, session_headers, args.timeout
        )
        delete_entry.update(
            {
                "label": "delete_conversation",
                "route": DELETE_ROUTE_TEMPLATE,
                "method": "DELETE",
                "conversation_id_sha256": conversation_id_digest(conversation_id),
            }
        )
        steps.append(delete_entry)
        # 删除同样是作用域请求：通过则说明本人对本会话有删除权。
        delete_ok = delete_entry.get("status") is not None and 200 <= int(delete_entry["status"]) < 300
        notes.append(
            "删除成功：会话归属登记在删除判权前已生效。"
            if delete_ok
            else "删除未返回 2xx：会话可能仍留在账号里，请在网页端手动删除；"
            "不要重复运行本探针。"
        )

        # 删除后回到列表：确认账号里没有留下这次真实写入。
        listed = http_request(
            opener,
            "GET",
            f"{base}/backend-api/conversations?offset=0&limit=20",
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
            "删除后列表可见条目为 0：本次真实写入没有在账号里留下会话。"
            if remaining == 0
            else f"删除后列表仍有 {remaining} 条：请人工确认，不要重复运行本探针。"
        )
        return evidence
    finally:
        stop_process(process)
        authority.shutdown()
        authority.server_close()
        evidence["authority_calls"] = authority.calls
        evidence["gateway_log_lines"] = len(log)
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="缺口 3 的真实上游探针（默认只读）")
    parser.add_argument("--token-file", type=Path, default=TOKEN_FILE)
    parser.add_argument("--evidence-dir", type=Path, default=EVIDENCE_DIR)
    parser.add_argument(
        "--binary",
        type=Path,
        default=PROBE_DIR.parent / "source" / "target" / "debug" / BINARY_NAME,
    )
    parser.add_argument("--chatgpt-base", default="https://chatgpt.com")
    parser.add_argument("--cdn-base", default="https://cdn.oaistatic.com")
    parser.add_argument("--cf-bypass-url", default=None)
    parser.add_argument("--account-id", default="1")
    parser.add_argument("--user", default="probe-alice")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--startup-seconds", type=float, default=20.0)
    parser.add_argument(
        "--allow-real-write",
        action="store_true",
        help="执行恰好一次真实新建会话与其删除；默认不发出任何写请求",
    )
    args = parser.parse_args()

    token = read_token(args.token_file)
    if not args.binary.exists():
        raise SystemExit(
            f"未找到候选二进制 {args.binary}：先在 source/ 下执行 "
            "cargo build --locked --offline，或用 --binary 指定路径。"
        )
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = run_probe(args, token)
    out = args.evidence_dir / f"probe-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("\n探针结果（证据文件只含状态码/字段名/sha256，不含正文与令牌）")
    for step in evidence["steps"]:
        status = step.get("status")
        detail = (
            f"status={status}" if status is not None else f"transport={step.get('transport_error')}"
        )
        code = f" code={step['code']}" if "code" in step else ""
        blocked = " upstream_blocked" if step.get("upstream_blocked") else ""
        count = f" items={step['item_count']}" if "item_count" in step else ""
        print(f"  {step['method']:6} {step['route']:52} {detail}{code}{blocked}{count}")
    for note in evidence["notes"]:
        print(f"  ! {note}")
    print(f"\n证据写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

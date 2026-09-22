"""Synthetic proxy/session-list observations for original/candidate/rollback.
Author: MingTea. Disposable guest only; loopback upstreams only; no external network.

Phase 0 reproduces the session cases shared with tools/observe_guest.py (fresh empty
state) so the three proxy session diffs stay comparable with
evidence/baseline-final-2: /0x/user/version-cfg passthrough, /backend-api/me raw
body and /backend-api/conversations isolation.
Phases 1-3 add raw-body/header shapes, dual-user shared-account ownership
filtering, pagination/total, invalid parameters, duplicate items, upstream
failures/malformed responses and restart persistence. Every upstream call and every
conversation table change is recorded.
The same case ids are emitted for every subject so results.json stays comparable.
"""
import hashlib
import http.client
import http.server
import json
import os
import shutil
import sqlite3
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlsplit

SECRET = "contract-admin-secret-0001"
KEY = "contract-encryption-key-000000000000001"
PORT = 40100
STUB_PORT = 18090
PUBLIC_IP = "93.184.216.34"  # literal IP; QEMU guest has no NIC, nothing can leave
BASELINE_SHA256 = "4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098"


def emit(value):
    print("RESULT:" + json.dumps(value, ensure_ascii=False), flush=True)


binary = os.environ.get("GATEWAY_TEST_BINARY", "/app/chatgpt-mirror-gateway")
subject = os.environ.get("GATEWAY_TEST_SUBJECT", "original")

if subject == "rollback":
    shutil.copyfile("/app/candidate", "/app/rollback-copy")
    result = subprocess.run(
        ["/app/ROLLBACK.sh", "/app/rollback-copy"], capture_output=True, text=True
    )
    digest = hashlib.sha256(open("/app/rollback-copy", "rb").read()).hexdigest()
    emit(
        {
            "kind": "rollback",
            "command": ["/app/ROLLBACK.sh", "/app/rollback-copy"],
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit": result.returncode,
            "sha256": digest,
        }
    )
    assert result.returncode == 0 and digest == BASELINE_SHA256
    binary = "/app/rollback-copy"


def emit_startup_probes():
    for value in (None, "short", SECRET):
        env = {"PATH": os.environ["PATH"], "DATABASE_PATH": "/tmp/startup-proxy.db",
               "PORT": "40002"}
        if value is not None:
            env["GATEWAY_ADMIN_SECRET"] = value
        if value == SECRET:
            env["GATEWAY_ADMIN_SECRET"] = "short"
            env["PORT"] = "bad"
        result = subprocess.run([binary], env=env, capture_output=True, text=True,
                                timeout=15)
        emit(
            {
                "kind": "startup",
                "secret": env.get("GATEWAY_ADMIN_SECRET"),
                "input_port": env["PORT"],
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit": result.returncode,
            }
        )


# ---------------------------------------------------------------------------
# Loopback stub upstream. Modes are switchable per phase; "default" reproduces
# the exact fixtures of tools/observe_guest.py.
# ---------------------------------------------------------------------------
mode = {"me": "default", "conv": "default"}
stub_case = {"id": None}
SMALL = ["conv-%d" % index for index in range(1, 6)]
BIG = ["conv-%03d" % index for index in range(1, 51)]
# Valid JSON whose whitespace, key order and non-ASCII payload survive only if the
# body is forwarded byte-for-byte instead of being re-serialized.
RAW_ME_BODY = (
    '{\n  "name" : "Fixture",\n  "id":"synthetic-id",\n'
    '  "email" :"fixture@example.invalid",\n  "unicode" : "中文-✓"\n}\n'
)
HTML_BODY = b"<html><body>probe-page</body></html>"


def set_mode(record=True, **kwargs):
    mode.update(kwargs)
    if record:
        emit({"kind": "mode", **mode})


def conv_payload(universe, path):
    query = parse_qs(urlsplit(path).query)

    def number(name, default):
        raw = query.get(name, [str(default)])[0]
        try:
            return int(raw)
        except ValueError:
            return default

    offset = max(0, number("offset", 0))
    limit = max(0, min(number("limit", 20), 50))
    items = [
        {
            "id": conversation,
            "title": "title-" + conversation,
            "create_time": 1790064000 + offset + index,
            "update_time": 1790064000 + offset + index,
        }
        for index, conversation in enumerate(universe[offset:offset + limit])
    ]
    return {"items": items, "total": len(universe), "limit": limit, "offset": offset}


class Stub(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        emit(
            {
                "kind": "upstream",
                "case": stub_case["id"],
                "mode": dict(mode),
                "method": self.command,
                "path": self.path,
                "headers": list(self.headers.items()),
                "body": body.decode("utf-8", errors="replace"),
            }
        )
        if self.path.startswith("/cloudflare5s/"):
            self.send(
                200,
                {
                    "cookies": [
                        {
                            "name": "cf_probe",
                            "value": "EXTRA1",
                            "domain": "127.0.0.1",
                            "path": "/",
                        },
                        {
                            "name": "cf_clearance",
                            "value": "SYNTHETIC",
                            "domain": "127.0.0.1",
                            "path": "/",
                        },
                    ],
                    "user_agent": "ContractFixture/1",
                },
            )
            return
        if self.path.startswith("/backend-api/me"):
            self.me()
            return
        if self.path.startswith("/backend-api/conversations"):
            self.conversations()
            return
        if "/probe/" in self.path:
            if "/probe/html" in self.path:
                self.send_raw(200, HTML_BODY, content_type="text/html")
                return
            self.send(
                200,
                {"probe": True, "path": self.path, "method": self.command},
                extra_headers=[
                    ("Content-Security-Policy", "STUB-CSP-MARKER"),
                    ("X-Upstream-Marker", "csp-probe"),
                    ("Cache-Control", "public, max-age=99"),
                ],
            )
            return
        self.send(200, {"stub": True, "path": self.path, "method": self.command})

    def me(self):
        if mode["me"] == "raw":
            self.send_raw(200, RAW_ME_BODY.encode(), extra_headers=[
                ("X-Stub-Serialization", "raw-spacing"),
            ])
        elif mode["me"] == "html":
            self.send_raw(200, HTML_BODY, content_type="text/html")
        elif mode["me"] == "error":
            self.send(500, {"detail": "me upstream failure"})
        elif mode["me"] == "badjson":
            self.send_raw(200, b"not-json{", content_type="application/json")
        else:
            self.send(
                200,
                {"id": "synthetic-id", "email": "fixture@example.invalid", "name": "Fixture"},
            )

    def conversations(self):
        if mode["conv"] == "default":
            self.send(200, {"stub": True, "path": self.path, "method": self.command})
        elif mode["conv"] == "error":
            self.send(503, {"detail": "conversations upstream failure"})
        elif mode["conv"] == "badjson":
            self.send_raw(200, b"<html>not json</html>", content_type="text/html")
        elif mode["conv"] == "empty":
            self.send(200, {"items": [], "total": 0})
        elif mode["conv"] == "extra":
            items = conv_payload(SMALL, self.path)["items"][:1]
            items[0]["extra_item_field"] = "keep"
            self.send(200, {"items": items, "total": 7, "limit": 20, "offset": 0,
                            "cursor": "abc", "ext": "junk"})
        elif mode["conv"] == "error500":
            self.send(500, {"detail": "conversations upstream 500"})
        elif mode["conv"] == "dup":
            items = conv_payload(SMALL, self.path)["items"][:2]
            self.send(200, {"items": items + items, "total": len(SMALL)})
        elif mode["conv"] == "big":
            self.send(200, conv_payload(BIG, self.path))
        else:
            self.send(200, conv_payload(SMALL, self.path))

    def send(self, status, payload, extra_headers=()):
        self.send_raw(status, json.dumps(payload).encode(), extra_headers=extra_headers)

    def send_raw(self, status, data, content_type="application/json", extra_headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)


server = http.server.ThreadingHTTPServer(("127.0.0.1", STUB_PORT), Stub)
threading.Thread(target=server.serve_forever, daemon=True).start()


def gateway_env(database):
    return {
        "PATH": os.environ["PATH"],
        "HOST": "127.0.0.1",
        "PORT": str(PORT),
        "DATABASE_PATH": database,
        "GATEWAY_ADMIN_SECRET": SECRET,
        "CREDENTIAL_ENCRYPTION_KEY": KEY,
        "REQUEST_TIMEOUT_SECS": "2",
        "DJANGO_UPSTREAM": f"http://127.0.0.1:{STUB_PORT}",
        "ADMIN_UPSTREAM": f"http://127.0.0.1:{STUB_PORT}",
        "CF_BYPASS_URL": f"http://127.0.0.1:{STUB_PORT}",
        "CHATGPT_BASE_URL": f"http://127.0.0.1:{STUB_PORT}",
        "CHATGPT_CDN_BASE_URL": f"http://127.0.0.1:{STUB_PORT}",
        "CHATGPT_AB_BASE_URL": f"http://127.0.0.1:{STUB_PORT}",
        "GATEWAY_COMPAT_PROFILE": "original",
    }


gateway = None
gateway_log = None


def start_gateway(database):
    global gateway, gateway_log
    tag = os.path.basename(database)
    gateway_log = (
        open("/tmp/proxy-" + tag + ".out", "w+"),
        open("/tmp/proxy-" + tag + ".err", "w+"),
    )
    gateway = subprocess.Popen(
        [binary], env=gateway_env(database), stdout=gateway_log[0], stderr=gateway_log[1]
    )
    for _ in range(150):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=0.2)
            conn.connect()
            conn.close()
            return
        except OSError:
            if gateway.poll() is not None:
                raise RuntimeError("Gateway exited during startup: " + str(gateway.returncode))
            time.sleep(0.1)
    raise TimeoutError("Gateway did not listen in time")


def stop_gateway():
    global gateway, gateway_log
    if gateway is None:
        return
    gateway.terminate()
    gateway.wait(timeout=10)
    gateway_log[0].seek(0)
    gateway_log[1].seek(0)
    emit(
        {
            "kind": "process",
            "stdout": gateway_log[0].read(),
            "stderr": gateway_log[1].read(),
            "exit": gateway.returncode,
        }
    )
    gateway_log[0].close()
    gateway_log[1].close()
    gateway = None


def raw_call(method, path, payload=None, auth=False, headers=None, kind="http", case=None,
             extra=None, timeout=8, content_type=True):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request_headers = dict(headers or {})
    if auth:
        request_headers["Authorization"] = "Bearer " + SECRET
    if body is not None and content_type:
        request_headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        data = response.read().decode("utf-8", errors="replace")
        record = {
            "kind": kind,
            "id": case,
            "method": method,
            "path": path,
            "auth": auth,
            "input": payload,
            "status": response.status,
            "headers": response.getheaders(),
            "body": data,
        }
        if extra:
            record.update(extra)
        emit(record)
        return response.status, response.getheaders(), data
    finally:
        conn.close()


def scenario(case, method, path, payload=None, auth=True, headers=None, timeout=8,
             content_type=True):
    return raw_call(method, path, payload, auth, headers, "scenario", case, None, timeout,
                    content_type)


def probe(case, method, path, payload=None, cookie=None, headers=None, timeout=10):
    """Session-cookie call whose upstream trace is tagged with the case id."""
    stub_case["id"] = case
    request_headers = dict(headers or {})
    if cookie:
        request_headers["Cookie"] = cookie
    try:
        return scenario(case, method, path, payload, False, request_headers, timeout)
    finally:
        stub_case["id"] = None


def db_rows(database, sql, args=()):
    conn = sqlite3.connect(database, timeout=5)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def db_execute(database, sql, args=()):
    conn = sqlite3.connect(database, timeout=5)
    try:
        conn.execute(sql, args)
        conn.commit()
    finally:
        conn.close()


OWNERS_SQL = ("SELECT chatgpt_username, conversation_id, user_name, created_at, updated_at"
              " FROM conversation_owners ORDER BY chatgpt_username, conversation_id")
STATISTICS_SQL = ("SELECT chatgpt_username, conversation_id, user_name, title, message_count,"
                  " conversation_counted, created_at, updated_at FROM conversation_statistics"
                  " ORDER BY chatgpt_username, conversation_id")


def dump_table(database, case, table, sql):
    emit({"kind": "db", "case": case, "table": table, "rows": db_rows(database, sql)})


def dump_conversations(database, case):
    dump_table(database, case, "conversation_owners", OWNERS_SQL)
    dump_table(database, case, "conversation_statistics", STATISTICS_SQL)


OWNER_SEEDS = [
    ("fixture@example.invalid", "conv-2", "alice"),
    ("fixture@example.invalid", "conv-4", "bob"),
    ("other@example.invalid", "conv-3", "carol"),
    ("fixture@example.invalid", "conv-007", "alice"),
    ("fixture@example.invalid", "conv-009", "bob"),
    ("other@example.invalid", "conv-011", "carol"),
    # Cross-account scope probes: alice rows outside the session account. If the
    # list filter or the total count ignored chatgpt_username these would leak.
    ("other@example.invalid", "conv-1", "alice"),
    ("other@example.invalid", "conv-90", "alice"),
]


def login(case, user="alice", extra_cookies=None):
    return scenario(
        case,
        "POST",
        "/api/login",
        {
            "user_name": user,
            "access_token": "synthetic-access-token",
            "session_token": "",
            "login_mode": "api",
            "isolated_session": True,
            "limits": [],
            "daily_quota": 0,
            "monthly_quota": 0,
            "force_chat_mode": True,
            **({"extra_cookies": extra_cookies} if extra_cookies else {}),
        },
    )


def handoff_cookie(case, login_body, join_all=False):
    login_url = json.loads(login_body)["login_url"]
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    conn.request("GET", login_url)
    response = conn.getresponse()
    cookies = [
        value.split(";", 1)[0]
        for name, value in response.getheaders()
        if name.lower() == "set-cookie"
    ]
    emit(
        {
            "kind": "scenario",
            "id": case,
            "method": "GET",
            "path": login_url.split("?")[0],
            "auth": False,
            "status": response.status,
            "headers": response.getheaders(),
            "body": response.read().decode(errors="replace"),
        }
    )
    conn.close()
    if join_all:
        return "; ".join(cookies)
    for cookie in cookies:
        if cookie.startswith("mirror_token="):
            return cookie
    return ""


def phase0_shared_surface(database):
    """Reproduce the session surface shared with tools/observe_guest.py."""
    _, _, body = login("login-fixture")
    cookie = handoff_cookie("handoff", body, join_all=True)
    for path in (
        "/api/auth/session",
        "/api/user-blocked-paths",
        "/backend-api/me",
        "/backend-api/conversations?offset=0&limit=20",
        "/0x/user/version-cfg?fixture=1",
    ):
        stub_case["id"] = "session:" + path
        scenario("session:" + path, "GET", path, None, False, {"Cookie": cookie})
    stub_case["id"] = None


def phase1_dual_user_probes(database, live):
    """Two mirror users share one chatgpt account; probes for raw body and headers."""
    _, _, body_a = login("p1-login-alice")
    live["alice"] = handoff_cookie("p1-handoff-alice", body_a)
    _, _, body_b = login("p1-login-bob", user="bob")
    live["bob"] = handoff_cookie("p1-handoff-bob", body_b)
    emit(
        {
            "kind": "db",
            "case": "p1-sessions",
            "table": "gateway_sessions",
            "rows": db_rows(
                database,
                "SELECT user_name, chatgpt_username, login_mode FROM gateway_sessions"
                " ORDER BY user_name",
            ),
        }
    )

    set_mode(me="raw")
    probe("p1-me-raw", "GET", "/backend-api/me", cookie=live["alice"])
    probe(
        "p1-me-client-headers",
        "GET",
        "/backend-api/me",
        cookie=live["alice"],
        headers={
            "User-Agent": "ProbeUA/1.0",
            "Origin": "https://probe.example",
            "Referer": "https://probe.example/page",
            "Accept": "text/probe",
            "Accept-Language": "zz-ZZ",
            "Authorization": "Bearer CLIENT-THROWAWAY",
            "X-Custom-E2E": "keep-me",
        },
    )
    set_mode(me="error")
    probe("p1-me-upstream-error", "GET", "/backend-api/me", cookie=live["alice"])
    set_mode(me="badjson")
    probe("p1-me-upstream-badjson", "GET", "/backend-api/me", cookie=live["alice"])
    set_mode(me="default")
    probe("p1-me-no-cookie", "GET", "/backend-api/me")
    probe("p1-me-bad-cookie", "GET", "/backend-api/me",
          cookie="mirror_token=deadbeef")
    set_mode(me="html")
    probe("p1-me-html", "GET", "/backend-api/me", cookie=live["alice"])
    probe("p1-me-html-bob", "GET", "/backend-api/me", cookie=live["bob"])
    scenario('p1-work-false', 'POST', '/api/user-work-mode', {'user_name':'alice','force_chat_mode':False}, True)
    probe('p1-me-html-work-false', 'GET', '/backend-api/me', cookie=live['alice'])
    scenario('p1-work-true', 'POST', '/api/user-work-mode', {'user_name':'alice','force_chat_mode':True}, True)
    set_mode(me="default")

    probe("p1-cfg-base", "GET", "/0x/user/version-cfg?fixture=1", cookie=live["alice"])
    probe("p1-cfg-token-authorization", "GET", "/0x/user/version-cfg?fixture=1", headers={"Authorization":"Token synthetic-django-token"})
    probe("p1-cfg-bearer-authorization", "GET", "/0x/user/version-cfg?fixture=1", headers={"Authorization":"Bearer synthetic-client-value"})
    probe(
        "p1-cfg-client-ip-headers",
        "GET",
        "/0x/user/version-cfg?fixture=1",
        cookie=live["alice"],
        headers={"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.7"},
    )
    probe(
        "p1-cfg-spoofed-header",
        "GET",
        "/0x/user/version-cfg?fixture=1",
        cookie=live["alice"],
        headers={"X-Chatgpt-Mirror-Client-Ip": "198.51.100.5"},
    )
    probe(
        "p1-cfg-post",
        "POST",
        "/0x/user/version-cfg?fixture=1",
        payload={"ping": 1},
        cookie=live["alice"],
    )
    probe("p1-cfg-no-cookie", "GET", "/0x/user/version-cfg?fixture=1")
    probe("p1-probe-0x", "GET", "/0x/probe/headers", cookie=live["alice"])
    probe("p1-probe-chat", "GET", "/backend-api/probe/headers", cookie=live["alice"])
    probe("p1-probe-html-0x", "GET", "/0x/probe/html?fixture=1", cookie=live["alice"])
    probe("p1-probe-html-chat", "GET", "/backend-api/probe/html", cookie=live["alice"])

    # Upstream request-construction probes: client cookies, UA, accept-encoding and
    # hop-by-hop filtering.
    probe(
        "p1-cfg-client-cookie-ua",
        "GET",
        "/0x/user/version-cfg?fixture=1",
        headers={"Cookie": "a=1; b=2", "User-Agent": "ProbeUA/2.0",
                 "Accept-Encoding": "gzip, deflate"},
    )
    probe(
        "p1-me-accept-encoding",
        "GET",
        "/backend-api/me",
        cookie=live["alice"],
        headers={"Accept-Encoding": "gzip, deflate"},
    )
    probe(
        "p1-me-client-cookie",
        "GET",
        "/backend-api/me",
        cookie="a=1; " + live["alice"] + "; b=2",
    )
    probe(
        "p1-me-connection-token",
        "GET",
        "/backend-api/me",
        cookie=live["alice"],
        headers={"Connection": "x-conn-token", "X-Conn-Token": "drop-me",
                 "X-Keep": "keep-me"},
    )

    # Third-user login that stores extra_cookies. Original login deserializes
    # extra_cookies as a sequence of cookie objects (string payload was rejected
    # with 422 in evidence/proxy-v3-original-003/-004); the guest must keep running
    # even if this optional probe is rejected, so failures are recorded and skipped.
    live["carol"] = None
    try:
        _, _, body_c = login(
            "p1-login-carol",
            user="carol",
            extra_cookies=[
                {"name": "probe_extra", "value": "EV", "domain": "127.0.0.1",
                 "path": "/", "secure": False, "http_only": False,
                 "same_site": "Lax", "expires": None, "source": "manual"}
            ],
        )
        live["carol"] = handoff_cookie("p1-handoff-carol", body_c)
    except (ValueError, KeyError) as error:
        emit({"kind": "scenario", "id": "p1-carol-aborted", "status": str(error)})
    if live["carol"]:
        set_mode(conv="small")
        probe("p1-carol-extra-cookies", "GET",
              "/backend-api/conversations?offset=0&limit=20", cookie=live["carol"])


def phase1_seed(database):
    dump_conversations(database, "p1-conversations-before-seed")
    for account, conversation, user in OWNER_SEEDS:
        db_execute(
            database,
            "INSERT OR REPLACE INTO conversation_owners"
            " (chatgpt_username, conversation_id, user_name, created_at, updated_at)"
            " VALUES (?1, ?2, ?3, 1790064000, 1790064000)",
            (account, conversation, user),
        )
        emit(
            {
                "kind": "seed",
                "case": "conversation-owner",
                "input": {
                    "chatgpt_username": account,
                    "conversation_id": conversation,
                    "user_name": user,
                },
            }
        )
    dump_conversations(database, "p1-conversations-after-seed")


def phase2_conversations(database, live):
    alice, bob = live["alice"], live["bob"]
    set_mode(conv="small")
    probe("p2-small-alice-page1", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    dump_conversations(database, "p2-after-alice-page1")
    probe("p2-small-bob-page1", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=bob)
    dump_conversations(database, "p2-after-bob-page1")
    probe("p2-small-alice-repeat", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    dump_conversations(database, "p2-after-alice-repeat")
    probe("p2-small-bob-window", "GET", "/backend-api/conversations?offset=2&limit=2",
          cookie=bob)
    probe("p2-small-alice-tail", "GET", "/backend-api/conversations?offset=4&limit=10",
          cookie=alice)
    probe("p2-small-alice-limit0", "GET", "/backend-api/conversations?offset=0&limit=0",
          cookie=alice)
    probe("p2-small-alice-negative", "GET", "/backend-api/conversations?offset=-1&limit=-5",
          cookie=alice)
    probe("p2-small-alice-limit1000", "GET", "/backend-api/conversations?offset=0&limit=1000",
          cookie=alice)
    dump_conversations(database, "p2-after-small-windows")

    set_mode(conv="dup")
    probe("p2-dup-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    dump_conversations(database, "p2-after-dup")

    set_mode(conv="extra")
    probe("p2-extra-keys-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)

    set_mode(conv="big")
    probe("p2-big-alice-page1", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    probe("p2-big-bob-page1", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=bob)
    probe("p2-big-alice-page2", "GET", "/backend-api/conversations?offset=20&limit=20",
          cookie=alice)
    probe("p2-big-alice-no-query", "GET", "/backend-api/conversations", cookie=alice)
    probe("p2-big-alice-bad-params", "GET",
          "/backend-api/conversations?offset=abc&limit=def", cookie=alice)
    probe("p2-conversations-no-cookie", "GET", "/backend-api/conversations?offset=0&limit=20")
    probe("p2-conversations-bad-cookie", "GET",
          "/backend-api/conversations?offset=0&limit=20", cookie="mirror_token=deadbeef")
    dump_conversations(database, "p2-after-big")

    set_mode(conv="empty")
    probe("p2-empty-upstream-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    set_mode(conv="error")
    probe("p2-upstream-error-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    set_mode(conv="error500")
    probe("p2-upstream-error500-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    set_mode(conv="badjson")
    probe("p2-upstream-badjson-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=alice)
    set_mode(conv="default")
    dump_conversations(database, "p2-final")


def phase3_restart(database, live):
    set_mode(conv="big")
    probe("p3-big-alice-after-restart", "GET",
          "/backend-api/conversations?offset=0&limit=20", cookie=live["alice"])
    dump_conversations(database, "p3-after-restart-list")
    set_mode(conv="error")
    probe("p3-offline-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=live["alice"])
    dump_conversations(database, "p3-after-offline")
    set_mode(conv="empty")
    probe("p3-empty-upstream-alice", "GET", "/backend-api/conversations?offset=0&limit=20",
          cookie=live["alice"])
    set_mode(conv="small")
    probe("p3-small-bob-after-restart", "GET",
          "/backend-api/conversations?offset=0&limit=20", cookie=live["bob"])
    dump_conversations(database, "p3-final")


def main():
    emit({"kind": "subject", "subject": subject, "binary": binary})
    emit_startup_probes()
    live = {}
    try:
        start_gateway("/tmp/proxy-a.db")
        phase0_shared_surface("/tmp/proxy-a.db")
        stop_gateway()
        start_gateway("/tmp/proxy-b.db")
        phase1_dual_user_probes("/tmp/proxy-b.db", live)
        phase1_seed("/tmp/proxy-b.db")
        phase2_conversations("/tmp/proxy-b.db", live)
        stop_gateway()
        start_gateway("/tmp/proxy-b.db")
        phase3_restart("/tmp/proxy-b.db", live)
        stop_gateway()
    finally:
        stop_gateway()
        server.shutdown()


main()

"""Synthetic management-endpoint observations for original/candidate/rollback.
Author: MingTea. Disposable guest only; loopback upstreams only; no external network.

Reusable by the primary agent for candidate and rollback runs: the same case ids and
record kinds are emitted for every subject so results.json stays comparable.

Phase 0 reproduces the shared case ids of tools/observe_guest.py (empty state) so the
six previously-404 management routes can be diffed against evidence/baseline-final-2.
Phases 1-3 add populated counts, mirror-token, close-memory and moderation probes.
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
        env = {"PATH": os.environ["PATH"], "DATABASE_PATH": "/tmp/startup-v3.db", "PORT": "40002"}
        if value is not None:
            env["GATEWAY_ADMIN_SECRET"] = value
        if value == SECRET:
            env["GATEWAY_ADMIN_SECRET"] = "short"
            env["PORT"] = "bad"
        result = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=15)
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


# Mutable stub behaviour: proxy replies by default, moderation replies per case.
stub = {"response": None, "case": None}


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
                "case": stub["case"],
                "method": self.command,
                "path": self.path,
                "headers": list(self.headers.items()),
                "body": body.decode("utf-8", errors="replace"),
            }
        )
        response = stub["response"]
        if response is not None:
            status, payload, delay = response
            if delay:
                time.sleep(delay)
            data = payload if isinstance(payload, bytes) else payload.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/cloudflare5s/"):
            value = {
                "cookies": [
                    {
                        "name": "cf_clearance",
                        "value": "SYNTHETIC",
                        "domain": "127.0.0.1",
                        "path": "/",
                    }
                ],
                "user_agent": "ContractFixture/1",
            }
        elif self.path.startswith("/backend-api/me"):
            value = {
                "id": "synthetic-id",
                "email": "fixture@example.invalid",
                "name": "Fixture",
            }
        else:
            value = {"stub": True, "path": self.path, "method": self.command}
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
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
        open("/tmp/mgmt-" + tag + ".out", "w+"),
        open("/tmp/mgmt-" + tag + ".err", "w+"),
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


def dump_sessions(database, case):
    emit(
        {
            "kind": "db",
            "case": case,
            "table": "gateway_sessions",
            "rows": db_rows(
                database,
                "SELECT id, user_name, chatgpt_username, login_mode, mirror_token, created_at,"
                " updated_at FROM gateway_sessions ORDER BY id",
            ),
        }
    )


def dump_session_flags(database, case):
    emit(
        {
            "kind": "db",
            "case": case,
            "table": "gateway_sessions(detail)",
            "rows": db_rows(
                database,
                "SELECT id, user_name, chatgpt_username, login_mode, isolated_session,"
                " force_chat_mode, limits, proxy_node_id, daily_quota, monthly_quota"
                " FROM gateway_sessions ORDER BY id",
            ),
        }
    )


def dump_accounts(database, case):
    emit(
        {
            "kind": "db",
            "case": case,
            "table": "chatgpt_accounts",
            "rows": db_rows(
                database,
                "SELECT id, chatgpt_username, auth_status, plan_type, access_token, remark"
                " FROM chatgpt_accounts ORDER BY id",
            ),
        }
    )


def dump_visit_logs(database, case):
    emit(
        {
            "kind": "db",
            "case": case,
            "table": "visit_logs",
            "rows": db_rows(
                database,
                "SELECT id, username, chatgpt_username, log_type, created_at, ip, user_agent"
                " FROM visit_logs ORDER BY id",
            ),
        }
    )


def dump_settings(database, case):
    emit(
        {
            "kind": "db",
            "case": case,
            "table": "gateway_settings",
            "rows": db_rows(database, "SELECT key, value, updated_at FROM gateway_settings ORDER BY key"),
        }
    )


ENDPOINTS = [
    "login",
    "logout",
    "user-work-mode",
    "get-user-info",
    "diagnose-chatgpt-auth",
    "get-mirror-token",
    "get-user-use-count",
    "get-chatgpt-use-count",
    "conversation-statistics",
    "conversation-statistics/reset",
    "get-user-quota-usage",
    "backup/export",
    "backup/restore",
    "operations-overview",
    "close-chatgpt-memory",
    "mirror-proxy-config",
    "test-mirror-proxy-config",
    "custom-scripts",
    "political-moderation-config",
    "political-moderation-config/test",
    "blocked-paths",
    "auth/session",
    "not-login",
    "refresh-cfbypass",
    "user-blocked-paths",
]

MANAGEMENT = [
    "get-mirror-token",
    "get-user-use-count",
    "get-chatgpt-use-count",
    "close-chatgpt-memory",
    "political-moderation-config",
    "political-moderation-config/test",
]


def login(case):
    return scenario(
        case,
        "POST",
        "/api/login",
        {
            "user_name": "alice",
            "access_token": "synthetic-access-token",
            "session_token": "",
            "login_mode": "api",
            "isolated_session": True,
            "limits": [],
            "daily_quota": 0,
            "monthly_quota": 0,
            "force_chat_mode": True,
        },
    )


def session_cookie(headers):
    for name, value in headers:
        if name.lower() == "set-cookie" and value.startswith("mirror_token="):
            return value.split(";", 1)[0]
    return None


def phase0_empty_state(database):
    """Reproduce the shared empty-state surface of tools/observe_guest.py."""
    for path in ENDPOINTS:
        for method, auth in (("GET", False), ("GET", True), ("POST", True)):
            # Shared baseline sends Content-Type on GET too; that header decides
            # between 415 and the body-parser error, so it must stay identical.
            payload = {} if method == "POST" else None
            raw_call(method, "/api/" + path, payload, auth,
                     {"Content-Type": "application/json"} if method != "POST" else None)

    emit(
        {
            "kind": "schema",
            "sql": db_rows(
                database,
                "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name",
            ),
        }
    )

    cases = [
        ("login-minimal", "/api/login", {"user_name": "alice"}),
        ("logout-minimal", "/api/logout", {"user_name": "alice"}),
        ("work-mode", "/api/user-work-mode", {"user_name": "alice"}),
        ("mirror-token", "/api/get-mirror-token", {"user_name": "alice"}),
        ("quota-empty", "/api/get-user-quota-usage", {"user_name": "alice"}),
        ("quota-period", "/api/get-user-quota-usage",
         {"user_name": "alice", "day_start": 0, "month_start": 0}),
        ("mirror-list", "/api/get-mirror-token",
         {"user_name": "alice", "chatgpt_list": ["fixture@example.invalid"]}),
        ("work-set", "/api/user-work-mode", {"user_name": "alice", "force_chat_mode": False}),
        ("counts", "/api/get-user-use-count", {"username_list": ["alice", "bob"]}),
        ("account-counts", "/api/get-chatgpt-use-count",
         {"chatgpt_list": ["fixture@example.invalid"]}),
        ("overview", "/api/operations-overview", {"day_start": 0, "month_start": 0}),
        ("restore-v2", "/api/backup/restore",
         {"version": 2, "settings": [{"key": "custom_scripts",
          "value": "{\"scripts\":[{\"name\":\"fixture\",\"content\":\"void 0\"}]}",
          "updated_at": 1}]}),
        ("script-persist", "/api/custom-scripts",
         {"scripts": [{"name": "fixture", "content": "void 0", "enabled": True}],
          "trusted_cdn_sources": []}),
        ("blocked-persist", "/api/blocked-paths", {"paths": ["/secret", "/#settings/Test"]}),
        ("token-fixture", "/api/get-user-info", {"chatgpt_token": "synthetic-access-token"}),
    ]
    for case_id, path, payload in cases:
        scenario(case_id, "POST", path, payload)

    _, headers, body = login("login-fixture")
    if json.loads(body).get("login_url"):
        handoff = json.loads(body)["login_url"]
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        conn.request("GET", handoff)
        response = conn.getresponse()
        cookies = [
            value.split(";", 1)[0]
            for name, value in response.getheaders()
            if name.lower() == "set-cookie"
        ]
        emit(
            {
                "kind": "scenario",
                "id": "handoff",
                "method": "GET",
                "path": handoff.split("?")[0],
                "auth": False,
                "status": response.status,
                "headers": response.getheaders(),
                "body": response.read().decode(errors="replace"),
            }
        )
        conn.close()
        for path in (
            "/api/auth/session",
            "/api/user-blocked-paths",
            "/backend-api/me",
            "/backend-api/conversations?offset=0&limit=20",
            "/0x/user/version-cfg?fixture=1",
        ):
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
            conn.request("GET", path, headers={"Cookie": "; ".join(cookies)})
            response = conn.getresponse()
            emit(
                {
                    "kind": "scenario",
                    "id": "session:" + path,
                    "method": "GET",
                    "path": path,
                    "auth": False,
                    "status": response.status,
                    "headers": response.getheaders(),
                    "body": response.read().decode(errors="replace"),
                }
            )
            conn.close()
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    conn.request("GET", "/api/backup/export", headers={"Authorization": "Bearer " + SECRET})
    response = conn.getresponse()
    emit(
        {
            "kind": "scenario",
            "id": "export-populated",
            "method": "GET",
            "path": "/api/backup/export",
            "auth": True,
            "status": response.status,
            "body": response.read().decode(errors="replace"),
        }
    )
    conn.close()


def phase1_mirror_counts_close(database):
    live = {}

    # Route/method matrix variants that decide the extractor shape per route.
    for route in MANAGEMENT:
        path = "/api/" + route
        scenario("route-" + route + "-get-no-ct", "GET", path, None)
        scenario("route-" + route + "-put-ct-json", "PUT", path, {},
                 headers={"Content-Type": "application/json"})
    scenario("route-mod-get-ct-no-body", "GET", "/api/political-moderation-config", None,
             headers={"Content-Type": "application/json"})
    scenario("route-mod-get-ct-empty-json", "GET", "/api/political-moderation-config", {},
             headers={"Content-Type": "application/json"})
    scenario("route-mod-post-no-ct", "POST", "/api/political-moderation-config", {},
             content_type=False)
    scenario("route-test-get-ct-no-body", "GET",
             "/api/political-moderation-config/test", None,
             headers={"Content-Type": "application/json"})
    scenario("route-counts-put-json-body", "PUT", "/api/get-user-use-count", {})
    scenario("route-mirror-put-json-body", "PUT", "/api/get-mirror-token", {})
    scenario("route-close-put-json-body", "PUT", "/api/close-chatgpt-memory", {})

    # mirror-token with an existing session, then with a stored chatgpt account.
    fixture = "fixture@example.invalid"
    dump_sessions(database, "p1-sessions-before-mirror")
    dump_accounts(database, "p1-accounts-before-seed")
    scenario("mirror-live-basic", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture]})
    scenario("mirror-live-isolated-true", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture], "isolated_session": True})
    scenario("mirror-live-isolated-false", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture], "isolated_session": False})
    scenario("mirror-live-force-true", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture], "force_chat_mode": True})
    scenario("mirror-live-all-fields", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture], "isolated_session": True,
              "force_chat_mode": True, "limits": [], "daily_quota": 0, "monthly_quota": 0})
    scenario("mirror-live-other-user", "POST", "/api/get-mirror-token",
             {"user_name": "bob", "chatgpt_list": [fixture]})
    scenario("mirror-live-mixed", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": ["other@example.invalid", fixture]})
    scenario("mirror-live-dup", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture, fixture]})
    scenario("mirror-live-trim", "POST", "/api/get-mirror-token",
             {"user_name": " alice ", "chatgpt_list": [" " + fixture + " "]})
    scenario("mirror-live-case", "POST", "/api/get-mirror-token",
             {"user_name": "ALICE", "chatgpt_list": ["FIXTURE@EXAMPLE.INVALID"]})

    db_execute(
        database,
        "INSERT INTO chatgpt_accounts (chatgpt_username, auth_status, plan_type, access_token,"
        " session_token, extra_cookies, refresh_token, remark, created_time, updated_time)"
        " VALUES (?1, 1, 'free', 'synthetic-access-token', NULL, '[]', NULL, 'fixture', 0, 0)",
        (fixture,),
    )
    emit({"kind": "seed", "case": "chatgpt-account", "input":
          {"chatgpt_username": fixture, "auth_status": True}})
    dump_accounts(database, "p1-accounts-after-seed")
    scenario("mirror-account-basic", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture]})
    scenario("mirror-account-all-fields", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture], "isolated_session": True,
              "force_chat_mode": True, "limits": [], "daily_quota": 0, "monthly_quota": 0})
    scenario("mirror-account-other-user", "POST", "/api/get-mirror-token",
             {"user_name": "bob", "chatgpt_list": [fixture]})
    db_execute(
        database,
        "INSERT INTO chatgpt_accounts (chatgpt_username, auth_status, plan_type, access_token,"
        " session_token, extra_cookies, refresh_token, remark, created_time, updated_time)"
        " VALUES ('second@example.invalid', 1, 'free', 'synthetic-access-token', NULL, '[]',"
        " NULL, 'fixture2', 0, 0), ('disabled@example.invalid', 0, 'free',"
        " 'synthetic-access-token', NULL, '[]', NULL, 'disabled', 0, 0)",
    )
    emit({"kind": "seed", "case": "chatgpt-account-2", "input":
          {"chatgpt_username": "second@example.invalid", "auth_status": True}})
    dump_accounts(database, "p1-accounts-after-seed-2")
    scenario("mirror-two-accounts", "POST", "/api/get-mirror-token",
             {"user_name": "alice",
              "chatgpt_list": ["second@example.invalid", fixture]})
    scenario("mirror-disabled-account", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": ["disabled@example.invalid"]})
    scenario("mirror-unknown-account", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": ["none@example.invalid"]})
    scenario("mirror-mixed-known", "POST", "/api/get-mirror-token",
             {"user_name": "alice",
              "chatgpt_list": ["none@example.invalid", fixture, "second@example.invalid"]})
    scenario("mirror-dup-accounts", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture, fixture]})
    scenario("mirror-trim-account", "POST", "/api/get-mirror-token",
             {"user_name": " alice ", "chatgpt_list": [" " + fixture + " "]})
    scenario("mirror-case-account", "POST", "/api/get-mirror-token",
             {"user_name": "ALICE", "chatgpt_list": ["FIXTURE@EXAMPLE.INVALID"]})
    scenario("mirror-empty-list-live", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": []})
    scenario("mirror-empty-user-live", "POST", "/api/get-mirror-token",
             {"user_name": "", "chatgpt_list": [fixture]})
    scenario("mirror-blank-item", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": ["", fixture]})
    dump_sessions(database, "p1-sessions-after-mirror")
    dump_session_flags(database, "p1-flags-after-mirror")
    scenario("mirror-optional-overrides", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture], "isolated_session": False,
              "force_chat_mode": False, "limits": ["probe-limit"], "daily_quota": 11,
              "monthly_quota": 22})
    dump_session_flags(database, "p1-flags-after-overrides")
    db_execute(database,
               "UPDATE gateway_sessions SET login_mode='web' WHERE user_name='alice' AND"
               " chatgpt_username=?1", (fixture,))
    emit({"kind": "seed", "case": "session-login-mode-web", "input":
          {"user_name": "alice", "chatgpt_username": fixture}})
    scenario("mirror-login-mode-web", "POST", "/api/get-mirror-token",
             {"user_name": "alice", "chatgpt_list": [fixture]})
    db_execute(database,
               "UPDATE gateway_sessions SET login_mode='api' WHERE user_name='alice' AND"
               " chatgpt_username=?1", (fixture,))
    dump_session_flags(database, "p1-flags-after-login-mode-probe")

    now = int(time.time())
    seed = [
        ("alice", fixture, "proxy", now - 60),
        ("alice", fixture, "proxy", now - 120),
        ("alice", fixture, "proxy", now - 3700),
        ("alice", fixture, "proxy", now - 8000),
        ("alice", fixture, "proxy", now - 12000),
        ("alice", fixture, "chat", now - 60),
        ("alice", fixture, "chat", now - 90),
        ("bob", "other@example.invalid", "proxy", now - 60),
        ("bob", fixture, "proxy", now - 60),
        ("carol", fixture, "proxy", now - 20000),
    ]
    for index, (username, account, log_type, created) in enumerate(seed):
        db_execute(
            database,
            "INSERT INTO visit_logs (username, chatgpt_username, log_type, created_at, ip,"
            " user_agent) VALUES (?1,?2,?3,?4,'127.0.0.1','ContractFixture/1')",
            (username, account, log_type, created),
        )
        emit({"kind": "seed", "case": "visit-log-" + str(index), "input":
              {"username": username, "chatgpt_username": account, "log_type": log_type,
               "created_at": created}})
    dump_visit_logs(database, "p1-logs-after-seed")
    scenario("counts-users", "POST", "/api/get-user-use-count",
             {"username_list": ["alice", "bob", "carol"]})
    scenario("counts-accounts", "POST", "/api/get-chatgpt-use-count",
             {"chatgpt_list": [fixture, "other@example.invalid", "none@example.invalid"]})
    scenario("counts-trim", "POST", "/api/get-user-use-count",
             {"username_list": [" alice ", "bob"]})
    scenario("counts-case", "POST", "/api/get-user-use-count", {"username_list": ["ALICE"]})
    scenario("counts-empty-list", "POST", "/api/get-user-use-count", {"username_list": []})
    scenario("counts-blank-items", "POST", "/api/get-user-use-count",
             {"username_list": ["", "   "]})
    scenario("counts-dup", "POST", "/api/get-user-use-count",
             {"username_list": ["bob", "bob"]})
    db_execute(
        database,
        "INSERT INTO conversation_model_statistics (user_name, model_name, message_count,"
        " updated_at) VALUES ('alice','o3-mini',5,?1), ('alice','gpt-4o',7,?1)",
        (now,),
    )
    emit({"kind": "seed", "case": "conversation-model-statistics", "input":
          {"user_name": "alice", "models": ["o3-mini", "gpt-4o"]}})
    scenario("counts-users-after-model-seed", "POST", "/api/get-user-use-count",
             {"username_list": ["alice"]})
    scenario("counts-accounts-after-model-seed", "POST", "/api/get-chatgpt-use-count",
             {"chatgpt_list": [fixture]})
    scenario("counts-unknown-user", "POST", "/api/get-user-use-count",
             {"username_list": ["nobody"]})
    scenario("counts-many", "POST", "/api/get-user-use-count",
             {"username_list": ["alice", "bob", "carol", "nobody", "alice"]})
    db_execute(
        database,
        "INSERT INTO visit_logs (username, chatgpt_username, log_type, created_at, ip,"
        " user_agent) VALUES ('edge','edge@example.invalid','proxy',?1,'127.0.0.1','F')",
        (now - 3600,),
    )
    db_execute(
        database,
        "INSERT INTO visit_logs (username, chatgpt_username, log_type, created_at, ip,"
        " user_agent) VALUES ('edge','edge@example.invalid','proxy',?1,'127.0.0.1','F')",
        (now - 14400,),
    )
    emit({"kind": "seed", "case": "visit-log-edge", "input":
          {"username": "edge", "created_at": [now - 3600, now - 14400]}})
    dump_visit_logs(database, "p1-logs-after-edge")
    scenario("counts-edge", "POST", "/api/get-user-use-count", {"username_list": ["edge"]})

    # close-chatgpt-memory: empty/blank/type probes, then real deletions by
    # mirror_token, chatgpt_name and user_name.
    dump_sessions(database, "p1-sessions-before-close")
    scenario("close-empty", "POST", "/api/close-chatgpt-memory", {})
    scenario("close-blank-user", "POST", "/api/close-chatgpt-memory", {"user_name": "   "})
    scenario("close-blank-both", "POST", "/api/close-chatgpt-memory",
             {"user_name": "   ", "chatgpt_name": "  "})
    for probe in ("mirror_token", "chatgpt_name", "chatgpt_username", "name", "id",
                  "session_token", "access_token", "user_gateway_token", "login_mode",
                  "user", "chatgpt", "token", "tokens", "chatgpt_names", "user_names"):
        scenario("close-type-" + probe, "POST", "/api/close-chatgpt-memory", {probe: 7})
    scenario("close-type-isolated_session", "POST", "/api/close-chatgpt-memory",
             {"isolated_session": 7})
    scenario("close-type-force_chat_mode", "POST", "/api/close-chatgpt-memory",
             {"force_chat_mode": 7})

    _, headers, body = login("p1-login")
    live["token"] = json.loads(body)["login_url"].rsplit("=", 1)[1]
    dump_sessions(database, "p1-sessions-after-p1-login")
    scenario("close-token", "POST", "/api/close-chatgpt-memory",
             {"mirror_token": live["token"]})
    dump_sessions(database, "p1-sessions-after-close-token")
    scenario("close-session-check", "GET", "/api/auth/session", None, False,
             {"Cookie": "mirror_token=" + live["token"]})
    login("p1-login-2")
    dump_sessions(database, "p1-sessions-after-login-2")
    scenario("close-chatgpt-name", "POST", "/api/close-chatgpt-memory",
             {"chatgpt_name": fixture})
    dump_sessions(database, "p1-sessions-after-close-chatgpt-name")
    login("p1-login-3")
    scenario("close-user-name", "POST", "/api/close-chatgpt-memory", {"user_name": "alice"})
    dump_sessions(database, "p1-sessions-after-close-user-name")
    login("p1-login-4")
    scenario("close-unknown-user", "POST", "/api/close-chatgpt-memory",
             {"user_name": "nobody"})
    dump_sessions(database, "p1-sessions-after-close-unknown")
    scenario("close-chatgpt-username-field", "POST", "/api/close-chatgpt-memory",
             {"chatgpt_username": fixture})
    dump_sessions(database, "p1-sessions-after-close-chatgpt-username-field")
    _, headers2, body2 = login("p1-login-5")
    second_token = json.loads(body2)["login_url"].rsplit("=", 1)[1]
    scenario("close-token-other-user", "POST", "/api/close-chatgpt-memory",
             {"mirror_token": second_token})
    dump_sessions(database, "p1-sessions-after-close-token-other")
    login("p1-login-6")
    scenario("close-all-fields", "POST", "/api/close-chatgpt-memory",
             {"user_name": "alice", "chatgpt_name": fixture, "chatgpt_username": fixture,
              "mirror_token": "unused-synthetic-token"})
    dump_sessions(database, "p1-sessions-after-close-all-fields")
    login("p1-login-7")
    scenario("close-blank-token", "POST", "/api/close-chatgpt-memory",
             {"mirror_token": "   "})
    dump_sessions(database, "p1-sessions-after-close-blank-token")
    scenario("close-trimmed-user", "POST", "/api/close-chatgpt-memory",
             {"user_name": " alice "})
    dump_sessions(database, "p1-sessions-after-close-trimmed-user")
    login("p1-login-8")
    scenario("close-space-user", "POST", "/api/close-chatgpt-memory",
             {"user_name": "alice "})
    dump_sessions(database, "p1-sessions-after-close-space-user")
    _, _, body9 = login("p1-login-9")
    spaced_token = " " + json.loads(body9)["login_url"].rsplit("=", 1)[1] + " "
    scenario("close-spaced-token", "POST", "/api/close-chatgpt-memory",
             {"mirror_token": spaced_token})
    dump_sessions(database, "p1-sessions-after-close-spaced-token")


def mod_payload(**overrides):
    payload = {
        "enabled": False,
        "protocol": "openai_chat",
        "model": "gpt-4o-mini",
        "api_key": "sk-synthetic-secret-001",
        "base_url": f"https://{PUBLIC_IP}/v1",
        "mode": "strict",
        "custom_terms": ["甲", "乙"],
        "limit_per_minute": 5,
        "limit_per_five_minutes": 20,
        "limit_per_hour": 60,
    }
    payload.update(overrides)
    return payload


def phase2_moderation(database):
    loopback = f"https://127.0.0.1:{STUB_PORT}/v1"
    scenario("mod-get-default", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-before")

    # Deserialization surface: which fields are required and their types.
    scenario("mod-save-protocol-only", "POST", "/api/political-moderation-config",
             {"protocol": "openai_chat"})
    scenario("mod-save-protocol-model", "POST", "/api/political-moderation-config",
             {"protocol": "openai_chat", "model": "gpt-4o-mini"})
    scenario("mod-save-protocol-model-key", "POST", "/api/political-moderation-config",
             {"protocol": "openai_chat", "model": "gpt-4o-mini", "api_key": "sk-x"})
    scenario("mod-save-extra-field", "POST", "/api/political-moderation-config",
             {**mod_payload(), "surprise": "value"})
    scenario("mod-save-probe-mode-int", "POST", "/api/political-moderation-config",
             mod_payload(mode=7))
    scenario("mod-save-probe-terms-int", "POST", "/api/political-moderation-config",
             mod_payload(custom_terms=7))
    scenario("mod-save-probe-limit-str", "POST", "/api/political-moderation-config",
             mod_payload(limit_per_minute="5"))
    scenario("mod-save-probe-enabled-str", "POST", "/api/political-moderation-config",
             mod_payload(enabled="yes"))

    # Protocol acceptance.
    for protocol in ("openai_chat", "openai_responses", "anthropic_messages",
                     "gemini_generate_content", "generate_content", "gemini_generate_",
                     "bogus", ""):
        scenario("mod-save-protocol-" + (protocol or "empty"), "POST",
                 "/api/political-moderation-config", mod_payload(protocol=protocol, enabled=False,
                                                                 base_url=loopback))

    # Base URL validation order.
    for label, url in (
        ("http", f"http://{PUBLIC_IP}/v1"),
        ("loopback-http", f"http://127.0.0.1:{STUB_PORT}/v1"),
        ("loopback-https", loopback),
        ("private-ip", "https://10.0.0.5/v1"),
        ("credentials", f"https://user:pass@{PUBLIC_IP}/v1"),
        ("query", f"https://{PUBLIC_IP}/v1?x=1"),
        ("fragment", f"https://{PUBLIC_IP}/v1#frag"),
        ("plain", "not-a-url"),
        ("empty", ""),
        ("trailing-slash", f"https://{PUBLIC_IP}/v1/"),
        ("no-path", f"https://{PUBLIC_IP}"),
    ):
        scenario("mod-save-base-" + label, "POST", "/api/political-moderation-config",
                 mod_payload(base_url=url, enabled=False))

    # Optional fields with blank values.
    scenario("mod-save-blank-key", "POST", "/api/political-moderation-config",
             mod_payload(api_key="", enabled=False))
    scenario("mod-save-blank-model", "POST", "/api/political-moderation-config",
             mod_payload(model="", enabled=False))
    scenario("mod-save-blank-mode", "POST", "/api/political-moderation-config",
             mod_payload(mode="", enabled=False))

    # Enabled=true forces a connectivity/calibration attempt (public literal IP; the
    # guest has no NIC so the connection fails without touching the network).
    scenario("mod-save-enabled-true-public", "POST", "/api/political-moderation-config",
             mod_payload(enabled=True), timeout=12)
    scenario("mod-get-after-enabled-true", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-enabled-true")

    # Enabled=false persists the config without contacting the provider.
    scenario("mod-save-disabled-public", "POST", "/api/political-moderation-config",
             mod_payload(enabled=False))
    scenario("mod-get-after-save", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-save")
    scenario("mod-save-disabled-full2", "POST", "/api/political-moderation-config",
             mod_payload(model="gpt-4o", mode="relaxed", custom_terms=["丙"],
                         limit_per_minute=1, limit_per_five_minutes=2, limit_per_hour=3,
                         enabled=False))
    scenario("mod-get-after-save2", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-save2")
    scenario("mod-save-blank-key2", "POST", "/api/political-moderation-config",
             mod_payload(api_key="", enabled=False))
    scenario("mod-get-after-blank-key", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-blank-key")

    # Blank api_key retention matrix: does a changed base_url drop the stored key?
    base_a = f"https://{PUBLIC_IP}/v1"
    base_a2 = f"https://{PUBLIC_IP}/v1/"
    base_b = f"https://{PUBLIC_IP}/v2"
    scenario("mod-key-set-a", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_a, api_key="sk-key-one", enabled=False))
    scenario("mod-key-blank-same-base", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_a, api_key="", enabled=False))
    scenario("mod-key-blank-slash-base", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_a2, api_key="", enabled=False))
    scenario("mod-key-blank-other-base", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_b, api_key="", enabled=False))
    scenario("mod-key-blank-other-base-again", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_b, api_key="", enabled=False))
    scenario("mod-key-blank-back-a", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_a, api_key="", enabled=False))
    scenario("mod-key-set-a2", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_a, api_key="sk-key-two", enabled=False))
    scenario("mod-key-blank-after-protocol", "POST", "/api/political-moderation-config",
             mod_payload(base_url=base_a, protocol="openai_responses", api_key="",
                         enabled=False))
    dump_settings(database, "mod-after-key-matrix")
    scenario("mod-get-after-key-matrix", "GET", "/api/political-moderation-config", None)

    # Minimal save body: which fields have serde defaults?
    scenario("mod-save-minimal", "POST", "/api/political-moderation-config",
             {"protocol": "openai_chat", "model": "gpt-4o-mini", "base_url": base_a})
    scenario("mod-get-after-minimal", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-minimal")
    ladder = {"protocol": "openai_chat", "model": "gpt-4o-mini", "base_url": base_a}
    scenario("mod-ladder-mode", "POST", "/api/political-moderation-config",
             {**ladder, "mode": "relaxed"})
    scenario("mod-ladder-key", "POST", "/api/political-moderation-config",
             {**ladder, "mode": "relaxed", "api_key": "sk-ladder"})
    scenario("mod-ladder-terms", "POST", "/api/political-moderation-config",
             {**ladder, "mode": "relaxed", "api_key": "sk-ladder", "custom_terms": []})
    scenario("mod-ladder-minute", "POST", "/api/political-moderation-config",
             {**ladder, "mode": "relaxed", "api_key": "sk-ladder", "custom_terms": [],
              "limit_per_minute": 10})
    scenario("mod-ladder-five", "POST", "/api/political-moderation-config",
             {**ladder, "mode": "relaxed", "api_key": "sk-ladder", "custom_terms": [],
              "limit_per_minute": 10, "limit_per_five_minutes": 30})
    scenario("mod-ladder-hour", "POST", "/api/political-moderation-config",
             {**ladder, "mode": "relaxed", "api_key": "sk-ladder", "custom_terms": [],
              "limit_per_minute": 10, "limit_per_five_minutes": 30,
              "limit_per_hour": 120})
    scenario("mod-ladder-enabled", "POST", "/api/political-moderation-config",
             {**ladder, "mode": "relaxed", "api_key": "sk-ladder", "custom_terms": [],
              "limit_per_minute": 10, "limit_per_five_minutes": 30, "limit_per_hour": 120,
              "enabled": False})
    scenario("mod-get-after-ladder", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-ladder")

    # base_url normalisation probes.
    for label, url in (
        ("double-trailing", f"https://{PUBLIC_IP}/v1//"),
        ("spaces", f"  https://{PUBLIC_IP}/v1  "),
        ("upper-scheme", f"HTTPS://{PUBLIC_IP}/v1"),
        ("hostname", "https://example.invalid/v1"),
        ("ipv6-loopback", f"https://[::1]:{STUB_PORT}/v1"),
        ("userinfo-empty", f"https://@{PUBLIC_IP}/v1"),
    ):
        scenario("mod-save-norm-" + label, "POST", "/api/political-moderation-config",
                 mod_payload(base_url=url, enabled=False))
    dump_settings(database, "mod-after-norm")
    scenario("mod-save-enabled-true-loopback", "POST", "/api/political-moderation-config",
             mod_payload(base_url=loopback, enabled=True), timeout=12)
    scenario("mod-save-enabled-true-blank-key", "POST", "/api/political-moderation-config",
             mod_payload(enabled=True, api_key=""), timeout=12)
    scenario("mod-save-enabled-true-loopback-http", "POST",
             "/api/political-moderation-config",
             mod_payload(base_url=f"http://127.0.0.1:{STUB_PORT}/v1", enabled=True),
             timeout=12)

    # Validation order and type probes.
    scenario("mod-order-protocol-mode", "POST", "/api/political-moderation-config",
             mod_payload(protocol="bogus", mode="", enabled=False))
    scenario("mod-order-key-base", "POST", "/api/political-moderation-config",
             mod_payload(api_key="", base_url="not-a-url", enabled=True))
    scenario("mod-order-key-loopback", "POST", "/api/political-moderation-config",
             mod_payload(api_key="", base_url=loopback, enabled=True))
    scenario("mod-order-key-http", "POST", "/api/political-moderation-config",
             mod_payload(api_key="", base_url=f"http://{PUBLIC_IP}/v1", enabled=True))
    scenario("mod-type-terms-item", "POST", "/api/political-moderation-config",
             mod_payload(custom_terms=[7], enabled=False))
    scenario("mod-type-limit-negative", "POST", "/api/political-moderation-config",
             mod_payload(limit_per_minute=-1, enabled=False))
    scenario("mod-test-blank-mode", "POST", "/api/political-moderation-config/test",
             mod_payload(mode="", enabled=False))
    scenario("mod-test-blank-model", "POST", "/api/political-moderation-config/test",
             mod_payload(model="", enabled=False))

    # /test surface.
    scenario("mod-test-protocol-only", "POST", "/api/political-moderation-config/test",
             {"protocol": "openai_chat"})
    scenario("mod-test-protocol-model", "POST", "/api/political-moderation-config/test",
             {"protocol": "openai_chat", "model": "gpt-4o-mini"})
    scenario("mod-test-bogus-protocol", "POST", "/api/political-moderation-config/test",
             mod_payload(protocol="bogus", enabled=False))
    scenario("mod-test-loopback", "POST", "/api/political-moderation-config/test",
             mod_payload(base_url=loopback, enabled=False))
    scenario("mod-test-loopback-http", "POST", "/api/political-moderation-config/test",
             mod_payload(base_url=f"http://127.0.0.1:{STUB_PORT}/v1", enabled=False))
    scenario("mod-test-disabled-public", "POST", "/api/political-moderation-config/test",
             mod_payload(enabled=False), timeout=12)
    scenario("mod-test-enabled-public", "POST", "/api/political-moderation-config/test",
             mod_payload(enabled=True), timeout=12)
    scenario("mod-test-blank-key", "POST", "/api/political-moderation-config/test",
             mod_payload(api_key="", enabled=False), timeout=12)
    scenario("mod-get-after-tests", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-tests")

    # Restart persistence of the stored config.
    stop_gateway()
    start_gateway(database)
    scenario("mod-get-restarted", "GET", "/api/political-moderation-config", None)
    dump_settings(database, "mod-after-restart")


def main():
    emit({"kind": "subject", "subject": subject, "binary": binary})
    emit_startup_probes()
    try:
        start_gateway("/tmp/mgmt-a.db")
        phase0_empty_state("/tmp/mgmt-a.db")
        phase1_mirror_counts_close("/tmp/mgmt-a.db")
        stop_gateway()
        start_gateway("/tmp/mgmt-b.db")
        phase2_moderation("/tmp/mgmt-b.db")
        stop_gateway()
    finally:
        stop_gateway()
        server.shutdown()


main()

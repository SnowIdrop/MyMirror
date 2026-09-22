"""Backup/restore v3 HTTP contract observations on a non-empty DB copy, guest loopback only.

Runs inside the disposable QEMU guest (see tools/oracle.py). Every case starts from an
independent copy of one synthetic seed database and records the request response headers,
full-row snapshots of all tables before/after, and the gateway process stdout/stderr/exit.
Author: MingTea.
"""
import hashlib
import base64
import http.client
import http.server
import json
import os
import shutil
import sqlite3
import subprocess
import threading
import time

EXPECTED_ORIGINAL_SHA = "4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098"
binary = os.environ.get("GATEWAY_TEST_BINARY", "/app/chatgpt-mirror-gateway")
secret = "contract-admin-secret-0001"
key_a = "backup-v3-fixture-key-a-0000000001"
key_b = "backup-v3-fixture-key-b-0000000002"
stub_port = 18091
seed_path = "/tmp/v3-seed.db"

SEED_SQL = [
    "INSERT INTO chatgpt_accounts (id, chatgpt_username, auth_status, plan_type, access_token, \
session_token, extra_cookies, refresh_token, remark, created_time, updated_time) VALUES \
(1, 'fixture-one@example.invalid', 1, 'plus', 'synthetic-access-token-0001', \
'synthetic-session-token-0001', '[]', 'synthetic-refresh-token-0001', 'seed-one', \
1700000000, 1700000001)",
    "INSERT INTO chatgpt_accounts (id, chatgpt_username, auth_status, plan_type, access_token, \
session_token, extra_cookies, refresh_token, remark, created_time, updated_time) VALUES \
(2, 'fixture-two@example.invalid', 0, 'free', 'synthetic-access-token-0002', NULL, '[]', \
'synthetic-refresh-token-0002', 'seed-two', 1700000002, 1700000003)",
    "INSERT INTO gateway_settings (key, value, updated_at) VALUES \
('mirror_proxy', '{\"enabled\":true,\"nodes\":[]}', 1700000010)",
    "INSERT INTO gateway_settings (key, value, updated_at) VALUES \
('political_moderation', '{\"mode\":\"relaxed\"}', 1700000011)",
    "INSERT INTO gateway_settings (key, value, updated_at) VALUES \
('custom_scripts', '{\"scripts\":[]}', 1700000012)",
    "INSERT INTO gateway_settings (key, value, updated_at) VALUES \
('blocked_paths', '{\"paths\":[\"/seed\"]}', 1700000013)",
    "INSERT INTO gateway_sessions (id, user_name, chatgpt_username, access_token, \
session_token, extra_cookies, login_mode, mirror_token, isolated_session, force_chat_mode, \
limits, proxy_node_id, daily_quota, monthly_quota, created_at, updated_at) VALUES \
(1, 'seed-user', 'fixture-one@example.invalid', 'synthetic-session-access-0001', \
'synthetic-session-token-0002', '[]', 'api', 'synthetic-mirror-token-0001', 1, 1, '[]', \
NULL, 5, 50, 1700000020, 1700000021)",
    "INSERT INTO conversation_owners (chatgpt_username, conversation_id, user_name, \
created_at, updated_at) VALUES ('fixture-one@example.invalid', 'conv-seed-1', 'seed-user', \
1700000030, 1700000031)",
    "INSERT INTO project_owners (chatgpt_username, project_id, user_name, created_at, \
updated_at) VALUES ('fixture-one@example.invalid', 'proj-seed-1', 'seed-user', \
1700000040, 1700000041)",
    "INSERT INTO visit_logs (id, username, chatgpt_username, log_type, created_at, ip, \
user_agent) VALUES (1, 'seed-user', 'fixture-one@example.invalid', 'login', 1700000050, \
'127.0.0.1', 'SeedFixture/1')",
    "INSERT INTO conversation_statistics (chatgpt_username, conversation_id, user_name, \
title, message_count, conversation_counted, created_at, updated_at) VALUES \
('fixture-one@example.invalid', 'conv-seed-1', 'seed-user', 'seed-title', 3, 1, \
1700000060, 1700000061)",
    "INSERT INTO conversation_model_statistics (user_name, model_name, message_count, \
updated_at) VALUES ('seed-user', 'gpt-5', 2, 1700000070)",
]


def emit(value):
    # Single unbuffered write keeps RESULT framing intact on the shared serial console.
    os.write(1, ("RESULT:" + json.dumps(value, ensure_ascii=False, default=json_default)
                 + "\n").encode("utf-8"))


def json_default(obj):
    if isinstance(obj, bytes):
        return {"__bytes_hex__": obj.hex()}
    return repr(obj)


if os.environ.get("GATEWAY_TEST_SUBJECT") == "rollback":
    shutil.copyfile("/app/candidate", "/app/rollback-copy")
    result = subprocess.run(["/app/ROLLBACK.sh", "/app/rollback-copy"],
                            capture_output=True, text=True)
    digest = hashlib.sha256(open("/app/rollback-copy", "rb").read()).hexdigest()
    emit({"kind": "rollback", "command": ["/app/ROLLBACK.sh", "/app/rollback-copy"],
          "stdout": result.stdout, "stderr": result.stderr, "exit": result.returncode,
          "sha256": digest})
    assert result.returncode == 0 and digest == EXPECTED_ORIGINAL_SHA
    binary = "/app/rollback-copy"


class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        data = json.dumps({"stub": True, "path": self.path, "method": self.command}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass


class SilentServer(http.server.ThreadingHTTPServer):
    """Gateway shutdown closes prewarm connections mid-write; keep stdout clean for RESULT framing."""

    def handle_error(self, request, client_address):
        pass


def gateway_env(db_path, port, key):
    upstream = "http://127.0.0.1:%d" % stub_port
    return {"PATH": os.environ["PATH"], "HOST": "127.0.0.1", "PORT": str(port),
            "DATABASE_PATH": db_path, "GATEWAY_ADMIN_SECRET": secret,
            "CREDENTIAL_ENCRYPTION_KEY": key, "REQUEST_TIMEOUT_SECS": "2",
            "DJANGO_UPSTREAM": upstream, "ADMIN_UPSTREAM": upstream,
            "CF_BYPASS_URL": upstream, "CHATGPT_BASE_URL": upstream,
            "CHATGPT_CDN_BASE_URL": upstream, "CHATGPT_AB_BASE_URL": upstream,
            "GATEWAY_COMPAT_PROFILE": "original"}


def start_gateway(db_path, port, key, tag):
    stdout = open("/tmp/v3-%s.out" % tag, "w+")
    stderr = open("/tmp/v3-%s.err" % tag, "w+")
    process = subprocess.Popen([binary], env=gateway_env(db_path, port, key),
                               stdout=stdout, stderr=stderr)
    ready = False
    for _ in range(150):
        if process.poll() is not None:
            break
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=.2)
            conn.connect()
            conn.close()
            ready = True
            break
        except OSError:
            time.sleep(.1)
    return process, stdout, stderr, ready


def collect_process(process, stdout, stderr, tag):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    stdout.seek(0)
    stderr.seek(0)
    record = {"kind": "process", "case": tag, "stdout": stdout.read(), "stderr": stderr.read(),
              "exit": process.returncode}
    stdout.close()
    stderr.close()
    return record


def stop_gateway(process, stdout, stderr, tag):
    emit(collect_process(process, stdout, stderr, tag))


def require_ready(tag, process, stdout, stderr, ready):
    """Seed/export phases are prerequisites; when they fail, surface the captured output."""
    if ready:
        return
    record = collect_process(process, stdout, stderr, tag)
    emit(record)
    raise RuntimeError("gateway not ready: %s exit=%r stdout=%r stderr=%r"
                       % (tag, record["exit"], record["stdout"][:600], record["stderr"][:600]))


def dump_db(path):
    conn = sqlite3.connect(path, timeout=5)
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' \
ORDER BY name")]
    snapshot = {}
    for name in tables:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(%s)" % name)]
        rows = [list(row) for row in conn.execute("SELECT * FROM %s ORDER BY rowid" % name)]
        snapshot[name] = {"columns": columns, "rows": rows}
    conn.close()
    return snapshot


def diff_tables(before, after):
    changed = {}
    for name in sorted(set(before) | set(after)):
        if before.get(name) != after.get(name):
            changed[name] = {
                "before_rows": len(before.get(name, {}).get("rows", [])),
                "after_rows": len(after.get(name, {}).get("rows", [])),
            }
    return changed


def request(port, method, path, payload=None):
    headers = {"Authorization": "Bearer " + secret}
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(method, path, body, headers)
    response = conn.getresponse()
    data = response.read().decode("utf-8", "replace")
    status, response_headers = response.status, response.getheaders()
    conn.close()
    return {"status": status, "headers": response_headers, "body": data}


def build_cases(base):
    cases = [
        ("empty-object", {}, "same", "{} envelope"),
        ("legacy-settings-only", {"settings": base["settings"]}, "same",
         "no version, settings array only"),
        ("v2-settings-only", {"version": 2, "settings": base["settings"]}, "same",
         "version 2 with settings only (task-reported 400 case)"),
        ("complete-v2", base, "same", "full export verbatim"),
    ]
    missing_first = {k: v for k, v in base.items() if k != "chatgpt_accounts"}
    cases.append(("v2-missing-accounts", missing_first, "same", "drop chatgpt_accounts key"))
    missing_middle = {k: v for k, v in base.items() if k != "conversation_statistics"}
    cases.append(("v2-missing-statistics", missing_middle, "same",
                  "drop conversation_statistics key"))
    envelope_type = json.loads(json.dumps(base))
    envelope_type["settings"] = {"unexpected": True}
    cases.append(("v2-settings-not-array", envelope_type, "same",
                  "settings replaced by object"))
    row_missing = json.loads(json.dumps(base))
    row_missing["chatgpt_accounts"][0].pop("access_token", None)
    cases.append(("v2-row-missing-field", row_missing, "same",
                  "accounts[0].access_token removed"))
    row_type = json.loads(json.dumps(base))
    row_type["chatgpt_accounts"][0]["id"] = []
    cases.append(("v2-row-object-type", row_type, "same", "accounts[0].id = []"))
    row_float = json.loads(json.dumps(base))
    row_float["conversation_statistics"][0]["message_count"] = 1.5
    cases.append(("v2-row-float-integer", row_float, "same",
                  "statistics[0].message_count = 1.5"))
    unknown_envelope = json.loads(json.dumps(base))
    unknown_envelope["surprise"] = []
    cases.append(("v2-unknown-envelope-field", unknown_envelope, "same", "extra envelope key"))
    unknown_row = json.loads(json.dumps(base))
    unknown_row["visit_logs"][0]["surprise"] = 1
    cases.append(("v2-unknown-row-field", unknown_row, "same", "extra visit_logs column"))
    cases.append(("repeat-restore", base, "same", "same payload posted twice"))
    cases.append(("wrong-key", base, "rotated", "payload key A, gateway key B"))
    corrupt_tail = json.loads(json.dumps(base))
    tail = corrupt_tail["chatgpt_accounts"][0]["access_token"]
    encoded=tail[len('enc:v1:'):]
    damaged=bytearray(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
    damaged[-1] ^= 1
    corrupt_tail["chatgpt_accounts"][0]["access_token"] = \
        'enc:v1:'+base64.urlsafe_b64encode(damaged).decode().rstrip('=')
    cases.append(("corrupt-ciphertext-tail", corrupt_tail, "same",
                  "accounts[0].access_token authentication-tag byte flipped; canonical base64"))
    corrupt_format = json.loads(json.dumps(base))
    for row in corrupt_format["settings"]:
        if row["key"] == "mirror_proxy":
            row["value"] = "enc:v1:%%%%not-base64"
    cases.append(("corrupt-settings-format", corrupt_format, "same",
                  "mirror_proxy value replaced by malformed envelope"))
    legacy_changed = json.loads(json.dumps(base["settings"]))
    for row in legacy_changed:
        if row["key"] == "custom_scripts":
            row["value"] = "{\"scripts\":[\"legacy-probe\"]}"
            row["updated_at"] = 999
    cases.append(("legacy-settings-changed", {"settings": legacy_changed}, "same",
                  "no version, settings with changed custom_scripts"))
    cases.append(("legacy-settings-new-key",
                  {"settings": [{"key": "legacy_probe_key", "value": "{\"probe\":1}",
                                 "updated_at": 999}]}, "same",
                  "no version, one previously absent settings key"))
    for version in (1, 3):
        mismatch = json.loads(json.dumps(base))
        mismatch["version"] = version
        cases.append(("v%d-full" % version, mismatch, "same",
                      "all tables verbatim with version %d" % version))
    all_empty = dict((k, []) for k in base)
    all_empty["version"] = 2
    cases.append(("v2-all-empty-arrays", all_empty, "same",
                  "version 2 with every table array empty"))
    row_missing_value = json.loads(json.dumps(base))
    row_missing_value["settings"][0].pop("value", None)
    cases.append(("v2-settings-row-missing-value", row_missing_value, "same",
                  "settings[0].value removed"))
    session_missing = json.loads(json.dumps(base))
    session_missing["gateway_sessions"][0].pop("access_token", None)
    cases.append(("v2-sessions-row-missing-token", session_missing, "same",
                  "gateway_sessions[0].access_token removed"))
    owner_missing = json.loads(json.dumps(base))
    owner_missing["conversation_owners"][0].pop("user_name", None)
    cases.append(("v2-owners-row-missing-user", owner_missing, "same",
                  "conversation_owners[0].user_name removed"))
    # Final bounded probe batch: remaining table messages, version dispatch, legacy table semantics.
    project_missing = json.loads(json.dumps(base))
    project_missing["project_owners"][0].pop("user_name", None)
    cases.append(("v2-projects-row-missing-user", project_missing, "same",
                  "project_owners[0].user_name removed"))
    stats_missing = json.loads(json.dumps(base))
    stats_missing["conversation_statistics"][0].pop("title", None)
    cases.append(("v2-statistics-row-missing-title", stats_missing, "same",
                  "conversation_statistics[0].title removed"))
    modelstats_missing = json.loads(json.dumps(base))
    modelstats_missing["conversation_model_statistics"][0].pop("model_name", None)
    cases.append(("v2-modelstats-row-missing-model", modelstats_missing, "same",
                  "conversation_model_statistics[0].model_name removed"))
    visit_missing = json.loads(json.dumps(base))
    visit_missing["visit_logs"][0].pop("ip", None)
    cases.append(("v2-visitlogs-row-missing-ip", visit_missing, "same",
                  "visit_logs[0].ip removed"))
    visit_type = json.loads(json.dumps(base))
    visit_type["visit_logs"][0]["id"] = []
    cases.append(("v2-visitlogs-id-type", visit_type, "same", "visit_logs[0].id = []"))
    accounts_missing_optional = json.loads(json.dumps(base))
    accounts_missing_optional["chatgpt_accounts"][0].pop("remark", None)
    cases.append(("v2-accounts-missing-remark", accounts_missing_optional, "same",
                  "accounts[0].remark (nullable) removed"))
    cases.append(("v1-settings-only", {"version": 1, "settings": base["settings"]}, "same",
                  "version 1 with settings only"))
    legacy_new_row = {"chatgpt_accounts": [{
        "id": 9, "chatgpt_username": "legacy-probe@example.invalid", "auth_status": True,
        "plan_type": "free", "access_token": "plain-legacy-token", "session_token": "",
        "extra_cookies": "[]", "refresh_token": "", "remark": "legacy-probe",
        "created_time": 1800000000, "updated_time": 1800000001}]}
    cases.append(("legacy-accounts-new-row", legacy_new_row, "same",
                  "no version, one new accounts row"))
    cases.append(("legacy-accounts-empty", {"chatgpt_accounts": []}, "same",
                  "no version, empty accounts array"))
    legacy_missing = {"chatgpt_accounts": [{
        "id": 8, "chatgpt_username": "legacy-missing@example.invalid",
        "plan_type": "free", "created_time": 1800000000, "updated_time": 1800000001}]}
    cases.append(("legacy-accounts-missing-field", legacy_missing, "same",
                  "no version, accounts row without access_token"))
    cases.append(("legacy-unknown-envelope", {"surprise": [], "settings": base["settings"]},
                  "same", "no version with unknown envelope key"))
    # Last bounded probe batch: per-column required vs default for the strict v2 path.
    def drop(table, field):
        payload = json.loads(json.dumps(base))
        payload[table][0].pop(field, None)
        return payload

    cases.append(("v2-accounts-created-time-missing",
                  drop("chatgpt_accounts", "created_time"), "same",
                  "accounts[0].created_time removed"))
    cases.append(("v2-statistics-message-count-missing",
                  drop("conversation_statistics", "message_count"), "same",
                  "statistics[0].message_count removed"))
    cases.append(("v2-accounts-session-token-missing",
                  drop("chatgpt_accounts", "session_token"), "same",
                  "accounts[0].session_token removed"))
    cases.append(("v2-accounts-auth-status-missing",
                  drop("chatgpt_accounts", "auth_status"), "same",
                  "accounts[0].auth_status removed"))
    cases.append(("v2-sessions-mirror-token-missing",
                  drop("gateway_sessions", "mirror_token"), "same",
                  "gateway_sessions[0].mirror_token removed"))
    cases.append(("v2-settings-key-missing", drop("settings", "key"), "same",
                  "settings[0].key removed"))
    cases.append(("v2-accounts-extra-cookies-missing",
                  drop("chatgpt_accounts", "extra_cookies"), "same",
                  "accounts[0].extra_cookies removed"))
    cases.append(("v2-accounts-plan-type-missing",
                  drop("chatgpt_accounts", "plan_type"), "same",
                  "accounts[0].plan_type removed"))
    cases.append(("v2-statistics-row-missing-conversation",
                  drop("conversation_statistics", "conversation_id"), "same",
                  "statistics[0].conversation_id removed"))
    cases.append(("v2-statistics-row-missing-user",
                  drop("conversation_statistics", "user_name"), "same",
                  "statistics[0].user_name removed"))
    cases.append(("v2-owners-row-missing-conversation",
                  drop("conversation_owners", "conversation_id"), "same",
                  "conversation_owners[0].conversation_id removed"))
    cases.append(("v2-modelstats-row-missing-user",
                  drop("conversation_model_statistics", "user_name"), "same",
                  "conversation_model_statistics[0].user_name removed"))
    cases.append(("v2-sessions-row-missing-user",
                  drop("gateway_sessions", "user_name"), "same",
                  "gateway_sessions[0].user_name removed"))
    cases.append(("v2-visitlogs-row-missing-username",
                  drop("visit_logs", "username"), "same",
                  "visit_logs[0].username removed"))
    not_object = json.loads(json.dumps(base))
    not_object["chatgpt_accounts"][0] = "oops"
    cases.append(("v2-accounts-row-not-object", not_object, "same",
                  "accounts[0] replaced by a string"))
    # Final defaults/plain/type batch: per-table missing-column semantics for the strict path.
    def drop_many(table, fields):
        payload = json.loads(json.dumps(base))
        for field in fields:
            payload[table][0].pop(field, None)
        return payload

    cases.append(("v2-accounts-missing-optional",
                  drop_many("chatgpt_accounts",
                            ["chatgpt_username", "refresh_token", "updated_time"]),
                  "same", "accounts[0] without username/refresh/updated_time"))
    cases.append(("v2-sessions-missing-optional",
                  drop_many("gateway_sessions",
                            ["id", "chatgpt_username", "session_token", "extra_cookies",
                             "login_mode", "isolated_session", "force_chat_mode", "limits",
                             "proxy_node_id", "daily_quota", "monthly_quota",
                             "created_at", "updated_at"]),
                  "same", "gateway_sessions[0] without id and optional columns"))
    cases.append(("v2-sessions-with-id-optional",
                  drop_many("gateway_sessions",
                            ["chatgpt_username", "session_token", "extra_cookies",
                             "login_mode", "isolated_session", "force_chat_mode", "limits",
                             "proxy_node_id", "daily_quota", "monthly_quota",
                             "created_at", "updated_at"]),
                  "same", "gateway_sessions[0] without optional columns, id kept"))
    cases.append(("v2-settings-missing-updated", drop_many("settings", ["updated_at"]),
                  "same", "settings[0].updated_at removed"))
    cases.append(("v2-owners-missing-optional",
                  drop_many("conversation_owners",
                            ["chatgpt_username", "created_at", "updated_at"]),
                  "same", "conversation_owners[0] without chatgpt_username/timestamps"))
    cases.append(("v2-owners-missing-timestamps",
                  drop_many("conversation_owners", ["created_at", "updated_at"]),
                  "same", "conversation_owners[0] without timestamps"))
    cases.append(("v2-projects-missing-optional",
                  drop_many("project_owners",
                            ["chatgpt_username", "project_id", "created_at", "updated_at"]),
                  "same", "project_owners[0] without chatgpt_username/project_id/timestamps"))
    cases.append(("v2-projects-missing-timestamps",
                  drop_many("project_owners", ["created_at", "updated_at"]),
                  "same", "project_owners[0] without timestamps"))
    cases.append(("v2-visitlogs-missing-optional",
                  drop_many("visit_logs",
                            ["chatgpt_username", "log_type", "created_at", "user_agent"]),
                  "same", "visit_logs[0] without chatgpt_username/log_type/timestamps/ua"))
    cases.append(("v2-visitlogs-missing-logtype-chain",
                  drop_many("visit_logs", ["log_type", "created_at", "user_agent"]),
                  "same", "visit_logs[0] without log_type/timestamps/ua"))
    cases.append(("v2-visitlogs-missing-timestamps-ua",
                  drop_many("visit_logs", ["created_at", "user_agent"]),
                  "same", "visit_logs[0] without created_at/user_agent"))
    cases.append(("v2-stats-missing-optional",
                  drop_many("conversation_statistics",
                            ["chatgpt_username", "conversation_counted",
                             "created_at", "updated_at"]),
                  "same", "statistics[0] without chatgpt_username/counted/timestamps"))
    cases.append(("v2-stats-missing-timestamps",
                  drop_many("conversation_statistics", ["created_at", "updated_at"]),
                  "same", "statistics[0] without timestamps"))
    cases.append(("v2-modelstats-missing-optional",
                  drop_many("conversation_model_statistics", ["message_count", "updated_at"]),
                  "same", "model stats row without message_count/updated_at"))
    plain_values = json.loads(json.dumps(base))
    plain_values["chatgpt_accounts"][0]["access_token"] = "plain-token-x"
    plain_values["chatgpt_accounts"][0]["session_token"] = "plain-session-x"
    for row in plain_values["settings"]:
        if row["key"] == "mirror_proxy":
            row["value"] = "{\"enabled\":false}"
        elif row["key"] == "political_moderation":
            row["value"] = "{\"mode\":\"strict\"}"
    cases.append(("v2-plain-values", plain_values, "same",
                  "strict v2 with plaintext tokens and plain settings JSON"))
    legacy_plain = {"chatgpt_accounts": [{
        "id": 9, "chatgpt_username": "legacy-plain@example.invalid", "auth_status": True,
        "plan_type": "free", "access_token": "plain-legacy-token", "session_token": "plain-legacy-session",
        "extra_cookies": "[]", "refresh_token": "plain-legacy-refresh", "remark": "legacy-plain",
        "created_time": 1800000000, "updated_time": 1800000001}]}
    cases.append(("legacy-accounts-plain", legacy_plain, "same",
                  "no version, plaintext credentials in new accounts row"))
    settings_number = json.loads(json.dumps(base))
    for row in settings_number["settings"]:
        if row["key"] == "custom_scripts":
            row["key"] = "legacy_probe_key"
            row["value"] = 123
    cases.append(("v2-settings-value-number", settings_number, "same",
                  "settings row value replaced by integer 123"))
    username_number = json.loads(json.dumps(base))
    username_number["chatgpt_accounts"][0]["chatgpt_username"] = 7
    cases.append(("v2-accounts-username-number", username_number, "same",
                  "accounts[0].chatgpt_username replaced by integer"))
    auth_status_string = json.loads(json.dumps(base))
    auth_status_string["chatgpt_accounts"][0]["auth_status"] = "yes"
    cases.append(("v2-accounts-auth-status-string", auth_status_string, "same",
                  "accounts[0].auth_status replaced by string \"yes\""))
    # Last probe batch: close remaining column semantics and retry one bind-conflicted case.
    cases.append(("v2-visitlogs-missing-timestamps-ua-retry",
                  drop_many("visit_logs", ["created_at", "user_agent"]), "same",
                  "visit_logs[0] without created_at/user_agent (retry)"))
    cases.append(("v2-visitlogs-missing-chatgpt-username",
                  drop_many("visit_logs", ["chatgpt_username"]), "same",
                  "visit_logs[0].chatgpt_username removed"))
    cases.append(("v2-accounts-missing-refresh-updated",
                  drop_many("chatgpt_accounts", ["refresh_token", "updated_time"]), "same",
                  "accounts[0] without refresh_token/updated_time"))
    cases.append(("v2-sessions-missing-optional-rest",
                  drop_many("gateway_sessions",
                            ["session_token", "extra_cookies", "login_mode",
                             "isolated_session", "force_chat_mode", "limits",
                             "proxy_node_id", "daily_quota", "monthly_quota",
                             "created_at", "updated_at"]),
                  "same", "gateway_sessions[0] optional columns removed"))
    cases.append(("v2-projects-missing-project-id",
                  drop_many("project_owners", ["project_id"]), "same",
                  "project_owners[0].project_id removed"))
    cases.append(("v2-stats-missing-counted",
                  drop_many("conversation_statistics", ["conversation_counted"]), "same",
                  "statistics[0].conversation_counted removed"))
    cases.append(("v2-settings-missing-updated-retry", drop_many("settings", ["updated_at"]),
                  "same", "settings[0].updated_at removed (repeat for stability)"))
    blocked_row = [row for row in base["settings"] if row["key"] == "blocked_paths"][0]
    blocked_updated = json.loads(json.dumps(blocked_row))
    blocked_updated["value"] = "{\"paths\":[\"/legacy-updated\"]}"
    blocked_updated["updated_at"] = 999999
    cases.append(("legacy-settings-not-array", {"settings": {"unexpected": True}}, "same",
                  "no version, settings replaced by object"))
    cases.append(("legacy-accounts-row-not-object", {"chatgpt_accounts": ["oops"]}, "same",
                  "no version, accounts row replaced by string"))
    cases.append(("legacy-version-string", {"version": "2", "settings": base["settings"]},
                  "same", "version as string \"2\" with settings array"))
    cases.append(("legacy-settings-update-blocked", {"blocked_paths": [blocked_updated]},
                  "same", "no version, existing blocked_paths row replaced"))
    political_row = [row for row in base["settings"] if row["key"] == "political_moderation"][0]
    political_updated = json.loads(json.dumps(political_row))
    political_updated["value"] = "{\"mode\":\"strict\"}"
    political_updated["updated_at"] = 888888
    cases.append(("legacy-settings-update-political", {"settings": [political_updated]}, "same",
                  "no version, existing political_moderation row replaced"))
    accounts_updated = json.loads(json.dumps(base["chatgpt_accounts"][0]))
    accounts_updated["remark"] = "changed-remark"
    cases.append(("legacy-accounts-update-remark", {"chatgpt_accounts": [accounts_updated]}, "same",
                  "no version, existing accounts row remark changed"))
    stats_updated = json.loads(json.dumps(base["conversation_statistics"][0]))
    stats_updated["title"] = "changed-title"
    cases.append(("legacy-stats-update-title",
                  {"conversation_statistics": [stats_updated]}, "same",
                  "no version, existing statistics row title changed"))
    custom_valid = json.loads(json.dumps([row for row in base["settings"]
                                          if row["key"] == "custom_scripts"][0]))
    custom_valid["value"] = "{\"scripts\":[{\"name\":\"fixture\",\"content\":\"void 0\"}]}"
    custom_valid["updated_at"] = 777777
    cases.append(("legacy-settings-update-custom-valid", {"settings": [custom_valid]}, "same",
                  "no version, custom_scripts replaced by valid script config"))
    return cases


server = SilentServer(("127.0.0.1", stub_port), Stub)
threading.Thread(target=server.serve_forever, daemon=True).start()

try:
    # Seed schema, then synthetic plaintext rows, then a startup pass so the gateway
    # migrates sensitive columns exactly like production.
    for path in (seed_path,):
        if os.path.exists(path):
            os.remove(path)
    process, stdout, stderr, ready = start_gateway(seed_path, 20210, key_a, "seed-schema")
    require_ready("seed-schema", process, stdout, stderr, ready)
    stop_gateway(process, stdout, stderr, "seed-schema")
    time.sleep(.3)
    conn = sqlite3.connect(seed_path)
    for sql in SEED_SQL:
        conn.execute(sql)
    conn.commit()
    conn.close()
    process, stdout, stderr, ready = start_gateway(seed_path, 20212, key_a, "seed-migrate")
    require_ready("seed-migrate", process, stdout, stderr, ready)
    stop_gateway(process, stdout, stderr, "seed-migrate")
    time.sleep(.3)
    emit({"kind": "seed", "path": seed_path, "sql": SEED_SQL, "snapshot": dump_db(seed_path)})

    # Export of the populated seed is the base payload for every case.
    shutil.copyfile(seed_path, "/tmp/v3-export.db")
    process, stdout, stderr, ready = start_gateway("/tmp/v3-export.db", 20211, key_a, "export")
    require_ready("export", process, stdout, stderr, ready)
    export_response = request(20211, "GET", "/api/backup/export")
    emit({"kind": "export", "path": "/api/backup/export", "response": export_response})
    stop_gateway(process, stdout, stderr, "export")
    assert export_response["status"] == 200, "populated export must succeed before cases"
    base = json.loads(export_response["body"])

    for index, (case_id, payload, key_mode, note) in enumerate(build_cases(base)):
        # 使用低于 Linux 临时客户端端口范围的监听端口，避免前一请求占用下一用例端口。
        port = 20220 + index
        case_db = "/tmp/v3-case-%02d.db" % index
        shutil.copyfile(seed_path, case_db)
        process, stdout, stderr, ready = start_gateway(
            case_db, port, key_b if key_mode == "rotated" else key_a, case_id)
        record = {"kind": "case", "id": case_id, "note": note, "db": case_db,
                  "key_mode": key_mode, "payload": payload}
        if not ready:
            record["startup_ready"] = False
            emit(record)
            stop_gateway(process, stdout, stderr, case_id)
            continue
        record["startup_ready"] = True
        before = dump_db(case_db)
        if case_id == "repeat-restore":
            first = request(port, "POST", "/api/backup/restore", payload)
            middle = dump_db(case_db)
            second = request(port, "POST", "/api/backup/restore", payload)
            after = dump_db(case_db)
            record["responses"] = [first, second]
            record["mid"] = middle
            record["mid_changed"] = diff_tables(before, middle)
        else:
            record["responses"] = [request(port, "POST", "/api/backup/restore", payload)]
            after = dump_db(case_db)
        record["before"] = before
        record["after"] = after
        record["changed"] = diff_tables(before, after)
        emit(record)
        stop_gateway(process, stdout, stderr, case_id)

    emit({"kind": "summary", "cases": [case[0] for case in build_cases(base)],
          "binary": binary, "subject": os.environ.get("GATEWAY_TEST_SUBJECT", "original")})
finally:
    server.shutdown()

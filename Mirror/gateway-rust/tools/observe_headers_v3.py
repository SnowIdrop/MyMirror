"""Response header / compression observations for original/candidate/rollback.
Author: MingTea. Disposable QEMU guest only; loopback stub upstream; no external network.

Focus of this contract:
- real compression threshold sweep at body lengths 28..34 (client asks gzip),
- content types json/text/html/binary/image/SSE,
- Accept-Encoding negotiation: gzip/br/deflate/zstd/identity, q values, aliases, unknown,
- admin 401 (gateway secret missing) vs user 401 (session missing), 405 method rejection,
- Vary layering: `Cookie, Authorization` from the private/header layer plus one
  `accept-encoding` appended by the compression layer, including upstream-supplied Vary.

Recording rules:
- `body` is the response body after decoding; it is what tools/compare.py compares,
- `body_raw_b64` / `body_raw_sha256` / `body_raw_length` keep the on-wire bytes,
- gzip/deflate are decoded in the guest (stdlib only); brotli/zstd payloads cannot be
  decoded by the guest interpreter, so their `body` is a stable placeholder and the raw
  bytes stay available for host-side decoding,
- `content-length` is moved out of `headers` whenever it cannot equal the decoded body
  length (compressed passthrough), so compare.py never sees a self-contradictory record.
"""
import base64
import gzip
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
import zlib

SECRET = "contract-admin-secret-0001"
KEY = "contract-encryption-key-000000000000001"
PORT = 40200
STUB_PORT = 18092
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


CONTENT_TYPES = {
    "json": "application/json",
    "vary-ae": "application/json",
    "vary-cookie": "application/json",
    "gz-json": "application/json",
    "text": "text/plain; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "bin": "application/octet-stream",
    "img": "image/png",
    "sse": "text/event-stream",
}


def fixture_body(kind, length):
    """Deterministic payload of an exact byte length for the requested fixture kind."""
    if kind in ("json", "vary-ae", "vary-cookie", "gz-json"):
        body = b'{"p":"' + b"a" * max(length - 8, 0) + b'"}'
    elif kind == "text":
        body = b"a" * length
    elif kind == "html":
        body = b"<html>" + b"a" * max(length - 6, 0)
    elif kind == "bin":
        body = b"B" * length
    elif kind == "img":
        body = b"I" * length
    elif kind == "sse":
        body = (b"data: " + b"a" * 8 + b"\n\n") * (length // 15 + 1)
    else:
        raise ValueError("unknown fixture kind: " + kind)
    body = body[:length]
    return body + b"a" * (length - len(body))


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
        parts = self.path.split("?")[0].strip("/").split("/")
        if self.path.startswith("/backend-api/conversations"):
            # `limit` drives the fixture length so the proxied response keeps a
            # Content-Length header (documented baseline behaviour for this route).
            length = 22
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            for pair in query.split("&"):
                if pair.startswith("limit="):
                    length = int(pair.split("=", 1)[1])
            payload = fixture_body("json", length)
            emit(
                {
                    "kind": "upstream",
                    "case": "backend-api-conversations-" + str(length),
                    "method": self.command,
                    "path": self.path,
                    "headers": list(self.headers.items()),
                    "body_length": len(body),
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if len(parts) >= 5 and parts[0] == "0x" and parts[1] == "fx":
            kind = parts[2]
            length = int(parts[3])
            label = parts[4]
            emit(
                {
                    "kind": "upstream",
                    "case": label,
                    "method": self.command,
                    "path": self.path,
                    "headers": list(self.headers.items()),
                    "body_length": len(body),
                }
            )
            payload = fixture_body(kind, length)
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPES[kind])
            if kind == "gz-json":
                payload = gzip.compress(payload, mtime=0)
                self.send_header("Content-Encoding", "gzip")
            elif kind == "vary-ae":
                self.send_header("Vary", "accept-encoding")
            elif kind == "vary-cookie":
                self.send_header("Vary", "Cookie, Authorization")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
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
    gateway_log = (
        open("/tmp/headers-v3.out", "w+"),
        open("/tmp/headers-v3.err", "w+"),
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


def decode_body(raw, content_encoding):
    """Returns (body_text, decoded, decode_status, raw_is_text)."""
    if content_encoding is None:
        return raw.decode("utf-8", errors="replace"), True, "none", True
    encoding = content_encoding.strip().lower()
    if encoding == "gzip":
        try:
            return gzip.decompress(raw).decode("utf-8", errors="replace"), True, "gzip", True
        except Exception:
            return "<gzip-decode-failed>", False, "gzip-decode-failed", False
    if encoding == "deflate":
        try:
            return zlib.decompress(raw).decode("utf-8", errors="replace"), True, "deflate", True
        except Exception:
            return "<deflate-decode-failed>", False, "deflate-decode-failed", False
    # brotli/zstd have no stdlib decoder in the guest image; keep a stable placeholder.
    return f"<{encoding}-encoded body>", False, f"{encoding}-encoded", False


def probe(case_id, method, path, payload=None, auth=False, headers=None, cookie=None,
          note=None, content_type=True):
    request_headers = dict(headers or {})
    if auth:
        request_headers["Authorization"] = "Bearer " + SECRET
    if cookie:
        request_headers["Cookie"] = cookie
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        if content_type:
            request_headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        raw = response.read()
        status = response.status
        observed_headers = response.getheaders()
    finally:
        conn.close()
    lowered = {}
    for name, value in observed_headers:
        lowered.setdefault(name.lower(), []).append(value)
    content_encoding = (lowered.get("content-encoding") or [None])[0]
    decoded_text, decoded, decode_status, raw_is_text = decode_body(raw, content_encoding)
    recorded_headers = []
    observed_content_length = None
    for name, value in observed_headers:
        if name.lower() == "content-length":
            try:
                numeric = int(value)
            except ValueError:
                numeric = None
            if numeric is not None and decode_status == "none" \
                    and numeric == len(decoded_text.encode()):
                recorded_headers.append([name, value])
            else:
                observed_content_length = numeric
            continue
        recorded_headers.append([name, value])
    record = {
        "kind": "scenario",
        "id": case_id,
        "method": method,
        "path": path,
        "auth": auth,
        "request_headers": sorted(request_headers.items()),
        "status": status,
        "headers": recorded_headers,
        "body": decoded_text,
        "body_raw_b64": base64.b64encode(raw).decode(),
        "body_raw_sha256": hashlib.sha256(raw).hexdigest(),
        "body_raw_length": len(raw),
        "content_encoding": content_encoding,
        "body_decoded": decoded,
        "decode_status": decode_status,
        "body_raw_is_utf8_text": raw_is_text,
        "zstd_magic": raw[:4] == b"\x28\xb5\x2f\xfd",
        "first_bytes_hex": raw[:16].hex(),
        "observed_content_length": observed_content_length,
    }
    if note:
        record["note"] = note
    emit(record)
    return status, recorded_headers, decoded_text


def seed_sessions(database, user_name, count):
    """Seed gateway_sessions rows so close-chatgpt-memory reports an exact affected count."""
    if count == 0:
        return
    conn = sqlite3.connect(database, timeout=10)
    try:
        conn.executemany(
            "INSERT INTO gateway_sessions (user_name, chatgpt_username, access_token, \
             mirror_token) VALUES (?1, ?2, ?3, ?4)",
            [
                (
                    user_name,
                    f"sweep-{index}@example.invalid",
                    "synthetic-access-token",
                    "sha256:" + ("%064x" % (index + 1)),
                )
                for index in range(count)
            ],
        )
        conn.commit()
    finally:
        conn.close()


def handoff_cookie():
    _, _, body = probe(
        "hdr-login",
        "POST",
        "/api/login",
        {
            "user_name": "headers",
            "access_token": "synthetic-access-token",
            "session_token": "",
            "login_mode": "api",
            "isolated_session": True,
            "limits": [],
            "daily_quota": 0,
            "monthly_quota": 0,
            "force_chat_mode": True,
        },
        auth=True,
    )
    login_url = json.loads(body)["login_url"]
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        conn.request("GET", login_url)
        response = conn.getresponse()
        raw = response.read()
        cookies = [
            value.split(";", 1)[0]
            for name, value in response.getheaders()
            if name.lower() == "set-cookie" and value.startswith("mirror_token=")
        ]
        emit(
            {
                "kind": "scenario",
                "id": "hdr-handoff",
                "method": "GET",
                "path": login_url.split("?")[0],
                "auth": False,
                "status": response.status,
                "headers": response.getheaders(),
                "body": raw.decode("utf-8", errors="replace"),
            }
        )
    finally:
        conn.close()
    return "; ".join(cookies)


def threshold_sweep(database, cookie):
    """Pin the compression threshold on buffered native bodies whose byte length is exact.

    `close-chatgpt-memory` echoes `{"affected":<count>,"message":"ok"}`; one additional
    digit adds exactly one byte: 0→29, 10→30, 100→31, 1000→32, 10000→33.
    """
    for count, length in ((0, 29), (10, 30), (100, 31), (1000, 32), (10000, 33)):
        user = f"hdr-sweep-{count}"
        seed_sessions(database, user, count)
        probe(
            f"len-{length}-close-gzip",
            "POST",
            "/api/close-chatgpt-memory",
            {"user_name": user},
            auth=True,
            headers={"Accept-Encoding": "gzip"},
            note=f"exact body length {length} (affected={count})",
        )
    # Boundary controls: identity keeps content-length, and the vary append follows the
    # predicate (>=32) even when no encoder runs.
    for length, count in ((31, 100), (32, 1000)):
        user = f"hdr-sweep-{count}-identity"
        seed_sessions(database, user, count)
        probe(
            f"len-{length}-close-identity",
            "POST",
            "/api/close-chatgpt-memory",
            {"user_name": user},
            auth=True,
            headers={"Accept-Encoding": "identity"},
            note=f"identity client, exact body length {length}",
        )
    seed_sessions(database, "hdr-sweep-32br", 1000)
    probe("len-32-close-br", "POST", "/api/close-chatgpt-memory",
          {"user_name": "hdr-sweep-32br"}, auth=True,
          headers={"Accept-Encoding": "br"},
          note="br wins negotiation but only gzip is encoded; 32-byte body")
    seed_sessions(database, "hdr-sweep-33-id", 10000)
    probe("len-33-close-no-header", "POST", "/api/close-chatgpt-memory",
          {"user_name": "hdr-sweep-33-id"}, auth=True,
          note="no accept-encoding header, 33-byte body")
    # Streamed (unknown length) proxied bodies still compress regardless of size.
    for length in (8, 29, 33):
        probe(
            f"len-{length}-proxy-streamed-gzip",
            "GET",
            f"/0x/fx/json/{length}/len-{length}-proxy-streamed-gzip",
            headers={"Accept-Encoding": "gzip"},
            cookie=cookie,
            note="streamed proxied body without content-length",
        )
    # Conversation list envelope: buffered native body of 22 bytes with content-length.
    probe("len-22-conversations-gzip", "GET",
          "/backend-api/conversations?offset=0&limit=20",
          headers={"Accept-Encoding": "gzip"}, cookie=cookie,
          note="rebuilt conversations envelope is 22 bytes")


def statistics_shape_cases():
    """Shape probes for /api/conversation-statistics (original answered `{}` for
    `{"username_list": [...]}`; these cases pin which input key is honoured)."""
    probe("stat-shape-username-list", "POST", "/api/conversation-statistics",
          {"username_list": ["probe-user"]}, auth=True,
          note="list of names under username_list")
    probe("stat-shape-array-body", "POST", "/api/conversation-statistics",
          ["probe-user"], auth=True, note="bare JSON array body")
    probe("stat-shape-user-name", "POST", "/api/conversation-statistics",
          {"user_name": "probe-user"}, auth=True, note="single user_name key")
    probe("stat-shape-user-names", "POST", "/api/conversation-statistics",
          {"user_names": ["probe-user", "other-user"]}, auth=True)
    db=sqlite3.connect('/tmp/headers-v3.db')
    rows=[('fixture@example.invalid','s1','probe-user','one',3,1,1700000000,1700000020),
          ('fixture@example.invalid','s2','probe-user','two',5,0,1700000001,1700000010),
          ('other@example.invalid','s3','other-user','three',7,1,1700000000,1700000030)]
    db.executemany('INSERT INTO conversation_statistics VALUES(?,?,?,?,?,?,?,?)', rows)
    db.execute('INSERT INTO conversation_model_statistics VALUES(?,?,?,?)',('probe-user','gpt-4o',8,1700000010))
    db.commit(); db.close()
    emit({'kind':'seed','id':'statistics','rows':rows})
    probe('stat-populated-single','POST','/api/conversation-statistics',{'user_name':'probe-user'},auth=True)
    probe('stat-populated-list','POST','/api/conversation-statistics',{'user_name_list':['probe-user','other-user','absent']},auth=True)
    probe('stat-populated-both','POST','/api/conversation-statistics',{'user_name':'probe-user','user_name_list':['other-user']},auth=True)


def content_type_cases(cookie):
    for kind in ("json", "text", "html", "bin", "img", "sse"):
        probe(
            f"ct-{kind}-64-gzip",
            "GET",
            f"/0x/fx/{kind}/64/ct-{kind}-64-gzip",
            headers={"Accept-Encoding": "gzip"},
            cookie=cookie,
        )
    probe("ct-json-64-no-header", "GET", "/0x/fx/json/64/ct-json-no-header",
          cookie=cookie, note="client sends no accept-encoding")
    probe("ct-sse-64-no-header", "GET", "/0x/fx/sse/64/ct-sse-no-header", cookie=cookie)
    probe("ct-json-29-gzip", "GET", "/0x/fx/json/29/ct-json-29-gzip",
          headers={"Accept-Encoding": "gzip"}, cookie=cookie,
          note="upstream proxied body below the adaptive threshold")
    probe("ct-json-8-gzip", "GET", "/0x/fx/json/8/ct-json-8-gzip",
          headers={"Accept-Encoding": "gzip"}, cookie=cookie,
          note="streamed body far below any size threshold")
    probe("ct-json-20-gzip", "GET", "/0x/fx/json/20/ct-json-20-gzip",
          headers={"Accept-Encoding": "gzip"}, cookie=cookie)


def negotiation_cases(cookie):
    variants = [
        ("gzip", "gzip"),
        ("br", "br"),
        ("deflate", "deflate"),
        ("zstd", "zstd"),
        ("identity", "identity"),
        ("empty", ""),
        ("gzip-br", "gzip, br"),
        ("zstd-gzip", "zstd, gzip"),
        ("gzip-q05-br", "gzip;q=0.5, br"),
        ("gzip-q1-zstd-q01", "gzip;q=1.0, zstd;q=0.1"),
        ("gzip-q0", "gzip;q=0"),
        ("gzip-q0-br-q0", "gzip;q=0, br;q=0"),
        ("q-abc", "gzip;q=abc"),
        ("star", "*"),
        ("x-gzip", "x-gzip"),
        ("deflate-x-gzip", "deflate,x-gzip"),
        ("zstd-q08-br-q09", "zstd;q=0.8,br;q=0.9"),
        ("upper-gzip", "GZIP"),
        ("identity-q1-gzip", "identity;q=1.0, gzip"),
        ("identity-q09-gzip-q05", "identity;q=0.9, gzip;q=0.5"),
        ("identity-q0", "identity;q=0"),
        ("all-four", "zstd,gzip,deflate,br"),
        ("br-q1-gzip-q09", "br;q=1.0, gzip;q=0.9"),
        ("deflate-q1-gzip-q09", "deflate;q=1.0, gzip;q=0.9"),
        ("zstd-q1-gzip-q09", "zstd;q=1.0, gzip;q=0.9"),
        ("gzip-q09", "gzip;q=0.9"),
    ]
    for label, value in variants:
        probe(
            f"neg-{label}",
            "POST",
            "/api/blocked-paths",
            {"paths": ["/" + "a" * 8]},
            auth=True,
            headers={"Accept-Encoding": value},
            note="native 68-byte JSON response",
        )
    for label, value in (
        ("br", "br"),
        ("deflate", "deflate"),
        ("zstd", "zstd"),
        ("gzip-q05-br", "gzip;q=0.5, br"),
    ):
        probe(
            f"neg-proxy-{label}",
            "GET",
            f"/0x/fx/json/64/neg-proxy-{label}",
            headers={"Accept-Encoding": value},
            cookie=cookie,
            note="streamed 64-byte JSON response",
        )


def handler_and_error_cases(cookie):
    probe("native-close-29-identity", "GET", "/api/close-chatgpt-memory", auth=True)
    probe("native-close-29-gzip", "GET", "/api/close-chatgpt-memory", auth=True,
          headers={"Accept-Encoding": "gzip"})
    probe("native-quota-33-gzip", "POST", "/api/get-user-quota-usage",
          {"user_name": "nobody", "day_start": 0, "month_start": 0}, auth=True,
          headers={"Accept-Encoding": "gzip"})
    probe("native-testproxy-32-identity", "POST", "/api/test-mirror-proxy-config",
          {"enabled": False}, auth=True)
    probe("native-testproxy-32-gzip", "POST", "/api/test-mirror-proxy-config",
          {"enabled": False}, auth=True, headers={"Accept-Encoding": "gzip"})
    probe("native-overview-40-gzip", "POST", "/api/operations-overview",
          {"day_start": 0, "month_start": 0}, auth=True,
          headers={"Accept-Encoding": "gzip"})
    probe("native-overview-40-br", "POST", "/api/operations-overview",
          {"day_start": 0, "month_start": 0}, auth=True,
          headers={"Accept-Encoding": "br"})
    probe("native-counts-2-br", "POST", "/api/get-user-use-count",
          {"username_list": []}, auth=True, headers={"Accept-Encoding": "br"})
    probe("native-logout-26-gzip", "POST", "/api/logout", {"user_name": "nobody"},
          auth=True, headers={"Accept-Encoding": "gzip"})
    probe("native-logout-26-no-header", "POST", "/api/logout", {"user_name": "nobody"},
          auth=True)
    probe("admin-401-gzip", "GET", "/api/close-chatgpt-memory",
          headers={"Accept-Encoding": "gzip"}, note="no gateway secret")
    probe("admin-401-no-header", "GET", "/api/close-chatgpt-memory",
          note="no gateway secret")
    probe("admin-401-br", "GET", "/api/close-chatgpt-memory",
          headers={"Accept-Encoding": "br"}, note="no gateway secret")
    probe("user-401-gzip", "GET", "/api/user-blocked-paths",
          headers={"Accept-Encoding": "gzip"}, note="no session cookie")
    probe("user-401-br", "GET", "/api/user-blocked-paths",
          headers={"Accept-Encoding": "br"}, note="no session cookie")
    probe("method-405-export", "POST", "/api/backup/export", {}, auth=True,
          headers={"Accept-Encoding": "gzip"})
    probe("method-405-session", "POST", "/api/auth/session", {}, auth=True,
          headers={"Accept-Encoding": "gzip"})
    probe("method-405-not-login", "POST", "/api/not-login", {}, auth=True,
          headers={"Accept-Encoding": "gzip"})
    probe("proxy-vary-ae", "GET", "/0x/fx/vary-ae/64/proxy-vary-ae",
          headers={"Accept-Encoding": "gzip"}, cookie=cookie)
    probe("proxy-vary-cookie", "GET", "/0x/fx/vary-cookie/64/proxy-vary-cookie",
          headers={"Accept-Encoding": "gzip"}, cookie=cookie)
    probe("proxy-upstream-gzip-no-header", "GET", "/0x/fx/gz-json/64/proxy-gz-no-header",
          cookie=cookie, note="upstream already gzip encoded")
    probe("proxy-upstream-gzip-client-gzip", "GET", "/0x/fx/gz-json/64/proxy-gz-client-gzip",
          headers={"Accept-Encoding": "gzip"}, cookie=cookie,
          note="upstream already gzip encoded")
    probe("proxy-json-64-no-cookie", "GET", "/0x/fx/json/64/proxy-json-no-cookie",
          headers={"Accept-Encoding": "gzip"}, note="no session cookie")


def main():
    emit({"kind": "subject", "subject": subject, "binary": binary})
    try:
        database = "/tmp/headers-v3.db"
        start_gateway(database)
        cookie = handoff_cookie()
        threshold_sweep(database, cookie)
        content_type_cases(cookie)
        negotiation_cases(cookie)
        handler_and_error_cases(cookie)
        statistics_shape_cases()
        stop_gateway()
    finally:
        stop_gateway()
        server.shutdown()


main()

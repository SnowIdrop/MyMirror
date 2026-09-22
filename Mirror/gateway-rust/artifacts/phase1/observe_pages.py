"""Original-gateway observations in QEMU with no NIC, synthetic loopback services only."""
import hashlib
import http.client
import http.server
import json
import os
import sqlite3
import subprocess
import threading
import time

SECRET = "contract-admin-secret-0001"
KEY = "contract-encryption-key-000000000000001"
case = "startup"
mode = {"me": 200, "accounts": 200}

def emit(value):
    print("RESULT:" + json.dumps(value, ensure_ascii=False), flush=True)

class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_HEAD(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        emit({"kind": "upstream", "case": case, "service": self.server.service,
              "method": self.command, "path": self.path, "headers": list(self.headers.items()),
              "body": data.decode(errors="replace")})
        status = 200
        content_type = "application/json"
        if self.path.startswith("/cloudflare5s/"):
            body = {"cookies": [{"name": "cf_clearance", "value": "SYNTHETIC", "domain": "127.0.0.1", "path": "/"}]}
        elif self.path.startswith("/backend-api/me"):
            status = mode["me"]
            body = {"id": "synthetic-id", "email": "fixture@example.invalid", "name": "Fixture"}
        elif self.path.startswith("/backend-api/accounts/check/"):
            status = mode["accounts"]
            body = {"accounts": {"default": {"account": {"plan_type": "plus", "account_id": "fixture-account"}}}, "account_ordering": ["default"]}
        elif self.path.split("?", 1)[0].endswith(".js"):
            content_type = "application/javascript"
            body = b'export const fixture = "public-static";'
        elif self.path.split("?", 1)[0].endswith(".css"):
            content_type = "text/css"
            body = b'body{background:#fff}'
        elif self.path == "/" or self.path.startswith("/c/"):
            content_type = "text/html"
            body = b'<html><head><script src="https://cdn.oaistatic.com/assets/fixture.js"></script></head><body>fixture-page</body></html>'
        else:
            body = {"service": self.server.service, "path": self.path}
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Fixture-Service", self.server.service)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

servers = []
for name, port in (("chat", 18090), ("django", 18091), ("cdn", 18092)):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Stub)
    server.service = name
    threading.Thread(target=server.serve_forever, daemon=True).start()
    servers.append(server)

env = {"PATH": os.environ["PATH"], "HOST": "127.0.0.1", "PORT": "40100", "DATABASE_PATH": "/tmp/page-contract.db",
       "GATEWAY_ADMIN_SECRET": SECRET, "CREDENTIAL_ENCRYPTION_KEY": KEY, "REQUEST_TIMEOUT_SECS": "2",
       "DJANGO_UPSTREAM": "http://127.0.0.1:18091", "ADMIN_UPSTREAM": "http://127.0.0.1:18091",
       "CHATGPT_BASE_URL": "http://127.0.0.1:18090", "CHATGPT_CDN_BASE_URL": "http://127.0.0.1:18092",
       "CHATGPT_AB_BASE_URL": "http://127.0.0.1:18090", "CF_BYPASS_URL": "http://127.0.0.1:18090",
       "GATEWAY_COMPAT_PROFILE": "original"}

def request(label, path, method="GET", body=None, headers=None):
    global case
    case = label
    connection = http.client.HTTPConnection("127.0.0.1", 40100, timeout=10)
    connection.request(method, path, body, headers or {})
    response = connection.getresponse()
    raw = response.read()
    record = {"kind": "response", "case": label, "method": method, "path": path,
              "status": response.status, "headers": response.getheaders(), "body": raw.decode(errors="replace")}
    emit(record)
    connection.close()
    return record

binary = os.environ.get("GATEWAY_TEST_BINARY", "/app/chatgpt-mirror-gateway")
with open("/tmp/page.out", "w+") as stdout, open("/tmp/page.err", "w+") as stderr:
    gateway = subprocess.Popen([binary], env=env, stdout=stdout, stderr=stderr)
    try:
        for _ in range(150):
            try:
                connection = http.client.HTTPConnection("127.0.0.1", 40100, timeout=.2)
                connection.connect()
                connection.close()
                break
            except OSError:
                if gateway.poll() is not None:
                    raise RuntimeError("gateway exited during startup")
                time.sleep(.1)
        for label, path in (("anonymous-root", "/"), ("anonymous-asset", "/assets/fixture.js?v=1"),
                            ("anonymous-cdn", "/cdn/fixture.css"), ("anonymous-session", "/api/auth/session")):
            request(label, path)
        payload = {"user_name": "alice", "access_token": "synthetic-access-token", "session_token": "",
                   "login_mode": "api", "isolated_session": True, "limits": [], "daily_quota": 0, "monthly_quota": 0}
        login = request("login", "/api/login", "POST", json.dumps(payload), {"Content-Type": "application/json", "Authorization": "Bearer " + SECRET})
        assert login["status"] == 200
        handoff = request("handoff", json.loads(login["body"])["login_url"])
        cookie = "; ".join(value.split(";", 1)[0] for name, value in handoff["headers"] if name.lower() == "set-cookie")
        for label, path in (("authenticated-root", "/"), ("chat-shell", "/c/guessed-conversation"),
                            ("asset", "/assets/fixture.js?v=2"), ("cdn-prefix", "/cdn/fixture.css"),
                            ("cdn-assets", "/cdn/assets/fixture.js"), ("session-first", "/api/auth/session"),
                            ("session-repeat", "/api/auth/session"), ("session-refresh", "/api/auth/session?refresh_account=1")):
            request(label, path, headers={"Cookie": cookie, "Authorization": "Bearer browser-must-not-be-upstream"})
        request("asset-head", "/assets/fixture.js", "HEAD", headers={"Cookie": cookie})
        mode["accounts"] = 500
        request("session-accounts-failure", "/api/auth/session?refresh_account=1", headers={"Cookie": cookie})
        mode["accounts"] = 200
        mode["me"] = 401
        request("session-me-failure", "/api/auth/session?refresh_account=1", headers={"Cookie": cookie})
        db = sqlite3.connect("/tmp/page-contract.db")
        emit({"kind": "database", "accounts": db.execute("SELECT chatgpt_username,plan_type FROM chatgpt_accounts").fetchall()})
        db.close()
    finally:
        gateway.terminate()
        gateway.wait(timeout=10)
        stdout.seek(0)
        stderr.seek(0)
        emit({"kind": "process", "stdout": stdout.read(), "stderr": stderr.read(), "exit": gateway.returncode})
        for server in servers:
            server.shutdown()

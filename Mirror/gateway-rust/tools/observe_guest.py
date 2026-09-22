"""Synthetic original contract observations, guest loopback only. Author: MingTea."""
import http.client
import http.server
import json
import os
import sqlite3
import subprocess
import threading
import time

binary = os.environ.get("GATEWAY_TEST_BINARY", "/app/chatgpt-mirror-gateway")
secret = "contract-admin-secret-0001"
key = "contract-encryption-key-000000000000001"


def emit(value):
    print("RESULT:" + json.dumps(value, ensure_ascii=False), flush=True)


if os.environ.get("GATEWAY_TEST_SUBJECT")=="rollback":
    import shutil,hashlib
    shutil.copyfile("/app/candidate","/app/rollback-copy")
    result=subprocess.run(["/app/ROLLBACK.sh","/app/rollback-copy"],capture_output=True,text=True)
    digest=hashlib.sha256(open("/app/rollback-copy","rb").read()).hexdigest()
    emit({"kind":"rollback","command":["/app/ROLLBACK.sh","/app/rollback-copy"],"stdout":result.stdout,"stderr":result.stderr,"exit":result.returncode,"sha256":digest})
    assert result.returncode==0 and digest=="4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098"
    binary="/app/rollback-copy"


for value in (None, "short", secret):
    env = {"PATH": os.environ["PATH"], "DATABASE_PATH": "/tmp/startup.db", "PORT": "40002"}
    if value is not None:
        env["GATEWAY_ADMIN_SECRET"] = value
    if value == secret:
        env["GATEWAY_ADMIN_SECRET"] = "short"
        env["PORT"] = "bad"
    result = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=15)
    emit({"kind": "startup", "secret": env.get("GATEWAY_ADMIN_SECRET"), "input_port": env["PORT"], "stdout": result.stdout,
          "stderr": result.stderr, "exit": result.returncode})


class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        emit({"kind": "upstream", "method": self.command, "path": self.path,
              "headers": list(self.headers.items()), "body": body.decode(errors="replace")})
        if self.path.startswith("/cloudflare5s/"):
            value = {"cookies": [{"name": "cf_clearance", "value": "SYNTHETIC", "domain": "127.0.0.1", "path": "/"}], "user_agent": "ContractFixture/1"}
        elif self.path.startswith("/backend-api/me"):
            value = {"id": "synthetic-id", "email": "fixture@example.invalid", "name": "Fixture"}
        else:
            value = {"stub": True, "path": self.path, "method": self.command}
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 18090), Stub)
threading.Thread(target=server.serve_forever, daemon=True).start()
env = {"PATH": os.environ["PATH"], "HOST": "127.0.0.1", "PORT": "40100", "DATABASE_PATH": "/tmp/contract.db",
       "GATEWAY_ADMIN_SECRET": secret, "CREDENTIAL_ENCRYPTION_KEY": key,
       "REQUEST_TIMEOUT_SECS": "2", "DJANGO_UPSTREAM": "http://127.0.0.1:18090",
       "ADMIN_UPSTREAM": "http://127.0.0.1:18090", "CF_BYPASS_URL": "http://127.0.0.1:18090",
       "CHATGPT_BASE_URL": "http://127.0.0.1:18090", "CHATGPT_CDN_BASE_URL": "http://127.0.0.1:18090",
       "CHATGPT_AB_BASE_URL": "http://127.0.0.1:18090", "GATEWAY_COMPAT_PROFILE":"original"}
with open("/tmp/oracle.out", "w+") as stdout, open("/tmp/oracle.err", "w+") as stderr:
    gateway = subprocess.Popen([binary], env=env, stdout=stdout, stderr=stderr)
    try:
        for _ in range(120):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", 40100, timeout=.2)
                conn.connect()
                conn.close()
                break
            except OSError:
                if gateway.poll() is not None:
                    raise RuntimeError("Original exited during startup")
                time.sleep(.1)
        endpoints = ["login", "logout", "user-work-mode", "get-user-info", "diagnose-chatgpt-auth", "get-mirror-token",
                     "get-user-use-count", "get-chatgpt-use-count", "conversation-statistics", "conversation-statistics/reset",
                     "get-user-quota-usage", "backup/export", "backup/restore", "operations-overview", "close-chatgpt-memory",
                     "mirror-proxy-config", "test-mirror-proxy-config", "custom-scripts", "political-moderation-config",
                     "political-moderation-config/test", "blocked-paths", "auth/session", "not-login", "refresh-cfbypass", "user-blocked-paths"]
        for path in endpoints:
            for method, auth in (("GET", False), ("GET", True), ("POST", True)):
                headers = {"Content-Type": "application/json"}
                if auth:
                    headers["Authorization"] = "Bearer " + secret
                conn = http.client.HTTPConnection("127.0.0.1", 40100, timeout=8)
                conn.request(method, "/api/" + path, body="{}" if method == "POST" else None, headers=headers)
                res = conn.getresponse()
                data = res.read().decode("utf-8", errors="replace")
                emit({"kind": "http", "method": method, "path": "/api/" + path, "auth": auth,
                      "input": {} if method == "POST" else None, "status": res.status,
                      "headers": res.getheaders(), "body": data})
                conn.close()
        db = sqlite3.connect("/tmp/contract.db")
        emit({"kind": "schema", "sql": db.execute("select name, sql from sqlite_master where type='table' order by name").fetchall()})
        db.close()
        cases = [
            ("login-minimal", "/api/login", {"user_name":"alice"}),
            ("logout-minimal", "/api/logout", {"user_name":"alice"}),
            ("work-mode", "/api/user-work-mode", {"user_name":"alice"}),
            ("mirror-token", "/api/get-mirror-token", {"user_name":"alice"}),
            ("quota-empty", "/api/get-user-quota-usage", {"user_name":"alice"}),
            ("quota-period", "/api/get-user-quota-usage", {"user_name":"alice","day_start":0,"month_start":0}),
            ("mirror-list", "/api/get-mirror-token", {"user_name":"alice","chatgpt_list":["fixture@example.invalid"]}),
            ("work-set", "/api/user-work-mode", {"user_name":"alice","force_chat_mode":False}),
            ("counts", "/api/get-user-use-count", {"username_list":["alice","bob"]}),
            ("account-counts", "/api/get-chatgpt-use-count", {"chatgpt_list":["fixture@example.invalid"]}),
            ("overview", "/api/operations-overview", {"day_start":0,"month_start":0}),
            ("restore-v2", "/api/backup/restore", {"version":2,"settings":[{"key":"custom_scripts","value":"{\"scripts\":[{\"name\":\"fixture\",\"content\":\"void 0\"}]}","updated_at":1}]}),
            ("script-persist", "/api/custom-scripts", {"scripts":[{"name":"fixture","content":"void 0","enabled":True}],"trusted_cdn_sources":[]}),
            ("blocked-persist", "/api/blocked-paths", {"paths":["/secret","/#settings/Test"]}),
            ("token-fixture", "/api/get-user-info", {"chatgpt_token":"synthetic-access-token"}),
            ("login-fixture", "/api/login", {"user_name":"alice","access_token":"synthetic-access-token","session_token":"","login_mode":"api","isolated_session":True,"limits":[],"daily_quota":0,"monthly_quota":0,"force_chat_mode":True}),
        ]
        for case_id, path, payload in cases:
            conn = http.client.HTTPConnection("127.0.0.1", 40100, timeout=15)
            conn.request("POST", path, json.dumps(payload,separators=(",",":")),
                         {"Content-Type":"application/json","Authorization":"Bearer "+secret})
            res = conn.getresponse()
            response_body=res.read().decode(errors="replace")
            emit({"kind":"scenario","id":case_id,"method":"POST","path":path,"input":payload,
                  "status":res.status,"headers":res.getheaders(),"body":response_body})
            conn.close()
            if case_id=="login-fixture" and res.status==200:
                from urllib.parse import urlsplit
                handoff=json.loads(response_body)["login_url"]
                conn=http.client.HTTPConnection("127.0.0.1",40100,timeout=10)
                conn.request("GET",handoff)
                res=conn.getresponse()
                cookies=[v.split(";",1)[0] for k,v in res.getheaders() if k.lower()=="set-cookie"]
                emit({"kind":"scenario","id":"handoff","status":res.status,"headers":res.getheaders(),"body":res.read().decode(errors="replace")})
                conn.close()
                for path in ("/api/auth/session","/api/user-blocked-paths","/backend-api/me","/backend-api/conversations?offset=0&limit=20","/0x/user/version-cfg?fixture=1"):
                    conn=http.client.HTTPConnection("127.0.0.1",40100,timeout=10)
                    conn.request("GET",path,headers={"Cookie":"; ".join(cookies)})
                    res=conn.getresponse()
                    emit({"kind":"scenario","id":"session:"+path,"status":res.status,"headers":res.getheaders(),"body":res.read().decode(errors="replace")})
                    conn.close()
        conn = http.client.HTTPConnection("127.0.0.1",40100,timeout=15)
        conn.request("GET","/api/backup/export",headers={"Authorization":"Bearer "+secret})
        res=conn.getresponse()
        emit({"kind":"scenario","id":"export-populated","status":res.status,"body":res.read().decode()})
        conn.close()
    finally:
        gateway.terminate()
        gateway.wait(timeout=10)
        stdout.seek(0)
        stderr.seek(0)
        emit({"kind": "process", "stdout": stdout.read(), "stderr": stderr.read(), "exit": gateway.returncode})
        server.shutdown()

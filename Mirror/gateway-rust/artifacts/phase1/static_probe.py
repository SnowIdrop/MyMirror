"""Same-input static proxy observation against a supplied source copy; loopback only."""
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

here = Path(__file__).resolve().parent
root = here.parent.parent
source = Path(sys.argv[1]).resolve()
label = sys.argv[2]
env = os.environ.copy()
env.update({"CARGO_HOME": str(root / ".build/phase1-toolchain/cargo"),
            "RUSTUP_HOME": str(root / ".build/phase1-toolchain/rustup"),
            "CARGO_TARGET_DIR": str(root / ".build/phase1-probe-targets" / label.lower())})
env["PATH"] = str(Path(env["CARGO_HOME"]) / "bin") + os.pathsep + env["PATH"]
command = [str(Path(env["CARGO_HOME"]) / "bin/cargo.exe"), "build", "--locked", "--offline", "--manifest-path", str(source / "Cargo.toml"), "--bin", "mirror-gateway"]
build = subprocess.run(command, env=env, capture_output=True)
record = {"label": label, "build": {"command": command, "exit_status": build.returncode, "stdout": build.stdout.decode(), "stderr": build.stderr.decode()}}
record["build_environment"] = {key: env[key] for key in ("CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR")}
if build.returncode:
    (here / f"static-{label}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    sys.exit(build.returncode)
calls = []

class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        calls.append({"method": self.command, "path": self.path, "headers": list(self.headers.items())})
        body = b'export const fixture = "public-static";'
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "must_not_escape=1")
        self.end_headers()
        self.wfile.write(body)

stub = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=stub.serve_forever, daemon=True).start()
with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
with tempfile.TemporaryDirectory(prefix="mirror-static-") as temp:
    stub_url = f"http://127.0.0.1:{stub.server_port}"
    env.update({"HOST": "127.0.0.1", "PORT": str(port), "DATABASE_PATH": str(Path(temp) / "fresh.db"),
                "GATEWAY_ADMIN_SECRET": "fixture-admin-secret-0001", "CREDENTIAL_ENCRYPTION_KEY": "fixture-encryption-key-000000000001",
                "GATEWAY_COMPAT_PROFILE": "mirror", "GATEWAY_UPSTREAM_MODE": "offline", "COOKIE_SECURE": "false",
                "DJANGO_UPSTREAM": stub_url, "CHATGPT_BASE_URL": stub_url, "CHATGPT_CDN_BASE_URL": stub_url})
    env.pop("CF_BYPASS_URL", None)
    binary = Path(env["CARGO_TARGET_DIR"]) / "debug/mirror-gateway.exe"
    record["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    record["command"] = [str(binary)]
    record["input"] = {"path": "/assets/fixture.js?v=1", "method": "GET", "headers": {"Authorization": "Bearer browser-secret", "Cookie": "mirror_token=browser-secret", "X-Mirror-Token": "browser-secret"}, "upstream_policy": "all configured origins point to the same fresh loopback fixture; ephemeral ports and database path are run identities"}
    process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), .1):
                    break
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError("gateway exited during startup")
                time.sleep(.05)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(record["input"]["method"], record["input"]["path"], headers=record["input"]["headers"])
        response = connection.getresponse()
        record["response"] = {"status": response.status, "headers": response.getheaders(), "body": response.read().decode()}
        connection.close()
        record["upstream"] = calls
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=10)
        record["process"] = {"stdout": stdout.decode(), "stderr": stderr.decode(), "exit_status": process.returncode, "termination": "fixture teardown"}
        stub.shutdown()
        stub.server_close()
(here / f"static-{label}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"label": label, "response": record["response"], "upstream": calls}, ensure_ascii=False))

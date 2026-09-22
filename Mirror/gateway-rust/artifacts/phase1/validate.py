"""Offline compilation and configuration regression, using only synthetic inputs."""
import json
import os
from pathlib import Path
import subprocess
import sys

here = Path(__file__).resolve().parent
root = here.parent.parent
source = here / "source"
env = os.environ.copy()
env.update({
    "CARGO_HOME": str(root / ".build/phase1-toolchain/cargo"),
    "RUSTUP_HOME": str(root / ".build/phase1-toolchain/rustup"),
    "CARGO_TARGET_DIR": str(root / ".build/phase1-target"),
})
env["PATH"] = str(Path(env["CARGO_HOME"]) / "bin") + os.pathsep + env["PATH"]
cargo = str(Path(env["CARGO_HOME"]) / "bin/cargo.exe")
records = []

def run(label, command, run_env=env, expected_exit=0, expected_json=None):
    result = subprocess.run(command, env=run_env, capture_output=True)
    record = {"label": label, "command": command, "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8"), "exit_status": result.returncode, "expected_exit": expected_exit}
    record["passed"] = result.returncode == expected_exit
    if expected_json is not None and result.returncode == 0:
        record["expected_json"] = expected_json
        record["passed"] &= json.loads(record["stdout"]) == expected_json
    records.append(record)
    (here / "checks.json").write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{label}: exit={result.returncode} passed={record['passed']}", flush=True)
    return record["passed"]

for label, arguments in [
    ("rust-tests", ["test", "--all-targets"]),
    ("clippy", ["clippy", "--all-targets"]),
    ("examples-build", ["build", "--examples"]),
]:
    command = [cargo, *arguments, "--locked", "--offline", "--manifest-path", str(source / "Cargo.toml")]
    if label == "clippy":
        command += ["--", "-D", "warnings"]
    if not run(label, command):
        sys.exit(1)

probe = str(Path(env["CARGO_TARGET_DIR"]) / "debug/examples/check_config.exe")
base = env.copy()
base.update({
    "GATEWAY_ADMIN_SECRET": "fixture-admin-secret-0001",
    "CREDENTIAL_ENCRYPTION_KEY": "fixture-encryption-key-000000000001",
    "GATEWAY_COMPAT_PROFILE": "mirror",
    "GATEWAY_UPSTREAM_MODE": "configured",
    "DJANGO_UPSTREAM": "http://django:8000",
    "CHATGPT_BASE_URL": "https://chat.example.invalid",
    "CHATGPT_CDN_BASE_URL": "https://static.example.invalid:8443",
    "CF_BYPASS_URL": "http://cfbypass:8000",
})
cases = [
    ("configured-separated-origins", {}, 0, {"django": "http://django:8000/", "chat": "https://chat.example.invalid/", "cdn": "https://static.example.invalid:8443/", "cfbypass": "http://cfbypass:8000/"}),
    ("configured-no-cf-service", {"CF_BYPASS_URL": None}, 0, None),
    ("configured-missing-cdn", {"CHATGPT_CDN_BASE_URL": None}, 1, None),
    ("configured-empty-cdn", {"CHATGPT_CDN_BASE_URL": ""}, 1, None),
    ("configured-empty-cf", {"CF_BYPASS_URL": ""}, 1, None),
    ("invalid-mode", {"GATEWAY_UPSTREAM_MODE": "configure"}, 1, None),
    ("default-offline-rejects-domains", {"GATEWAY_UPSTREAM_MODE": None}, 1, None),
    ("explicit-offline-rejects-domains", {"GATEWAY_UPSTREAM_MODE": "offline"}, 1, None),
]
for field in ("DJANGO_UPSTREAM", "CHATGPT_BASE_URL", "CHATGPT_CDN_BASE_URL", "CF_BYPASS_URL"):
    for suffix, invalid in (("credentials", "https://user:secret@example.invalid"), ("path", "http://127.0.0.1/prefix"), ("query", "http://127.0.0.1/?url=https://example.invalid"), ("fragment", "http://127.0.0.1/#part"), ("scheme", "file:///tmp/target")):
        cases.append((f"{field}-{suffix}", {field: invalid}, 1, None))
offline = {"GATEWAY_UPSTREAM_MODE": None, "DJANGO_UPSTREAM": "http://127.0.0.1:18090", "CHATGPT_BASE_URL": "http://[::1]:18091", "CHATGPT_CDN_BASE_URL": None, "CF_BYPASS_URL": None}
cases.append(("old-offline-environment", offline, 0, {"django": "http://127.0.0.1:18090/", "chat": "http://[::1]:18091/", "cdn": None, "cfbypass": None}))
cases.append(("offline-cdn-cannot-escape", {**offline, "CHATGPT_CDN_BASE_URL": "https://static.example.invalid"}, 1, None))
for label, changes, expected_exit, expected_json in cases:
    case_env = base.copy()
    for key, value in changes.items():
        if value is None:
            case_env.pop(key, None)
        else:
            case_env[key] = value
    run(label, [probe], case_env, expected_exit, expected_json)
    records[-1]["input"] = {key: value for key, value in case_env.items() if key in base and (key.endswith("_URL") or key in ("DJANGO_UPSTREAM", "GATEWAY_UPSTREAM_MODE", "GATEWAY_COMPAT_PROFILE", "GATEWAY_ADMIN_SECRET", "CREDENTIAL_ENCRYPTION_KEY"))}
(here / "checks.json").write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
sys.exit(0 if all(record["passed"] for record in records) else 1)

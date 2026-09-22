import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

here = Path(__file__).resolve().parent
root = here.parent.parent

def read(name):
    return json.loads((here / name).read_text(encoding="utf-8"))

roles = {name: str(here / filename) for name, filename in {
    "MODIFIED_FILE": "MODIFIED_FILE.zip",
    "DIFF_FILE": "DIFF_FILE.patch",
    "VERIFICATION": "VERIFICATION.txt",
    "ROLLBACK": "ROLLBACK.sh",
}.items()}
behaviors = [read(f"{label}.json") for label in ("BASELINE", "MODIFIED", "ROLLBACK")]
assert behaviors[0]["input"] == behaviors[1]["input"] == behaviors[2]["input"]
assert [item["exit_status"] for item in behaviors] == [1, 0, 1]
assert behaviors[0]["stdout"] == behaviors[2]["stdout"]
assert behaviors[0]["stderr"] == behaviors[2]["stderr"]
checks = read("checks.json")
assert all(item["passed"] for item in checks)
rust_tests = sum(map(int, re.findall(r"test result: ok\. (\d+) passed", checks[0]["stdout"])))
manifest = read("baseline-manifest.json")
assert all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in manifest.items())
with zipfile.ZipFile(roles["MODIFIED_FILE"]) as archive:
    assert archive.testzip() is None
    archive_entries = archive.namelist()
command = ["E:/T/Git2026_6/bin/bash.exe", "-c", "test -x artifacts/phase1/ROLLBACK.sh"]
result = subprocess.run(command, cwd=root, capture_output=True)
assert result.returncode == 0
summary = {
    "implementation": "phase1 configuration batch implemented in a source copy; original source unchanged",
    "rust_tests": rust_tests,
    "clippy": "passed --all-targets -- -D warnings",
    "configuration_cases": len(checks) - 3,
    "real_environment_acceptance": "not run",
    "full_replacement_complete": False,
}
ledger = {
    "TARGET": str(root),
    "candidate_source": str(here / "source"),
    "changed_symbols": ["Config::from_env", "Config.cdn_upstream", "service_url", "GATEWAY_UPSTREAM_MODE"],
    "roles": roles,
    "summary": summary,
    "same_input_behaviors": behaviors,
    "rollback_execution": read("rollback-execution.json"),
    "package": read("package.json"),
    "reapplied_goal": read("reapply.json"),
    "checks": checks,
    "rollback_executable_check": {"command": command, "exit_status": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode()},
    "original_source_manifest": manifest,
    "archive_entries": archive_entries,
    "baseline_tests": {"command": "cargo test --locked --manifest-path artifacts/phase1/source/Cargo.toml", "exit_status": 0, "combined_output_path": str(here / "baseline-tests.log"), "note": "dependency download enabled on baseline preparation; all subsequent Cargo checks used --locked --offline"},
    "defensive_review": "Reviewed scoped source diff. Kept fail-fast origin validation because existing callers replace/join absolute paths; kept offline guard, TLS verification and unknown-route gate. No generic fallback/retry/framework introduced. No unrelated simplifications needed.",
    "scope": "Source archive rollback only; no database restore, upstream rollback, browser validation, TLS live validation, Docker build or production switch.",
    "environment": "Private workspace Rust 1.98.1 toolchain installed without changing global PATH; existing Cargo.lock unchanged. Subagent routing failed, investigation completed by primary agent.",
}
(here / "VERIFICATION.txt").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
status = {
    "ACTIVE_OBJECT": str(here / "source"),
    "LAST_CONFIRMED_RESULT": summary,
    "NEXT_EXECUTABLE_ACTION": "Extend the offline page/static/auth-session contract fixture on this same candidate, then run it; do not open unverified routes or use real accounts.",
    "INPUT_PATHS": [str(here / "source/PHASE1_CONTRACT.md"), str(root / "tools/observe_proxy_v3.py"), str(root / "src/assets/gateway-client.html")],
    "ACCEPTANCE_EVENT": "Recorded fixture requests, resource IDs and response/stream/error behavior for page/static/auth refresh, followed by candidate regression; no full-release claim.",
    "roles": roles,
    "phase": 1,
    "phase_complete": False,
    "remaining": ["页面、静态路由及同源改写", "auth/session 刷新链", "第二至五阶段权限底座、后台和业务能力", "第六阶段统一验收与部署交付"],
    "rollback_scope": "restore a disposable source archive; not databases or already-executed upstream operations",
    "legacy_evidence": str(root / "STATUS.json"),
}
(here / "STATUS.json").write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False))
for role, path in roles.items():
    print(f"{role}={path}")

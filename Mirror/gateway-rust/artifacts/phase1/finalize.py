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
static_behaviors = [read(f"static-{label}.json") for label in ("BASELINE", "MODIFIED", "ROLLBACK")]
assert [item["response"]["status"] for item in static_behaviors] == [401, 200, 401]
assert static_behaviors[0]["input"] == static_behaviors[1]["input"] == static_behaviors[2]["input"]
assert static_behaviors[0]["response"]["body"] == static_behaviors[2]["response"]["body"]
assert len(static_behaviors[1]["upstream"]) == 1
assert not {key.lower() for key, value in static_behaviors[1]["upstream"][0]["headers"]} & {"authorization", "cookie", "x-mirror-token", "x-api-key"}
assert not any(key.lower() == "set-cookie" for key, value in static_behaviors[1]["response"]["headers"])
auth_behaviors = [read(f"auth-{label}.json") for label in ("BASELINE", "MODIFIED", "ROLLBACK")]
assert auth_behaviors[0]["input"] == auth_behaviors[1]["input"] == auth_behaviors[2]["input"]
assert [json.loads(item["response"]["body"])["planType"] for item in auth_behaviors] == ["free", "plus", "free"]
assert [len(item["upstream"]) for item in auth_behaviors] == [0, 2, 0]
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
    "implementation": "configuration, public JS/CSS and auth-session refresh implemented; reviewed independent ACL module and upgraded boundary tests integrated without product ACL wiring; original source unchanged",
    "rust_tests": rust_tests,
    "clippy": "passed --all-targets -- -D warnings",
    "configuration_cases": len(checks) - 3,
    "original_page_observations": 40,
    "static_integration_tests": 5,
    "auth_refresh_tests": 3,
    "independent_acl_tests": 28,
    "integrated_boundary_tests": 8,
    "real_environment_acceptance": "not run",
    "full_replacement_complete": False,
}
ledger = {
    "TARGET": str(root),
    "candidate_source": str(here / "source"),
    "changed_symbols": ["Config::from_env", "Config.cdn_upstream", "service_url", "GATEWAY_UPSTREAM_MODE", "server::static_assets::serve", "server::static_assets::asset_path", "server::proxy::chat_proxy", "server::auth_session", "server::proxy::refresh_auth_session", "resource_acl (unexported independent module)"],
    "roles": roles,
    "summary": summary,
    "metadata_followups": read("metadata-followups.json") if (here / "metadata-followups.json").exists() else [],
    "same_input_behaviors": behaviors,
    "same_input_static_behaviors": static_behaviors,
    "same_input_auth_behaviors": auth_behaviors,
    "integrations": read("integrations/manifest.json"),
    "auth_test_development": {"before_exit":101,"before_combined_output":str(here / "auth-before.log"),"before_result":"0 passed; 3 failed on static implementation","after_exit":0,"after_combined_output":str(here / "auth-after.log"),"after_result":"3 passed; 0 failed","additional_verifier_failures":["E0560 in old shared target: Config source had cdn_upstream but stale baseline rlib did not; validate.py and all candidate tests moved to phase1-candidate-tests. Original failed output retained in auth-before-target-collision.log.","Auth runtime probe first cleanup failed exit1 WinError32: Python sqlite transaction context left connection open; fixed with contextlib.closing and reran successfully."]},
    "history": [str(here / "history/config-b837ba2/VERIFICATION.txt"), str(here / "history/static-680aed1/VERIFICATION.txt")],
    "corrected_verifier_failure": {"evidence": str(here / "history/static-shared-target-failure/static-artifact-events.json"), "observed_exit": 1, "cause": "baseline and candidate Cargo packages shared output filenames; final MODIFIED probe ran the previously built rollback executable", "fix": "run_probe.py/static_probe.py use separate CARGO_TARGET_DIR per BASELINE/MODIFIED/ROLLBACK; rerun all same-input probes; product source was unchanged"},
    "commit_before_continuation": "b837ba2556bc3363570d247e61246e6b8f43421c",
    "new_original_observation": {"command": read("page-original-001/command.json"), "summary_path": str(here / "page-original-001/summary.json"), "results_sha256": hashlib.sha256((here / "page-original-001/results.json").read_bytes()).hexdigest(), "kind": "synthetic loopback only, QEMU -nic none; not live account validation"},
    "rollback_execution": read("rollback-execution.json"),
    "package": read("package.json"),
    "reapplied_goal": read("reapply.json"),
    "checks": checks,
    "rollback_executable_check": {"command": command, "exit_status": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode()},
    "original_source_manifest": manifest,
    "archive_entries": archive_entries,
    "baseline_tests": {"command": "cargo test --locked --manifest-path artifacts/phase1/source/Cargo.toml", "exit_status": 0, "combined_output_path": str(here / "baseline-tests.log"), "note": "dependency download enabled on baseline preparation; all subsequent Cargo checks used --locked --offline"},
    "defensive_review": "Reviewed scoped source diff. Retained fail-fast origin validation and fixed-origin/path/MIME/method gates for the new public static boundary. Positive header lists prevent observed original credential leakage; no buffering, retry or ownership inference. See static-review.md. No unrelated simplifications needed.",
    "scope": "Source archive rollback only; no database restore, upstream rollback, browser validation, TLS live validation, Docker build or production switch.",
    "environment": "Private workspace Rust 1.98.1 toolchain installed without changing global PATH; existing Cargo.lock unchanged. Subagent routing failed, investigation completed by primary agent.",
}
(here / "VERIFICATION.txt").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
status = {
    "ACTIVE_OBJECT": str(here / "source"),
    "LAST_CONFIRMED_RESULT": summary,
    "NEXT_EXECUTABLE_ACTION": "Create and execute focused regressions for ordinary me/list credential-generation binding and saved proxy/profile effective egress, then make the smallest authorized local fix. No silent direct/identity fallback. Keep pages/media/realtime gated; architecture changes and real-account testing require separate confirmation.",
    "INPUT_PATHS": [str(here / "section12-intake.json"), str(here / "integrations/section12/SECTION12_REPORT.md"), str(here / "source/src/server.rs"), str(here / "source/src/server/proxy.rs"), str(here / "COORDINATION.json")],
    "ACCEPTANCE_EVENT": "Focused tests prove no adoption of new credentials by old in-flight requests and actual approved egress/profile selection or fail-closed behavior. Existing regressions retained; this does not imply end-to-end browser identity acceptance.",
    "roles": roles,
    "phase": 1,
    "phase_complete": False,
    "remaining": ["第12节：普通请求代次、实际出口绑定及浏览器/传输身份一致性门禁", "页面初始化隔离及同源改写，字体/图片/其他静态类型", "初次登录accounts检查、更多真实响应/失败协议", "第二阶段可信身份、账号映射、新库ACL/备份/后台/实时撤权接线；ACL仅独立暂存", "第三至五阶段业务能力及第六阶段统一验收与部署交付"],
    "rollback_scope": "restore a disposable source archive; not databases or already-executed upstream operations",
    "legacy_evidence": str(root / "STATUS.json"),
}
# Source packaging must not silently drop the separately received identity gate.
if (here / "STATUS.json").exists():
    previous = read("STATUS.json")
    if "upstream_visible_identity_acceptance" in previous:
        status["upstream_visible_identity_acceptance"] = previous["upstream_visible_identity_acceptance"]
(here / "STATUS.json").write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False))
for role, path in roles.items():
    print(f"{role}={path}")

"""Replay the approved offline contracts against one candidate and its rollback.
Author: MingTea. Each oracle owns its disconnected VM; previous evidence is immutable.
"""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUITES = {
    "core": ("observe_guest.py", "baseline-final-2"),
    "headers": ("observe_headers_v3.py", "headers-v3-original-008"),
    "management": ("observe_management_v3.py", "management-v3-original-006"),
    "proxy": ("observe_proxy_v3.py", "proxy-v3-original-011"),
    "backup": ("observe_backup_v3.py", "backup-v3-original-014"),
}


def logged(label, command):
    return subprocess.run(
        [sys.executable, "tools/run_logged.py", "--output", f"evidence/{label}", *command],
        cwd=ROOT, check=False,
    ).returncode


def run_subject(subject, port):
    outcomes = []
    for suite, (script, baseline) in SUITES.items():
        stem = f"{suite}-v3-{subject}-delivery"
        execution = logged(stem + "-command", [sys.executable, "tools/oracle.py",
            "--guest-script", f"tools/{script}", "--subject", subject,
            "--serial-port", str(port), "--output", f"evidence/{stem}"])
        outcome = {"suite": suite, "subject": subject, "execution_exit": execution}
        if execution == 0:
            inputs = [f"evidence/{baseline}/results.json", f"evidence/{stem}/results.json"]
            comparator = "compare_backup_v3.py" if suite == "backup" else "compare.py"
            outcome["comparison_exit"] = logged(stem + "-compare-command",
                [sys.executable, f"tools/{comparator}", *inputs, f"evidence/{stem}-diff.json"])
            if suite in ("headers", "management", "proxy"):
                outcome["audit_exit"] = logged(stem + "-audit-command",
                    [sys.executable, "tools/audit_v3.py", "--mode", suite,
                     *inputs, f"evidence/{stem}-audit.json"])
        outcomes.append(outcome)
    return outcomes


def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run_subject, "candidate", 45631),
                   pool.submit(run_subject, "rollback", 45632)]
        outcomes = [row for future in futures for row in future.result()]
    report = ROOT / "evidence/delivery-v3-runs.json"
    report.write_text(json.dumps(outcomes, indent=2), encoding="utf-8")
    print(json.dumps(outcomes), flush=True)
    return int(any(value != 0 for row in outcomes for key, value in row.items() if key.endswith("_exit")))


if __name__ == "__main__":
    sys.exit(main())

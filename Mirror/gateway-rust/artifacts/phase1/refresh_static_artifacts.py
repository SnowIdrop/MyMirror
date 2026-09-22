"""Extend the same four-role source transaction with static proxy evidence."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

here = Path(__file__).resolve().parent
root = here.parent.parent
events = []

def run(command, expected=0):
    result = subprocess.run(command, cwd=root, capture_output=True)
    record = {"command": list(map(str, command)), "exit_status": result.returncode, "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8")}
    events.append(record)
    (here / "static-artifact-events.json").write_text(json.dumps(events, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    assert result.returncode == expected, record
    return result.stdout

run([sys.executable, str(here / "package.py")])
rollback_command = ["E:/T/Git2026_6/bin/bash.exe", "-c", "artifacts/phase1/ROLLBACK.sh artifacts/phase1/rollback-copy.zip"]
run(rollback_command)
digest = hashlib.sha256((here / "rollback-copy.zip").read_bytes()).hexdigest()
assert digest == hashlib.sha256((here / "baseline.source.zip").read_bytes()).hexdigest()
rollback = {**events[-1], "restored_sha256": digest}
(here / "rollback-execution.json").write_text(json.dumps(rollback, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
restored = Path(tempfile.mkdtemp(prefix="static-rollback-", dir=root / ".build"))
with zipfile.ZipFile(here / "rollback-copy.zip") as archive:
    assert archive.testzip() is None
    archive.extractall(restored)
run([sys.executable, str(here / "run_probe.py"), str(restored), "ROLLBACK"], expected=1)
run([sys.executable, str(here / "static_probe.py"), str(restored), "ROLLBACK"])
run([sys.executable, str(here / "static_probe.py"), str(restored), "ROLLBACK", "auth"])

work = here / "patch-work"
shutil.copyfile(here / "rollback-copy.zip", work / "source.zip")
run(["git", "-C", str(work), "apply", str(here / "DIFF_FILE.patch")])
assert (work / "source.zip").read_bytes() == (here / "MODIFIED_FILE.zip").read_bytes()
shutil.copyfile(work / "source.zip", here / "MODIFIED_FILE.zip")

source_work = Path(tempfile.mkdtemp(prefix="static-source-diff-", dir=root / ".build"))
with zipfile.ZipFile(here / "baseline.source.zip") as archive:
    archive.extractall(source_work)
run(["git", "-C", str(source_work), "init", "--quiet"])
run(["git", "-C", str(source_work), "-c", "core.autocrlf=false", "add", "."])
with zipfile.ZipFile(here / "MODIFIED_FILE.zip") as archive:
    assert archive.testzip() is None
    archive.extractall(source_work)
run(["git", "-C", str(source_work), "add", "-N", "."])
patch = run(["git", "-C", str(source_work), "-c", "core.autocrlf=false", "diff", "--binary", "--"])
(here / "SOURCE.patch").write_bytes(patch)
run(["git", "-C", str(source_work), "apply", "--reverse", "--check", str(here / "SOURCE.patch")])
run(["git", "-C", str(source_work), "-c", "core.autocrlf=false", "diff", "--check"])
(here / "reapply.json").write_text(json.dumps({"reapplied_sha256": hashlib.sha256((here / "MODIFIED_FILE.zip").read_bytes()).hexdigest(), "commands": events}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
run([sys.executable, str(here / "run_probe.py"), str(here / "source"), "MODIFIED"])
print("Source archive rollback, same-input probes, patch reconstruction and reapplication passed.")

"""Reproducible source transaction; never changes the original source tree."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

here = Path(__file__).resolve().parent
source = here / "source"
archive = here / "MODIFIED_FILE.zip"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.relative_to(source).as_posix() == "examples/upstream_probe.rs":
            continue
        info = zipfile.ZipInfo(path.relative_to(source).as_posix(), date_time=(2026, 9, 22, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        output.writestr(info, path.read_bytes())

work = here / "patch-work"
work.mkdir(exist_ok=True)
shutil.copyfile(here / "baseline.source.zip", work / "source.zip")
commands = []

def git(*args, expected=0):
    command = ["git", "-C", str(work), *args]
    result = subprocess.run(command, capture_output=True)
    commands.append({"command": command, "exit_status": result.returncode, "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8")})
    if result.returncode != expected:
        raise RuntimeError(commands[-1])
    return result.stdout

git("init", "--quiet")
git("-c", "core.autocrlf=false", "add", "source.zip")
shutil.copyfile(archive, work / "source.zip")
patch = git("diff", "--binary", "--", "source.zip")
(here / "DIFF_FILE.patch").write_bytes(patch)
git("checkout", "--", "source.zip")
git("apply", str(here / "DIFF_FILE.patch"))
assert sha(work / "source.zip") == sha(archive)
# A second reconstruction after rollback will reapply this same patch.
shutil.copyfile(archive, here / "rollback-copy.zip")
manifest = json.loads((here / "baseline-manifest.json").read_text())
root = here.parent.parent
assert all(sha(root / name) == digest for name, digest in manifest.items())
metadata = {
    "baseline_sha256": sha(here / "baseline.source.zip"),
    "modified_sha256": sha(archive),
    "patch_sha256": sha(here / "DIFF_FILE.patch"),
    "patch_reconstruction": True,
    "original_source_files_unchanged": len(manifest),
    "commands": commands,
}
(here / "package.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: value for key, value in metadata.items() if key != "commands"}))

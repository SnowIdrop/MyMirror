"""Run the same configuration-only input; never start a server or contact upstreams."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

here = Path(__file__).resolve().parent
root = here.parent.parent
source = Path(sys.argv[1]).resolve()
label = sys.argv[2]
example = source / "examples/upstream_probe.rs"
example.parent.mkdir(exist_ok=True)
shutil.copyfile(here / "config_probe.rs", example)
env = os.environ.copy()
env.update({
    "CARGO_HOME": str(root / ".build/phase1-toolchain/cargo"),
    "RUSTUP_HOME": str(root / ".build/phase1-toolchain/rustup"),
    "CARGO_TARGET_DIR": str(root / ".build/phase1-probe-targets" / label.lower()),
    "GATEWAY_ADMIN_SECRET": "fixture-admin-secret-0001",
    "CREDENTIAL_ENCRYPTION_KEY": "fixture-encryption-key-000000000001",
    "GATEWAY_COMPAT_PROFILE": "mirror",
    "GATEWAY_UPSTREAM_MODE": "configured",
    "DJANGO_UPSTREAM": "http://django:8000",
    "CHATGPT_BASE_URL": "https://chat.example.invalid",
    "CHATGPT_CDN_BASE_URL": "https://static.example.invalid",
})
env.pop("CF_BYPASS_URL", None)
env["PATH"] = str(Path(env["CARGO_HOME"]) / "bin") + os.pathsep + env["PATH"]
command = [str(Path(env["CARGO_HOME"]) / "bin/cargo.exe"), "run", "--locked", "--offline", "--quiet", "--manifest-path", str(source / "Cargo.toml"), "--example", "upstream_probe"]
result = subprocess.run(command, env=env, capture_output=True)
record = {"label": label, "command": command, "input": {k: env[k] for k in ("GATEWAY_ADMIN_SECRET", "CREDENTIAL_ENCRYPTION_KEY", "GATEWAY_COMPAT_PROFILE", "GATEWAY_UPSTREAM_MODE", "DJANGO_UPSTREAM", "CHATGPT_BASE_URL", "CHATGPT_CDN_BASE_URL")}, "stdout": result.stdout.decode("utf-8", errors="replace"), "stderr": result.stderr.decode("utf-8", errors="replace"), "exit_status": result.returncode}
record["build_environment"] = {key: env[key] for key in ("CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR")}
(here / f"{label}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(record, ensure_ascii=False))
sys.exit(result.returncode)

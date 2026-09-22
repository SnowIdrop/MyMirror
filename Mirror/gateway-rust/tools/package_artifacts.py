"""Package executable transaction and verify binary patch reconstruction. Author: MingTea."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL=Path(r"D:\Project\MirrorNiXiang\reverse\extracted\chatgpt-mirror-gateway")


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    artifacts=ROOT/"artifacts"
    artifacts.mkdir(exist_ok=True)
    original_hash=digest(ORIGINAL)
    if original_hash!="4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098":
        raise RuntimeError("Original no longer matches the confirmed baseline")
    modified=artifacts/"MODIFIED_FILE"
    shutil.copyfile(ROOT/"target/x86_64-unknown-linux-musl/debug/mirror-gateway",modified)
    shutil.copyfile(ORIGINAL,artifacts/"baseline.gateway")
    (artifacts/"ROLLBACK.sh").chmod(0o755)
    commands=[]
    with tempfile.TemporaryDirectory(dir=ROOT/".build",prefix="patch-") as tmp:
        tmp=Path(tmp)
        def run(command):
            result=subprocess.run(command,capture_output=True)
            commands.append({"command":command,"exit":result.returncode,
                "stdout":result.stdout.decode(errors="replace"),"stderr":result.stderr.decode(errors="replace")})
            if result.returncode!=0:raise RuntimeError(commands[-1])
            return result.stdout
        run(["git","init","--quiet",str(tmp)])
        shutil.copyfile(ORIGINAL,tmp/"gateway")
        run(["git","-C",str(tmp),"add","gateway"])
        shutil.copyfile(modified,tmp/"gateway")
        patch=run(["git","-C",str(tmp),"diff","--binary","--","gateway"])
        # The binary patch is stored natively, not truncated in the command log.
        commands[-1]["stdout"]="[literal binary patch is in DIFF_FILE.patch]"
        (artifacts/"DIFF_FILE.patch").write_bytes(patch)
        run(["git","-C",str(tmp),"checkout","--","gateway"])
        if digest(tmp/"gateway")!=original_hash:raise RuntimeError("Patch fixture is not baseline")
        run(["git","-C",str(tmp),"apply",str(artifacts/"DIFF_FILE.patch")])
        if digest(tmp/"gateway")!=digest(modified):raise RuntimeError("Patch does not reproduce candidate")
    result={"original_sha256":original_hash,"modified_sha256":digest(modified),
            "patch_sha256":digest(artifacts/"DIFF_FILE.patch"),"patch_reconstruction":True,
            "commands":commands}
    (artifacts/"package.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k!="commands"}))


if __name__=="__main__":main()

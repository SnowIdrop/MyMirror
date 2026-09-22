"""Assemble literal evidence and source delivery without claiming compatibility. Author: MingTea."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
ART=ROOT/"artifacts"
EVIDENCE=ROOT/"evidence"


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    package=json.loads((ART/"package.json").read_text(encoding="utf-8"))
    roles={name:str((ART/name).resolve()) for name in ("MODIFIED_FILE","DIFF_FILE.patch","VERIFICATION.txt","ROLLBACK.sh")}
    diff=json.loads((EVIDENCE/"response-diff-final.json").read_text(encoding="utf-8"))
    restored=json.loads((EVIDENCE/"rollback-diff-final.json").read_text(encoding="utf-8"))
    baseline=json.loads((EVIDENCE/"baseline-final-2/results.json").read_text(encoding="utf-8"))
    candidate_meta=json.loads((EVIDENCE/"modified-final-2/command.json").read_text(encoding="utf-8"))
    rollback=json.loads((EVIDENCE/"rollback-final-2/results.json").read_text(encoding="utf-8"))
    rollback_event=next(r for r in rollback if r["kind"]=="rollback")
    assert sha(ART/"MODIFIED_FILE")==candidate_meta["initramfs"]["candidate_sha256"]==package["modified_sha256"]
    assert rollback_event["sha256"]==package["original_sha256"]==sha(ART/"baseline.gateway")
    assert rollback_event["exit"]==0 and restored["different"]==0
    cases=[f"- `{v['case']}`" for v in diff["differences"]]
    (ROOT/"COMPATIBILITY.md").write_text(
        "# 兼容矩阵：未通过完整验收\n\n"
        f"当前记录了 {diff['response_cases']} 个响应级对照；{diff['matched']} 个一致，{diff['different']} 个仍有差异。\n"
        "这不是整个产品的覆盖率。完整 SSE/WebSocket、指纹传输、MCP/Skills 请求侧、会话/项目读写隔离、完整配额与审核仍未完成。\n"
        "JSON 正文按结构比较；响应头逐项比较。仅规范化经过验证的时间戳、HTTP Date、令牌及密文随机性；密文使用原版实测密钥解密后比较明文，持久化 token 摘要必须对应已签发 token。\n"
        "Content-Length 与实际 UTF-8 正文长度自校验，不要求 JSON 空白格式相同。上游完整报文已保留但没有自动全量差分。\n\n"
        f"回滚后的 {restored['response_cases']} 个响应级对照全部与原版一致，恢复哈希亦一致。\n\n"
        "## 仍有差异的已执行用例\n\n"+"\n".join(cases)+"\n\n"
        "详情：evidence/response-diff-final.json；原始请求、响应、上游记录：evidence/*-final-2/results.json 与 serial.log。\n",
        encoding="utf-8")
    status={"state":"in_progress","release_gate":"failed","baseline_sha256":package["original_sha256"],
        "candidate_sha256":package["modified_sha256"],"roles":roles,"response_comparison":{k:diff[k] for k in ("response_cases","matched","different")},
        "remaining":["Eliminate observed response differences without weakening checks","Full account isolation and conversation/project data flow","SSE and WebSocket lifecycle","Original fingerprint transports","MCP/Skills request protocol and quotas","Full upstream/database differential","Docker packaging verification","Separately authorized real-upstream acceptance"],
        "next_work":"Use existing baseline-final-2 and response-diff-final.json to implement the first missing management/session contract; retain all completed observations."}
    (ROOT/"STATUS.json").write_text(json.dumps(status,ensure_ascii=False,indent=2),encoding="utf-8")
    sources=[]
    for folder in ("src","tests","tools"):
        sources.extend(p for p in (ROOT/folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    sources.extend(ROOT/name for name in ("Cargo.toml","Cargo.lock",".gitignore",".dockerignore","Dockerfile","compose.offline.yml","README.md","COMPATIBILITY.md","DEFENSIVE_REVIEW.md","STATUS.json"))
    with tempfile.TemporaryDirectory(dir=ROOT/".build",prefix="source-review-") as tmp:
        tmp=Path(tmp)
        subprocess.run(["git","init","--quiet",str(tmp)],check=True,capture_output=True)
        for source in sources:
            dest=tmp/source.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
        subprocess.run(["git","-C",str(tmp),"add","--intent-to-add","."],check=True,capture_output=True)
        check=subprocess.run(["git","-C",str(tmp),"diff","--check"],capture_output=True)
        (EVIDENCE/"source-diff-check.json").write_text(json.dumps({"exit":check.returncode,"stdout":check.stdout.decode(),"stderr":check.stderr.decode()},indent=2),encoding="utf-8")
        if check.returncode:raise RuntimeError("Source diff whitespace validation failed")
        patch=subprocess.run(["git","-C",str(tmp),"diff","--binary"],check=True,capture_output=True)
        (ART/"SOURCE.patch").write_bytes(patch.stdout)
    with zipfile.ZipFile(ART/"gateway-rust-source.zip","w",zipfile.ZIP_DEFLATED) as archive:
        for source in sources:archive.write(source,source.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(ART/"gateway-rust-source.zip") as archive:
        assert archive.testzip() is None
    sections=["Mirror Rust gateway verification ledger", "RESULT: INCOMPLETE / DO NOT DEPLOY",json.dumps(status,ensure_ascii=False,indent=2),
              "Changed symbols: Config::from_env; server::{router,login,handoff,logout,revoke,private_headers}; Database::{migrate,restore_backup}; Policy::{check_model,check_capability,Revocation::matches}.",
              "Baseline was recorded before Rust candidate construction. Existing source and original artifact were not patched.",
              "BASELINE/MODIFIED/ROLLBACK share the same guest script, numeric loopback fixtures and fresh independent guest disks. QEMU uses -nic none. Subject executable and run identity are the intended differences.",
              "QEMU is terminated by its owner after guest exit 0; its host termination code is not a test result. Original/native child SIGTERM exits are recorded literally.",
              "Normalization and untested boundaries are specified in COMPATIBILITY.md and tools/compare.py.",json.dumps(package,ensure_ascii=False,indent=2)]
    for label,folder in [("BASELINE","baseline-final-2"),("MODIFIED","modified-final-2"),("ROLLBACK","rollback-final-2")]:
        sections.append(f"=== {label} COMMAND ===\n"+(EVIDENCE/folder/"command.json").read_text())
        sections.append(f"=== {label} LITERAL GUEST SERIAL STDOUT/STDERR ===\n"+(EVIDENCE/folder/"serial.log").read_text(encoding="utf-8",errors="replace"))
        sections.append(f"=== {label} QEMU STDERR ===\n"+(EVIDENCE/folder/"qemu.stderr").read_text(encoding="utf-8",errors="replace"))
    for folder in ("tests-final-2","clippy-final","build-final-2","compare-candidate-final","compare-rollback-final"):
        for name in ("command.json","stdout.txt","stderr.txt"):
            sections.append(f"=== {folder}/{name} ===\n"+(EVIDENCE/folder/name).read_text(encoding="utf-8",errors="replace"))
    sections.append("FAILURE HISTORY (retained, not presented as success): original-001 lacked Python and exited 127; check-server had E0277/E0308 exit101; tests-001 original ciphertext decoded [] rather than the guessed empty string, exit101; compare-candidate-001 had 82 differences, exit1.")
    sections.append("Original hash and rollback: "+json.dumps(rollback_event,ensure_ascii=False))
    sections.append("Source archive SHA256: "+sha(ART/"gateway-rust-source.zip"))
    (ART/"VERIFICATION.txt").write_text("\n\n".join(sections),encoding="utf-8")
    print(json.dumps({"response_cases":diff["response_cases"],"matched":diff["matched"],"different":diff["different"],"rollback_matches":restored["matched"],"roles":roles},ensure_ascii=False))


if __name__=="__main__":main()

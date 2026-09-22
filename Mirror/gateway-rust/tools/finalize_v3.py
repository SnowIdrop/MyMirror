"""Publish verified v3 artifacts, preserving failures and the previous ledger.
Author: MingTea. This is evidence assembly, not a compatibility-success override.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from verify_delivery_v3 import SUITES

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
EVIDENCE = ROOT / "evidence"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def summary(report):
    return {key: value for key, value in report.items()
            if key in ("cases", "response_cases", "matched", "different",
                       "baseline_checked", "candidate_checked", "scope")}


def main():
    package = read(ART / "package.json")
    assert package["patch_reconstruction"]
    assert sha(ART / "MODIFIED_FILE") == package["modified_sha256"]
    original = Path(r"D:\Project\MirrorNiXiang\reverse\extracted\chatgpt-mirror-gateway")
    assert sha(original) == sha(ART / "baseline.gateway") == package["original_sha256"]
    history = EVIDENCE / "verification-before-v3.txt"
    if not history.exists():
        shutil.copyfile(ART / "VERIFICATION.txt", history)
    runs = read(EVIDENCE / "delivery-v3-runs.json")
    reports = {}
    events = []
    inputs = {}
    for suite, (_, baseline) in SUITES.items():
        original_meta = read(EVIDENCE / baseline / "command.json")
        inputs[suite] = {"baseline": baseline, "guest_script_sha256": original_meta["guest_script_sha256"]}
        for subject in ("candidate", "rollback"):
            stem = f"{suite}-v3-{subject}-delivery" + ("-2" if suite == "backup" else "")
            meta = read(EVIDENCE / stem / "command.json")
            assert meta["initramfs"]["candidate_sha256"] == package["modified_sha256"]
            assert meta["guest_script_sha256"] == original_meta["guest_script_sha256"], (suite, "input drift")
            assert meta["external_network"] is False
            report = read(EVIDENCE / (stem + "-diff.json"))
            reports[f"{suite}/{subject}"] = summary(report)
            audit = EVIDENCE / (stem + "-audit.json")
            if audit.exists():
                reports[f"{suite}/{subject}/audit"] = summary(read(audit))
            if subject == "rollback":
                event = next(row for row in read(EVIDENCE / stem / "results.json") if row["kind"] == "rollback")
                assert event["exit"] == 0 and event["sha256"] == package["original_sha256"]
                events.append({"suite": suite, **event})
    assert all(row["execution_exit"] == 0 for row in runs)
    for name in ("tests", "clippy", "build", "prepare", "package"):
        assert read(EVIDENCE / f"{name}-v3-delivery/command.json")["exit"] == 0
    roles = {name: str((ART / name).resolve()) for name in
             ("MODIFIED_FILE", "DIFF_FILE.patch", "VERIFICATION.txt", "ROLLBACK.sh")}
    remaining = [
        "审核 provider 成功请求/校准协议未获原版 TLS 观测；5 个扩展响应用例保留显式 503 门禁差异",
        "管理非空数据库 gateway_sessions 自增 ID 偏移与上游调用序列仍有差异，未忽略 ID",
        "auth/session 上游 accounts/check + me 刷新链未对齐",
        "Connection 命名头按安全要求过滤，与原版泄漏行为显式不同",
        "两个未知 chat 探针路径继续 503；不为通过测试整体开放聊天路由",
        "login extra_cookies 字符串/缺失/错误类型的严格原版提取契约仍需完善",
        "完整 SSE/WebSocket、指纹传输、MCP/Skills 请求侧与限额、会话/项目读写隔离独立门禁",
        "Docker 未验证；真实账号/真实上游/浏览器联调未批准，本次未运行",
    ]
    status = {"state": "in_progress", "release_gate": "failed", "batch_complete": False,
        "baseline_sha256": package["original_sha256"], "candidate_sha256": package["modified_sha256"],
        "roles": roles, "response_comparison": reports["core/candidate"],
        "reports": reports, "same_input_contracts": inputs, "remaining": remaining,
        "next_work": "先定位管理会话 ID 首次偏移和 auth/session 刷新副作用；保留审核成功协议门禁，不伪造观测。",
        "rollback_scope": "程序副本恢复；不回滚数据库；生产切换未执行",
        "history": str(history)}
    (ROOT / "STATUS.json").write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# v3 兼容矩阵：本批未完整通过", "",
        "旧 101 项与新增契约分开验收。下列计数存在重叠，不可相加为产品覆盖率。",
        "四角色已更新为同一最终 Linux x86-64 候选；原版和旧证据不变。", "",
        "| 契约/制品 | 比较量 | 一致 | 差异 |", "|---|---:|---:|---:|"]
    for key, report in reports.items():
        count = report.get("response_cases", report.get("cases", report.get("candidate_checked")))
        lines.append(f"| {key} | {count} | {report.get('matched', 'wire integrity')} | {report['different']} |")
    lines.extend(["", "## 判定与边界", "",
        "BASELINE 使用已记录原版结果，MODIFIED 与 ROLLBACK 使用完全相同脚本哈希、独立 QEMU 无网卡实例、合成数据和本地模拟上游。",
        "回滚逐套实际执行 ROLLBACK.sh、验证恢复 SHA-256，再执行同输入。它只恢复程序，不处理数据库。",
        "61 个 Rust 测试、Clippy -D warnings、locked/offline Linux musl 构建已通过。强制防御性审查见 DEFENSIVE_REVIEW.md。",
        "响应 JSON 按结构比较，HTTP Date/随机令牌使用原有校验规则；未新增随机字段忽略规则。",
        "Header 压缩审计绑定原始字节长度、摘要、gzip 校验和及解码正文，不要求不同编码器输出相同 DEFLATE 字节。",
        "管理 DB 审计验证签发令牌与持久化摘要、认证解密、明示时间列；ID 偏移未归为随机性。备份另比恢复前后八表与输入。",
        "历史子代理 contract.md 是当时的移交笔记，不代表当前实现；本文件与 STATUS.json、delivery 报告为最新判定。", "",
        "## 未完成/显式差异", "", *["- " + item for item in remaining], "",
        "## 证据", "",
        "- evidence/delivery-v3-runs.json：每个进程实际退出状态，比较有差异时 exit 1。",
        "- 备份首轮端口占用失败保留在 delivery；调整监听端口后的最终三方证据为 backup-v3-original-014、backup-v3-{candidate,rollback}-delivery-2 及对应 compare-command。",
        "- evidence/*-v3-{candidate,rollback}-delivery{-diff,-audit}.json：最终比较及差异原值。",
        "- evidence/*-delivery/command.json、serial.log、results.json：执行、原始输出和数据库/上游记录。",
        "- artifacts/VERIFICATION.txt：原版/候选/回滚 literal 命令与输出、退出、哈希。",
        "- evidence/verification-before-v3.txt：上一轮 ledger 原样保留。", ""])
    (ROOT / "COMPATIBILITY.md").write_text("\n".join(lines), encoding="utf-8")
    sources = []
    for folder in ("src", "tests", "tools"):
        sources.extend(p for p in (ROOT / folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    sources.extend(ROOT / name for name in ("Cargo.toml", "Cargo.lock", ".gitignore", ".dockerignore",
        "Dockerfile", "compose.offline.yml", "README.md", "COMPATIBILITY.md", "DEFENSIVE_REVIEW.md", "STATUS.json"))
    with tempfile.TemporaryDirectory(dir=ROOT / ".build", prefix="source-v3-") as temp:
        temp = Path(temp)
        subprocess.run(["git", "init", "--quiet", str(temp)], check=True, capture_output=True)
        for source in sources:
            dest = temp / source.relative_to(ROOT)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
        subprocess.run(["git", "-C", str(temp), "add", "--intent-to-add", "."], check=True, capture_output=True)
        check = subprocess.run(["git", "-C", str(temp), "diff", "--check"], capture_output=True)
        (EVIDENCE / "source-v3-diff-check.json").write_text(json.dumps({"exit": check.returncode,
            "stdout": check.stdout.decode(), "stderr": check.stderr.decode()}, indent=2), encoding="utf-8")
        if check.returncode:
            raise RuntimeError("Source diff --check failed; evidence retained")
        patch = subprocess.run(["git", "-C", str(temp), "diff", "--binary"], check=True, capture_output=True)
        (ART / "SOURCE.patch").write_bytes(patch.stdout)
    with zipfile.ZipFile(ART / "gateway-rust-source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sources:
            archive.write(source, source.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(ART / "gateway-rust-source.zip") as archive:
        assert archive.testzip() is None
    sections = ["Mirror Rust gateway v3 verification ledger", "RESULT: INCOMPLETE / DO NOT DEPLOY",
        json.dumps(status, ensure_ascii=False, indent=2),
        "Changed symbols: server::{private_headers,login,authorize_login_payload,restore,conversation_statistics}; "
        "server::management::{mirror_token,user_use_count,chatgpt_use_count,close_chatgpt_memory,political_moderation_config_save}; "
        "server::proxy::{django_proxy,chat_proxy,strip_request_hop_by_hop}; compression::{GzipBody,GunzipBody}; "
        "Database::restore_http_backup_validated. Strict migration kept separate.",
        "QEMU -nic none, synthetic fixtures. Original asset unchanged. No live upstream/browser tests.",
        "QEMU owner termination after guest completion is not the test verdict; guest and oracle exits are recorded literally.",
        "Previous ledger retained at " + str(history) + " SHA256=" + sha(history),
        json.dumps(package, ensure_ascii=False, indent=2), json.dumps(events, ensure_ascii=False, indent=2)]
    for suite, (_, baseline) in SUITES.items():
        suffix = "-2" if suite == "backup" else ""
        for label, folder in (("BASELINE", baseline), ("MODIFIED", f"{suite}-v3-candidate-delivery{suffix}"),
                              ("ROLLBACK", f"{suite}-v3-rollback-delivery{suffix}")):
            for name in ("command.json", "serial.log", "qemu.stderr"):
                path = EVIDENCE / folder / name
                sections.append(f"=== {suite} {label} {path} LITERAL ===\n" + path.read_text(encoding="utf-8", errors="replace"))
    folders = sorted(p for p in EVIDENCE.iterdir() if p.is_dir() and
        ("-delivery" in p.name or p.name == "delivery-v3-command") and
        (p / "stdout.txt").exists() and (p / "command.json").exists())
    for folder in folders:
        for name in ("command.json", "stdout.txt", "stderr.txt"):
            sections.append(f"=== LITERAL {folder / name} ===\n" + (folder / name).read_text(encoding="utf-8", errors="replace"))
    sections.append("Source ZIP SHA256=" + sha(ART / "gateway-rust-source.zip"))
    sections.append("Historical failures remain under evidence; TLS provider success was never observed. No failure has been recast as success. "
        "Initial backup delivery had two Address in use (os error 98) exits and comparator KeyError before; "
        "delivery-2 reran all three subjects on identical low-port fixtures. Initial delivery-v3-runs.json remains unchanged.")
    (ART / "VERIFICATION.txt").write_text("\n\n".join(sections), encoding="utf-8")
    print(json.dumps({"roles": roles, "reports": reports, "release_gate": "failed"}, ensure_ascii=False))


if __name__ == "__main__":
    main()

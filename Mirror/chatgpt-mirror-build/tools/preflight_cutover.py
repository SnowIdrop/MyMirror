"""上线前就绪检查（只读）：把「能不能开始切换」变成一条命令。

Author: MingTea. 只依赖标准库；对目标机只做只读探测，不改任何文件、不重启任何服务。

为什么需要它：切换闭源 all-in-one 的那次，真正卡住的不是构建，而是
「回滚材料在不在」「旧库副本还在不在」「.env 里的密钥还是不是那一份」这类事实。
这些事实都写在 DEPLOYMENT.md 里，但每次手抄一遍既慢又容易漏，所以做成检查项。

用法（在本机 Windows 或 WSL 里跑）：

    py -3 tools/preflight_cutover.py
    py -3 tools/preflight_cutover.py --host ubuntu@54.95.51.66 --key "C:/.../key.pem"
    py -3 tools/preflight_cutover.py --json          # 机器可读输出

退出码：0 = 可以开始；1 = 有 FAIL（暂缓）；2 = 连不上或参数错误。
WARN 不算失败，但每条都给出「为什么值得看一眼」。
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

# 目标机上的固定布局（见 DEPLOYMENT.md「目标机上的目录」）。
DEFAULT_HOST = "ubuntu@54.95.51.66"
DEFAULT_KEY = r"C:\Users\peropero\Downloads\LightsailDefaultKey-ap-northeast-1.pem"
DEFAULT_ROOT = "/home/ubuntu/mirror"
BACKUP_DIR = "/home/ubuntu/mirror-backups/20260930-pre-switch"

# 必须存在且非空的 .env 键：缺任何一个都会让新栈起不来或读不出既有凭据。
REQUIRED_ENV_KEYS = (
    "DJANGO_SECRET_KEY",
    "CREDENTIAL_ENCRYPTION_KEY",
    "GATEWAY_ADMIN_SECRET",
    "ADMIN_USERNAME",
    "ADMIN_PASSWORD",
)

# 切换后应当存在的四个候选镜像；缺哪个就说明构建没做完。
CANDIDATE_IMAGES = (
    "mirror-gateway:phase1",
    "mirror-django:phase1",
    "mirror-cfbypass:phase1",
    "mirror-frontend:phase1",
)

# 回滚材料：少一样就必须在开始前补齐，因为切换后旧目录会被删掉。
ROLLBACK_FILES = (
    "original-compose.yml",
    "original.env",
    "Caddyfile.before-switch",
    "SHA256SUMS",
    "data/backend-db/db.sqlite3",
)

ROLLBACK_IMAGE = "lisa666520/chatgpt-mirror-django:all-in-one"


def remote_probe_script(root: str, backup_dir: str) -> str:
    """生成远端只读探测脚本：只输出 `KEY<TAB>VALUE`，不打印任何密钥值。"""
    return f"""
set -u
emit() {{ printf '%s\\t%s\\n' "$1" "$2"; }}

emit uname "$(uname -srm)"
emit disk_free_gb "$(df -Pk / | awk 'NR==2 {{print int($4/1024/1024)}}')"
emit mem_total_gb "$(awk '/MemTotal/ {{print int($2/1024/1024)}}' /proc/meminfo)"
emit docker "$(command -v docker >/dev/null 2>&1 && docker --version || echo missing)"
emit compose "$(docker compose version --short 2>/dev/null || echo missing)"
emit containers "$(docker ps -a --format '{{{{.Names}}}}:{{{{.Status}}}}' 2>/dev/null | tr '\\n' ',' )"
emit ports "$(ss -ltn 2>/dev/null | awk 'NR>1 {{split($4,a,":"); print a[length(a)]}}' | sort -un | tr '\\n' ',')"

emit source_tree "$(test -f {root}/gateway-rust/artifacts/phase1/source/Cargo.toml && test -f {root}/gateway-rust/artifacts/phase1/source/Dockerfile && echo yes || echo no)"
emit compose_files "$(test -f {root}/chatgpt-mirror-build/docker-compose.rust-gateway.yml && test -f {root}/chatgpt-mirror-build/docker-compose.prod.yml && echo yes || echo no)"
emit env_file "$(test -f {root}/chatgpt-mirror-build/.env && echo yes || echo no)"
emit backend_db "$(stat -c '%s' {root}/chatgpt-mirror-build/backend/db/db.sqlite3 2>/dev/null || echo 0)"
emit source_gateway_db "$(stat -c '%s' {root}/source-gateway.db 2>/dev/null || echo 0)"

for key in {' '.join(REQUIRED_ENV_KEYS)}; do
  value="$(sed -n "s/^${{key}}=//p" {root}/chatgpt-mirror-build/.env 2>/dev/null | head -1)"
  if [ -n "$value" ]; then emit "env_${{key}}" "set"; else emit "env_${{key}}" "empty"; fi
done
emit env_ADMIN_PUBLIC_URL "$(sed -n 's/^ADMIN_PUBLIC_URL=//p' {root}/chatgpt-mirror-build/.env 2>/dev/null | head -1)"
emit env_MIRROR_PUBLIC_URL "$(sed -n 's/^MIRROR_PUBLIC_URL=//p' {root}/chatgpt-mirror-build/.env 2>/dev/null | head -1)"

emit backup_dir "$(test -d {backup_dir} && echo yes || echo no)"
for name in {' '.join(ROLLBACK_FILES)}; do
  if [ -f "{backup_dir}/${{name}}" ]; then emit "rollback_${{name}}" "yes"; else emit "rollback_${{name}}" "no"; fi
done

for image in {' '.join(CANDIDATE_IMAGES)}; do
  emit "image_${{image}}" "$(docker image inspect "$image" >/dev/null 2>&1 && echo yes || echo no)"
done
emit "image_{ROLLBACK_IMAGE}" "$(docker image inspect '{ROLLBACK_IMAGE}' >/dev/null 2>&1 && echo yes || echo no)"

emit caddy_active "$(systemctl is-active caddy 2>/dev/null || echo unknown)"
emit caddy_split "$(sudo -n grep -q '127.0.0.1:40003' /etc/caddy/Caddyfile 2>/dev/null && echo yes || echo no)"
emit gateway_volume "$(docker volume inspect mirror-build_gateway-data >/dev/null 2>&1 && echo yes || echo no)"
"""


def run_remote(host: str, key: str, root: str, backup_dir: str,
               timeout: int) -> dict[str, str]:
    ssh = shutil.which("ssh")
    if ssh is None:
        raise SystemExit("本机找不到 ssh，可执行文件必须在 PATH 里")
    if key and not Path(key).exists():
        raise SystemExit(f"SSH 私钥不存在：{key}")
    command = [ssh]
    if key:
        command += ["-i", key]
    command += ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}",
                "-o", "ServerAliveInterval=15", host, "bash -s"]
    # 必须按字节传脚本：Windows 上 `text=True` 会把 `\n` 翻成 `\r\n`，
    # 远端 bash 会把它读成 `$'\r'` 而整段脚本语法错误（已踩过一次）。
    script = remote_probe_script(root, backup_dir).encode("utf-8")
    result = subprocess.run(
        command,
        input=script,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout + 60,
    )
    stdout = result.stdout.decode("utf-8", "replace")
    stderr = result.stderr.decode("utf-8", "replace")
    if result.returncode != 0:
        detail = (stderr or stdout).strip()[-400:]
        raise SystemExit(f"远端探测失败（exit={result.returncode}）：{detail}")
    facts: dict[str, str] = {}
    for line in stdout.splitlines():
        if "\t" not in line:
            continue
        name, value = line.split("\t", 1)
        facts[name.strip()] = value.strip()
    return facts


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, level: str, name: str, detail: str) -> None:
        self.rows.append((level, name, detail))

    def ok(self, name: str, detail: str) -> None:
        self.add("PASS", name, detail)

    def warn(self, name: str, detail: str) -> None:
        self.add("WARN", name, detail)

    def fail(self, name: str, detail: str) -> None:
        self.add("FAIL", name, detail)

    def verdict(self) -> str:
        if any(level == "FAIL" for level, _, _ in self.rows):
            return "NO-GO"
        if any(level == "WARN" for level, _, _ in self.rows):
            return "GO（有 WARN，逐条看过再开始）"
        return "GO"


def evaluate(facts: dict[str, str], min_free_gb: int, min_mem_gb: int) -> Report:
    report = Report()

    report.ok("远端连通", facts.get("uname", "?"))

    free = int(facts.get("disk_free_gb", "0") or 0)
    (report.ok if free >= min_free_gb else report.fail)(
        "磁盘余量", f"{free} GiB（要求 ≥ {min_free_gb}）：四个镜像约 2 GiB，构建缓存另算")

    mem = int(facts.get("mem_total_gb", "0") or 0)
    (report.ok if mem >= min_mem_gb else report.warn)(
        "内存", f"{mem} GiB（建议 ≥ {min_mem_gb}）：BoringSSL 编译是内存敏感的")

    docker = facts.get("docker", "missing")
    (report.ok if docker != "missing" else report.fail)("docker", docker)
    compose = facts.get("compose", "missing")
    (report.ok if compose != "missing" else report.fail)("docker compose v2", compose)

    ports = {p for p in facts.get("ports", "").split(",") if p}
    (report.ok if "80" in ports else report.warn)("对外监听", f"已监听端口：{sorted(ports)}")
    # 40002/40003 在稳态下本来就被新栈占着；只有「不是新栈占的」才是切换风险。
    new_stack_running = "mirror-build-gateway-1" in facts.get("containers", "")
    for port in ("40002", "40003"):
        if port not in ports:
            report.ok("端口占用", f"{port} 空闲")
        elif new_stack_running:
            report.ok("端口占用", f"{port} 由候选栈占用（稳态）")
        else:
            report.warn("端口占用", f"{port} 被别人占着：切换前要先 down 掉旧栈，否则新栈绑不上")

    (report.ok if facts.get("source_tree") == "yes" else report.fail)(
        "网关源码树", "Cargo.toml + Dockerfile 齐备" if facts.get("source_tree") == "yes"
        else "缺少 Cargo.toml/Dockerfile：源码没上传完整，先做「上传源码」这一步")
    (report.ok if facts.get("compose_files") == "yes" else report.fail)(
        "编排文件", "rust-gateway + prod 覆盖都在" if facts.get("compose_files") == "yes"
        else "缺 docker-compose.rust-gateway.yml 或 docker-compose.prod.yml")
    (report.ok if facts.get("env_file") == "yes" else report.fail)(
        "'.env'", "存在（值不读取）" if facts.get("env_file") == "yes" else "缺 .env")

    for key in REQUIRED_ENV_KEYS:
        state = facts.get(f"env_{key}", "missing")
        (report.ok if state == "set" else report.fail)(
            f".env {key}", "已设置" if state == "set" else "缺失或为空：换掉/遗漏会导致既有凭据不可解密")

    mirror_url = facts.get("env_MIRROR_PUBLIC_URL", "")
    (report.ok if mirror_url == "" else report.warn)(
        "MIRROR_PUBLIC_URL", "留空（同源部署的正确取值）" if mirror_url == "" else f"当前为 {mirror_url}：仅在管理面与镜像面不同源时才需要")
    admin_url = facts.get("env_ADMIN_PUBLIC_URL", "")
    (report.ok if admin_url.startswith("http") else report.warn)(
        "ADMIN_PUBLIC_URL", admin_url or "为空：注入脚本的「返回后台」会退回同源相对跳转")

    size = int(facts.get("backend_db", "0") or 0)
    (report.ok if size > 0 else report.fail)("Django 库", f"{size} B")
    size = int(facts.get("source_gateway_db", "0") or 0)
    (report.ok if size > 0 else report.warn)(
        "旧网关库副本", f"{size} B" if size > 0 else
        "不在：网关库只能从旧容器卷里现取，迁移前先备份")

    if facts.get("backup_dir") != "yes":
        report.fail("备份目录", f"{BACKUP_DIR} 不存在：先做「切换前备份」")
    else:
        report.ok("备份目录", BACKUP_DIR)
    for name in ROLLBACK_FILES:
        present = facts.get(f"rollback_{name}") == "yes"
        (report.ok if present else report.fail)(
            f"回滚材料 {name}", "在" if present else "缺失：回滚时补不出来，先补齐再切换")

    missing = [i for i in CANDIDATE_IMAGES if facts.get(f"image_{i}") != "yes"]
    (report.ok if not missing else report.warn)(
        "候选镜像", "四个都在" if not missing else f"缺 {missing}：切换前要先构建")
    (report.ok if facts.get(f"image_{ROLLBACK_IMAGE}") == "yes" else report.fail)(
        "回滚镜像", ROLLBACK_IMAGE if facts.get(f"image_{ROLLBACK_IMAGE}") == "yes"
        else f"{ROLLBACK_IMAGE} 不在：回滚会没有可跑的旧栈")

    (report.ok if facts.get("caddy_active") == "active" else report.fail)(
        "Caddy", facts.get("caddy_active", "?"))
    (report.ok if facts.get("caddy_split") == "yes" else report.warn)(
        "Caddy 分流", "已按 /admin/* 分流" if facts.get("caddy_split") == "yes"
        else "还是单条 reverse_proxy：本次切换要改它（保留 Caddyfile.before-switch）")
    (report.ok if facts.get("gateway_volume") == "yes" else report.warn)(
        "网关数据卷", "mirror-build_gateway-data 存在" if facts.get("gateway_volume") == "yes"
        else "不存在：migrate 子命令要先把 compose up 一次或手动 volume create")

    containers = facts.get("containers", "")
    report.ok("当前容器", containers or "（无）")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="上线前就绪检查（只读）")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--key", default=DEFAULT_KEY)
    parser.add_argument("--remote-root", default=DEFAULT_ROOT)
    parser.add_argument("--backup-dir", default=BACKUP_DIR)
    parser.add_argument("--min-free-gb", type=int, default=20)
    parser.add_argument("--min-mem-gb", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--json", action="store_true", help="输出机器可读的 JSON")
    args = parser.parse_args()

    facts = run_remote(args.host, args.key, args.remote_root, args.backup_dir, args.timeout)
    report = evaluate(facts, args.min_free_gb, args.min_mem_gb)

    if args.json:
        print(json.dumps(
            {"verdict": report.verdict(),
             "checks": [{"level": l, "name": n, "detail": d} for l, n, d in report.rows]},
            ensure_ascii=False, indent=2))
    else:
        width = max(len(name) for _, name, _ in report.rows)
        for level, name, detail in report.rows:
            print(f"{level:4}  {name:<{width}}  {detail}")
        print()
        print(f"结论：{report.verdict()}")

    return 1 if report.verdict() == "NO-GO" else 0


if __name__ == "__main__":
    sys.exit(main())

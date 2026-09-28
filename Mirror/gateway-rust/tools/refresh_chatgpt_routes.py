"""刷新 /backend-api 路由快照（artifacts/phase1/source/src/assets/chatgpt-api-routes.json）。

Author: MingTea. 只依赖标准库，不接触任何账号凭据。

上游前端每次发版都会换一批内容寻址的 CDN 分块。本工具从一份**真实浏览器观测**
（`artifacts/phase1/probe/evidence/accept-*.json`，由 `probe_browser_accept.py`
产出）里取分块清单，逐个拉取分块并按固定规则抽取 `METHOD 路径模板`，再与仓库里
的快照比对（`--check`）或重写（`--write`）。

抽取规则（与快照里的 `extraction` 字段一致）：

    safe(Get|Post|Put|Patch|Delete)(`<path>`)

即前端 SDK 的 `safeXxx` 调用字面量。含 `${...}` 插值与不以 `/` 开头的模板跳过，
非 `/backend-api` 前缀补上该前缀。该规则已对着 2026-09-23 的 923 条快照逐条复算
（零差异），因此刷新结果可以与历史快照直接比较。

用法：

    py -3 tools/refresh_chatgpt_routes.py --check    # 只比对，有漂移非零退出
    py -3 tools/refresh_chatgpt_routes.py --write    # 按抽取结果重写快照

分块按内容寻址、不可变，因此默认缓存在系统临时目录，重复运行只做网络增量。
"""

import argparse
import datetime
import hashlib
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT = ROOT / "artifacts/phase1/source/src/assets/chatgpt-api-routes.json"
DEFAULT_EVIDENCE = ROOT / "artifacts/phase1/probe/evidence"
DEFAULT_ASSETS_BASE = "https://cdn.oaistatic.com/assets/"
DEFAULT_CACHE = Path(tempfile.gettempdir()) / "chatgpt-route-chunks"

# CDN 会按 UA/指纹拒绝默认的 `Python-urllib/3.x`（实测 403），因此取分块时带上与
# 网关 `src/server/identity.rs` 同值的浏览器形状头。这里只影响这一次只读下载，
# 运行期指纹的唯一来源仍是 identity.rs。
CHUNK_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    # 明确要求不压缩：正文要按原字节算 sha256 并做文本抽取。
    "Accept-Encoding": "identity",
    "Referer": "https://chatgpt.com/",
    "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
}

CHUNK_PATTERN = re.compile(r"^/cdn/assets/([^/]+\.js)$")
ROUTE_PATTERN = re.compile(r"safe(Get|Post|Put|Patch|Delete)\(\s*`([^`$]+)`")
ROUTE_PREFIX = "/backend-api"

SUMMARY = (
    "ChatGPT Web 前端 CDN 分块里提取的 /backend-api 路由模板快照。未显式分类的"
    "上游路由由 server/acl.rs 按请求/响应里的资源 id 判定，本文件用于对照与审计："
    "tools/refresh_chatgpt_routes.py --check 报出上游前端新增或删除的路由。"
)
EXTRACTION = (
    "正则 safe(Get|Post|Put|Patch|Delete)(`<path>`)，跳过含 ${...} 插值与不以 / "
    "开头的模板，非 /backend-api 前缀补 /backend-api"
)


def newest_observation(evidence: Path) -> Path:
    """默认观测：evidence 目录里最新的一份 accept-*.json。"""
    candidates = sorted(evidence.glob("accept-*.json"))
    if not candidates:
        raise SystemExit(f"没有观测文件：{evidence}/accept-*.json（先用 probe_browser_accept.py 跑一次）")
    return candidates[-1]


def chunk_names(observation: Path) -> list[str]:
    """观测文件里浏览器实际请求过的 `/cdn/assets/*.js` 清单。"""
    payload = json.loads(observation.read_text(encoding="utf-8"))
    requests = (payload.get("network") or {}).get("requests") or []
    names = {
        match.group(1)
        for request in requests
        if (match := CHUNK_PATTERN.match(str(request.get("path", ""))))
    }
    if not names:
        raise SystemExit(f"观测文件里没有 /cdn/assets/*.js：{observation}")
    return sorted(names)


def fetch_chunk(name: str, base: str, cache: Path, timeout: float) -> bytes:
    """取一个分块：命中缓存直接读，否则下载并落缓存（分块按内容寻址、不可变）。"""
    cached = cache / name
    if cached.is_file():
        return cached.read_bytes()
    url = f"{base}{name}"
    try:
        request = urllib.request.Request(url, headers=CHUNK_HEADERS)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except (urllib.error.URLError, TimeoutError) as cause:
        raise SystemExit(f"分块下载失败：{url}（{cause}）")
    cache.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(body)
    return body


def extract_routes(source: str) -> list[tuple[str, str]]:
    """按 `safeXxx(`path`)` 抽取 (方法, 模板)；同一模板在一个分块内只算一次。"""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for method, path in ROUTE_PATTERN.findall(source):
        if not path.startswith("/"):
            continue
        if not path.startswith(ROUTE_PREFIX):
            path = ROUTE_PREFIX + path
        pair = (method.upper(), path)
        if pair not in seen:
            seen.add(pair)
            found.append(pair)
    return found


def collect(
    observation: Path, base: str, cache: Path, timeout: float
) -> tuple[list[dict], list[dict]]:
    """返回 (chunks, routes)：分块与去重后的路由，两者都按稳定顺序排列。"""
    chunks: list[dict] = []
    routes: dict[tuple[str, str], str] = {}
    for name in chunk_names(observation):
        body = fetch_chunk(name, base, cache, timeout)
        chunks.append(
            {
                "name": name,
                "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
            }
        )
        for pair in extract_routes(body.decode("utf-8", errors="replace")):
            # 同一路由出现在多个分块时保留第一个（分块名已排序，结果可复现）。
            routes.setdefault(pair, name)
    ordered = [
        {"method": method, "path": path, "chunk": chunk}
        # 按 (路径, 方法) 排序：同一路径的不同方法相邻，快照 diff 稳定。
        for (method, path), chunk in sorted(
            routes.items(), key=lambda item: (item[0][1], item[0][0])
        )
    ]
    return chunks, ordered


def load_snapshot(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"快照不存在：{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def describe(label: str, before: set, after: set, limit: int) -> bool:
    """打印一组的差异；返回是否有漂移。"""
    added = sorted(after - before)
    removed = sorted(before - after)
    drift = bool(added or removed)
    state = "有漂移" if drift else "一致"
    print(f"{label}：快照 {len(before)} → 抽取 {len(after)}（新增 {len(added)}、消失 {len(removed)}）{state}")
    for prefix, rows in (("+", added), ("-", removed)):
        for row in rows[:limit]:
            print(f"  {prefix} {row}")
        if len(rows) > limit:
            print(f"  {prefix} …另有 {len(rows) - limit} 条")
    return drift


def main() -> int:
    parser = argparse.ArgumentParser(description="刷新 /backend-api 路由快照")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="只比对并打印差异（默认）")
    mode.add_argument("--write", action="store_true", help="按抽取结果重写快照")
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--chunks-from", type=Path, default=None, help="指定一份 accept-*.json")
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--assets-base", default=DEFAULT_ASSETS_BASE)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--report-limit", type=int, default=40, help="每类差异打印多少条")
    args = parser.parse_args()

    observation = args.chunks_from or newest_observation(args.evidence_dir)
    snapshot = load_snapshot(args.snapshot)
    chunks, routes = collect(observation, args.assets_base, args.cache_dir, args.timeout)
    print(f"观测：{observation}")
    print(
        f"分块：{len(chunks)} 个、"
        f"{sum(chunk['bytes'] for chunk in chunks) / (1024 * 1024):.1f} MB"
    )

    known_chunks = {chunk["name"] for chunk in snapshot.get("chunks", [])}
    known_routes = {
        f"{route['method']} {route['path']}" for route in snapshot.get("routes", [])
    }
    drifted = describe(
        "分块",
        known_chunks,
        {chunk["name"] for chunk in chunks},
        args.report_limit,
    )
    drifted |= describe(
        "路由",
        known_routes,
        {f"{route['method']} {route['path']}" for route in routes},
        args.report_limit,
    )

    if not args.write:
        if drifted:
            print("\n快照已过期：确认差异后运行 --write 重写。")
            return 1
        print("\n快照与上游前端一致。")
        return 0

    payload = {
        "summary": SUMMARY,
        "captured_at": datetime.date.today().isoformat(),
        "origin": f"{observation} 观测到的 cdn.oaistatic.com/assets/*.js 请求清单",
        "upstream_origin": args.assets_base,
        "extraction": EXTRACTION,
        "chunk_count": len(chunks),
        "route_count": len(routes),
        "chunks": chunks,
        "routes": routes,
    }
    args.snapshot.write_text(
        json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print(f"\n已写入 {args.snapshot}：{len(chunks)} 个分块、{len(routes)} 条路由")
    return 0


if __name__ == "__main__":
    sys.exit(main())

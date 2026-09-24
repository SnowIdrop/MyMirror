# -*- coding: utf-8 -*-
"""用真实 Chromium **直连** chatgpt.com，抓 browser→上游 的完整请求头。

用途：候选网关的 `identity::IDENTITY_HEADERS` 是「整组强制覆盖」（UA + 低熵/高熵
client hints 全发）。要判断这一组是否等于「正常用户」，只能看真浏览器直连
chatgpt.com 时到底发不发高熵 hints，以及 `sec-fetch-*`/`priority` 的真实取值。

只读：匿名加载首页与页面自己发起的同源请求，不登录、不写入、不发送任何消息。
证据只落头名与白名单头值（`sec-ch-ua*`、`sec-fetch-*`、`priority`、`accept*`、
`oai-language` 等），Cookie、Authorization 与正文一律不落。
"""

import argparse
import hashlib
import json
import time
from pathlib import Path

ORIGIN = "https://chatgpt.com"

SAFE_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "priority",
    "oai-language",
    "sec-ch-ua",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-mobile",
    "sec-ch-ua-model",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "upgrade-insecure-requests",
}

# 即使出现在 allHeaders 里也不落盘的凭据类头。
CREDENTIALS = {"cookie", "authorization", "x-mirror-token", "set-cookie"}


def capture(timeout: float, idle: float) -> dict:
    from playwright.sync_api import sync_playwright

    records = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chromium")
        try:
            context = browser.new_context(locale="zh-CN")
            page = context.new_page()

            def on_request(request):
                if not request.url.startswith(ORIGIN):
                    return
                if request.resource_type not in ("document", "xhr", "fetch", "script"):
                    return
                headers = {name.lower(): value for name, value in request.all_headers().items()}
                records.append({
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "path": request.url[len(ORIGIN):].split("?")[0],
                    "header_names": sorted(name for name in headers if name not in CREDENTIALS),
                    "safe_headers": {
                        name: value for name, value in headers.items() if name in SAFE_HEADERS
                    },
                })

            page.on("request", on_request)
            status = None
            error = None
            try:
                response = page.goto(ORIGIN + "/", wait_until="domcontentloaded", timeout=timeout * 1000)
                status = response.status if response else None
            except Exception as cause:  # 记录真实失败，不重试也不换路
                error = type(cause).__name__
            page.wait_for_timeout(int(idle * 1000))
            title = page.title()
            return {
                "status": status,
                "error": error,
                "title_sha256": hashlib.sha256(title.encode("utf-8")).hexdigest(),
                "user_agent": page.evaluate("() => navigator.userAgent"),
                "records": records,
            }
        finally:
            browser.close()


def summarize(records: list) -> dict:
    """按资源类型汇总：哪些头在真浏览器请求 chatgpt.com 时稳定出现。"""
    summary: dict = {}
    for record in records:
        bucket = summary.setdefault(record["resource_type"], {"count": 0, "headers": {}})
        bucket["count"] += 1
        for name in record["header_names"]:
            bucket["headers"][name] = bucket["headers"].get(name, 0) + 1
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="抓真 Chromium 直连 chatgpt.com 的请求头")
    parser.add_argument("--evidence", default=None, help="证据输出路径")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--idle", type=float, default=12.0, help="加载后继续观察的秒数")
    args = parser.parse_args()

    captured = capture(args.timeout, args.idle)
    evidence = {
        "probe": "browser-chatgpt-headers",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "origin": ORIGIN,
        "write": False,
        "status": captured["status"],
        "error": captured["error"],
        "title_sha256": captured["title_sha256"],
        "user_agent": captured["user_agent"],
        "summary": summarize(captured["records"]),
        "records": captured["records"],
        "notes": [
            "只读：匿名加载首页与页面自发请求，不登录、不写入。",
            "只落头名与白名单头值；Cookie/Authorization/正文不落盘。",
        ],
    }
    destination = Path(args.evidence) if args.evidence else (
        Path(__file__).resolve().parent / "evidence" /
        f"chatgpt-headers-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"证据已写入 {destination}")
    print(f"HTTP {captured['status']} error={captured['error']} 记录 {len(captured['records'])} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

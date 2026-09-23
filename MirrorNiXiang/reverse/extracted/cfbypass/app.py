from __future__ import annotations

import asyncio
import hmac
import ipaddress
import os
import shutil
import socket
import time
import traceback
from typing import Any
from urllib.parse import urlparse

from DrissionPage import ChromiumOptions, ChromiumPage
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl, field_validator

from proxy_relay import AuthenticatedProxyRelay

DEFAULT_USER_AGENT = os.getenv(
    "CF_BYPASS_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
)
DEFAULT_ACCEPT_LANGUAGE = os.getenv("CF_BYPASS_ACCEPT_LANGUAGE", "zh-CN,zh")
DEFAULT_HEADLESS = os.getenv("CF_BYPASS_HEADLESS", "true").lower() not in {
    "0",
    "false",
    "no",
}
MAX_WAIT_SECONDS = int(os.getenv("CF_BYPASS_MAX_WAIT_SECONDS", "20"))
PAGE_LOAD_TIMEOUT_SECONDS = max(
    5.0,
    float(os.getenv("CF_BYPASS_PAGE_LOAD_TIMEOUT_SECONDS", "15")),
)
POLL_INTERVAL_SECONDS = float(os.getenv("CF_BYPASS_POLL_INTERVAL_SECONDS", "0.5"))
FIRST_COOKIE_WAIT_SECONDS = max(
    1.0,
    float(os.getenv("CF_BYPASS_FIRST_COOKIE_WAIT_SECONDS", "6")),
)
COOKIE_STABLE_POLLS = max(
    2,
    int(os.getenv("CF_BYPASS_COOKIE_STABLE_POLLS", "2")),
)
NAVIGATION_RETRIES = int(os.getenv("CF_BYPASS_NAVIGATION_RETRIES", "1"))
ELEMENT_LOOKUP_TIMEOUT_SECONDS = float(
    os.getenv("CF_BYPASS_ELEMENT_LOOKUP_TIMEOUT_SECONDS", "0.2")
)
DISPLAY_SIZE = os.getenv("CF_BYPASS_DISPLAY_SIZE", "1920x1080")
CF_BYPASS_SECRET = os.getenv("CF_BYPASS_SECRET", "").strip()
CF_BYPASS_ALLOWED_HOSTS = tuple(
    item.strip().lower()
    for item in os.getenv(
        "CF_BYPASS_ALLOWED_HOSTS",
        "chatgpt.com,.chatgpt.com",
    ).split(",")
    if item.strip()
)

CLOUDFLARE_COOKIE_NAMES = {"cf_clearance", "__cf_bm", "__cflb", "_cfuvid"}
CLICK_SELECTORS = (".spacer", "input[type='checkbox']")

app = FastAPI()
_BYPASS_LOCK = asyncio.Lock()
_XVFB_DISPLAY = None


@app.exception_handler(HTTPException)
async def log_http_error(_request: Request, error: HTTPException) -> JSONResponse:
    log(f"request rejected status={error.status_code} detail={error.detail}")
    return JSONResponse(
        status_code=error.status_code,
        content={"detail": error.detail},
        headers=error.headers,
    )


def require_cfbypass_auth(authorization: str | None = Header(default=None)) -> None:
    supplied = (authorization or "").strip()
    if supplied.lower().startswith("bearer "):
        supplied = supplied[7:].strip()
    if not CF_BYPASS_SECRET or not hmac.compare_digest(supplied, CF_BYPASS_SECRET):
        raise HTTPException(status_code=401, detail="无效的服务认证信息")


def is_allowed_target_host(host: str) -> bool:
    normalized = host.strip().rstrip(".").lower()
    return any(
        normalized == allowed
        or (allowed.startswith(".") and normalized.endswith(allowed))
        for allowed in CF_BYPASS_ALLOWED_HOSTS
    )


def target_origin_for_log(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    return f"{parsed.scheme}://{parsed.hostname or 'unknown'}"


async def validate_target_url(raw_url: str) -> None:
    parsed = urlparse(raw_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise HTTPException(status_code=400, detail="目标地址仅支持 HTTPS")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise HTTPException(status_code=400, detail="目标地址包含不允许的认证信息或端口")
    if not is_allowed_target_host(parsed.hostname):
        raise HTTPException(status_code=400, detail="目标主机不在允许列表")

    try:
        records = await asyncio.to_thread(
            socket.getaddrinfo,
            parsed.hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise HTTPException(status_code=400, detail="目标主机解析失败") from error
    addresses = {record[4][0] for record in records}
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise HTTPException(status_code=400, detail="目标主机解析到非公网地址")


class CloudFlare5sQuerySchema(BaseModel):
    url: HttpUrl = Field(..., description="cloudflare target url")
    user_agent: str | None = Field(default=None, description="user agent")
    proxy_server: str | None = Field(
        default=None,
        description="http/https/socks5/socks5h proxy",
    )

    @field_validator("user_agent")
    @classmethod
    def normalize_user_agent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("proxy_server")
    @classmethod
    def validate_proxy_server(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None

        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
            raise ValueError(
                "proxy_server 必须是合法的 http/https/socks5/socks5h 代理地址"
            )
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            raise ValueError("proxy_server 不能包含路径或查询参数")
        return normalized


def log(message: str) -> None:
    print(f"[cfbypass] {message}", flush=True)


def parse_display_size() -> tuple[int, int]:
    try:
        width_raw, height_raw = DISPLAY_SIZE.lower().split("x", 1)
        width = max(int(width_raw), 800)
        height = max(int(height_raw), 600)
        return width, height
    except Exception:
        return 1920, 1080


def ensure_virtual_display() -> None:
    global _XVFB_DISPLAY
    if DEFAULT_HEADLESS or os.getenv("DISPLAY") or _XVFB_DISPLAY is not None:
        return

    from pyvirtualdisplay import Display

    width, height = parse_display_size()
    _XVFB_DISPLAY = Display(
        backend="xvfb",
        visible=True,
        size=(width, height),
        use_xauth=True,
    )
    _XVFB_DISPLAY.start()
    log(f"virtual display started: DISPLAY={os.getenv('DISPLAY')}")


def resolve_browser_path() -> str | None:
    for candidate in (
        os.getenv("CF_BYPASS_BROWSER_PATH"),
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def is_interesting_cookie_name(name: str) -> bool:
    normalized = name.strip()
    return normalized in CLOUDFLARE_COOKIE_NAMES


def normalize_cookies(raw_cookies: list[dict[str, Any]]) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    now = time.time()
    for raw in raw_cookies:
        name = str(raw.get("name", "")).strip()
        value = str(raw.get("value", "")).strip()
        domain = str(raw.get("domain", "")).strip()
        if not name or not value or not is_interesting_cookie_name(name):
            continue
        try:
            expires = float(raw.get("expires", raw.get("expiry", -1)))
        except (TypeError, ValueError):
            expires = -1
        if expires > 0 and expires <= now:
            continue

        item = {"name": name, "value": value}
        if domain:
            item["domain"] = domain
        cookies.append(item)
    return cookies


class Cloudflare5sBypass:
    def __init__(
        self,
        user_agent: str | None = None,
        proxy_server: str | None = None,
    ):
        ensure_virtual_display()
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.proxy_server = proxy_server
        self.driver: ChromiumPage | None = None
        self.proxy_relay: AuthenticatedProxyRelay | None = None
        self.last_raw_cookie_names: tuple[str, ...] = ()

    def _configure_proxy(self, options: ChromiumOptions) -> None:
        if not self.proxy_server:
            return

        parsed = urlparse(self.proxy_server)
        if parsed.username is None and parsed.password is None:
            options.set_proxy(self.proxy_server)
            return

        relay = AuthenticatedProxyRelay(self.proxy_server)
        relay.start()
        try:
            options.set_proxy(relay.proxy_url)
        except Exception:
            relay.stop()
            raise
        self.proxy_relay = relay
        log(f"authenticated proxy relay started scheme={parsed.scheme}")

    def _cleanup_proxy_relay(self) -> None:
        if self.proxy_relay is None:
            return
        self.proxy_relay.stop()
        self.proxy_relay = None

    def _build_options(self) -> ChromiumOptions:
        browser_path = resolve_browser_path()
        if not browser_path:
            raise RuntimeError("未找到 Chromium/Chrome 可执行文件")

        options = ChromiumOptions()
        options.set_paths(browser_path=browser_path)
        # Cloudflare/OAI 的边缘 Cookie 可能由页面加载阶段的脚本设置。
        # 使用默认完整加载策略，并由 page_load timeout 控制上限。
        options.set_load_mode("normal")
        options.set_timeouts(page_load=PAGE_LOAD_TIMEOUT_SECONDS)
        if self.user_agent:
            options.set_user_agent(self.user_agent)
        self._configure_proxy(options)

        width = 1920
        height = 1080
        accept_language = DEFAULT_ACCEPT_LANGUAGE
        arguments = [
            f"--accept-lang={accept_language}",
            "--lang=zh-CN",
            "--disable-background-mode",
            "--disable-dev-shm-usage",
            "--disable-features=FlashDeprecationWarning,EnablePasswordsAccountStorage,PrivacySandboxSettings4",
            "--disable-gpu",
            "--disable-infobars",
            "--disable-popup-blocking",
            "--disable-suggestions-ui",
            "--disable-extensions",
            "--force-color-profile=srgb",
            "--hide-crash-restore-bubble",
            "--metrics-recording-only",
            "--no-default-browser-check",
            "--no-first-run",
            "--password-store=basic",
            "--use-mock-keychain",
            f"--window-size={width},{height}",
        ]
        for argument in arguments:
            options.set_argument(argument)

        if DEFAULT_HEADLESS:
            options.headless(True)
        else:
            options.headless(False)
            options.set_argument("--start-maximized")

        if os.name != "nt":
            options.set_argument("--no-sandbox")
            options.set_argument("--disable-setuid-sandbox")

        return options

    def _ensure_driver(self) -> ChromiumPage:
        if self.driver is None:
            try:
                self.driver = ChromiumPage(addr_or_opts=self._build_options())
            except Exception:
                self._cleanup_proxy_relay()
                raise
        return self.driver

    def _close_driver(self) -> None:
        if self.driver is not None:
            try:
                self.driver.quit()
            except Exception as error:
                log(f"quit browser failed: {error}")
            finally:
                self.driver = None
        self._cleanup_proxy_relay()

    def _read_cookies(self) -> list[dict[str, str]]:
        driver = self._ensure_driver()
        raw_cookies = driver.cookies()
        if not isinstance(raw_cookies, list):
            self.last_raw_cookie_names = ()
            return []
        self.last_raw_cookie_names = tuple(
            sorted(
                {
                    str(cookie.get("name", "")).strip()
                    for cookie in raw_cookies
                    if str(cookie.get("name", "")).strip()
                }
            )
        )
        return normalize_cookies(raw_cookies)

    def _page_state(self) -> str:
        driver = self._ensure_driver()
        try:
            title = str(driver.title or "").lower()
            html = str(driver.html or "").lower()[:200_000]
        except Exception:
            return "unavailable"
        content = f"{title}\n{html}"
        if "just a moment" in content or "cf-chl-" in content:
            return "cloudflare_challenge"
        if "access denied" in content or "error 403" in content:
            return "access_denied"
        if "err_proxy_connection_failed" in content or "err_tunnel_connection_failed" in content:
            return "proxy_error"
        if "err_name_not_resolved" in content or "err_internet_disconnected" in content:
            return "network_error"
        if "chatgpt" in title:
            return "chatgpt"
        return "other"

    def _maybe_click_verification(self) -> bool:
        driver = self._ensure_driver()
        for selector in CLICK_SELECTORS:
            try:
                if not driver.wait.ele_displayed(
                    selector,
                    timeout=ELEMENT_LOOKUP_TIMEOUT_SECONDS,
                ):
                    continue
                element = driver.ele(
                    selector,
                    timeout=ELEMENT_LOOKUP_TIMEOUT_SECONDS,
                )
                if element is None:
                    continue
                element.click()
                log(f"clicked verification selector: {selector}")
                return True
            except Exception:
                continue
        return False

    async def get_cf_cookie(self, url: str) -> dict[str, Any]:
        last_cookies: list[dict[str, str]] = []
        last_error: Exception | None = None

        for attempt in range(1, NAVIGATION_RETRIES + 1):
            partial_cookie_signature: tuple[tuple[str, str, str], ...] | None = None
            partial_cookie_stable_polls = 0
            first_cookie_logged = False
            first_cookie_wait_logged = False
            attempt_started_at = time.monotonic()
            try:
                driver_started_at = time.monotonic()
                driver = self._ensure_driver()
                log(
                    f"driver initialized attempt={attempt} "
                    f"phase_elapsed={time.monotonic() - driver_started_at:.2f}s "
                    f"total_elapsed={time.monotonic() - attempt_started_at:.2f}s"
                )
                try:
                    driver.set.cookies.clear()
                except Exception:
                    pass

                log(f"navigate attempt={attempt} target={target_origin_for_log(url)}")
                navigation_started_at = time.monotonic()
                # DrissionPage 的 get() 默认会自行重试多次，timeout 并不是整个
                # 调用的总壁钟上限。cfbypass 外层已经负责重试，这里必须关闭
                # 内层重试，避免一次网络故障被放大到 60 秒以上。
                driver.get(url, retry=0, timeout=PAGE_LOAD_TIMEOUT_SECONDS)
                log(
                    f"navigation completed attempt={attempt} "
                    f"phase_elapsed={time.monotonic() - navigation_started_at:.2f}s "
                    f"total_elapsed={time.monotonic() - attempt_started_at:.2f}s "
                    f"page_state={self._page_state()}"
                )
                try:
                    await validate_target_url(str(driver.url))
                except HTTPException as error:
                    raise RuntimeError(
                        "浏览器未到达允许的 HTTPS 目标，"
                        f"current={target_origin_for_log(str(driver.url))}; "
                        f"reason={error.detail}"
                    ) from error

                polling_started_at = time.monotonic()
                deadline = polling_started_at + MAX_WAIT_SECONDS
                first_cookie_warning_at = min(
                    deadline,
                    polling_started_at + FIRST_COOKIE_WAIT_SECONDS,
                )
                while time.monotonic() < deadline:
                    cookies = self._read_cookies()
                    if cookies:
                        last_cookies = cookies
                        if not first_cookie_logged:
                            first_cookie_logged = True
                            cookie_names = ",".join(
                                sorted(cookie["name"] for cookie in cookies)
                            )
                            log(
                                f"first cookies observed attempt={attempt} "
                                f"elapsed={time.monotonic() - attempt_started_at:.2f}s "
                                f"names={cookie_names}"
                            )
                        if any(
                            cookie["name"] == "cf_clearance"
                            for cookie in cookies
                        ):
                            log(
                                f"verification completed attempt={attempt} "
                                f"elapsed={time.monotonic() - attempt_started_at:.2f}s"
                            )
                            return {"user_agent": self.user_agent, "cookies": cookies}
                        cloudflare_cookies = [
                            cookie
                            for cookie in cookies
                            if cookie["name"] in CLOUDFLARE_COOKIE_NAMES
                        ]
                        if cloudflare_cookies:
                            signature = tuple(
                                sorted(
                                    (
                                        cookie["name"],
                                        cookie["value"],
                                        cookie.get("domain", ""),
                                    )
                                    for cookie in cloudflare_cookies
                                )
                            )
                            if signature == partial_cookie_signature:
                                partial_cookie_stable_polls += 1
                            else:
                                partial_cookie_signature = signature
                                partial_cookie_stable_polls = 1
                            if partial_cookie_stable_polls >= COOKIE_STABLE_POLLS:
                                log(
                                    f"partial cookies accepted attempt={attempt} "
                                    f"elapsed={time.monotonic() - attempt_started_at:.2f}s "
                                    f"stable_polls={partial_cookie_stable_polls}"
                                )
                                return {
                                    "user_agent": self.user_agent,
                                    "cookies": cookies,
                                }
                        else:
                            partial_cookie_signature = None
                            partial_cookie_stable_polls = 0

                    if (
                        not first_cookie_logged
                        and not first_cookie_wait_logged
                        and time.monotonic() >= first_cookie_warning_at
                    ):
                        first_cookie_wait_logged = True
                        log(
                            f"no cookies yet attempt={attempt} "
                            f"elapsed={time.monotonic() - attempt_started_at:.2f}s; "
                            "continue waiting"
                        )

                    self._maybe_click_verification()
                    await asyncio.sleep(POLL_INTERVAL_SECONDS)

                if not first_cookie_logged:
                    raw_cookie_names = ",".join(self.last_raw_cookie_names) or "none"
                    log(
                        f"no cookies observed attempt={attempt} "
                        f"elapsed={time.monotonic() - attempt_started_at:.2f}s "
                        f"page_state={self._page_state()} "
                        f"raw_cookie_names={raw_cookie_names}"
                    )
            except HTTPException:
                raise
            except Exception as error:
                last_error = error
                log(f"attempt={attempt} failed: {error}")
                log(traceback.format_exc())
            finally:
                self._close_driver()

        if last_cookies:
            log(
                "returning partial cookies after timeout: "
                + ",".join(cookie["name"] for cookie in last_cookies)
            )
            return {"user_agent": self.user_agent, "cookies": last_cookies}

        if last_error is not None:
            log(f"all attempts failed: {last_error}")
        return {"user_agent": self.user_agent, "cookies": []}


@app.get("/")
async def index() -> dict[str, Any]:
    return {"message": "ok"}


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"status": "ok", "headless": DEFAULT_HEADLESS}


async def solve(query_params: CloudFlare5sQuerySchema) -> dict[str, Any]:
    await validate_target_url(str(query_params.url))
    async with _BYPASS_LOCK:
        bypass = Cloudflare5sBypass(
            user_agent=query_params.user_agent,
            proxy_server=query_params.proxy_server,
        )
        target_url = str(query_params.url)
        result = await asyncio.to_thread(
            lambda: asyncio.run(bypass.get_cf_cookie(target_url))
        )
        if not result.get("cookies"):
            raise HTTPException(status_code=502, detail="未获取到有效的 Cloudflare Cookie")
        return result


@app.post("/cloudflare5s/bypass-v1", dependencies=[Depends(require_cfbypass_auth)])
async def bypass_v1(query_params: CloudFlare5sQuerySchema) -> dict[str, Any]:
    return await solve(query_params)


@app.post("/cloudflare5s/bypass-v2", dependencies=[Depends(require_cfbypass_auth)])
async def bypass_v2(query_params: CloudFlare5sQuerySchema) -> dict[str, Any]:
    return await solve(query_params)

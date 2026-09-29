"""cfbypass 兼容服务（FastAPI + Playwright）。

用途：按网关请求打开白名单内的目标页面，等待页面 Cookie（例如 cf_clearance）
连续多个轮询保持稳定后，返回 Cookie 与会话 User-Agent，供网关使用同一浏览器
指纹继续访问上游。

边界与约定：
- 导航目标必须命中 CF_BYPASS_ALLOWED_HOSTS 白名单，服务不会被当作任意代理使用；
- 导航接口需要 Authorization: Bearer <CF_BYPASS_SECRET>，与仓库既有服务间
  认证约定一致；
- 浏览器固定为镜像内的系统 chromium（CF_BYPASS_BROWSER_PATH，默认 /usr/bin/chromium），
  不用 Playwright 自带浏览器；响应新增 identity 字段，取自实际浏览器会话，
  供网关比对 Chrome146/Linux 声称值（见 README「身份一致性」）；
- 本实现不包含任何真实 ChatGPT 凭据；仓库内验证只使用 127.0.0.1 本地目标，
  不对生产 Cloudflare 做验证；
- 与根目录 docker-compose.yml 中的 cfbypass 服务对齐：容器内监听 8000，
  通过 uvicorn app:app --host 0.0.0.0 --port 8000 启动，
  宿主机诊断口映射为 127.0.0.1:18001。
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from hmac import compare_digest
from urllib.parse import unquote, urlparse

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright
from pydantic import BaseModel, Field, ValidationError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
LOGGER = logging.getLogger("cfbypass")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

# 系统 chromium：容器内由 Dockerfile 从 snapshot.debian.org 固定版本安装，
# 本地开发用 CF_BYPASS_BROWSER_PATH 指向本机 Chrome/Chromium 可执行文件。
DEFAULT_BROWSER_PATH = "/usr/bin/chromium"

# 回环页：只用来在浏览器内读一次原生 UA-CH 元数据，不产生真实网络请求（由 page.route
# 本地应答）。必须是 https 才会被当成安全上下文——只有安全上下文里才有 navigator.userAgentData。
NATIVE_HINTS_URL = "https://native-hints.invalid/identity"
NATIVE_HINTS_PAGE = "<!doctype html><meta charset=utf-8><title>native hints</title>"

# 在真实页面上下文里采集该跳的身份。逐字段 try/catch，取不到就是 null；
# 不用环境变量补值，网关要据此发现 UA/UA-CH/版本错配。
IDENTITY_PROBE_SCRIPT = """
async () => {
  const read = (getter) => {
    try {
      const value = getter();
      return value === undefined ? null : value;
    } catch (error) {
      return null;
    }
  };
  const brands = (list) => {
    if (!Array.isArray(list)) {
      return null;
    }
    return list.map((entry) => ({brand: String(entry.brand), version: String(entry.version)}));
  };
  const data = navigator.userAgentData || null;
  let entropy = null;
  if (data && typeof data.getHighEntropyValues === "function") {
    try {
      entropy = await data.getHighEntropyValues([
        "architecture",
        "bitness",
        "fullVersion",
        "fullVersionList",
        "platformVersion",
      ]);
    } catch (error) {
      entropy = null;
    }
  }
  const high = entropy || {};
  return {
    user_agent: read(() => navigator.userAgent || null),
    language: read(() => navigator.language || null),
    languages: read(() => (Array.isArray(navigator.languages) ? Array.from(navigator.languages) : null)),
    timezone: read(() => Intl.DateTimeFormat().resolvedOptions().timeZone || null),
    user_agent_data: data === null ? null : {
      brands: read(() => brands(data.brands)),
      platform: read(() => data.platform || null),
      mobile: read(() => (typeof data.mobile === "boolean" ? data.mobile : null)),
      architecture: high.architecture ?? null,
      bitness: high.bitness ?? null,
      full_version: high.fullVersion ?? null,
      full_version_list: brands(high.fullVersionList ?? null),
      platform_version: high.platformVersion ?? null,
    },
  };
}
"""

# 单进程内同时运行的浏览器实例上限，避免并发请求耗尽容器内存与 /dev/shm。
BROWSER_SLOTS = asyncio.Semaphore(2)

# 读浏览器**原生**的 UA-CH 元数据（必须在任何 UA 覆盖之前执行）。
NATIVE_CLIENT_HINTS_SCRIPT = """
async () => {
  const data = navigator.userAgentData;
  if (!data || typeof data.getHighEntropyValues !== "function") {
    return null;
  }
  const brands = (list) => (Array.isArray(list)
    ? list.map((entry) => ({brand: String(entry.brand), version: String(entry.version)}))
    : []);
  const high = await data.getHighEntropyValues([
    "architecture",
    "bitness",
    "fullVersionList",
    "model",
    "platformVersion",
  ]);
  return {
    brands: brands(data.brands),
    fullVersionList: brands(high.fullVersionList),
    platform: String(data.platform || ""),
    platformVersion: String(high.platformVersion || ""),
    architecture: String(high.architecture || ""),
    model: String(high.model || ""),
    mobile: data.mobile === true,
    bitness: String(high.bitness || ""),
  };
}
"""

# 挑战页探测选择器，仅用于日志诊断。
CHALLENGE_SELECTORS = "#challenge-form, .cf-challenge, iframe[src*='challenges.cloudflare.com']"


def _env_text(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} 需要布尔值（true/false），当前为 {raw!r}")


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        raise ValueError(f"{name} 需要数字，当前为 {raw!r}") from None


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        raise ValueError(f"{name} 需要整数，当前为 {raw!r}") from None


def _env_display_size() -> tuple[int, int]:
    raw = _env_text("CF_BYPASS_DISPLAY_SIZE", "1920x1080")
    width, _, height = raw.partition("x")
    try:
        return int(width), int(height)
    except ValueError:
        raise ValueError(f"CF_BYPASS_DISPLAY_SIZE 需要 宽x高 格式，当前为 {raw!r}") from None


def _env_allowed_hosts() -> tuple[str, ...]:
    raw = _env_text("CF_BYPASS_ALLOWED_HOSTS", "127.0.0.1,localhost")
    return tuple(part.strip().lower() for part in raw.split(",") if part.strip())


def _parse_proxy(raw: str) -> dict | None:
    """把代理地址解析成 Playwright launch(proxy=...) 参数。

    支持 http://、https://、socks5://、socks5h://（映射为 socks5），
    用户名与密码需 URL 编码，与 .env.example 的说明保持一致。
    """
    raw = raw.strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if not parsed.hostname or scheme not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(f"无法解析代理地址 {raw!r}（支持 http/https/socks5/socks5h）")
    server = f"{'socks5' if scheme == 'socks5h' else scheme}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"
    proxy = {"server": server}
    if parsed.username:
        proxy["username"] = unquote(parsed.username)
    if parsed.password:
        proxy["password"] = unquote(parsed.password)
    return proxy


@dataclass(frozen=True)
class Settings:
    secret: str
    allowed_hosts: tuple[str, ...]
    user_agent: str
    browser_path: str
    accept_language: str
    headless: bool
    max_wait_seconds: float
    page_load_timeout_seconds: float
    first_cookie_wait_seconds: float
    poll_interval_seconds: float
    cookie_stable_polls: int
    navigation_retries: int
    element_lookup_timeout_seconds: float
    viewport_width: int
    viewport_height: int
    proxy_server: str


def _load_settings() -> Settings:
    viewport_width, viewport_height = _env_display_size()
    proxy_server = _env_text("CF_BYPASS_PROXY_SERVER", "")
    _parse_proxy(proxy_server)  # 启动时校验一次，配置错误立即暴露
    return Settings(
        secret=os.getenv("CF_BYPASS_SECRET", "").strip(),
        allowed_hosts=_env_allowed_hosts(),
        user_agent=_env_text("CF_BYPASS_USER_AGENT", DEFAULT_USER_AGENT),
        browser_path=_env_text("CF_BYPASS_BROWSER_PATH", DEFAULT_BROWSER_PATH),
        # 这一跳是网关**自己去连** chatgpt.com 取 Cookie，没有对应的页面 JS，因此
        # 与网关身份表的 ACCEPT_LANGUAGE（server/identity.rs）逐字一致即可；转发跳的
        # accept-language 跟随访客浏览器，那属于另一类（浏览器指纹随宿主）。
        # 请求体里带了 accept_language 时以请求为准，这里只是独立调试的兜底。
        accept_language=_env_text("CF_BYPASS_ACCEPT_LANGUAGE", "zh-CN,zh;q=0.9,en;q=0.8"),
        headless=_env_bool("CF_BYPASS_HEADLESS", True),
        max_wait_seconds=_env_float("CF_BYPASS_MAX_WAIT_SECONDS", 20.0),
        page_load_timeout_seconds=_env_float("CF_BYPASS_PAGE_LOAD_TIMEOUT_SECONDS", 15.0),
        first_cookie_wait_seconds=_env_float("CF_BYPASS_FIRST_COOKIE_WAIT_SECONDS", 6.0),
        poll_interval_seconds=_env_float("CF_BYPASS_POLL_INTERVAL_SECONDS", 0.5),
        cookie_stable_polls=_env_int("CF_BYPASS_COOKIE_STABLE_POLLS", 2),
        navigation_retries=_env_int("CF_BYPASS_NAVIGATION_RETRIES", 1),
        element_lookup_timeout_seconds=_env_float("CF_BYPASS_ELEMENT_LOOKUP_TIMEOUT_SECONDS", 0.2),
        viewport_width=viewport_width,
        viewport_height=viewport_height,
        proxy_server=proxy_server,
    )


SETTINGS = _load_settings()

if not SETTINGS.secret:
    LOGGER.warning("CF_BYPASS_SECRET 未配置，/bypass 将拒绝所有请求")
if not SETTINGS.allowed_hosts:
    LOGGER.warning("CF_BYPASS_ALLOWED_HOSTS 为空，/bypass 将拒绝所有目标")
if not os.path.exists(SETTINGS.browser_path):
    LOGGER.warning("CF_BYPASS_BROWSER_PATH 指向的可执行文件不存在: %s，浏览器启动会失败", SETTINGS.browser_path)
LOGGER.info(
    "cfbypass 配置: allowed_hosts=%s browser=%s headless=%s max_wait=%.1fs page_load_timeout=%.1fs stable_polls=%d retries=%d proxy=%s",
    SETTINGS.allowed_hosts,
    SETTINGS.browser_path,
    SETTINGS.headless,
    SETTINGS.max_wait_seconds,
    SETTINGS.page_load_timeout_seconds,
    SETTINGS.cookie_stable_polls,
    SETTINGS.navigation_retries,
    "已配置" if SETTINGS.proxy_server else "未配置",
)


class BrandVersion(BaseModel):
    brand: str
    version: str


class BypassRequest(BaseModel):
    url: str = Field(description="目标页面地址，主机必须在 CF_BYPASS_ALLOWED_HOSTS 内")
    proxy_server: str = Field(default="", description="可选，覆盖本次请求的代理")
    # 身份的唯一事实来源是网关的身份表（gateway server/identity.rs）。这一跳必须
    # 采用它下发的取值，否则上游会在两跳上看到两个浏览器：镜像内的 chromium 是
    # **无品牌** Chrome-for-Testing 构建，原生只报 2 个品牌且 UA 不含 "Google Chrome"，
    # 而网关声称的是带品牌的 Chrome/146（3 个品牌）。缺省为空表示沿用本服务的
    # 环境变量默认值，仅供独立调试。
    user_agent: str = Field(default="", description="可选，覆盖该跳 UA；由网关身份表下发")
    accept_language: str = Field(default="", description="可选，覆盖该跳 accept-language")
    brands: list[BrandVersion] | None = Field(default=None, description="可选，低熵品牌表")
    full_version_list: list[BrandVersion] | None = Field(default=None, description="可选，完整版本品牌表")


@dataclass(frozen=True)
class RequestIdentity:
    """该次请求实际使用的声称身份：请求体优先，缺省回落到 SETTINGS。"""

    user_agent: str
    accept_language: str
    brands: list[dict] | None
    full_version_list: list[dict] | None

    @classmethod
    def resolve(cls, payload: "BypassRequest") -> "RequestIdentity":
        def listed(items: list[BrandVersion] | None) -> list[dict] | None:
            return [item.model_dump() for item in items] if items else None

        return cls(
            user_agent=payload.user_agent.strip() or SETTINGS.user_agent,
            accept_language=payload.accept_language.strip() or SETTINGS.accept_language,
            brands=listed(payload.brands),
            full_version_list=listed(payload.full_version_list),
        )


class CookieInfo(BaseModel):
    name: str
    value: str
    domain: str
    path: str
    expires: float
    http_only: bool
    secure: bool
    same_site: str


class UserAgentBrand(BaseModel):
    """User-Agent Client Hints 的品牌条，字段名沿用规范 camelCase 的 snake_case 写法。"""

    brand: str
    version: str


class UserAgentDataInfo(BaseModel):
    """`navigator.userAgentData` 低熵字段 + `getHighEntropyValues` 可选结果，取不到为 null。"""

    brands: list[UserAgentBrand] | None = None
    platform: str | None = None
    mobile: bool | None = None
    architecture: str | None = None
    bitness: str | None = None
    full_version: str | None = None
    full_version_list: list[UserAgentBrand] | None = None
    platform_version: str | None = None


class IdentityInfo(BaseModel):
    """该跳浏览器会话的实测身份，供网关与自己的 Chrome146 常量逐字段比对。

    全部字段都取自实际浏览器（`navigator`/`Intl`/`Browser.getVersion`）与本次启动参数，
    探测失败时对应字段为 null，不用环境变量补值。
    """

    user_agent: str | None = None
    browser_version: str | None = None
    language: str | None = None
    languages: list[str] | None = None
    timezone: str | None = None
    proxied: bool
    proxy_server: str | None = None
    user_agent_data: UserAgentDataInfo | None = None


class BypassResponse(BaseModel):
    ok: bool = True
    url: str
    user_agent: str
    identity: IdentityInfo
    cookies: list[CookieInfo]
    elapsed_seconds: float


class CookieWaitTimeout(RuntimeError):
    def __init__(self, cookie_count: int, waited_seconds: float) -> None:
        super().__init__(f"等待 Cookie 稳定超时（已获得 {cookie_count} 个，等待 {waited_seconds:.1f}s）")
        self.cookie_count = cookie_count
        self.waited_seconds = waited_seconds


class RedirectNotAllowed(RuntimeError):
    def __init__(self, final_url: str) -> None:
        super().__init__(f"导航最终地址主机不在白名单内: {final_url}")
        self.final_url = final_url


def _to_cookie_info(cookie: dict) -> CookieInfo:
    return CookieInfo(
        name=cookie["name"],
        value=cookie["value"],
        domain=cookie["domain"],
        path=cookie["path"],
        expires=float(cookie.get("expires", -1.0)),
        http_only=bool(cookie.get("httpOnly")),
        secure=bool(cookie.get("secure")),
        same_site=str(cookie.get("sameSite", "")),
    )


def _host_allowed(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    for pattern in SETTINGS.allowed_hosts:
        if pattern.startswith("."):
            if host == pattern[1:] or host.endswith(pattern):
                return True
        elif host == pattern:
            return True
    return False


def _validated_target(raw_url: str) -> str:
    target = raw_url.strip()
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_url", "message": "仅支持带主机的 http/https 地址"},
        )
    if not _host_allowed(parsed.hostname):
        raise HTTPException(
            status_code=400,
            detail={"code": "host_not_allowed", "message": f"主机 {parsed.hostname!r} 不在白名单内"},
        )
    return target


def require_secret(authorization: str = Header(default="")) -> None:
    if not SETTINGS.secret:
        raise HTTPException(
            status_code=503,
            detail={"code": "server_misconfigured", "message": "服务未配置 CF_BYPASS_SECRET"},
        )
    expected = f"Bearer {SETTINGS.secret}"
    if not compare_digest(authorization.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(
            status_code=401,
            detail={"code": "unauthorized", "message": "缺少或错误的 Bearer 密钥"},
        )


async def _challenge_present(page) -> bool:
    try:
        await page.wait_for_selector(
            CHALLENGE_SELECTORS,
            state="attached",
            timeout=SETTINGS.element_lookup_timeout_seconds * 1000,
        )
        return True
    except PlaywrightTimeoutError:
        return False


async def _wait_for_stable_cookies(page, context) -> list[CookieInfo]:
    """等待目标站点的 Cookie 连续稳定。

    与 .env.example 的约定一致：CF_BYPASS_FIRST_COOKIE_WAIT_SECONDS 只用于首次
    仍无 Cookie 时输出日志提示，不会提前结束；总截止时间为
    CF_BYPASS_MAX_WAIT_SECONDS。截止时仍未稳定则抛出 CookieWaitTimeout。
    """
    started = time.monotonic()
    deadline = started + SETTINGS.max_wait_seconds
    previous_snapshot: tuple = ()
    stable_polls = 0
    hint_logged = False
    cookie_count = 0
    while True:
        cookies = await context.cookies()
        snapshot = tuple(
            sorted((cookie["name"], cookie["domain"], cookie["path"], cookie["value"]) for cookie in cookies)
        )
        cookie_count = len(cookies)
        if snapshot and snapshot == previous_snapshot:
            stable_polls += 1
        else:
            stable_polls = 0
        previous_snapshot = snapshot
        if snapshot and stable_polls >= SETTINGS.cookie_stable_polls:
            LOGGER.info("Cookie 已稳定: %d 个，用时 %.2fs", cookie_count, time.monotonic() - started)
            return [_to_cookie_info(cookie) for cookie in cookies]
        elapsed = time.monotonic() - started
        if not hint_logged and not snapshot and elapsed >= SETTINGS.first_cookie_wait_seconds:
            hint_logged = True
            LOGGER.info(
                "已等待 %.1fs 仍无 Cookie，继续等待至 %.0fs（挑战页仍在: %s）",
                elapsed,
                SETTINGS.max_wait_seconds,
                await _challenge_present(page),
            )
        if time.monotonic() >= deadline:
            raise CookieWaitTimeout(cookie_count, time.monotonic() - started)
        await asyncio.sleep(SETTINGS.poll_interval_seconds)


async def _goto_with_retries(page, target: str) -> None:
    attempts = SETTINGS.navigation_retries + 1
    for attempt in range(1, attempts + 1):
        try:
            await page.goto(
                target,
                timeout=SETTINGS.page_load_timeout_seconds * 1000,
                wait_until="domcontentloaded",
            )
            return
        except PlaywrightError as error:
            if attempt >= attempts:
                raise
            LOGGER.warning("导航失败（第 %d/%d 次），准备重试: %s（%s）", attempt, attempts, target, error)


async def _serve_native_hints(route) -> None:
    """回环页的本地应答：不经过网络，只提供一个安全上下文让页面能读 navigator.userAgentData。"""
    await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=NATIVE_HINTS_PAGE)


async def _apply_upstream_identity(context, page, identity: RequestIdentity) -> None:
    """把该跳的身份对齐成「网关下发的 UA 字符串 + 浏览器原生 UA-CH 元数据」。

    不能用 `browser.new_context(user_agent=...)`：Playwright 会连 UA-CH 元数据一起替换成它
    自己派生的值——实测 Linux 上 `architecture` 变成 `x64`、`fullVersionList` 也不再来自浏览器，
    与网关声称的 `x86`/146 不一致（真实 Chromium 在 POSIX 上由 `GetCpuArchitecture()`
    对 `x86_64` 固定返回 `x86`）。另外两种更差的形态也实测过：只发 `userAgent` 的 CDP 覆盖、
    以及启动参数 `--user-agent=`，都会把 UA-CH 全部清空。

    因此顺序是：先在回环页读原生元数据，再用 CDP 把「网关下发的 UA + 原生元数据」一起装上，
    让该跳在线上看到的每一跳都与网关常量逐字段相同。

    **品牌表例外**：架构/位宽/平台这些机器事实必须保持原生，但品牌表不是机器事实，
    而是构建的品牌属性。镜像内的 chromium 是无品牌构建，原生只报 `Chromium` +
    `Not-A.Brand` 两项；网关声称的 UA 是带品牌的 `Chrome/146`，对应 3 项品牌。
    两者同时出现，上游一眼就能看出这两跳不是同一个浏览器。因此网关下发品牌表时
    以网关为准——UA 说什么品牌，UA-CH 就必须报什么品牌。
    """
    await page.route(f"{NATIVE_HINTS_URL}**", _serve_native_hints)
    await page.goto(NATIVE_HINTS_URL, wait_until="domcontentloaded")
    metadata = await page.evaluate(NATIVE_CLIENT_HINTS_SCRIPT)
    await page.unroute(f"{NATIVE_HINTS_URL}**")
    if not isinstance(metadata, dict) or not metadata.get("brands"):
        # `userAgentData` 只存在于安全上下文；读不到说明这套 chromium 的行为变了。
        # 此时宁可让取 Cookie 失败并报错，也不发一条 UA 与 UA-CH 互相矛盾的请求。
        raise PlaywrightError(f"浏览器原生 UA-CH 元数据不可用: {metadata!r}")
    if identity.brands:
        metadata["brands"] = identity.brands
    if identity.full_version_list:
        metadata["fullVersionList"] = identity.full_version_list
    session = await context.new_cdp_session(page)
    await session.send(
        "Emulation.setUserAgentOverride",
        {
            "userAgent": identity.user_agent,
            "acceptLanguage": identity.accept_language,
            "platform": metadata["platform"],
            "userAgentMetadata": metadata,
        },
    )
    LOGGER.info(
        "身份已对齐: brands=%s arch=%s bitness=%s platform=%s platform_version=%r full_version_list=%s",
        metadata["brands"],
        metadata["architecture"],
        metadata["bitness"],
        metadata["platform"],
        metadata["platformVersion"],
        metadata["fullVersionList"],
    )


async def _probe_identity(browser, page, proxy: dict | None) -> IdentityInfo:
    """从实际浏览器会话采集身份（UA、UA-CH、语言、时区、浏览器版本）。

    探测失败时对应字段为 null 并记日志，不用环境变量补值：网关只有看到真实结果，
    才能发现「CF_BYPASS_USER_AGENT 与浏览器实际 UA 不一致」这类错配。
    """
    probed: dict = {}
    try:
        probed = await page.evaluate(IDENTITY_PROBE_SCRIPT)
    except PlaywrightError as error:
        LOGGER.error("身份探测失败（浏览器会话）: %s", error)
    raw = probed
    proxy_server = (proxy or {}).get("server")
    fields = {
        "user_agent": raw.get("user_agent"),
        # playwright-python 里 `Browser.version` 是属性，不是方法：写成
        # `browser.version()` 会让整个取 Cookie 接口 500（实测踩到）。
        "browser_version": browser.version,
        "language": raw.get("language"),
        "languages": raw.get("languages"),
        "timezone": raw.get("timezone"),
        "user_agent_data": raw.get("user_agent_data"),
        "proxied": proxy_server is not None,
        "proxy_server": proxy_server,
    }
    missing = sorted(name for name, value in fields.items() if value is None)
    if missing:
        LOGGER.warning("身份探测缺失字段（按 null 返回，网关据此刻画错配）: %s", ", ".join(missing))
    try:
        identity = IdentityInfo(**fields)
    except ValidationError as error:
        # 目标页面可以改写 navigator.*，形状异常时按未知处理，不能让整次取 Cookie 失败。
        LOGGER.error("身份探测结果结构异常，按缺失字段返回: %s", error)
        return IdentityInfo(proxied=proxy_server is not None, proxy_server=proxy_server)
    LOGGER.info(
        "身份探测: chromium=%s ua_data_full_version=%s platform=%s languages=%s timezone=%s proxied=%s",
        identity.browser_version,
        identity.user_agent_data.full_version if identity.user_agent_data else None,
        identity.user_agent_data.platform if identity.user_agent_data else None,
        identity.languages,
        identity.timezone,
        identity.proxied,
    )
    return identity


async def _navigate(
    target: str, proxy: dict | None, identity_override: RequestIdentity
) -> tuple[list[CookieInfo], str, IdentityInfo]:
    async with async_playwright() as playwright:
        # executable_path 指向系统 chromium（镜像内由 Dockerfile 固定版本安装）：
        # Playwright 自带的浏览器不参与这一跳的身份。chromium_sandbox=False 与
        # Playwright 默认值一致（容器内以 root 运行，无法用 user namespace 沙箱），
        # 见 https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch
        browser = await playwright.chromium.launch(
            executable_path=SETTINGS.browser_path,
            headless=SETTINGS.headless,
            chromium_sandbox=False,
            proxy=proxy,
        )
        try:
            context = await browser.new_context(
                # `locale` 只吃语言标签，不吃 q 值：`zh-CN,zh;q=0.9,…` 的首段即是。
                locale=identity_override.accept_language.split(",")[0],
                viewport={"width": SETTINGS.viewport_width, "height": SETTINGS.viewport_height},
                extra_http_headers={"Accept-Language": identity_override.accept_language},
            )
            page = await context.new_page()
            await _apply_upstream_identity(context, page, identity_override)
            await _goto_with_retries(page, target)
            final_url = page.url
            if not _host_allowed(urlparse(final_url).hostname or ""):
                raise RedirectNotAllowed(final_url)
            identity = await _probe_identity(browser, page, proxy)
            cookies = await _wait_for_stable_cookies(page, context)
            return cookies, final_url, identity
        finally:
            await browser.close()


app = FastAPI(
    title="cfbypass",
    version="0.1.0",
    description="ChatGPT Mirror 的 Cloudflare 放行服务（Playwright）",
)


@app.exception_handler(RequestValidationError)
async def on_request_validation_error(_request, _error: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"detail": {"code": "invalid_request", "message": "请求体不是合法的 JSON 或缺少必需字段"}},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "cfbypass"}


# 网关按原版 all-in-one 契约调用 /cloudflare5s/bypass-v1（/v2 与之等价，见报告 02）；
# /bypass 保留给本地诊断。三条路径共用同一实现，身份探测在所有路径上都生效。
@app.post("/bypass", response_model=BypassResponse, operation_id="bypass")
@app.post("/cloudflare5s/bypass-v1", response_model=BypassResponse, operation_id="bypass_v1")
@app.post("/cloudflare5s/bypass-v2", response_model=BypassResponse, operation_id="bypass_v2")
async def bypass(payload: BypassRequest, _: None = Depends(require_secret)) -> BypassResponse:
    target = _validated_target(payload.url)
    try:
        proxy = _parse_proxy(payload.proxy_server.strip() or SETTINGS.proxy_server)
    except ValueError as error:
        raise HTTPException(
            status_code=400, detail={"code": "invalid_proxy", "message": str(error)}
        ) from error
    identity_override = RequestIdentity.resolve(payload)

    started = time.monotonic()
    async with BROWSER_SLOTS:
        try:
            cookies, final_url, identity = await _navigate(target, proxy, identity_override)
        except RedirectNotAllowed as error:
            raise HTTPException(
                status_code=403,
                detail={"code": "redirect_host_not_allowed", "message": str(error)},
            ) from error
        except CookieWaitTimeout as error:
            raise HTTPException(
                status_code=504,
                detail={
                    "code": "cookie_wait_timeout",
                    "message": str(error),
                    "url": target,
                    "cookie_count": error.cookie_count,
                },
            ) from error
        except PlaywrightTimeoutError as error:
            raise HTTPException(
                status_code=504,
                detail={"code": "page_load_timeout", "message": f"页面加载超时: {target}"},
            ) from error
        except PlaywrightError as error:
            raise HTTPException(
                status_code=502,
                detail={
                    "code": "navigation_failed",
                    "message": f"页面加载失败: {target}",
                    "detail": str(error),
                },
            ) from error

    elapsed = round(time.monotonic() - started, 3)
    LOGGER.info(
        "导航完成: %s -> %s（%d 个 Cookie，%.2fs，chromium=%s）",
        target,
        final_url,
        len(cookies),
        elapsed,
        identity.browser_version,
    )
    return BypassResponse(
        url=final_url,
        # 回这一跳**实际使用**的 UA，不是环境变量默认值：网关拿它做交叉校验，
        # 报一个没用上的值会让校验永远通过。
        user_agent=identity_override.user_agent,
        identity=identity,
        cookies=cookies,
        elapsed_seconds=elapsed,
    )

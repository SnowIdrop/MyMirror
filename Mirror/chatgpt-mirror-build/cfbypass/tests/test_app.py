import asyncio
import os


os.environ.setdefault("CF_BYPASS_SECRET", "test-secret")
os.environ.setdefault("CF_BYPASS_ALLOWED_HOSTS", "127.0.0.1,localhost")

from fastapi.testclient import TestClient

import app as app_module


client = TestClient(app_module.app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_bypass_requires_secret():
    response = client.post("/bypass", json={"url": "http://127.0.0.1/"})
    assert response.status_code == 401


def test_bypass_rejects_host_outside_allowlist():
    response = client.post(
        "/bypass",
        json={"url": "https://example.invalid/"},
        headers={"Authorization": "Bearer test-secret"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "host_not_allowed"


class _StubBrowser:
    """playwright-python 的 `Browser.version` 是属性。

    桩对象只提供属性、不提供同名方法，因此把 `browser.version` 写成 `browser.version()`
    会被这条用例拦下——该错误只在真实容器里取 Cookie 时才暴露（接口直接 500）。
    """

    version = "146.0.7680.177"


class _StubPage:
    async def evaluate(self, script):
        return {
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/146.0.0.0 Safari/537.36",
            "language": "zh-CN",
            "languages": ["zh-CN", "zh"],
            "timezone": "Asia/Shanghai",
            "user_agent_data": {
                "brands": [{"brand": "Chromium", "version": "146"}],
                "platform": "Linux",
                "mobile": False,
                "architecture": "x86",
                "bitness": "64",
                "full_version": "146.0.7680.177",
                "full_version_list": [{"brand": "Chromium", "version": "146.0.7680.177"}],
                "platform_version": "",
            },
        }


def test_probe_identity_reports_browser_version():
    identity = asyncio.run(app_module._probe_identity(_StubBrowser(), _StubPage(), None))
    assert identity.browser_version == "146.0.7680.177"
    assert identity.proxied is False
    assert identity.user_agent_data.platform == "Linux"


class _StubNativePage:
    """回环页的桩：只回镜像里那套**无品牌** chromium 的原生 UA-CH 元数据。"""

    async def route(self, _pattern, _handler):
        pass

    async def unroute(self, _pattern):
        pass

    async def goto(self, _url, wait_until=None):
        pass

    async def evaluate(self, _script):
        return {
            # 无品牌构建只有两项，且没有 "Google Chrome"。
            "brands": [
                {"brand": "Chromium", "version": "146"},
                {"brand": "Not-A.Brand", "version": "24"},
            ],
            "fullVersionList": [{"brand": "Chromium", "version": "146.0.7680.177"}],
            "platform": "Linux",
            "platformVersion": "",
            "architecture": "x86",
            "model": "",
            "mobile": False,
            "bitness": "64",
        }


class _StubSession:
    def __init__(self):
        self.sent = []

    async def send(self, method, params):
        self.sent.append((method, params))


class _StubContext:
    def __init__(self):
        self.session = _StubSession()

    async def new_cdp_session(self, _page):
        return self.session


def test_upstream_identity_takes_brands_from_the_gateway():
    """网关下发的身份必须真的装到该跳上：品牌表按下发值覆盖，机器事实保持原生。

    无品牌构建原生只报两个品牌，而网关声称的 UA 是带品牌的 Chrome/146（三个品牌）。
    不覆盖就等于两跳报了两个浏览器。
    """
    context = _StubContext()
    identity = app_module.RequestIdentity(
        user_agent="gateway-ua/146",
        accept_language="zh-CN,zh;q=0.9,en;q=0.8",
        brands=[
            {"brand": "Chromium", "version": "146"},
            {"brand": "Not-A.Brand", "version": "24"},
            {"brand": "Google Chrome", "version": "146"},
        ],
        full_version_list=[{"brand": "Google Chrome", "version": "146.0.7680.177"}],
    )
    asyncio.run(app_module._apply_upstream_identity(context, _StubNativePage(), identity))

    method, params = context.session.sent[0]
    assert method == "Emulation.setUserAgentOverride"
    assert params["userAgent"] == "gateway-ua/146"
    assert params["acceptLanguage"] == "zh-CN,zh;q=0.9,en;q=0.8"
    metadata = params["userAgentMetadata"]
    assert metadata["brands"] == identity.brands
    assert metadata["fullVersionList"] == identity.full_version_list
    # 机器事实仍取浏览器原生值，不跟着网关走。
    assert metadata["architecture"] == "x86"
    assert metadata["bitness"] == "64"
    assert metadata["platformVersion"] == ""


def test_request_identity_falls_back_to_settings():
    """不下发时回落环境变量，且兜底默认值与网关身份表同值。"""
    identity = app_module.RequestIdentity.resolve(
        app_module.BypassRequest(url="http://127.0.0.1/")
    )
    assert identity.user_agent == app_module.SETTINGS.user_agent
    assert identity.accept_language == app_module.SETTINGS.accept_language
    if not os.getenv("CF_BYPASS_ACCEPT_LANGUAGE"):
        assert identity.accept_language == "zh-CN,zh;q=0.9,en;q=0.8"
    assert identity.brands is None
    assert identity.full_version_list is None

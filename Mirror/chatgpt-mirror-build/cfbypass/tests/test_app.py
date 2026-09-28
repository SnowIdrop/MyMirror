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

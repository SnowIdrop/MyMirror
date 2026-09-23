import os


os.environ.setdefault("CF_BYPASS_SECRET", "test-secret")
os.environ.setdefault("CF_BYPASS_ALLOWED_HOSTS", "127.0.0.1,localhost")

from fastapi.testclient import TestClient

from app import app


client = TestClient(app)


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

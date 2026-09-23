import os


os.environ.setdefault("GATEWAY_ADMIN_SECRET", "test-secret")

from fastapi.testclient import TestClient

from main import app
from database import Base, engine


Base.metadata.create_all(bind=engine)


client = TestClient(app)
headers = {"Authorization": "Bearer test-secret"}


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "gateway"}


def test_get_user_info_requires_secret():
    response = client.post("/api/get-user-info", json={"chatgpt_token": "abc"})
    assert response.status_code == 401


def test_get_user_info_returns_contract():
    response = client.post("/api/get-user-info", json={"chatgpt_token": "abc"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["user_info"]["email"]
    assert data["user_info"]["plan_type"]
    assert data["access_token"]


def test_diagnose_returns_bools():
    response = client.post(
        "/api/diagnose-chatgpt-auth",
        json={"access_token": "a", "session_token": ""},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["access_token_valid"] is True
    assert data["session_token_valid"] is False


def test_revoke_returns_true():
    response = client.post(
        "/api/revoke-authorization",
        json={"subject": "user", "version": "v1"},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json() == {"revoked": True}


def test_backup_export_contains_collections():
    response = client.get("/api/backup/export", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == 2
    for name in (
        "chatgpt_accounts",
        "gateway_sessions",
        "settings",
        "conversation_owners",
        "project_owners",
        "visit_logs",
        "conversation_statistics",
        "conversation_model_statistics",
    ):
        assert isinstance(data[name], list)


def test_backup_restore_round_trip():
    export = client.get("/api/backup/export", headers=headers).json()
    response = client.post("/api/backup/restore", json=export, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"message": "restored"}


def test_unknown_api_is_explicitly_not_implemented():
    response = client.get("/api/get-mirror-token", headers=headers)
    assert response.status_code == 501

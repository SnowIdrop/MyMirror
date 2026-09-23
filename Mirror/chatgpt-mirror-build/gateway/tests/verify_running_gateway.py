import json
import os
import sys

import httpx


base_url = "http://127.0.0.1:8000"
headers = {"Authorization": "Bearer " + os.environ["GATEWAY_ADMIN_SECRET"]}
failures = []


def check(name, response, expected, actual):
    if expected != actual:
        failures.append(f"{name}: expected {expected!r}, got {actual!r}")
    print(f"{name}: status={response.status_code} actual={actual}")


client = httpx.Client(base_url=base_url, timeout=3)


response = client.get("/health")
check("health", response, 200, response.status_code)

response = client.post(
    "/api/revoke-authorization",
    json={"subject": "route-a-admin", "version": "x"},
    headers=headers,
)
check("revoke", response, 200, response.status_code)
check("revoke_payload", response, {"revoked": True}, response.json())

response = client.get("/api/backup/export", headers=headers)
payload = response.json()
required = {
    "chatgpt_accounts",
    "gateway_sessions",
    "settings",
    "conversation_owners",
    "project_owners",
    "visit_logs",
    "conversation_statistics",
    "conversation_model_statistics",
}
check("backup", response, 200, response.status_code)
check("backup_version", response, 2, payload.get("version"))
check("backup_collections", response, True, required.issubset(payload))

response = client.post("/api/backup/restore", json=payload, headers=headers)
check("restore", response, 200, response.status_code)
check("restore_payload", response, {"message": "restored"}, response.json())

if failures:
    print(json.dumps({"failures": failures}, ensure_ascii=False))
    sys.exit(1)

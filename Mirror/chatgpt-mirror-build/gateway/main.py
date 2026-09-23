import hashlib
import hmac
import os
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine
from models import (
    ChatgptAccount,
    ConversationModelStatistic,
    ConversationOwner,
    ConversationStatistic,
    GatewaySession,
    GatewaySetting,
    ProjectOwner,
    VisitLog,
)


GATEWAY_ADMIN_SECRET = os.getenv("GATEWAY_ADMIN_SECRET", "")
DJANGO_UPSTREAM = os.getenv("DJANGO_UPSTREAM", "http://backend:8000")
GATEWAY_CONNECT_TIMEOUT_SECONDS = float(os.getenv("GATEWAY_CONNECT_TIMEOUT_SECONDS", "5"))
GATEWAY_READ_TIMEOUT_SECONDS = float(os.getenv("GATEWAY_READ_TIMEOUT_SECONDS", "60"))
GATEWAY_BACKUP_VERSION = 2
GATEWAY_BACKUP_COLLECTIONS = (
    "chatgpt_accounts",
    "gateway_sessions",
    "settings",
    "conversation_owners",
    "project_owners",
    "visit_logs",
    "conversation_statistics",
    "conversation_model_statistics",
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="chatgpt-mirror gateway", version="route-a-0.1.0", lifespan=lifespan)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_gateway_secret(authorization: str = Header(default="")) -> None:
    expected = f"Bearer {GATEWAY_ADMIN_SECRET}".encode("utf-8")
    received = authorization.encode("utf-8")
    if not GATEWAY_ADMIN_SECRET or not hmac.compare_digest(received, expected):
        raise HTTPException(status_code=401, detail="无效的网关认证")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _now() -> int:
    return int(time.time())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "gateway"}


@app.post("/api/get-user-info", dependencies=[Depends(verify_gateway_secret)])
def get_user_info(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    chatgpt_token = str(payload.get("chatgpt_token") or "").strip()
    refresh_token = str(payload.get("refresh_token") or "").strip()
    client_id = str(payload.get("client_id") or "").strip()

    if not chatgpt_token and not refresh_token:
        raise HTTPException(status_code=400, detail="chatgpt_token 或 refresh_token 必须提供")

    access_token = chatgpt_token or f"refresh-{_digest(refresh_token)}"
    username = f"user-{_digest(access_token)}@example.com"
    now = _now()

    account = db.query(ChatgptAccount).filter(ChatgptAccount.chatgpt_username == username).first()
    if account is None:
        account = ChatgptAccount(
            chatgpt_username=username,
            created_time=now,
            updated_time=now,
        )
        db.add(account)

    account.auth_status = True
    account.plan_type = account.plan_type or "free"
    account.access_token = access_token
    account.access_token_valid = True
    account.updated_time = now
    if refresh_token:
        account.refresh_token = refresh_token
        account.refresh_client_id = client_id

    db.commit()

    return {
        "user_info": {
            "email": account.chatgpt_username,
            "plan_type": account.plan_type,
        },
        "access_token": account.access_token,
        "session_token": account.session_token,
        "extra_cookies": {},
        "refresh_token": account.refresh_token,
        "refresh_client_id": account.refresh_client_id,
        "access_token_valid": account.access_token_valid,
        "session_token_valid": account.session_token_valid,
    }


@app.post("/api/login", dependencies=[Depends(verify_gateway_secret)])
async def login(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, str]:
    subject = str(payload.get("user_name") or "").strip()
    authorization = str(payload.get("authorization") or "").strip()
    if not subject or not authorization:
        raise HTTPException(status_code=400, detail="user_name 和 authorization 必须提供")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(GATEWAY_READ_TIMEOUT_SECONDS, connect=GATEWAY_CONNECT_TIMEOUT_SECONDS),
            follow_redirects=False,
        ) as client:
            upstream_response = await client.post(
                f"{DJANGO_UPSTREAM}/0x/user/gateway-authorization",
                headers={"Authorization": f"Bearer {GATEWAY_ADMIN_SECRET}"},
                json={"authorization": authorization, "subject": subject},
            )
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Django 服务不可用")

    if upstream_response.status_code != 200:
        raise HTTPException(status_code=401, detail="登录已失效，请重新登录")

    details = upstream_response.json()
    db.add(
        GatewaySession(
            subject=subject,
            authorization=authorization,
            version=str(details.get("version") or ""),
            expires_at=int(details.get("expires_at") or _now() + 3600),
            created_at=_now(),
        )
    )
    db.commit()

    return {"login_url": "/handoff"}


@app.post("/api/diagnose-chatgpt-auth", dependencies=[Depends(verify_gateway_secret)])
def diagnose_chatgpt_auth(payload: dict[str, Any]) -> dict[str, bool]:
    access_token = str(payload.get("access_token") or "").strip()
    session_token = str(payload.get("session_token") or "").strip()
    return {
        "access_token_valid": bool(access_token),
        "session_token_valid": bool(session_token),
    }


@app.post("/api/revoke-authorization", dependencies=[Depends(verify_gateway_secret)])
def revoke_authorization(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, bool]:
    subject = str(payload.get("subject") or "").strip()
    if not subject:
        raise HTTPException(status_code=400, detail="subject 必须提供")

    db.query(GatewaySession).filter(GatewaySession.subject == subject).delete()
    db.commit()
    return {"revoked": True}


@app.post("/api/close-chatgpt-memory", dependencies=[Depends(verify_gateway_secret)])
def close_chatgpt_memory(_: dict[str, Any]) -> dict[str, str]:
    return {"message": "ok"}


@app.get("/api/backup/export", dependencies=[Depends(verify_gateway_secret)])
def backup_export(db: Session = Depends(get_db)) -> dict[str, Any]:
    return {
        "version": GATEWAY_BACKUP_VERSION,
        "chatgpt_accounts": [
            {
                "id": row.id,
                "chatgpt_username": row.chatgpt_username,
                "auth_status": row.auth_status,
                "plan_type": row.plan_type,
                "access_token": row.access_token,
                "session_token": row.session_token,
                "extra_cookies": row.extra_cookies,
                "refresh_token": row.refresh_token,
                "refresh_client_id": row.refresh_client_id,
                "access_token_valid": row.access_token_valid,
                "session_token_valid": row.session_token_valid,
                "proxy_node_id": row.proxy_node_id,
                "last_check_at": row.last_check_at,
                "last_error": row.last_error,
                "login_count": row.login_count,
                "remark": row.remark,
                "created_time": row.created_time,
                "updated_time": row.updated_time,
            }
            for row in db.query(ChatgptAccount).order_by(ChatgptAccount.id).all()
        ],
        "gateway_sessions": [
            {
                "id": row.id,
                "subject": row.subject,
                "authorization": row.authorization,
                "version": row.version,
                "expires_at": row.expires_at,
                "created_at": row.created_at,
            }
            for row in db.query(GatewaySession).order_by(GatewaySession.id).all()
        ],
        "settings": [
            {"key": row.key, "value": row.value}
            for row in db.query(GatewaySetting).order_by(GatewaySetting.key).all()
        ],
        "conversation_owners": [
            {"id": row.id, "user_name": row.user_name, "conversation_id": row.conversation_id}
            for row in db.query(ConversationOwner).order_by(ConversationOwner.id).all()
        ],
        "project_owners": [
            {"id": row.id, "user_name": row.user_name, "project_id": row.project_id}
            for row in db.query(ProjectOwner).order_by(ProjectOwner.id).all()
        ],
        "visit_logs": [
            {"id": row.id, "user_name": row.user_name, "log_type": row.log_type, "created_at": row.created_at}
            for row in db.query(VisitLog).order_by(VisitLog.id).all()
        ],
        "conversation_statistics": [
            {
                "id": row.id,
                "user_name": row.user_name,
                "conversation_id": row.conversation_id,
                "title": row.title,
                "message_count": row.message_count,
                "updated_at": row.updated_at,
            }
            for row in db.query(ConversationStatistic).order_by(ConversationStatistic.id).all()
        ],
        "conversation_model_statistics": [
            {
                "id": row.id,
                "user_name": row.user_name,
                "model": row.model,
                "message_count": row.message_count,
                "updated_at": row.updated_at,
            }
            for row in db.query(ConversationModelStatistic).order_by(ConversationModelStatistic.id).all()
        ],
    }


@app.post("/api/backup/restore", dependencies=[Depends(verify_gateway_secret)])
def backup_restore(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, str]:
    if payload.get("version") != GATEWAY_BACKUP_VERSION:
        raise HTTPException(status_code=400, detail="Gateway 备份版本不匹配")
    for name in GATEWAY_BACKUP_COLLECTIONS:
        if not isinstance(payload.get(name), list):
            raise HTTPException(status_code=400, detail=f"Gateway 备份缺少 {name}")

    try:
        db.query(ConversationModelStatistic).delete()
        db.query(ConversationStatistic).delete()
        db.query(VisitLog).delete()
        db.query(ProjectOwner).delete()
        db.query(ConversationOwner).delete()
        db.query(GatewaySetting).delete()
        db.query(GatewaySession).delete()
        db.query(ChatgptAccount).delete()

        for item in payload["chatgpt_accounts"]:
            db.add(ChatgptAccount(**item))
        for item in payload["gateway_sessions"]:
            db.add(GatewaySession(**item))
        for item in payload["settings"]:
            db.add(GatewaySetting(**item))
        for item in payload["conversation_owners"]:
            db.add(ConversationOwner(**item))
        for item in payload["project_owners"]:
            db.add(ProjectOwner(**item))
        for item in payload["visit_logs"]:
            db.add(VisitLog(**item))
        for item in payload["conversation_statistics"]:
            db.add(ConversationStatistic(**item))
        for item in payload["conversation_model_statistics"]:
            db.add(ConversationModelStatistic(**item))

        db.commit()
    except Exception:
        db.rollback()
        raise

    return {"message": "restored"}


@app.api_route("/0x/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_to_django(path: str, request: Request) -> Response:
    url = f"{DJANGO_UPSTREAM}/0x/{path}"
    excluded_headers = {"host", "content-length", "connection", "transfer-encoding"}
    headers = {key: value for key, value in request.headers.items() if key.lower() not in excluded_headers}
    body = await request.body()

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(GATEWAY_READ_TIMEOUT_SECONDS, connect=GATEWAY_CONNECT_TIMEOUT_SECONDS),
            follow_redirects=False,
        ) as client:
            upstream_response = await client.request(request.method, url, headers=headers, content=body)
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Django 服务不可用")

    response_headers = {
        key: value
        for key, value in upstream_response.headers.items()
        if key.lower() not in excluded_headers
    }
    return Response(
        status_code=upstream_response.status_code,
        content=upstream_response.content,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def not_implemented(path: str) -> dict[str, str]:
    raise HTTPException(status_code=501, detail=f"接口 /api/{path} 尚未实现")

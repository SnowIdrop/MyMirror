from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class ChatgptAccount(Base):
    __tablename__ = "chatgpt_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chatgpt_username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    auth_status: Mapped[bool] = mapped_column(Boolean, default=True)
    plan_type: Mapped[str] = mapped_column(String(64), default="free")
    access_token: Mapped[str] = mapped_column(Text, default="")
    session_token: Mapped[str] = mapped_column(Text, default="")
    extra_cookies: Mapped[str] = mapped_column(Text, default="{}")
    refresh_token: Mapped[str] = mapped_column(Text, default="")
    refresh_client_id: Mapped[str] = mapped_column(String(255), default="")
    access_token_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    session_token_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    proxy_node_id: Mapped[str] = mapped_column(String(255), default="")
    last_check_at: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(Text, default="")
    login_count: Mapped[int] = mapped_column(Integer, default=0)
    remark: Mapped[str] = mapped_column(Text, default="")
    created_time: Mapped[int] = mapped_column(Integer, default=0)
    updated_time: Mapped[int] = mapped_column(Integer, default=0)


class GatewaySession(Base):
    __tablename__ = "gateway_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject: Mapped[str] = mapped_column(String(255), index=True)
    authorization: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(String(255), default="")
    expires_at: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[int] = mapped_column(Integer, default=0)


class GatewaySetting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class ConversationOwner(Base):
    __tablename__ = "conversation_owners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(String(255), index=True)
    conversation_id: Mapped[str] = mapped_column(String(255), index=True)


class ProjectOwner(Base):
    __tablename__ = "project_owners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(String(255), index=True)
    project_id: Mapped[str] = mapped_column(String(255), index=True)


class VisitLog(Base):
    __tablename__ = "visit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(String(255), index=True)
    log_type: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[int] = mapped_column(Integer, default=0)


class ConversationStatistic(Base):
    __tablename__ = "conversation_statistics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(String(255), index=True)
    conversation_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[int] = mapped_column(Integer, default=0)


class ConversationModelStatistic(Base):
    __tablename__ = "conversation_model_statistics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(String(255), index=True)
    model: Mapped[str] = mapped_column(String(255), index=True)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[int] = mapped_column(Integer, default=0)

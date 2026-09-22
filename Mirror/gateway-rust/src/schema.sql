-- -----------------------------------------------------------------------------
-- Author  : MingTea
-- File    : schema.sql
-- Created : 2026-09-22
-- Summary : 原版网关 SQLite schema（8 表 + 3 索引 + 存量回填）。
--           逐字复刻自 reverse/reports/05-database-schema.md §3
--           （原版 db::init_db 单一批次 DDL @0xD8C916 len 0xF8B），
--           仅归一缩进，SQL 语义未改。
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS chatgpt_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chatgpt_username TEXT UNIQUE NOT NULL,
    auth_status BOOLEAN DEFAULT TRUE,
    plan_type TEXT DEFAULT 'free',
    access_token TEXT NOT NULL,
    session_token TEXT,
    extra_cookies TEXT DEFAULT '[]',
    refresh_token TEXT,
    remark TEXT,
    created_time INTEGER,
    updated_time INTEGER
);

CREATE TABLE IF NOT EXISTS visit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    chatgpt_username TEXT,
    log_type TEXT NOT NULL,
    created_at INTEGER,
    ip TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS gateway_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT NOT NULL,
    chatgpt_username TEXT NOT NULL,
    access_token TEXT NOT NULL,
    session_token TEXT,
    extra_cookies TEXT DEFAULT '[]',
    login_mode TEXT NOT NULL DEFAULT 'api',
    mirror_token TEXT NOT NULL,
    isolated_session BOOLEAN DEFAULT TRUE,
    force_chat_mode BOOLEAN NOT NULL DEFAULT TRUE,
    limits TEXT DEFAULT '[]',
    proxy_node_id INTEGER,
    daily_quota INTEGER NOT NULL DEFAULT 0,
    monthly_quota INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER,
    updated_at INTEGER,
    UNIQUE(user_name, chatgpt_username),
    UNIQUE(mirror_token)
);

CREATE TABLE IF NOT EXISTS gateway_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS conversation_owners (
    chatgpt_username TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(chatgpt_username, conversation_id)
);

CREATE INDEX IF NOT EXISTS idx_conversation_owners_user
    ON conversation_owners(chatgpt_username, user_name);

CREATE TABLE IF NOT EXISTS project_owners (
    chatgpt_username TEXT NOT NULL,
    project_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(chatgpt_username, project_id)
);

CREATE INDEX IF NOT EXISTS idx_project_owners_user
    ON project_owners(chatgpt_username, user_name);

CREATE TABLE IF NOT EXISTS conversation_statistics (
    chatgpt_username TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    message_count INTEGER NOT NULL DEFAULT 0,
    conversation_counted BOOLEAN NOT NULL DEFAULT TRUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(chatgpt_username, conversation_id)
);

CREATE INDEX IF NOT EXISTS idx_conversation_statistics_user
    ON conversation_statistics(user_name, updated_at DESC);

CREATE TABLE IF NOT EXISTS conversation_model_statistics (
    user_name TEXT NOT NULL,
    model_name TEXT NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(user_name, model_name)
);

INSERT OR IGNORE INTO conversation_statistics (
    chatgpt_username, conversation_id, user_name, title, message_count,
    conversation_counted, created_at, updated_at
)
SELECT chatgpt_username, conversation_id, user_name, '', 0, TRUE, created_at, updated_at
FROM conversation_owners;

# 05 · gateway SQLite 数据库 Schema 报告（chatgpt-mirror-gateway）

> 目标制品：`D:\Project\MirrorNiXiang\reverse\extracted\chatgpt-mirror-gateway`（ELF x86-64，23,252,912 B，SHA-256 `4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098`）
> 证据来源：`reports/gateway-ghidra-export.txt`（Ghidra 导出，`SelectedFunctions=144`）＋ 二进制 `.rodata` 只读字符串提取（PowerShell 只读）＋ `03-gateway-static-analysis.md` §9/§10 交叉核对
> 取证方式：纯静态、只读。未运行 gateway、未执行其数据库、未联网、未访问 api.zxcbug.com
> 偏移约定：文中「文件偏移」= ELF 文件内偏移（与 03 报告一致）；Ghidra 导出地址 = 文件偏移 + 0x00100000（例：Ghidra `DAT_00e8c916` ↔ 文件 `0xD8C916`）。函数地址采用 Ghidra 导出中的 ENTRY。

## 0. 摘要（可先读）

- 引擎：`rusqlite 0.31.0`（bundled sqlite3；`.symtab` 内 276 个 `sqlite3_*` 定义符号，无动态导入），DB 文件路径来自环境变量 `DATABASE_PATH`（0xD96436）。
- Schema 由 `db::init_db`（ENTRY `0x00349540`）一键初始化：单条 `execute_batch` 批量 DDL（字符串 @0xD8C916，长度 0xF8B=3979）建立 **8 张表 + 3 个索引 + 1 条存量回填**；随后用 `PRAGMA table_info`＋`ALTER TABLE` 为旧库补列，并执行加密迁移 `db::migrate_sensitive_rows`（ENTRY `0x0034b9b0`）。
- 表：`chatgpt_accounts`、`visit_logs`、`gateway_sessions`、`gateway_settings`、`conversation_owners`、`project_owners`、`conversation_statistics`、`conversation_model_statistics`（DDL 偏移见 §3）。
- 未发现任何 `FOREIGN KEY` / `REFERENCES` 子句（见 §4）；3 处 `AUTOINCREMENT`；主键/UNIQUE 约束如 §3/§4 所列。
- 密文：应用层 `enc:v1:` 封套（0xD8C699）＋ base64url；**加密列**（由写路径/迁移路径证实）：`chatgpt_accounts.access_token / session_token / extra_cookies / refresh_token`、`gateway_sessions.access_token / session_token / extra_cookies`；`gateway_settings` 中 `mirror_proxy`、`political_moderation` 为**整值加密**；`mirror_token` 列为 `sha256:` 前缀哈希（非加密）。详见 §6。
- 备份格式：`export_backup` 输出 JSON 信封 `version=2`＋8 个表数组（键名与偏移见 §7）；`restore_backup` 校验 `version==2` 后，在 `BEGIN DEFERRED` 事务中先执行 8 表 `DELETE` 批（400 B，@0xD8FF3A），再按 8 条 `INSERT … ON CONFLICT … DO UPDATE` 回填。

## 1. 引擎、连接与 schema 版本

- 引擎与依赖：`rusqlite 0.31.0` bundled sqlite3（依赖表见 03 报告 §5；`.dynsym` 无 `sqlite3_*` 导入，03 报告 §3.3/§9）。加密栈 `aes 0.8.4 + aead 0.5.2`（03 报告 §5）。
- DB 路径：环境变量 `DATABASE_PATH`（0xD96436）。`init_db` 会先对路径取 `std::path::Path::parent` 并用 `std::fs::DirBuilder::_create` 创建目录（导出 `db::init_db` 行 5532–5535）。
- 打开标志：`InnerConnection::open_with_flags(..., 0x8046, 0)`（`init_db` 行 5582–5583）。0x8046 与 rusqlite `OpenFlags` 默认位组合一致（READ_WRITE|CREATE|URI|NO_MUTEX）【判读】；各 db 函数（如 `save_gateway_session` 行 8054、`restore_backup` 行 25527）均使用同一常量。
- schema/备份版本：备份 JSON 的 `version` 恒为 **2**：导出端写入 `2`（`export_backup` 行 24722–24730，键 `version` @0xD8FED4 len 7）；恢复端校验 `version==2` 才继续（`restore_backup` 行 25635–25638）。
- 本报告未发现独立的 schema 版本号表/字段；「迁移状态」由列存在性与数据前缀（`enc:v1:`、`sha256:`）自描述（见 §5、§6）。

## 2. 表结构总览

| # | 表 | 建表语句偏移（文件） | 主键 | 用途（判读依据） |
|---|---|---|---|---|
| 1 | `chatgpt_accounts` | 0xD8C91F | `id INTEGER PK AUTOINCREMENT` + `chatgpt_username UNIQUE` | ChatGPT 账号/凭证池（列含 access/session/refresh token、extra_cookies、plan_type、auth_status） |
| 2 | `visit_logs` | 0xD8CB10 | `id INTEGER PK AUTOINCREMENT` | 访问/用量日志（`log_type='proxy'` 计入配额，见 §9） |
| 3 | `gateway_sessions` | 0xD8CC3A | `id INTEGER PK AUTOINCREMENT` + `UNIQUE(user_name, chatgpt_username)` + `UNIQUE(mirror_token)` | 用户会话（登录模式、隔离、配额、代理节点、limits） |
| 4 | `gateway_settings` | 0xD8CF83 | `key TEXT PK` | 键值设置（mirror_proxy / custom_scripts / political_moderation / blocked_paths） |
| 5 | `conversation_owners` | 0xD8D027 | 复合 PK `(chatgpt_username, conversation_id)` | 会话归属（多用户去重协作判权） |
| 6 | `project_owners` | 0xD8D1F7 | 复合 PK `(chatgpt_username, project_id)` | 项目归属 |
| 7 | `conversation_statistics` | 0xD8D3AE | 复合 PK `(chatgpt_username, conversation_id)` | 会话统计（title、message_count、conversation_counted） |
| 8 | `conversation_model_statistics` | 0xD8D62B | 复合 PK `(user_name, model_name)` | 按模型维度消息计数 |

## 3. 完整 DDL（逐条，含偏移）

来源：`db::init_db`（`0x00349540`）行 5631 调用 `Connection::execute_batch(&local_d8, &local_90, &DAT_00e8c916, 0xf8b)`；即文件偏移 **0xD8C916** 起、长度 **0xF8B** 的单一批次字符串（03 报告 §9 记作 0xd8c917，为同一字符串）。以下为按表拆分的原文（缩进已归一，SQL 文本未改）。

### 3.1 chatgpt_accounts（@0xD8C91F）

```sql
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
```

### 3.2 visit_logs（@0xD8CB10）

```sql
CREATE TABLE IF NOT EXISTS visit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    chatgpt_username TEXT,
    log_type TEXT NOT NULL,
    created_at INTEGER,
    ip TEXT,
    user_agent TEXT
);
```

### 3.3 gateway_sessions（@0xD8CC3A）

```sql
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
```

### 3.4 gateway_settings（@0xD8CF83）

```sql
CREATE TABLE IF NOT EXISTS gateway_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER
);
```

### 3.5 conversation_owners（@0xD8D027）＋索引

```sql
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
```

（索引语句 @0xD8D175）

### 3.6 project_owners（@0xD8D1F7）＋索引

```sql
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
```

（索引语句 @0xD8D336）

### 3.7 conversation_statistics（@0xD8D3AE）＋索引

```sql
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
```

（索引语句 @0xD8D5A2）

### 3.8 conversation_model_statistics（@0xD8D62B）

```sql
CREATE TABLE IF NOT EXISTS conversation_model_statistics (
    user_name TEXT NOT NULL,
    model_name TEXT NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(user_name, model_name)
);
```

### 3.9 批次内附带：存量回填（@0xD8D753）

```sql
INSERT OR IGNORE INTO conversation_statistics (
    chatgpt_username, conversation_id, user_name, title, message_count,
    conversation_counted, created_at, updated_at
)
SELECT chatgpt_username, conversation_id, user_name, '', 0, TRUE, created_at, updated_at
FROM conversation_owners;
```

## 4. 约束、索引与默认值汇总

- 主键：`chatgpt_accounts.id`、`visit_logs.id`、`gateway_sessions.id`（均 `INTEGER PRIMARY KEY AUTOINCREMENT`，AUTOINCREMENT 字面量在 0xD8C970 / 0xD8CB5B / 0xD8CC8B 各出现 1 次，全库共 3 处）；其余 5 表为复合/单列 TEXT 主键（见 §3）。
- 唯一约束：`chatgpt_accounts.chatgpt_username UNIQUE`；`gateway_sessions.UNIQUE(user_name, chatgpt_username)` 与 `UNIQUE(mirror_token)`（SQLite 会为 UNIQUE 自动建索引，名称未在 DDL 中显式给出）。
- 显式索引：`idx_conversation_owners_user`、`idx_project_owners_user`、`idx_conversation_statistics_user(user_name, updated_at DESC)`（0xD8D175 / 0xD8D336 / 0xD8D5A2）。未发现其他 `CREATE INDEX` / `CREATE UNIQUE INDEX` 语句（.rodata 应用区扫描：`CREATE UNIQUE INDEX` 0 命中）。
- 外键：**未发现**。对 `.rodata` 应用字符串区 0xD84000–0xD98000 扫描 `FOREIGN KEY`、`REFERENCES ` 均 0 命中；Ghidra 导出内亦无相应 DDL/SQL。`PRAGMA foreign_keys`（0xF29D4A）仅存在于 bundled sqlite3 内部字符串区，未见于应用代码调用。
- 默认值（DDL 内）：`auth_status=TRUE`、`plan_type='free'`、`extra_cookies='[]'`（两表）、`login_mode='api'`、`isolated_session=TRUE`、`force_chat_mode=TRUE`、`limits='[]'`、`daily_quota/monthly_quota=0`、`title=''`、`message_count=0`、`conversation_counted=TRUE`；时间戳类列无默认值，由应用写入（`db::now_ts`，ENTRY 见 `now_ts` 符号；`save_gateway_session` 行 13178 调 `now_ts()`）。

## 5. 迁移与初始化逻辑（`db::init_db`，ENTRY `0x00349540`）

执行顺序（导出行号）：

1. 目录准备与打开 DB（行 5532–5583）。
2. **批量建表**：`execute_batch(DDL 批次 @0xD8C916, 0xF8B)`（行 5631）。新建库即得到 §3 的全部 8 表/3 索引/回填（DDL 已包含较新列）。
3. **旧库补列（chatgpt_accounts）**：`PRAGMA table_info(chatgpt_accounts)`（@0xD9118A，行 5671–5672）→ 检查是否已有 `extra_cookies`（比较字面量组合 `extra_co`+`_cookies`，行 5790–5793）→ 缺失则 `ALTER TABLE chatgpt_accounts ADD COLUMN extra_cookies TEXT DEFAULT '[]'`（@0xD911AD，行 5797）。
4. **旧库补列（gateway_sessions，本函数内 3 组）**：`PRAGMA table_info(gateway_sessions)`（@0xD9112D，行 5847/6032/6201，共 3 次）→ 依次：
   - `ALTER TABLE gateway_sessions ADD COLUMN session_token TEXT`（@0xD91150，行 5903）；
   - `ALTER TABLE gateway_sessions ADD COLUMN extra_cookies TEXT DEFAULT '[]'`（@0xD91297，行 6153）；
   - `ALTER TABLE gateway_sessions ADD COLUMN login_mode TEXT NOT NULL DEFAULT 'api'`（@0xD911F4，行 6255）。
5. **调用列保障与数据迁移函数**（行 6378–6384；CALLS 表行 6484–6487）：
   - `ensure_gateway_sessions_force_chat_mode_column`（ENTRY `0x0036a060`）→ `ALTER TABLE gateway_sessions ADD COLUMN force_chat_mode BOOLEAN NOT NULL DEFAULT TRUE`（@0xD91242，行 27415）；
   - `ensure_gateway_sessions_proxy_node_id_column`（ENTRY `0x0036a800`）→ `ALTER TABLE gateway_sessions ADD COLUMN proxy_node_id INTEGER`（@0xD912DE，行 27725）；
   - `ensure_gateway_sessions_quota_columns`（ENTRY `0x0036af30`）→ `daily_quota INTEGER NOT NULL DEFAULT 0`（@0xD9131B，行 28087）＋ `monthly_quota INTEGER NOT NULL DEFAULT 0`（@0xD91369，行 28102）；
   - `migrate_sensitive_rows`（ENTRY `0x0034b9b0`）。
   （三个 ensure_* 均先 `PRAGMA table_info(gateway_sessions)` 再 ALTER；PRAGMA 字符串为共享常量 @0xD9112D。）
6. `db::migrate_sensitive_rows`（三段迁移，全部幂等）：
   - **gateway_sessions 段**：`SELECT id, access_token, session_token, extra_cookies, mirror_token FROM gateway_sessions`（@0xD8D8A1 len 0x59）→ 对 access_token / session_token / extra_cookies 调 `encrypt_secret`（行 6744/6793/6847）；`mirror_token` 若非 `sha256:` 前缀则调 `mirror_token_hash`（行 6879–6882）→ `UPDATE gateway_sessions SET access_token = ?1, session_token = ?2, extra_cookies = ?3, mirror_token = ?4 WHERE id = ?5`（@0xD8DA49 len 0x76，行 6902）。
   - **chatgpt_accounts 段**：`SELECT id, access_token, session_token, extra_cookies, refresh_token FROM chatgpt_accounts`（@0xD8D8FA len 0x5A）→ 4 个字段分别 `encrypt_secret`（行 7097/7144/7200/7233）→ `UPDATE chatgpt_accounts SET access_token = ?1, session_token = ?2, extra_cookies = ?3, refresh_token = ?4 WHERE id = ?5`（@0xD8D9D2 len 0x77，行 7294）。
   - **gateway_settings('mirror_proxy') 段**：`SELECT value FROM gateway_settings WHERE key = 'mirror_proxy'`（@0xD8D954 len 0x3D）→ `encrypt_secret`（整值，行 7429）→ `UPDATE gateway_settings SET value = ?1 WHERE key = 'mirror_proxy'`（@0xD8D991 len 0x41，行 7454）。
   - 幂等性：`encrypt_secret` 对已带 `enc:v1:` 前缀的输入直接原样返回（见 §6）；`mirror_token` 迁移对已带 `sha256:` 前缀的值跳过哈希（行 6879–6889）。
- 事务/批处理痕迹：应用区存在 `BEGIN DEFERRED`（@0xD8DBEB len 14）：`restore_backup` 行 25581 以 `execute_batch` 显式开启它；另见 §7。
- 说明：步骤 3–5 只对**旧库**有意义；新库由 §3 的全量 DDL 直接得到最终列集。

## 6. 密文列与加密实现

实现函数（Ghidra 导出）：

| 函数 | ENTRY | 行为（证据） |
|---|---|---|
| `db::credential_key` | 0x003478a0 | 读取环境变量 `CREDENTIAL_ENCRYPTION_KEY`（名 @0xD8C624，长度 25；出现于 0xD8C676 等）；trim 后要求 ≥32 字节，否则返回错误（错误消息由内联常量拼出，含“未配置/长度不足”提示，未逐字转写）；满足时经 `<D as digest::Digest>::digest` 派生 32 字节密钥（判读为 SHA-256 派生） |
| `db::encrypt_secret` | 0x00347aa0 | 若输入前 7 字节为 `enc:v1:`（@0xD8C699；比较常量 0x3a636e65 0x3a31763a）→ 原样返回（幂等）；否则用 32 字节密钥 `KeyInit::new_from_slice` 加密 |
| `db::decrypt_secret` | 0x00348050 | 用 AEAD `decrypt`（调用点行 3584）；切片形态显示 **12 字节 nonce 前置**、余下为密文（含认证标签）（判读：AES-GCM；具体算法名未在导出文本中出现） |
| `db::mirror_token_hash` | 0x00348630 | 生成 `sha256:` 前缀哈希（迁移/保存路径均检查该前缀，@0xD8C87C 为 `sha256:` 字面量） |

格式判读：密文列存文本 `enc:v1:` + base64url（字母表 @0xD8C6AC：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`，无填充符）+ `base64url(12B nonce || ciphertext+tag)`。

加密列清单（每列给出可证路径）：

| 表.列 | 加密证据（写/迁移） | 解密/负向证据 |
|---|---|---|
| `chatgpt_accounts.access_token` | 迁移行 7097；`save_gateway_session` 同构路径（下） | 导出范围内未见该表读取端的 `decrypt_secret` 调用（见“不确定项”） |
| `chatgpt_accounts.session_token` | 迁移行 7144 | 同上 |
| `chatgpt_accounts.extra_cookies` | 迁移行 7200 | `clear_stored_cloudflare_cookies` 对其解密→过滤→再加密（行 8814/8986；表集合含 `chatgpt_accounts`，行 8609） |
| `chatgpt_accounts.refresh_token` | 迁移行 7233 | 同上 |
| `gateway_sessions.access_token` | `save_gateway_session` 行 13119；迁移行 6744 | — |
| `gateway_sessions.session_token` | `save_gateway_session` 行 13253（Some 时）；迁移行 6793 | — |
| `gateway_sessions.extra_cookies` | `save_gateway_session` 行 13152；`update_gateway_session_extra_cookies` 行 13941；迁移行 6847 | `clear_stored_cloudflare_cookies`（表集合含 `gateway_sessions`，行 8611） |
| `gateway_settings.value`（key=`mirror_proxy`） | `save_mirror_proxy_config` 行 8160（整值加密后 UPDATE，见行 8116–8160 序列化→加密流程）；迁移行 7429 | `get_mirror_proxy_config` 行 7731（先解密再 `serde_json` 解析） |
| `gateway_settings.value`（key=`political_moderation`） | `save_political_moderation_config` 行 10571 | `get_political_moderation_config` 行 10127 |
| `gateway_sessions.mirror_token` | 非加密，存哈希：`save_gateway_session` 行 13177 恒调 `mirror_token_hash`；迁移行 6882（幂等） | 查询按哈希等值匹配（SQL @0xD8E658 等） |
| `gateway_settings.value`（key=`custom_scripts`） | **未见**加密/解密调用：`get_custom_script_config`（0x00350950）与 `save_custom_script_config`（0x003512a0）的 CALLS 列表中无 `encrypt_secret`/`decrypt_secret`（导出范围内） | 按导出内证据推断为明文 JSON 存储【限定：仅覆盖 SelectedFunctions=144 的函数集】 |

补充：
- `encrypt_secret` 的“已加密则跳过”前缀判断使其在保存路径可重复调用（例如 `update_gateway_session_extra_cookies` 直接加密传入值）。
- 读取端解密调用在导出内**仅 3 处**：`get_mirror_proxy_config`（行 7731）、`clear_stored_cloudflare_cookies`（行 8814）、`get_political_moderation_config`（行 10127）。`get_gateway_session_by_token`（0x003564f0）与 `get_chatgpt_credentials_for_user`（0x00357600）**未见**解密调用——其凭证字段的运行时明文化路径无法由本次导出证实（可能存在于未选中的函数或被后置处理；见 §10）。

## 7. 备份导出与恢复

### 7.1 导出 `db::export_backup`（ENTRY `0x003648e0`）

- 按表读取（8 条 SELECT，`prepare_with_flags` 调用点行 24002–24643）：

| 表 | SELECT 字符串偏移 | 长度 |
|---|---|---|
| chatgpt_accounts | 0xD8FB02 | 0xA8 |
| gateway_sessions | 0xD8FBAA | 0xF0 |
| gateway_settings | 0xD8FC9A | 0x33 |
| conversation_owners | 0xD8FCCD | 100 |
| project_owners | 0xD8FD31 | 0x5A |
| visit_logs | 0xD8FD8B | 0x5B |
| conversation_statistics | 0xD8FDE6 | 0x94 |
| conversation_model_statistics | 0xD8FE7A | 0x5A |

- 输出 JSON 信封（键名及偏移均实测；`serde_json` 序列化/BTreeMap 组装，行 24722–24904；键逐一对应 §7.2 恢复端校验）：

| 键 | 偏移(文件) | 键长 |
|---|---|---|
| `version` | 0xD8FED4 | 7 |
| `chatgpt_accounts` | 0xD8BF20 | 16 |
| `gateway_sessions` | 0xD8BF30 | 16 |
| `settings`（判读=gateway_settings 行集） | 0xD8C4B8 | 8 |
| `conversation_owners` | 0xD8FEDB | 19 |
| `project_owners` | 0xD8FEEE | 14 |
| `visit_logs` | 0xD8FEFC | 10 |
| `conversation_statistics` | 0xD8FF06 | 23 |
| `conversation_model_statistics` | 0xD8FF1D | 29 |

- 行数据以各表全列（含 `id`）序列化为 JSON 数组（各表备份 SELECT 均含 `id` 或主键列；如 accounts 为 `SELECT id, chatgpt_username, auth_status, plan_type, access_token, session_token, extra_cookies, refresh_token, remark, created_time, updated_time FROM chatgpt_accounts`）。导出内容**不加密**（明文 token 字段随 JSON 输出——与 §6“静态加密”并存，属备份明文设计，判读）。

### 7.2 恢复 `db::restore_backup`（ENTRY `0x00366de0`）

1. 打开 DB 后立刻 `execute_batch("BEGIN DEFERRED")`（@0xD8DBEB len 14，行 25581）→ 进入显式事务（函数退出前 `drop_in_place<rusqlite::transaction::Transaction>`，行 27216）。
2. 解析 JSON 并按 §7.1 的 9 个键校验：`version==2`（行 25635–25638）；随后逐键确认存在且为数组（行 25640–27074）。
3. 清空：`execute_batch(DELETE 批 @0xD8FF3A, 400)`（行 27076–27077）。该批按「子表→父表」顺序删除 8 表：`conversation_model_statistics → conversation_statistics → conversation_owners → project_owners → gateway_sessions → visit_logs → chatgpt_accounts → gateway_settings`（@0xD8FF3A 起 400 字节原文）。
4. 回填：8 条 `INSERT … ON CONFLICT … DO UPDATE`（执行点行号 / 字符串偏移 / 绑定参数数）：

| 表 | 偏移 | 长度 | 参数 | 执行点 |
|---|---|---|---|---|
| chatgpt_accounts | 0xD90193 | 0x273 | 11 | 行 25821 |
| gateway_sessions | 0xD9050E | 0x396 | 16 | 行 26118 |
| gateway_settings | 0xD908DA | 0xA1 | 3 | 行 26217 |
| conversation_owners | 0xD909D5 | 0x100 | 5 | 行 26356 |
| project_owners | 0xD90B2A | 0xF1 | 5 | 行 26490 |
| visit_logs | 0xD90C6C | 0x15E | 7 | 行 26646 |
| conversation_model_statistics | 0xD9102C | 0xEE | 4 | 行 26802 |
| conversation_statistics | 0xD90E34 | 0x1B2 | 8 | 行 26984 |

   - 冲突键：`ON CONFLICT(id) DO UPDATE`（@0xD90274/0xD90650/0xD90CEE 等）用于保留备份中的 `id`；`ON CONFLICT(user_name, chatgpt_username)`（@0xD8E38B，会话保存用同款）等按表主键/唯一键。
   - 缺省字段处理：条目缺少时间戳时会取 `SystemTime::now`（行 26948–26955），判读为缺省 `created_at/updated_at`。
   - 清空与回填的先后：由「BEGIN DEFERRED → 校验 → DELETE 批（唯一引用点 27077）→ 逐表 INSERT」的流程判读为**先清空后写入**；Ghidra 输出的基本块顺序非线性，未能逐块还原，标注为高置信判读。

## 8. gateway_settings 的 JSON 结构（序列化函数）

`gateway_settings.value` 均为 JSON 文本；键与结构由 serde 生成代码（Ghidra 导出的 Serialize/Deserialize 函数）还原：

| 设置键 | 结构 | 字段（serde visitor/serialize 证据） | 加密 |
|---|---|---|---|
| `mirror_proxy` | `MirrorProxyConfig` | `transport_mode`(14)、`enabled`(7)、`proxy_url`(9)、`username`(8)、`password`(8)、`nodes`(5，数组)；未知字段忽略（`__FieldVisitor::visit_str` ENTRY `0x0036bb80`） | 整值加密 |
| `mirror_proxy.nodes[]` | `MirrorProxyNodeConfig` | 序列化顺序 `id`(2)、`enabled`、`proxy_url`、`username`、`password`（`serialize` ENTRY `0x0036bc70`；visitor `0x0036bde0` 同字段集） | 随父值整值加密 |
| `transport_mode` 取值 | `UpstreamTransportMode` | `"reqwest"`(无标记)、`"wreq"`、`"curl-impersonate"`（`serialize` ENTRY `0x0036b830`，字符串由内联常量拼出） | — |
| `custom_scripts` | `CustomScriptConfig` | `scripts`(数组)、`trusted_cdn_sources`（名称池 0xD91300–0xD91500） | 导出内未见加密 |
| `custom_scripts.scripts[]` | `CustomScriptItem` | 6 字段：`id`、`enabled`、`name`、`language`、`position`、`content`（`serialize` ENTRY `0x0036c050`；`visit_str` ENTRY `0x0036c250`；`expecting`："struct CustomScriptItem" ENTRY `0x0036c310`） | 导出内未见加密 |
| `political_moderation` | `PoliticalModerationConfig` | visitor（ENTRY `0x0036c330`）接受长度 {4,5,7,7,8,8,0xc,0xe,0x10,0x16} 的键各一；已由 serialize/字符串池确证：`enabled`、`protocol`、`model`、`api_key`、`base_url`、`custom_terms`(12)、`limit_per_hour`(14)、`limit_per_five_minutes`(22)；4 字符键判读为 `mode`（默认值函数 `default_moderation_mode` ENTRY `0x00348720` 返回 `"relaxed"`）；16 字符键名未定位（不确定） | 整值加密 |
| `blocked_paths` | `BlockedPathsConfig` | `paths`、`hash_paths`（名称池 0xD91300–0xD91500；`Default`/`try_new`/`new`/`validate_blocked_path`/`normalize_blocked_path` 符号） | 导出内未见加密 |
| `extra_cookies`（两表 TEXT 列内嵌 JSON） | `Vec<SupplementalCookie>` | 字段：`name`、`value`、`domain`、`host_only`、`path`、`secure`、`http_only`、`expires`、`source`（`serialize` ENTRY `0x0036c730`；`visit_str` ENTRY `0x0036c940`） | 列值整体加密 |

## 9. 运行时代表性 SQL（配额、统计、会话）

以下均在 `.rodata` 应用区实测（偏移为字符串起点）：

- 配额/用量（`log_type='proxy'` 计入）：
  - `SELECT COUNT(*) FROM visit_logs WHERE username = ?1 AND log_type = 'proxy' AND created_at >= ?2`（@0xD8F77A）；
  - `SELECT COUNT(*) FROM visit_logs WHERE username = ?1 AND log_type = 'proxy' AND created_at >= CAST(strftime('%s', 'now', ?2) AS INTEGER)`（@0xD8F80B；`?2` 取 `'start of month'` / `'start of day'`，修饰符字面量 @0xD8F66D）——对应 `usage_count_current_period`；
  - `SELECT COUNT(*) FROM visit_logs WHERE log_type = 'proxy' AND created_at >= ?1`（@0xD8F892）与 `SELECT COUNT(*) FROM gateway_sessions WHERE created_at >= ?1`（@~0xD8F8DF）——对应 `operations_overview`。
- 会话读取（`get_gateway_session_by_token`）：包含 `... created_at + ?3 FROM gateway_sessions WHERE mirror_token = ?1 AND created_at >= ?2 LIMIT 1`（@0xD8E658；`created_at + ?3` 判读为有效期视图计算）。
- 凭证读取（`get_chatgpt_credentials_for_user`）：`SELECT access_token, session_token, COALESCE(extra_cookies, '[]') FROM chatgpt_accounts WHERE chatgpt_username = ?1 AND auth_status = TRUE LIMIT 1`（@0xD8E816 len 0x92）。
- 归属与统计：
  - `SELECT DISTINCT user_name FROM conversation_owners WHERE chatgpt_username = ?1 COLLATE NOCASE AND conversation_id = ?2`（@0xD8E970；查询级 `COLLATE NOCASE` 非 schema 约束）；
  - `SELECT COUNT(DISTINCT user_name), MIN(user_name) FROM conversation_owners ...`（@0xD8EAD4）；
  - 统计 upsert：`... message_count = message_count + 1, updated_at = excluded.updated_at ...`（@0xD8F0A2 / 0xD8F1EE）；`INSERT OR IGNORE INTO conversation_statistics ...`（运行期备份/按需回填 @0xD8EE5B，对应 `ensure_conversation_statistic` ENTRY 见导出 FUNCTION 表）；
  - 重置：`UPDATE conversation_statistics SET title = '', message_count = 0, conversation_counted = FALSE, updated_at = ?1 WHERE user_name = ?2` 与 `DELETE FROM conversation_model_statistics WHERE user_name = ?1`（`SET title = ''` @0xD8F5DF 附近；`reset_conversation_statistics`）。
- 会话写入（`save_gateway_session`）：大 INSERT（15 参数）@0xD8E17B len 0x4D4，`ON CONFLICT(user_name, chatgpt_username) DO UPDATE SET access_token/session_token/extra_cookies/login_mode/mirror_token/... = excluded.*`（冲突子句 @0xD8E38B），执行点行 13211–13212。
- `clear_stored_cloudflare_cookies`：动态表名模板 `SELECT id, extra_cookies FROM {}`（@0xD8DBF9）＋ `UPDATE {} SET extra_cookies = ?1 WHERE id = ?2`（@0xD8DC1F，拼接处呈现 `UPDATE  SET` 双空格），事务 `BEGIN DEFERRED`（@0xD8DBEB）；表集合在函数内构造为 `["chatgpt_accounts", "gateway_sessions"]`（行 8609–8611）。

## 10. 未确定项与限制

- `get_gateway_session_by_token` / `get_chatgpt_credentials_for_user` 在导出内**未见** `decrypt_secret` 调用；`gateway_sessions`/`chatgpt_accounts` 凭证列的运行时解密读取路径未被本导出证实（可能位于未选中的函数，或由调用方后处理）。**不确定**，未下结论。
- `PoliticalModerationConfig` 的 4 字符键判读为 `mode`（依据 `default_moderation_mode` 返回 `"relaxed"` 与字符串池）；16 字符键名未在池中定位。**不确定**。
- AES 具体模式（GCM/ChaCha 等）与 nonce 长度（12 B）为反编译切片形态判读；导出未给出算法名字符串。**判读**。
- `restore_backup` 的「先清空后回填」由块级证据组合判读（BEGIN DEFERRED 在行 25581、DELETE 批唯一引用在行 27077、INSERT 执行点 25821–26984），未逐块还原控制流。**判读**。
- 导出仅含 `SelectedFunctions=144` 个函数；不排除存在其他 db 相关函数（如其他读取/解密路径、close_chatgpt_memory 的具体 SQL）未覆盖。`close_chatgpt_memory`（ENTRY 见 FUNCTION 表）本次未展开。
- 未做动态验证（未运行二进制/数据库）；未核对 Python 参考实现（`D:\Project\Mirror\chatgpt-mirror-build`，范围外，仅 03 报告提及）。

## 附录 A：偏移速查（文件偏移）

- DDL 批：0xD8C916（len 0xF8B）｜表：0xD8C91F / 0xD8CB10 / 0xD8CC3A / 0xD8CF83 / 0xD8D027 / 0xD8D1F7 / 0xD8D3AE / 0xD8D62B｜索引：0xD8D175 / 0xD8D336 / 0xD8D5A2｜回填：0xD8D753
- 迁移：PRAGMA 0xD9112D / 0xD9118A；ALTER 0xD91150 / 0xD911AD / 0xD911F4 / 0xD91242 / 0xD91297 / 0xD912DE / 0xD9131B / 0xD91369；数据迁移 SQL 0xD8D8A1 / 0xD8D8FA / 0xD8DA49 / 0xD8D9D2 / 0xD8D954 / 0xD8D991
- 加密：`enc:v1:` 0xD8C699；base64url 表 0xD8C6AC；`sha256:` 0xD8C87C；`CREDENTIAL_ENCRYPTION_KEY` 0xD8C624 / 0xD8C676
- 备份：SELECT 0xD8FB02 / 0xD8FBAA / 0xD8FC9A / 0xD8FCCD / 0xD8FD31 / 0xD8FD8B / 0xD8FDE6 / 0xD8FE7A；信封键 0xD8FED4 / 0xD8BF20 / 0xD8BF30 / 0xD8C4B8 / 0xD8FEDB / 0xD8FEEE / 0xD8FEFC / 0xD8FF06 / 0xD8FF1D；DELETE 批 0xD8FF3A（400 B）；恢复 INSERT 0xD90193 / 0xD9050E / 0xD908DA / 0xD909D5 / 0xD90B2A / 0xD90C6C / 0xD90E34 / 0xD9102C
- 运行时 SQL：0xD8E658 / 0xD8E816 / 0xD8E970 / 0xD8EAD4 / 0xD8F0A2 / 0xD8F1EE / 0xD8F5DF / 0xD8F66D / 0xD8F77A / 0xD8F80B / 0xD8F892 / 0xD8E17B
- 函数（Ghidra ENTRY）：`init_db` 0x00349540｜`migrate_sensitive_rows` 0x0034b9b0｜`credential_key` 0x003478a0｜`encrypt_secret` 0x00347aa0｜`decrypt_secret` 0x00348050｜`mirror_token_hash` 0x00348630｜`export_backup` 0x003648e0｜`restore_backup` 0x00366de0｜`save_gateway_session` 0x003557d0｜`get_gateway_session_by_token` 0x003564f0｜`get_chatgpt_credentials_for_user` 0x00357600｜`ensure_gateway_sessions_force_chat_mode_column` 0x0036a060｜`ensure_gateway_sessions_proxy_node_id_column` 0x0036a800｜`ensure_gateway_sessions_quota_columns` 0x0036af30

（完）

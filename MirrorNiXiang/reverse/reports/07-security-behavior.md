# 07 · gateway 安全行为分析（凭证加密 / 鉴权 / SSRF / Cloudflare 绕过 / 代理链路 / 指纹 / 日志）

> 目标制品：`D:\Project\MirrorNiXiang\reverse\extracted\chatgpt-mirror-gateway`（ELF 64-bit LSB PIE，x86-64，Rust；23,252,912 B；sha256 `4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098`）
> 主证据：`D:\Project\MirrorNiXiang\reverse\reports\gateway-ghidra-export.txt`（Ghidra 导出：`ImageBase=0x00100000`，`SelectedFunctions=144`，32,335 行）
> 交叉证据：本目录 `03-gateway-static-analysis.md`、`02-cfbypass-analysis.md`、`01-target-inventory.md`；以及制品本体的只读字节级字符串定位
> 取证方式：**纯静态**。未访问网络、未访问 api.zxcbug.com、未运行二进制、未动态验证；本会话以 Python 只读方式对制品逐串复核了本报告使用的偏移
> 地址约定：`Ghidra ENTRY 0x00xxxxxxx` 一律等于**文件偏移 + 0x100000**（已验证：`db::credential_key` ENTRY `0x003478a0` ↔ 03 报告 §6.3 符号 vaddr `0x2478a0`；`DAT_00e8c624` ↔ 文件偏移 `0xd8c624`）；字符串偏移均指**文件偏移**（十六进制）
> 标注约定：【判读】=分析结论（非直接观测）；【未确认】=证据不足，需主代理复核；其余为直接观测值

## 0. 摘要

- 凭证加密为自实现 **`enc:v1:` 容器格式**：`db::credential_key`（ENTRY `0x003478a0`）→ `db::encrypt_secret`（ENTRY `0x00347aa0`）→ `db::decrypt_secret`（ENTRY `0x00348050`）。密钥 = `SHA-256(trim(CREDENTIAL_ENCRYPTION_KEY))`【判读】，加密 = 32 字节密钥 + 12 字节随机 nonce + AEAD（AES-256-GCM 形态【判读】）+ URL-safe Base64。
- `mirror_token` 不以明文落库：`db::mirror_token_hash`（ENTRY `0x00348630`）为摘要→十六进制字符串；`gateway_sessions.mirror_token` 列带 `UNIQUE(mirror_token)`（`0xd8cf5a`），查询一律以哈希值作参数（如 `0xd8e658` SQL）。
- 管理面鉴权 = 单值 `GATEWAY_ADMIN_SECRET`（`0xd96422`）+ 头 `x-gateway-secret`（`0xd86020`）；失败响应 `{"message":"缺少或无效的网关认证信息"}`（`0xd8a867`）。`api::require_gateway_admin`（vaddr `0x1dd8a0`，03 §6.3）**不在本 Ghidra 导出 144 函数内**，比较实现未确认。
- 归属校验 = `conversation_owners` / `project_owners` 表 + `conversation_belongs_to_user(_c)` / `project_belongs_to_user(_c)`，判定逻辑为「恰好 1 个 owner 且等于当前用户」【判读】；代理路径另有 `enforce_conversation_owner` / `enforce_project_owner`（符号）。
- SSRF 防护集中在「外链代理」路径：拒绝内网/localhost/非公网（`0xd685d6`、`0xd688c5`）+ 内部固定上游域名白名单（`0xd68634`，名单起点 `0xd6868f`）；`unsafeSkipTargetOriginCheck=true`（`0xd634d0`）为本次高关注未确认项。
- Cloudflare 绕过：gateway 以 Bearer 调 cfbypass `/cloudflare5s/bypass-v1`（`0xd84ec8`），结果进本地缓存（RwLock+信号量+Instant）并可与 `extra_cookies` 加密落库（`update_gateway_session_extra_cookies` ENTRY `0x00356d50`）。
- 浏览器指纹：`proxy::apply_chrome_146_network_identity`（ENTRY `0x0025c8b0`）注入 Chrome/146 UA（`0xd64ba2`，101 B）与 4 组 `sec-ch-ua*` 头（`0xd68ea6`/`0xd68ed7`/`0xd68eed`）。
- 日志为 tracing 结构化事件（`RUST_LOG` `0xe35fc2`；事件含 `file:line` 元数据，如 `src/proxy.rs:1112`、`src/api.rs:1539`、`src/db.rs:789`）。

## 1. 凭据加密 / 解密与 key derivation

### 1.1 密钥派生（`chatgpt_mirror_gateway::db::credential_key`，Ghidra ENTRY `0x003478a0`，BODY `0x003478a0–0x00347a65`）

- 读取环境变量 `CREDENTIAL_ENCRYPTION_KEY`（Ghidra 引用 `&DAT_00e8c624`，长度 `0x19`=25；制品侧串 `0xd8c624`）。
- 分支一（env 缺失）：返回错误串 `CREDENTIAL_ENCRYPTION_KEY 未配置`（文件偏移 `0xd8c676`，35 B，与函数内 `__rust_alloc(0x23)` 一致）。
- 分支二（存在）：`core::str::trim_matches` 去首尾空白；若长度 `< 0x20`（32）→ 错误串 `CREDENTIAL_ENCRYPTION_KEY 长度至少需要 32 个字符`（`0xd8c63d`，57 B，与 `__rust_alloc(0x39)` 一致）。
- 分支三（≥32）：`<D as digest::Digest>::digest` 计算 32 字节摘要并作为派生密钥返回（返回结构 32 B + 原 key 引用）。结合 32 字节输出、相邻字面量 `sha256:`（`0xd8c87c`）以及 `.text` 内出现内联 SHA-2 代码片段（文件偏移 `0x24bee2` 邻域）→ **判读为 SHA-256**；`sha2` 具体 crate 名未在导出符号中出现【未确认】。
- 注意：**无盐、无 KDF 拉伸**——密钥空间 = env 值本体（≥32 字符要求），env 泄露即可直接解库（见 §10 G1）。

### 1.2 加密（`db::encrypt_secret`，ENTRY `0x00347aa0`，BODY `0x00347aa0–0x00347f84`）

- 空串直通；若输入已以 `enc:v1:` 开头（按 4 字节字面量 XOR 掩码 `0x3a636e65`/`0x3a31763a` 判定，即 `enc:` + `:v1:`）则原样返回（幂等，避免双重加密）。
- 调 `credential_key` → `crypto_common::KeyInit::new_from_slice(..., 0x20)`（32 字节密钥）→ `OsRng::fill_bytes(..., 0xc)`（**12 字节随机 nonce**）→ `<Alg as aead::Aead>::encrypt`。
- 组包：`nonce(12) || 密文(+AEAD tag)` → `base64::Engine::encode`（引擎引用 `&DAT_00e8c6a9`；制品侧 URL-safe 字母表 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_` 位于 `0xd8c6aa` 邻域，03 §10.2 记 `0xd8c6ac`）→ 最终字符串 `enc:v1:<base64>`（前缀字面量 `0xd8c699`）。
- 失败错误串：`敏感凭据加密失败`（`0xd8c7ec`，24 B）。
- 加密算法具体类型名（`Alg`）未在导出中显现；按「32 字节密钥 + 12 字节 nonce + aead 0.5.2 + aes 0.8.4」组合**判读为 AES-256-GCM**【判读】。

### 1.3 解密（`db::decrypt_secret`，ENTRY `0x00348050`，BODY `0x00348050–0x00348517`）

- 长度 `< 7` 或前缀非 `enc:v1:` → **原样返回**（兼容历史明文；这是 G2 风险面）。
- 前缀匹配后从第 7 字节起做 Base64 解码（失败 → `敏感凭据编码损坏`，`0xd8c846`）。
- 解码产物长度 `<= 0xc`（12）→ `敏感凭据密文损坏`（`0xd8c82e`）。
- `credential_key` → `KeyInit::new_from_slice(..., 0x20)` → `<Alg as aead::Aead>::decrypt(nonce=前 12 字节, 密文=其余)`；解密失败 → `敏感凭据解密失败，请检查密钥`（`0xd8c804`，42 B）。
- 明文 `String::from_utf8` 失败 → 闭包 `decrypt_secret::{{closure}}`（ENTRY `0x00348570`）产出 `敏感凭据不是有效 UTF-8`（`0xd8c85e`，30 B，与闭包内 `__rust_alloc(0x1e)` 一致）。

### 1.4 落库字段与启动迁移（`db::migrate_sensitive_rows`，ENTRY `0x0034b9b0`）

- 迁移由 `db::init_db`（ENTRY `0x00349540`）在启动时调用（导出 CALLS 行 6484–6487：`ensure_gateway_sessions_*` ×3 → `migrate_sensitive_rows`）。
- 函数调用 `encrypt_secret` 与 `mirror_token_hash`（导出 CALLS 行 7540–7542），并包含整行重写 SQL：
  - `UPDATE chatgpt_accounts SET access_token = ?1, session_token = ?2, extra_cookies = ?3, refresh_token = ?4 WHERE id = ?5`（`0xd8d9d2`）
  - `UPDATE gateway_sessions SET access_token = ?1, session_token = ?2, extra_cookies = ?3, mirror_token = ?4 WHERE id = ?5`（`0xd8da49`）
- 加密字段集合（由 DDL/SQL 观测）：`gateway_sessions` = access_token / session_token / extra_cookies；`chatgpt_accounts` = access_token / session_token / extra_cookies / refresh_token。
- 其他调用点（导出 CALLS 行号）：`save_gateway_session` 13396、`update_gateway_session_extra_cookies` 14119、`clear_stored_cloudflare_cookies` 9252/9253（先解密再重写）、`save/get_mirror_proxy_config` 8334/7945（mirror_proxy 配置含 `nodes` 凭据）、`save/get_political_moderation_config` 10745/10333（审查服务 API key）。

## 2. mirror token 哈希

- 实现：`db::mirror_token_hash`（ENTRY `0x00348630`，BODY `0x00348630–0x003486ec`）。流程：`digest` → `FromIterator<char>`（字节→字符映射）→ `fmt::format_inner` 输出 `String`。即**摘要后转十六进制字符串**【判读：十六进制；大小写与是否带前缀未逐字节确认】。
- 存储：`gateway_sessions` 表列名 `mirror_token`，DDL 含 `UNIQUE(mirror_token)`（`0xd8cf5a`；表 DDL 起点 `0xd8cc3a` 窗口）。`INSERT INTO gateway_sessions (...)`（`0xd8e184`）。
- 查询与删除均以**哈希值**为参数：
  - `get_gateway_session_by_token`（ENTRY `0x003564f0`）在取行前调用 `mirror_token_hash`（CALLS 行 13759），随后 `prepare` SQL（Ghidra `&DAT_00e8e64f`, len `0x14e`=334；制品 SQL 词元起始 `0xd8e658`）：
    `SELECT user_name, chatgpt_username, access_token, session_token, extra_cookies, login_mode, mirror_token, isolated_session, force_chat_mode, limits, proxy_node_id, daily_quota, monthly_quota, created_at + ?3 FROM gateway_sessions WHERE mirror_token = ?1 AND created_at >= ?2 LIMIT 1`
  - `delete_gateway_session_by_token`（ENTRY `0x00358780`）→ `DELETE FROM gateway_sessions WHERE mirror_token = ?1`（`0xd8e92f`），CALLS 行 15246 调用哈希函数。
  - `update_gateway_session_extra_cookies`（ENTRY `0x00356d50`）→ `UPDATE gateway_sessions SET extra_cookies = ?2, updated_at = ?3 WHERE mirror_token = ?1`（0xd8e780–0xd8e830 窗口），CALLS 行 14119/14120 = encrypt + hash。
  - `db::close_chatgpt_memory`（ENTRY `0x00360dd0`）同样调用 `mirror_token_hash`（CALLS 行 21788）；具体用途未在导出中展开【未确认】。
- 会话时间窗常量：`get_gateway_session_by_token` 内出现 `SystemTime::now` / `duration_since` 与常量 `0x12750`（=75600 秒，21 小时）及回退值 `-0x93A80`（=604800 秒，7 天）【判读：会话有效期/查询回溯窗口；未逐指令确认对应 SQL 参数】。
- 相邻字面量 `sha256:`（`0xd8c87c`）与符号 `api::token_fingerprint` 并存；`sha256:` 的调用点未在导出函数中出现【未确认，勿过度解读】。制品中不存在大写 `Sha256` 字样（count=0）。

## 3. 管理员认证

- 主函数：`api::require_gateway_admin`（03 §6.3：vaddr `0x1dd8a0`，size `0x50f`）＋根级符号 `has_gateway_admin_secret`。**两者均不在本 Ghidra 导出（144 函数）内**，以下为字符串/符号级证据，逐指令实现未确认【未确认】。
- 凭证载体（03 §10.1 偏移复核）：
  - 头 `x-gateway-secret`（`0xd86020`，与 `isolated_session`、`limit_per_minute`、`connector_search`、`workspace_search` 同属"设置字段/头部名"粘连区 `0xd85fb0+`）
  - `Authorization`（`0xd64cf2` / `0xd8506d` / `0xd888a5`）、`Bearer`（`0xd64c22` / `0xd8841e` / `0xd9b2ec`）
  - env `GATEWAY_ADMIN_SECRET`（`0xd96422`，制品内仅 1 处；相邻为 `src/api.rs` 路径字面量与 `DATABASE_PATH`/`MIRROR_API_PREFIX`/`ADMIN_UPSTREAM`/`DJANGO_UPSTREAM` 配置区）
- 失败响应：`缺少或无效的网关认证信息`（`0xd87fe6`；JSON 形态 `{"message":"缺少或无效的网关认证信息"}` 位于 `0xd8a867`，其前紧邻 HSTS 头 `max-age=31536000; includeSubDomains; preload`）。
- 相邻管理面辅助消息（同一粘连窗口 `0xd87fe6–0xd88060`）：`当前网关未实现 refresh_token 刷新`（`0xd8800a`）、`token 校验失败`、`session_token 无法换取 access_token`、`session_token 校验失败: api/auth/session 返回状态 `（`0xd88106`）、`# Netscape HTTP Cookie File` 导入相关提示——即管理面支持导入 ChatGPT 会话并校验上游 session。
- 密钥域：与用户侧 `x-mirror-token`（`0xd6466b`）分离；但 cfbypass 侧无独立密钥（见 §6.4 G3）。
- 比较是否常量时间：03 §10.9 已指出 `subtle` 仅有 `black_box`（`0xbb4f30`）、未见 `ConstantTimeEq`；本导出同样未见 → **不做"恒时比较"结论**【未确认】。未见登录/管理端点速率限制或失败锁定证据（全静态）。

## 4. 会话与归属校验

### 4.1 会话记录（`gateway_sessions`）

- 写入：`db::save_gateway_session`（ENTRY `0x003557d0`）→ `INSERT INTO gateway_sessions (user_name, chatgpt_username, access_token, session_token, extra_cookies, login_mode, mirror_token, isolated_session, force_chat_mode, limits, proxy_node_id, daily_quota, monthly_quota, created_at, updated_at) ... ON CONFLICT(user_name, chatgpt_username) DO UPDATE ...`（`0xd8e184`）+ `SELECT` 回读 + 紧随的 `get` 语句（同窗口 `0xd8e184–0xd8e780`）；CALLS 行 13396–13399 调 `encrypt_secret` / `mirror_token_hash` / `now_ts`。
- 读取：`get_gateway_session_by_token`（ENTRY `0x003564f0`，见 §2），带 `created_at >= ?2` 时间窗过滤 + `created_at + ?3` 过期语义【判读】。
- 更新：`update_gateway_session_extra_cookies`（ENTRY `0x00356d50`）；删除：`delete_gateway_session_by_token`（ENTRY `0x00358780`）、`delete_gateway_sessions_by_user`（ENTRY `0x00357d00`，`DELETE FROM gateway_sessions WHERE user_name = ?1`，`0xd8e8a8`）。
- 单用户缓存：`tracked (std::time::Instant, GatewaySessionRecord)`、`get_cached_session`（符号）→ 会话记录在内存中带 TTL 缓存【判读】。
- 列迁移：`ensure_gateway_sessions_force_chat_mode_column`（ENTRY `0x0036a060`）/`ensure_gateway_sessions_proxy_node_id_column`（ENTRY `0x0036a800`）/`ensure_gateway_sessions_quota_columns`（ENTRY `0x0036af30`）由 `init_db` 串行调用。

### 4.2 归属校验（conversation / project）

- 函数族：`db::claim_conversation_owner`（ENTRY `0x00358cd0`）、`conversation_belongs_to_user`（ENTRY `0x00359d60`）、`conversation_belongs_to_user_c`（ENTRY `0x0035a110`）、`get_owned_conversation_ids`（ENTRY `0x0035a4b0`）；project 对应 `claim_project_owner`（ENTRY `0x0035ae60`）、`project_belongs_to_user`（ENTRY `0x0035b4a0`）、`project_belongs_to_user_c`（ENTRY `0x0035b850`）、`get_owned_project_ids`（ENTRY `0x0035bc00`）。
- SQL（制品偏移）：
  - 认领：`INSERT OR IGNORE INTO conversation_owners (chatgpt_username, conversation_id, user_name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)`（`0xd8ea14`）；项目版 `INSERT OR IGNORE INTO project_owners ...`（`0xd8ec89`）。
  - 判定：`SELECT COUNT(DISTINCT user_name), MIN(user_name) FROM conversation_owners WHERE chatgpt_username = ?1 COLLATE NOCASE AND conversation_id = ?2`（`0xd8ead4`，`conversation_belongs_to_user_c` 内 `prepare` len `0xbf`=191）。
  - 列表：`SELECT conversation_id FROM conversation_owners WHERE chatgpt_username = ?1 COLLATE NOCASE GROUP BY conversation_id HAVING CO…`（`0xd8eb8x` 窗口）。
  - 兼容视图：`SELECT DISTINCT user_name FROM conversation_owners WHERE chatgpt_username = ?1 COLLATE NOCASE AND conversation_id = ?2`（`0xd8e970`）。
- 判定逻辑（`conversation_belongs_to_user_c`）：结果 `count==1` 且 `MIN(user_name)` 与当前用户名按长度+`bcmp` 相等 → true；`count!=1`（含多 owner）→ false；SQLite 错误 → 返回 `Err`【判读】。
- 代理路径强制：`proxy::enforce_conversation_owner` / `enforce_project_owner`、`claim_conversation_ids_from_json_response`、`filter_conversation_collection_body/value`、`collect_project_ids_from_request`、`update_conversation_titles_from_body`（03 附录 A 符号）→ 代理响应会过滤他人会话、并静默认领新会话【判读，函数体未在导出中】。
- Cookie 作用域：`db::SupplementalCookie::is_mirror_local`（ENTRY `0x00348780`）、`is_current_at`（ENTRY `0x003488e0`）、`scope_identity`（ENTRY `0x00348920`）、`applies_to_url`（ENTRY `0x00348e40`，且其 CALLS 行 5424 调 `scope_identity`）→ supplemental cookie 按域/作用域/时效过滤后再合并【判读：函数体未逐行读取】。
- 统计侧：`record_conversation_message`（ENTRY `0x0036cd60`）、`ensure_conversation_statistic`、`conversation_statistics_for_users` / `_detail`（符号/导出均有）→ 管理员可见每用户会话统计。

## 5. SSRF / URL rewrite 防护

### 5.1 已确认的防护串与结构（符号函数体不在导出中【未确认】，以下为字符串证据）

| 检查点 | 消息（文件偏移） | 备注 |
| --- | --- | --- |
| 外链代理目标主检查 | `外链代理拒绝内网、localhost 或非公网主机`（`0xd685d6`） | 对应 `proxy::is_public_external_ip`（vaddr `0x149d60`，03 §6.3）与 `proxy::is_allowed_external_proxy_host`（`0x149230`）【判读关联】 |
| 解析结果复检 | `外链代理目标解析到非公网地址`（`0xd688c5`） | 同上；另有 `外链代理目标缺少主机` / `外链代理目标缺少端口`（同窗口） |
| 协议限制 | `外链代理仅支持 http/https 上游`（0xd685f5 邻域） | 仅 http/https，无 socks（与 mirror proxy 的 socks5/5h 支持不同面） |
| 内部固定上游 | `内部固定上游域名不在代码白名单中`（`0xd68634`）+ `内部固定上游仅支持 https`（0xd6865c 邻域） | 白名单域列表 `0xd6868f–0xd688a5`，共约 24 个域：static.cloudflareinsights.com、cdn.oaistatic.com、cdn.openai.com、images.openai.com、api.mapbox.com、events.mapbox.com、sdmntpr*.oaiusercontent.com ×3、www.google.com、persistent.oaistatic.com、connector-openai-deep-research.web-sandbox.oaiusercontent.com、web-sandbox.oaiusercontent.com、t0/t1/t2/t3.gstatic.com、lh3.googleusercontent.com、www.googletagmanager.com、www.google-analytics.com、chat.openai.com、ws.chatgpt.com、tt.chatgpt.com、feather.openai.com、skybridge.oaistatic.com、cdn.auth0.com |
| 审查模型地址 | `审查模型地址必须解析到公网 IP`（`0xd643de`） | moderation provider 出站也做公网校验 |

### 5.2 mirror proxy URL 校验（`validate_mirror_proxy_url` / `normalize_proxy_fields` 等符号）

- 消息（`0xd645f2–0xd64719` 窗口）：`仅支持 http://、socks5://、socks5h:// 代理地址`（`0xd64680` 邻域）、`代理地址缺少端口`、`代理地址缺少主机名`、`代理地址不是合法 URL`、`代理地址无效:`。
- 支持 socks5 / socks5h（字面量 `0xd6469a` / `0xd646a6`）；`socks5` 由本地解析、`socks5h` 远端解析（与 02 §6.2 的 relay 语义一致）——**是否对 socks5 目标做公网 IP 校验未确认**【未确认】。
- 脱敏：`redact_proxy_url`、`sanitized_proxy_url`、`sanitized_proxy_config`（03 附录 A 符号）→ 配置回显/日志中剔除凭据【判读】。

### 5.3 URL rewrite / 重定向改写

- 符号（03 附录 A）：`proxy::rewrite_location`、`rewrite_origin_prefix_to_local`、`rewrite_deep_research_connector_location`、`redirect_response_with_status`、`absolutize_estuary_content_urls`（estuary 内容 URL 绝对化）、`web_sandbox_asset_fallback_url`、`connector_fallback_response`。
- 内嵌 JS 片段（`0xd65a1c–0xd65b9x` 窗口）演示把 `wss://ws.chatgpt.com/` 前缀重写为 `window.location.host` 的本地 WS 前缀，返回对象形如 `{changed: true, value: localWsBase + ...}`——**归属未确认**（可能是内嵌默认脚本模板或响应注入器的一部分）【未确认】。
- 静态资源重写/缓存：`apply_static_asset_cache_headers`、`has_static_asset_extension`（符号）；静态缓存头样例 `public, max-age=31536000, immutable` 与 `cloudflare-cdn-cache-control`（0xd85080 窗口）。
- `unsafeSkipTargetOriginCheck=true`（`0xd634d0`，出现于 `初始化 HTTP 客户端失败` / `初始化 wreq 客户端失败` 邻域）——**含义未确认**：疑似 curl-impersonate/wreq 侧跳过 TLS 目标校验的选项串；建议主代理在 Ghidra 中对引用点反编译复核（列入 §10 G7）。

## 6. Cloudflare bypass 与 cookie 缓存

### 6.1 调用链（gateway → cfbypass）

- URL 字面量 `/cloudflare5s/bypass-v1`：`0xd84ec8`、`0xd88ee0`、`0xd9d4c4`（03 §7.4）；配置 `CF_BYPASS_URL`（`0xd964da`）、`CF_BYPASS_PROXY_SERVER`（`0xd964e7`）。
- 主实现：`proxy::get_cfbypass_payload_with_proxy_server::{{closure}}`（Ghidra ENTRY `0x002f6040`；**该函数反编译失败**：varnode 错误，仅 CALLS 可用）。CALLS（导出行 2780–2784, 2795–2810）证明其调用：`cf_cache_key_with_proxy`、`cfbypass_fallback_client`、`normalize_cfbypass_cookies`、`normalize_cfbypass_target_url`、`reqwest RequestBuilder::bearer_auth/json/send`、`serde_json::from_slice`、`tokio RwLock(read/write)`、`batch_semaphore`、`Instant::now`、`url::ParseOptions::parse`、`tracing` 事件。
- 缓存读路径：`proxy::get_cached_cfbypass_payload_with_proxy_server::{{closure}}`（ENTRY `0x002f94a0`，同样反编译失败）——CALLS 只有 RwLock read / HashMap / Instant / String::clone，无网络调用 → **纯缓存读取**【判读】。
- 缓存清除：`clear_cfbypass_cache_entry_with_proxy_server::{{closure}}`（仅以 drop_in_place 符号出现在导出第 391 行，函数体未导出）；启动时 `main` 调 `new_cf_bypass_cache`（CALLS 32263）。
- 语义消息：
  - `cfbypass 目标已归一化到根路径`（`0xd84ea1`）→ 请求目标先归一化（配合 `normalize_cfbypass_target_url`）。
  - `cfbypass 返回成功但 cookies 为空，视为失败`（`0xd84edf`）→ 调用方自检（缓解 02 R5 的误判）。
  - `cfbypass 请求失败`（`0xd84f15`）、`cfbypass fallback client`（`0xd84f2a`）、`cf_clearance`（`0xd84f42`）、`default|proxy=`（`0xd84f54`）→ fallback 客户端与直连/代理标记。
  - CF 拦截重试：`首次上游请求命中 Cloudflare 拦截，刷新 cfbypass 缓存后重试一次`（`0xd68c78`）；`Cloudflare 重试前刷新 cfbypass 缓存失败，继续使用原请求重试`、`Cloudflare 重试前已刷新并保存 cfbypass cookies重试`（0xd68cb5/0xd68cee 窗口）。
  - 预热：`开始异步预热 CF bypass 缓存`（`0xd9d531`）、`CF bypass 缓存预热失败，将在登录时重试`、`CF bypass 缓存预热失败，稍后重试`、`CF bypass 缓存预热完成`（`0xd9d554` 起；`src/main.rs` 前缀 = 启动期行为）。
- 调用方鉴权：`reqwest::RequestBuilder::bearer_auth`（CALLS）→ Bearer 直发 cfbypass；**gateway 二进制内不存在 `CF_BYPASS_SECRET` 字面量（count=0）**，结合 02 §2（入口脚本 `CF_BYPASS_SECRET←GATEWAY_ADMIN_SECRET`）→ **判读 gateway 复用 `GATEWAY_ADMIN_SECRET` 作为 cfbypass Bearer**【判读，未逐指令确认】（风险 G3）。

### 6.2 网关侧 cookie 处理（家族符号）

- `is_safe_cfbypass_cookie_name`、`normalize_cfbypass_cookies`、`merge_extra_cookies_with_cfbypass`、`persist_cfbypass_cookies_for_request`、`supplemental_has_cloudflare_cookie`（03 附录 A；与 02 §5「只透出 cf_clearance/__cf_bm/__cflb/_cfuvid」对应）。
- 落库：`update_gateway_session_extra_cookies`（ENTRY `0x00356d50`，CALLS encrypt+hash）→ `extra_cookies` 列加密存储、按 mirror_token 会话绑定；`clear_stored_cloudflare_cookies`（ENTRY `0x0034eec0`）先 `decrypt_secret` 再 `encrypt_secret`（CALLS 9252/9253）→ 定向清除已存 CF cookie【判读】。
- 读取侧窗口（0xd8e780–0xd8e830）的 `UPDATE gateway_sessions SET extra_cookies = ?2, updated_at = ?3 WHERE mirror_token = ?1` 表明：按 token 取会话时会回写（含新 cfbypass cookie 与续活时间）【判读】。
- cfbypass 服务本身的 URL/端口/DNS/cookie 策略见 02 报告 §3/§5/§8（本报告不重复，结论一致）。

## 7. 代理链路

### 7.1 三种上游传输（transport）

- 错误串（`0xd64509` 与 `0xd88b37` 窗口，均带 `src/proxy.rs` 前缀）：`reqwest 请求失败:`、`wreq 请求失败:`、`构造 curl-impersonate 请求失败:`、`curl-impersonate 请求失败:` → 进程内并存三套 HTTP 客户端（reqwest / wreq+BoringSSL / isahc+libcurl）；初始化串：`初始化 HTTP 客户端失败:`、`初始化 wreq 客户端失败:`（0xd634ba 窗口）、`初始化 curl-impersonate 客户端失败:`（0xd645f2 窗口）。
- 依赖佐证：`wreq 6.0.0-rc.31` + `btls/tokio-btls` + `isahc 2.0.1` + `curl 0.4.50`（03 §5/§4.4）；`LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so`（01 §8 · 03 §0.2）。
- 传输模式配置：`UpstreamTransportMode` 枚举（serde 符号；导出行 28260/28458）+ `gateway_settings.mirror_proxy` 配置字段 `messagetransport_modeenabledproxy_urlnodes`（`0xd8766d` 窗口）→ 管理面可选 transport（`MirrorProxyConfig`/`MirrorProxyNodeConfig`）。

### 7.2 代理选择与协议

- 家族符号：`build_http_client` / `build_upstream_http_client` / `new_mirror_proxy_runtime` / `select_mirror_proxy_node` / `effective_mirror_proxy_url` / `external_proxy_path_for_url` / `account_client_pool_key_from_headers` / `is_internal_fixed_upstream_url` / `is_proxyable_upstream_target`（03 附录 A）。
- 账号绑定节点：消息 `账号绑定的代理节点  未启用或不存在`、`启用代理时必须填写代理地址`（0xd645b0 窗口）；测试入口消息 `代理端口可连接，上游返回 HTTP …`（0xd88b70 窗口）→ 管理面 `POST /api/test-mirror-proxy-config`。
- 目录：`mirror_proxy` 设置读写 SQL `SELECT value FROM gateway_settings WHERE key = 'mirror_proxy'`（`0xd8d954`/`0xd8dabf`）。
- `CF_BYPASS_PROXY_SERVER`（`0xd964e7`）单独指定 cfbypass 请求的出口代理；`TRUSTED_PROXY_IPS`（`0xd96511`）用于信任来源判定【判读】。

### 7.3 WebSocket 桥

- `proxy::proxy_chatgpt_ws_via_configured_proxy::{{closure}}`（ENTRY `0x0023a100`）与其内层闭包（ENTRY `0x0028b4f0`，实现 tracing 事件）；drop 符号同时出现 `connect_chatgpt_ws_via_http_proxy` / `connect_chatgpt_ws_via_socks_proxy`（导出行 73–78）→ WS 可经 HTTP 代理或 SOCKS 代理连接上游。
- WS 头写入错误串：`写入 WebSocket Authorization 失败:`、`写入 WebSocket oai-device-id 失败:`、`写入 WebSocket Referer/Accept-Language/子协议 失败:`（0xd64c80 窗口）；`不支持的 WebSocket 代理协议`（0xd6472f 窗口）。

### 7.4 内部组件拓扑（与 01/02 交叉）

- gateway（`PORT`=40002）→ `DJANGO_UPSTREAM`（`0xd96462`，默认 127.0.0.1:8000）/ `ADMIN_UPSTREAM`（`0xd96454`）→ cfbypass（127.0.0.1:8001）；`/0x/*path`（`0xda10a5`）为管理上游通道（03 §7.2）。全部内部调用为 loopback 明文 HTTP；`NO_PROXY=localhost,127.0.0.1`（01 §4）。
- 客户端 IP 传递：`x-chatgpt-mirror-client-ip`（`0xd64726`）；来源解析候选头 `x-real-ip`（`0xd68e25`）、`true-client-ip`（`0xd68e2e`）、`x-forwarded-for`（`0xd68e3c`）、`cf-connecting-ip`（`0xd54a90`）→ 结合 `TRUSTED_PROXY_IPS`（`0xd96511`）决定可信度【判读】。

## 8. 浏览器指纹

- `proxy::apply_chrome_146_network_identity`（ENTRY `0x0025c8b0`，size `0x4b8`；03 §6.3 vaddr `0x15c8b0`）。行为：向请求头表 `http::HeaderMap::try_insert2` 插入下列头（插入失败路径为 `unwrap_failed` → panic）：

| 头 | 值 | 值偏移/长度 |
| --- | --- | --- |
| User-Agent（首插） | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36` | `0xd64ba2`，101 B（与函数内 `lVar1 == 0x65` 校验一致） |
| `sec-ch-ua` | `"Chromium";v="146", "Not_A Brand";v="99"` | 名 `0xd68ea6`(9B) / 值 `0xd68eaf`(40B) |
| `sec-ch-ua-full-version` | `"146.0.7680.177"` | 名 `0xd68ed7`(22B) / 值 `0xd54aa0`(16B，含引号) |
| `sec-ch-ua-full-version-list` | `"Chromium";v="146.0.7680.177", "Not_A Brand";v="99.0.0.0"` | 名 `0xd68eed`(27B) / 值 `0xd68f08`(57B) |

- 版本自洽：`146.0.7680.177` 与镜像内 Chromium 包版本一致（01 §9）；默认 UA 版本字面量 `Chrome/146.0.0.0`（`0xd64be9`，03 §0.2）；`.rodata` 内另存历史 Chrome UA 池（0xda29d2 起，Chrome/100–110 等，03 §10.6）→ 属 wreq 字面量池，**是否运行时随机化未确认**【未确认】。
- 设备标识：`oai-device-id`（`0xd64c07`；WS 头写入路径见 §7.3）；`browser_oai_device_id` / `server_oai_device_id` / `server_oai_device_cookie`（符号）→ 浏览器侧与服务端侧 device id 分流【判读】。
- TLS/HTTP2 指纹：静态链入 BoringSSL（`bssl` 698 符号）与 wreq 栈（03 §4.4）；`curl-impersonate` 提供 curl 系指纹（LD_PRELOAD）。
- 与 cfbypass 的 UA 配对：cfbypass 返回体携带 `user_agent`（02 §1.4），cf_clearance 与 UA 强绑定；gateway 侧按会话保存/复用【判读，来自 02 §5.5】。

## 9. 日志与隐藏行为

### 9.1 日志系统

- tracing 结构化事件：闭包样例 `proxy_request::{{closure}}::{{closure}}`（ENTRY `0x0028be10`）与 `proxy_chatgpt_ws_via_configured_proxy::{{closure}}::{{closure}}`（ENTRY `0x0028b4f0`）均为 `tracing_core::event::Event::dispatch(__CALLSITE, …)` + `log` crate 兜底（阈值比较 `MAX_LOG_LEVEL_FILTER`）。
- 过滤：`RUST_LOG`（`0xe35fc2`，tracing-subscriber env-filter 路径旁）→ 由 `init_tracing`（main CALLS 32260）初始化。
- 事件元数据（`file:line` 字面量，可直接定位源码结构）：
  - `event src/api.rs:1539 / 1555 / 1576 / 1594 / 1760 / 1768 / 1782 / 1882 / 2685`（`0xd892a9–0xd8938c` 窗口；target `chatgpt_mirror_gateway::api`，另见 `response_was_json` at `0xd8938c`）
  - `event src/proxy.rs:1112 / 1131 / 1153 / 1609 / 1628 / 3294 / 3373`（`0xd8519c–0xd851ed` 窗口；target `chatgpt_mirror_gateway::proxy`，相邻结构名 `struct CfBypassCookieEntry`）
  - `event src/db.rs:789`（`0xd9154f` 窗口；target `chatgpt_mirror_gateway::db`）
- 启动日志：`gateway upstreams configured`、`gateway listening on http://`（`0xd96651`；第二副本 `0xda127b`）；启动失败族 `初始化数据库失败:`、`读取政治敏感内容屏蔽配置失败:`、`初始化镜像代理客户端失败:`（同窗口）。
- 疑似脱敏函数（符号，函数体未在导出中）：`cookie_names_for_log`、`redact_proxy_url`、`log_chatgpt_document_response`、`sanitized_proxy_config`——**建议复核 `cookie_names_for_log` 是否确实只记名不记值**【未确认】。

### 9.2 隐式 / 后台行为（逐条给证据）

1. **会话续活与 cookie 静默回写**：按 token 取会话的同一事务窗口含 `UPDATE gateway_sessions SET extra_cookies = ?2, updated_at = ?3 WHERE mirror_token = ?1`（0xd8e780–0xd8e830 窗口）；调用侧 `update_gateway_session_extra_cookies`（ENTRY `0x00356d50`）加密落库。
2. **启动自动加密迁移**：`init_db`（ENTRY `0x00349540`）→ `ensure_gateway_sessions_*` ×3（CALLS 6484–6486）→ `migrate_sensitive_rows`（ENTRY `0x0034b9b0`）→ 对旧明文行整行重写（`0xd8d9d2`/`0xd8da49`）。
3. **CF cookie 预热**：`src/main.rs` 上下文 `开始异步预热 CF bypass 缓存`（`0xd9d531`）→ 进程启动即可能主动向 chatgpt.com（经 cfbypass）取 cookie，即使无用户请求。
4. **用户内容外发审查**：moderation 请求字段 `x-api-key`、`anthropic-version: 2023-06-01`（`0xd6436d` 窗口；另有 `instructions/input/max_output_tokens`/`systemInstruction/parts` 等 OpenAI/Vertex 形态 0xd642e8 窗口；`不支持的审查 API 格式` 0xd6431x 窗口）；前端提示串 `…正在由管理员配置的后端模型判定。审查通过后会自动继续发送。`（0xd84032 窗口）；响应头 `x-mirror-moderation`（0xd85000 窗口）；频率限制消息 `您每小时最多可调用审查模型  次`（0xd68900 窗口）。
5. **内容注入能力**：`custom_scripts`（settings key `0xd8dc73`）→ `render_custom_script` + `insert_before_closing_tag` / `insert_after_opening_tag` / `html_attr_escape`（符号）；约束消息 `自定义注入仅允许 CSS 或 JavaScript`、`可信 CDN 必须使用 https://example.com/* 格式`（0xd887f3 窗口）；`blocked_paths`（key `0xd8e0b7`）与 `political_moderation`（key `0xd8dda3`）。
6. **PoW 风险监控**：`record_chat_requirements_pow_if_present`（drop ENTRY `0x00213420`；结构 `PowRiskSnapshot`、`serde_json::Value`、信号量）→ 从上游响应提取 PoW difficulty 并记录；SSE 端点 `/api/pow-risk-stream`（`0xda0f11`）；`new_pow_risk_monitor`（main CALLS 32265）；`find_proof_of_work_difficulty`（符号）。
7. **统计与审计**：`visit_logs`（`INSERT INTO visit_logs (username, chatgpt_username, log_type, created_at, ip, user_agent) VALUES (...)`，`0xd8f6f0`；DDL 窗口 `0xd8cbe1`）；`conversation_statistics` / `conversation_model_statistics`（INSERT `0xd90c6c` 邻域）；`/api/conversation-statistics[/reset]`（03 §7.1）。
8. **备份/恢复**：`/api/backup/export`、`/api/backup/restore`（03 §7.1）；`db::export_backup`（ENTRY `0x003648e0`）、`db::restore_backup`（ENTRY `0x00366de0`）；restore 前整表 DELETE 序列（`DELETE FROM conversation_model_statistics` `0xd8ff4b` 起，03 §9）。
9. **归属静默认领**：`claim_conversation_owner`（ENTRY `0x00358cd0`）/`claim_project_owner`（ENTRY `0x0035ae60`）+ 代理端 `claim_conversation_ids_from_json_response`、`collect_project_ids_from_request`（符号）→ 新会话/项目自动登记到用户名下。
10. **记忆关闭**：`/api/close-chatgpt-memory`（`0xda0c25`）+ `db::close_chatgpt_memory`（ENTRY `0x00360dd0`，调用 `mirror_token_hash`）——具体副作用未在导出可见【未确认】；相邻字符串含 ChatGPT memory 工具名池 `memory/Memory/memory_search/workspace/…`（0xd87f95 窗口）。
11. **安全响应头注入**（`src/main.rs` 区 `0xd8a6db` 窗口）：`x-content-type-options nosniff`、`referrer-policy same-origin`、`x-frame-options SAMEORIGIN`、`cross-origin-opener-policy per…`；HSTS `max-age=31536000; includeSubDomains; preload`（`0xd8a83d` 邻域，紧邻 Unauthorized JSON）；CSP 样例 `sandbox; default-src 'none'; img-src data: https:; …`（`0xd699b9`，03 §10.5）；`private, no-store, no-cache, must-revalidate, max-age=0`（`0xd85014` 邻域）。
12. **Netscape cookie 导入**：`# Netscape HTTP Cookie File` 头识别与跳过非法行的消息（0xd8804e–0xd880d0 窗口）→ 管理面可导入 ChatGPT 登录态（含 `__Secure-next-auth.session-token` 等，03 §10.5）。
13. **兼容旧 ChatGPT 前端工具的令牌**：`/sentinel/20260423af3c/sdk.js`（`0xda0f3c`）、`/cdn-cgi/challenge-platform/*path`（`0xda0fb5`）、`/ga/collect`（`0xda0f79`）、`/vendor-batch/collect`（`0xda0f84`）、`/ces/*`（`0xda102c`）→ 代理层包含遥测/挑战路径透传（03 §7.2）。

## 10. 风险清单

| ID | 等级 | 内容 | 依据（函数/入口或偏移） |
| --- | --- | --- | --- |
| G1 | 中-高 | 加密密钥 = `SHA-256(trim(env CREDENTIAL_ENCRYPTION_KEY))`，无盐无 KDF 拉伸；env 泄露 ⇒ 全部密文（含 refresh_token/审查 API key）可解 | `db::credential_key` ENTRY `0x003478a0`；`0xd8c624/0xd8c63d/0xd8c676` |
| G2 | 中 | 解密对非 `enc:v1:` 输入**原样放行**；历史明文在迁移完成前依旧可用，且无强制阻断证据 | `db::decrypt_secret` ENTRY `0x00348050`（<7 或前缀不匹配路径） |
| G3 | 中 | 密钥域不分离：gateway 内无 `CF_BYPASS_SECRET`（count=0）→ 判读管理密钥兼作 cfbypass Bearer；一处泄露波及两组件 | `0xd96422`；02 §2 R4；§6.1 |
| G4 | 低-中 | 管理面比较实现未确认恒时；未见速率限制/锁定证据（全静态） | `api::require_gateway_admin` vaddr `0x1dd8a0`（**不在导出**）；03 §10.9 |
| G5 | 低-中 | 会话窗口 ≈21h 且访问即续活/回写 cookie；`mirror_token` 轮换机制无证据 | `0x12750`（ENTRY `0x003564f0`）；`0xd8e780` 窗口 |
| G6 | 中 | SSRF 防护仅覆盖"外链代理/审查模型"路径；内部白名单含 google-analytics/googletagmanager/mapbox 等第三方域，出网面较大；DNS TOCTOU 无法评估（函数体不在导出） | `0xd685d6/0xd688c5/0xd68634/0xd6868f+`；`is_public_external_ip` vaddr `0x149d60` |
| G7 | 待复核 | `unsafeSkipTargetOriginCheck=true`（wreq/curl 初始化上下文）语义未确认，疑似跳过目标校验类选项 | `0xd634d0` |
| G8 | 低-中 | cf_clearance 等经 `extra_cookies` 加密落库并跨请求复用；同一代理出口多用户可能共享/关联 Cloudflare 指纹 | ENTRY `0x00356d50`/`0x0034eec0`；`0xd84f42` |
| G9 | 低 | 部分 CF cookie 集合也可能视为成功（02 R5）；gateway 侧已有"cookies 为空视为失败"自检 | `0xd84edf`；02 §5.4 |
| G10 | 中 | 用户文本发送至管理员配置的第三方审查服务（含 x-api-key），前端明示"自动继续发送" | `0xd6436d`/`0xd84032`/`0xda0c56` |
| G11 | 中 | 管理面可向代理页面注入任意 JS/CSS（仅限 CSS/JS 与可信 CDN 校验）→ 供应链/XSS 面 | `0xd8dc73/0xd887f3`；`render_custom_script` 符号 |
| G12 | 低-中 | visit_logs 记录 ip/user_agent；备份导出含全表（含加密凭证）；防护完全依赖 G1 | `0xd8f6f0`；`export_backup` ENTRY `0x003648e0` |
| G13 | 低-中 | `x-chatgpt-mirror-client-ip` 与 `x-forwarded-for/x-real-ip/true-client-ip` 并存；若 `TRUSTED_PROXY_IPS` 配置不当，客户端可伪造来源 IP | `0xd64726/0xd68e25–0xd68e3c/0xd96511`；【判读】 |
| G14 | 低 | 日志面广（api/proxy/db 事件 + 启动日志）；`cookie_names_for_log` 等脱敏函数体未复核 | `0xd8519c/0xd892a9/0xd9154f`；符号 |
| G15 | 低 | 内部组件全 loopback 明文 HTTP；`LD_PRELOAD` 全局注入 curl-impersonate（容器信任面） | 01 §8；03 §0.2；`0xd96454/0xd96462` |
| G16 | 中 | 30+ 管理/业务 API（备份恢复、脚本注入、审查配置、代理配置、用户统计）全部依赖单一 `GATEWAY_ADMIN_SECRET` 鉴权 | 03 §7.1；`0xd8a867` |

## 11. 不确定项与未覆盖

1. `api::require_gateway_admin`、`is_public_external_ip`、`is_allowed_external_proxy_host`、`validate_mirror_proxy_url`、`cfbypass_fallback_client`、全部 `rewrite_*` 等关键函数**不在本 Ghidra 导出（144 函数）内**；相关结论依赖 03 报告的 vaddr/符号与制品字符串，未做反汇编级确认。
2. 两个 cfbypass 关键闭包（ENTRY `0x002f6040` / `0x002f94a0`）**反编译失败**（Ghidra varnode 错误）：缓存键算法、TTL 秒数、fallback 触发条件未确认。
3. 加密算法精确类型（AES-256-GCM【判读】）、mirror_token 十六进制大小写、`sha256:` 字面量调用点均未逐指令确认。
4. 会话 `0x12750`(75600s)/`-0x93A80`(604800s) 常量语义为【判读】。
5. 未运行二进制、未联网、未访问 api.zxcbug.com；未动态验证任何运行时行为。
6. 报告长度与哈希见交付回执；制品 sha256 已在本会话重新计算并与 01/03 报告一致（`4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098`）。

## 附录 A · 本会话新增的精确字符串定位（供主代理复核）

| 字符串 | 文件偏移 |
| --- | --- |
| `CREDENTIAL_ENCRYPTION_KEY`（env 名） / `…长度至少需要 32 个字符` / `…未配置` | `0xd8c624` / `0xd8c63d` / `0xd8c676` |
| `enc:v1:` / base64url 字母表（03 记 `0xd8c6ac`） | `0xd8c699` / `0xd8c6aa` 邻域 |
| `敏感凭据加密失败` / `…解密失败，请检查密钥` / `…密文损坏` / `…编码损坏` / `…不是有效 UTF-8` / `sha256:` | `0xd8c7ec` / `0xd8c804` / `0xd8c82e` / `0xd8c846` / `0xd8c85e` / `0xd8c87c` |
| `x-gateway-secret` / `缺少或无效的网关认证信息` / Unauthorized JSON | `0xd86020` / `0xd87fe6` / `0xd8a867` |
| `x-mirror-token` / `mirror_token` / `x-chatgpt-mirror-client-ip` | `0xd6466b` / `0xd6465f` / `0xd64726` |
| `外链代理拒绝内网…` / `内部固定上游域名不在代码白名单中` / `外链代理目标解析到非公网地址` / `审查模型地址必须解析到公网 IP` | `0xd685d6` / `0xd68634` / `0xd688c5` / `0xd643de` |
| `首次上游请求命中 Cloudflare 拦截…` / `cfbypass 目标已归一化到根路径` / `cfbypass 返回成功但 cookies 为空` | `0xd68c78` / `0xd84ea1` / `0xd84edf` |
| `开始异步预热 CF bypass 缓存` / `cf_clearance` / `政治敏感内容审查服务暂不可用` | `0xd9d531` / `0xd84f42` / `0xd84f8b` |
| UA（101B） / `sec-ch-ua` / `sec-ch-ua-full-version(-list)` / `"146.0.7680.177"` | `0xd64ba2` / `0xd68ea6,0xd68eaf` / `0xd68ed7,0xd68eed,0xd68f08` / `0xd54aa0` |
| `oai-device-id` / `unsafeSkipTargetOriginCheck` / `RUST_LOG` | `0xd64c07` / `0xd634d0` / `0xe35fc2` |
| `gateway upstreams configured`/`gateway listening on http://` | `0xd96651` |
| SQL：`INSERT INTO gateway_sessions` / `SELECT … WHERE mirror_token = ?1` / `DELETE … WHERE mirror_token` / `UNIQUE(mirror_token)` / `INSERT OR IGNORE INTO conversation_owners` / `SELECT COUNT(DISTINCT user_name)…` | `0xd8e184` / `0xd8e658`（prepare `0xd8e64f`, len 334） / `0xd8e92f` / `0xd8cf5a` / `0xd8ea14` / `0xd8ead4` |
| SQL：`UPDATE chatgpt_accounts SET access_token…` / `UPDATE gateway_sessions SET access_token…` | `0xd8d9d2` / `0xd8da49` |

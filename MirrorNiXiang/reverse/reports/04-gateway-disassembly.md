# 04 · 网关反汇编（关键函数 / 启动序列 / 调用图）

> 证据来源：`reports/gateway-ghidra-export.txt`（Ghidra 12.1.4 headless 导出，`SelectedFunctions=144`，`ImageBase=0x00100000`）。
> 文中行号 `L<n>` 均指该导出文件行号；地址均为 Ghidra VA。
> **文件偏移换算规则**：本二进制 VA = 文件偏移 + 0x100000（用 3 组已知串复核：`0xe64ba1→0xd64ba1` UA、`0xe68ea6→0xd68ea6` sec-ch-ua、`0xe8c624→0xd8c624` 环境变量名，均命中既有报告中的偏移）。
> 反编译失败项、未导出函数与判读项在 §7 明示，不当作已证实结论。

## 1. 摘要

- 导出含 144 个函数（77 个 `chatgpt_mirror_gateway::*`，其余为 drop 胶水/闭包/依赖库符号）；其中 5 个函数反编译失败（`proxy_request::{{closure}}`、`get_cfbypass_payload_with_proxy_server::{{closure}}`、`get_cached_cfbypass_payload_with_proxy_server::{{closure}}`、`moderation::review_text::{{closure}}`、`proxy_chatgpt_ws_via_configured_proxy::{{closure}}`），失败项仅保留调用列表。
- 本轮完成：**启动序列全链路**（main → Settings → init_db → 四个配置装载 → 客户端/运行时/监控/缓存 → AppState → 预热任务 spawn → build_router → 三层 layer → bind → serve）、**浏览器指纹头精确常量**、**凭据加密算法与格式**（AES-256-GCM + `enc:v1:` 前缀）、**Cookie 归类判定**、**cfbypass 客户端调用面**、**若干关键 SQL 与错误文案**。
- `build_router` 本体（0x3be440）不在导出集内，逐条 `Router::route` 绑定仍无法在本报告中指令级确认；路由表见 `08-reconstruction-notes.md §3`（其"未做指令级确认"的说明依然有效）。

## 2. 启动序列（`main` → `main::{{closure}}`）

### 2.1 线程与运行时的建立（`main` @ `0x004c22f0`，L30741-30818）

```text
tokio::runtime::builder::Builder::new_multi_thread → Builder::build → Runtime::block_on(main::{{closure}})
   （失败经 core::result::unwrap_failed；运行时的 drop 路径存在）
```

### 2.2 异步主体步骤（`main::{{closure}}` @ `0x004c2450`，L30819-32233）

按 L<行号> 顺序（均为实测反编译证据）：

| 步 | 动作 | 证据行 | 失败语义 |
|---|---|---|---|
| 1 | `dotenvy::dotenv()`（`.env` 装载） | L31028 | — |
| 2 | `init_tracing()` | L31073 | — |
| 3 | `config::Settings::from_env()` | L31074 | — |
| 4 | `db::init_db(...)` | L31079 | 错误 → `_eprint` + `exit(1)`（L31080-31093） |
| 5 | `db::get_mirror_proxy_config(...)` | L31096 | 同上（L31098-31109 判 Err/Ok 分支） |
| 6 | `db::get_custom_script_config(...)` | L31126 | 同上 |
| 7 | `db::get_political_moderation_config(...)` | L31148 | 同上 |
| 8 | `db::get_blocked_paths_config(...)` | L31172 | **Err → `BlockedPathsConfig::default()`**（L31174-31180，唯一带回退的配置） |
| 9 | `proxy::build_http_client(...)` | L31189 | 错误 → 终止路径（L31190-31195） |
| 10 | `proxy::new_mirror_proxy_runtime(...)` | L31213 | 同上 |
| 11 | `PowRiskSnapshot::default` → `clone` → `tokio::sync::watch::channel` | L31223-31227 | — |
| 12 | `proxy::new_pow_risk_monitor(...)` | L31402 | — |
| 13 | `proxy::new_cf_bypass_cache()` | L31405 | — |
| 14 | AppState 装配（字段写入 `param_3+0x358…0x3b8`） | L31633-31645 | — |
| 15 | 启动日志事件（4 个上游 URL 字段：django/admin/chatgpt_base/cf_bypass，对应运行时 `gateway upstreams configured`） | L31646-31761 | — |
| 16 | **若缓存字段存在** → `tokio::task::spawn` 后台任务（携带 AppState 克隆；运行时表现为 CF bypass 预热协程） | L31763-31771 | 导出中存在 `_eprint + exit(1)` 终止闭包（L30364-30395，归属见 §7 判读项） |
| 17 | `AppState::clone` → `build_router(&state)` | L31773-31774 | — |
| 18 | 三层中间件：`Router::layer`（带内容类型常量结构体）→ `Router::layer`（无参）→ `Router::layer`（小标志结构体） | L31798-31809 | — |
| 19 | 组装 `"{ip}:{port}"` 字符串（IpAddr Display） | L31812-31823 | — |
| 20 | `to_socket_addrs` → 地址迭代 `TcpListener::bind_addr`（逐个候选地址重试） | L31831-31986、L31995 | 全部失败 → `_eprint` + `exit(1)`（L31905 / L32203-32204） |
| 21 | 成功端口打日志（`gateway listening on http://…`，运行时复核） | L32038-32087 | — |
| 22 | `into_make_service_with_connect_info` → `axum::serve` future → await | L32135-32153 | — |

### 2.3 第 18 步内容类型常量（压缩/重写判定候选）

结构体内逐字节读出（配合二进制偏移换算）：

```text
"application/grpc" （len 0x10，@0xd94bb0）
"image/"           （len 6，@0xd9fa7a）
"image/svg+xml"    （len 0xd）
"t…"（len 0x11=17，仅存指针；候选 "text/event-stream"，判读）
```

即该层对 `application/grpc / image/* / image/svg+xml / text/event-stream` 一类内容有**按类型分流**的配置。与运行时观测一致：响应普遍带 `vary: accept-encoding`（压缩层活跃），SSE（`/api/pow-risk-stream`）属事件流。**具体归属（压缩谓词 or 响应重写分流）未在本导出中定案**。

### 2.4 中间件候选（结合运行时证据）

- 无参 layer（L31799）：候选 `TraceLayer::new_for_http()`——运行时日志出现 `tower_http::trace::on_failure: response failed classification=Status code: 5xx`（沙箱实测，见 06 报告），二者呼应（判读）。
- 带常量 layer（L31798）：§2.3 的内容类型分流结构体。
- 小标志 layer（L31809）：布尔/枚举标志结构体（`1/0x100/4/…`），候选 CORS 或安全响应头配置；运行时响应头含 `x-content-type-options/referrer-policy/x-frame-options/cross-origin-opener-policy/permissions-policy/strict-transport-security/accept-ch`（沙箱实测），**映射关系未确认**。

## 3. 关键函数反编译证据

### 3.1 `proxy::apply_chrome_146_network_identity` @ `0x0025c8b0`（L2047-2221）

对请求 HeaderMap 连续 `try_insert2`，名称/值均为静态常量（按 VA−0x100000 从二进制读出）：

```text
sec-ch-ua:                  "Chromium";v="146", "Not_A Brand";v="99"
sec-ch-ua-full-version:     "146.0.7680.177"
sec-ch-ua-full-version-list:"Chromium";v="146.0.7680.177", "Not_A Brand";v="99.0.0.0"
（另有首个插入：值 = 101 字节 UA 常量，@0xe64ba1：
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"，
  name 由函数前段构造，未在本导出窗口内完整呈现——判读为 user-agent）
```

插入前后对静态常量做逐字节有效性断言（非法即 `panic_fmt`，L2163-2177）。

### 3.2 凭据密钥 `db::credential_key` @ `0x003478a0`（L3079-3171）

```text
读环境变量 CREDENTIAL_ENCRYPTION_KEY（L3102，VA 0xe8c624，len 25）
缺失 → 错误文案 "CREDENTIAL_ENCRYPTION_KEY 未配置"（35B，按 store 命令还原）
trim 后 < 0x20(32) 字符 → 错误文案 "CREDENTIAL_ENCRYPTION_KEY 长度至少需要 32 …"（57B）
合格 → <D as Digest>::digest(…) 输出 32B 作为密钥（即 SHA-256 派生，D 泛型名未在导出中展开——判读为 Sha256）
```

### 3.3 `db::encrypt_secret` @ `0x00347aa0`（L3184-3431） / `decrypt_secret` @ `0x00348050`（L3432-3690）

- 明文判定：值以 **`enc:v1:`**（7 字节，位运算常量 `0x3a636e65`="enc:"、`0x3a31763a`=":v1:"）开头才进入加/解密；否则原样透传（L3260-3276 / L3534-3553、L3502-3517）。
- 加密路径：`credential_key()` → `crypto_common::KeyInit::new_from_slice(key, 0x20)` → `OsRng::fill_bytes(…, 0xc)`（12B nonce）→ `Alg as Aead::Aead::encrypt(…)` → 拼接 `nonce||ciphertext` → `base64::Engine::encode`（L3278-3354）。
- 解密路径：base64 解码失败 → **"敏感凭据编码损坏"**（24B，L3546-3548 还原）；解码长度 ≤12 或密钥错误/AEAD 失败 → 24B 错误文案族（"敏感凭据…"，L3650 起）；成功且 UTF-8 合法 → 明文（L3584-3616），非法 UTF-8 → `decrypt_secret::{{closure}}` 错误路径。
- **算法定案：AES-GCM**。符号表证据：`aes_gcm::AesGcm<…>::compute_tag`（`_ZN7aes_gcm39…`）、`aes::ni::aes256`、`polyval::backend::*`（aes-gcm 的 GHASH 后端）；`chacha20poly1305::` crate 路径 0 命中（BoringSSL 的 `.cc` 同名不属 Rust crate）。结合 32B 密钥 + 12B nonce → **AES-256-GCM，nonce 前置**。
- 密文格式：`enc:v1:` + Base64(`nonce[12] || ciphertext||tag`)。

### 3.4 `db::mirror_token_hash` @ `0x00348630`（L3735-3774）

`Digest::digest` → 逐字节 `FromIterator<char>` 收集 → `format_inner` 输出字符串（hex 化循环），用于 mirror_token 的**摘要寻址**（登录态校验不落明文，判读对应 `get_gateway_session_by_token`）。

### 3.5 `db::SupplementalCookie` 判定族

| 函数 | 地址 | 证据 |
|---|---|---|
| `is_mirror_local` | 0x00348780 | 按 **cookie 名** 长度分支：9=`csrftoken`（`0x656b6f7466727363`+"n"）、12=`mirror_token`（`0x745f726f7272696d`+"oken"）/`free_session`（`0x7365735f65657266`+"sion"）、16=`chatgpt_username`（逐字符比较 L4092-4108）；另有 1 个 10 字节与 1 个 16 字节 bcmp 目标未解码（L4079、L4124 起）→ 归为"镜像本地 Cookie 白名单" |
| `is_current_at` | 0x003488e0 | 名字 8 字节且 == **`cfbypass`**（`0x7373617079626663`）且无过期时间 → 恒 false；其余按 `(expires==0)‖(now<expires)`（L4286-4296） |
| `scope_identity` / `applies_to_url` | 0x00348920 / 0x00348e40 | 两函数均带大量内联逐字符比较（scope 域/路径匹配），`applies_to_url` 反编译体 652 行；仅确认调用面（12 callees）与"按 cookie 域/路径/时间限定生效范围"的语义，逐分支规则未还原（§7） |

### 3.6 `proxy::get_cfbypass_payload_with_proxy_server`（L2756-2811，DECOMP_FAILED，调用面可用）

调用列表证明的客户端行为：

```text
reqwest::Client::request → RequestBuilder::bearer_auth → RequestBuilder::json → send → bytes
serde_json::de::from_slice（响应 JSON 解析）
url::ParseOptions::parse（目标 URL 解析/校验）
cf_cache_key_with_proxy / normalize_cfbypass_target_url（缓存键与目标规范化）
normalize_cfbypass_cookies（Cookie 规范化）
cfbypass_fallback_client（回退客户端）
rwlock read/write + hashbrown::HashMap::insert + Instant::now/Add（TTL 缓存读写）
String::from_utf8_lossy（非 UTF-8 响应体容错）
```

与沙箱实测互证：`POST /cloudflare5s/bypass-v1`、`Authorization: Bearer <CF_BYPASS_SECRET>`、请求体 `{"url":…,"user_agent":…}`、缓存命中即跳过请求（06 报告 §4.1-4.2）。

### 3.7 `proxy::record_chat_requirements_pow_if_present` 内层闭包（L2537-2580）

纯 `tracing_core::event::Event::dispatch` + log 桥接（无业务分支）→ 该函数以**日志记录**为主，PowRisk 快照经 `watch::channel` 广播（§2.2 步 11）。

### 3.8 SQL 常量（`.rodata` 抽取，供 05 报告交叉引用）

```text
… FROM chatgpt_accounts WHERE chatgpt_username = ?1 AND auth_status = TRUE LIMIT 1
DELETE FROM gateway_sessions WHERE user_name = ?1
UPDATE gateway_sessions SET force_chat_mode = ?1, updated_at = ?2 WHERE user_name = ?3
DELETE FROM gateway_sessions WHERE mirror_token = ?1
DELETE FROM conversation_model_statistics WHERE user_name = ?1
```

`init_db` 的 25 个 callees 涵盖三支迁移函数：`ensure_gateway_sessions_force_chat_mode_column` / `ensure_gateway_sessions_proxy_node_id_column` / `ensure_gateway_sessions_quota_columns`（地址见 `tools/ghidra-export-index.json`）。

### 3.9 moderation 约束文案（`.rodata`，@0xd92c1d 窗口）

```text
"src/moderation.rs" / "不支持的审查 API 格式" / "审查模式只能是 relaxed 或 strict"
"API 密钥不能为空" / "审查频率限制必须在 1 到 10000 之间"
```

与 `db::default_moderation_mode`（0x00348720）及 `PoliticalModerationConfig` 序列化字段表（05 报告）一致；`https://api.openai.com/v1`、`sha256:openai_chat`、`model_limits` 等常量同窗出现。

## 4. 调用图

完整逐函数 callee 清单：`reports/04-callgraph-appendix.txt`（216 行，覆盖 main/代理/DB/加密 17 个关键函数）。主干摘要：

```text
main
└─ main::{{closure}} ──► dotenv / init_tracing / Settings::from_env
   ├─ db::init_db ──►(3 迁移 + 建表 SQL)
   ├─ db::get_mirror_proxy_config / get_custom_script_config / get_political_moderation_config / get_blocked_paths_config
   ├─ proxy::build_http_client / new_mirror_proxy_runtime / new_pow_risk_monitor / new_cf_bypass_cache
   ├─ tokio::task::spawn ──►（预热任务；错误终止闭包）
   ├─ build_router ──►（0x3be440，未导出）
   ├─ Router::layer ×3
   └─ into_make_service_with_connect_info → axum::serve

cfbypass 客户端链：get_cfbypass_payload_with_proxy_server
   └─ reqwest(bearer_auth/json/send/bytes) + serde_json + TTL 缓存 + fallback client

加密链：encrypt/decrypt_secret ──► credential_key ──► env CREDENTIAL_ENCRYPTION_KEY ──► digest(SHA-256)
                                                     └─► aes-gcm(AesGcm::compute_tag) + base64
```

## 5. 路由与端点（证据状态说明）

- `build_router` 被调用（L31774，callee 证实）；**路由注册本体不在本次 144 函数导出集**，因此 `08 §3` 的路由 token 清单与"方法大多未证实"的限定**保持有效**。
- 沙箱实测补充的**已证实行为**（06 报告）：`/` → 302 `/admin#/`；`/api/operations-overview` 401/422；`/api/not-login` → 400 `missing field user_gateway_token`；`/sentinel/…` → 200 原样代理；`/backend-api/*`、`/v1/chat/completions` 无会话 401。

## 6. 安全相关判读（本报告新增）

1. `enc:v1:` 之外的明文敏感值会被**原样透传**（加解密两侧均有此分支）→ 迁移/导入路径可能引入明文残留；对应 `migrate_sensitive_rows`（0x0034b9b0）。
2. `CREDENTIAL_ENCRYPTION_KEY` 仅要求 ≥32 字符且 SHA-256 派生、无 KDF 拉伸 → 低熵密钥场景防护弱（判读）。
3. `is_mirror_local` 表明镜像自有 Cookie 名（csrftoken/mirror_token/free_session/chatgpt_username…）与 ChatGPT 域 Cookie 分流存储；`cfbypass` 同名 Cookie 被特别对待（无过期即失效）。
4. 启动期对 `init_db`/三配置/客户端初始化采用 **fail-fast（exit 1）**，仅 `blocked_paths` 回退默认 → 与"防护配置残缺不静默降级"一致。

## 7. 未决项与限制

- 反编译失败 5 项（§1），其中 `proxy_request::{{closure}}` 为 timeout、`get_cfbypass_payload_*` 为 varnode 哈希失败；对应行为以调用面 + 运行时为准。
- `build_router` / `api` 模块 / `moderation::review_text` 本体未导出 → 路由绑定与审核流程判定仍待后续（见 06 遗留项）。
  **`refresh-cfbypass` 的 401 疑点已在运行时定案（06 §9.4）**：响应体 `{"message":"未登录"}` = 用户会话守卫
  （`x-mirror-token`/会话 Cookie 探测均被拒；管理密钥不适用）；管理守卫实测接受 `Authorization: Bearer`
  或 `x-gateway-secret`（`operations-overview` 对照通过）。
- **补充导出** `reports/gateway-auth-export.txt`（`DumpAuthFns.java`，85 个函数后因 Ghidra native 反编译器挂起而中止）：
  含 `api::sanitized_proxy_config` / `sanitized_proxy_url`（`url::ParseOptions` + `set_username/set_password` 脱敏）、
  `retain_secret_if_blank`（空密码保留旧值）、全部 handler 提取器签名（如 `gateway_refresh_cfbypass_as_axum`
  提取 `(ViaParts, State<AppState>, HeaderMap)`——与其"读 HeaderMap 校验会话"的运行时行为一致）。
  `require_gateway_admin` 本体仍未导出（挂起中止），其实现细节以运行时为准。
- §2.3 内容类型常量的**具体消费函数**、§2.4 三个 layer 的**中间件身份**、`scope_identity/applies_to_url` 的逐分支规则：均标注为未定案。
- `main::{{closure}}::{{closure}}`（exit(1) 闭包）与 spawn 任务的**直接归属**未定；标注判读。
- VA↔文件偏移换算基于 3 组已知串复核；本报告凡引用的常量均已按该规则实读，但未做全段 dump 校验。

## 8. 证据文件

| 文件 | 说明 |
|---|---|
| `reports/gateway-ghidra-export.txt` | 144 函数反编译导出（本报告行号来源） |
| `reports/04-callgraph-appendix.txt` | 17 个关键函数 callee 清单（自导出解析） |
| `tools/ghidra-export-index.json` | 全量函数索引（name/entry/body-ranges/callees/decomp-failed） |
| `extracted/chatgpt-mirror-gateway` | 常量实读所用二进制（只读） |

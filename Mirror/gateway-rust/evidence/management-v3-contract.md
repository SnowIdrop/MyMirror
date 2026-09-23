# 管理端点 v3：原版运行时契约（子代理交付给主代理）

观测来源：`evidence/management-v3-original-00{1..6}/results.json`（QEMU `-nic none`、
guest 内 127.0.0.1 stub 上游、合成账号/凭据；original profile）。
脚本：`tools/observe_management_v3.py`（可复用于 candidate / rollback）。

## 0. 脚本保真性（本轮关键结论）

`observe_management_v3.py` 的 phase0 + startup 复刻 `tools/observe_guest.py` 的同一批
case id。用 `tools/compare.py` 的 normalize 口径比对：
`evidence/baseline-final-2/results.json` vs `evidence/management-v3-original-006/results.json`
→ **101/101 键完全一致、0 差异**（含 export-populated 的字段省略方式）。
因此后续 candidate 差分中出现的差异都可归因于候选制品，而不是脚本漂移。

## 1. 实现文件与接线清单（主代理执行）

新增 `src/server/management.rs`（本子代理独占）。父文件 `src/server.rs` 需要：

```rust
mod management;

// admin router（require_admin 之后、与其它 .route 并列）：
.route("/api/get-mirror-token", any(management::mirror_token))
.route("/api/get-user-use-count", any(management::user_use_count))
.route("/api/get-chatgpt-use-count", any(management::chatgpt_use_count))
.route("/api/close-chatgpt-memory", any(management::close_chatgpt_memory))
.route(
    "/api/political-moderation-config",
    get(management::political_moderation_config_get)
        .post(management::political_moderation_config_save),
)
.route(
    "/api/political-moderation-config/test",
    any(management::political_moderation_config_test),
)
```

方法与提取器依据（观测）：

| 路由 | 方法 | 提取器 | 备注 |
|---|---|---|---|
| get-mirror-token | any | `State` + `Json<MirrorTokenRequest>` | GET 无 JSON 体 → 415；有 Content-Type 无体 → 400 EOF |
| get-user-use-count | any | `State` + `Json<UserUseCountRequest>` | 同上 |
| get-chatgpt-use-count | any | `State` + `Json<ChatgptUseCountRequest>` | 同上 |
| close-chatgpt-memory | any | `State` + `Json<CloseChatgptMemoryRequest>` | 四字段全部可缺省，`{}` → 200 |
| political-moderation-config | get + post | GET：`State`；POST：`State` + `Json<...>` | PUT → 405（vary 为空）；GET 忽略请求体 |
| political-moderation-config/test | any | `State` + `Json<PoliticalModerationConfigRequest>` | PUT `{}` → 422（说明 PUT 被接受） |

多余公共 helper 需求：**无**（仅用父模块既有 `App/Shared/ApiError/error/now/sha256_hex`）。

## 2. 契约要点（含原始 case id）

### get-mirror-token
- 请求 7 字段：`user_name`、`chatgpt_list` 必填；`isolated_session`(bool,默认 false)、
  `force_chat_mode`(bool,默认 **true**)、`limits`(sequence)、`daily_quota`(u64)、
  `monthly_quota`(u64) 可选；未列出的键被忽略（`mirror-field-*` 探针 200）。
- `user_name` trim 后为空、或 `chatgpt_list` 全部为空白 → 400
  `{"message":"user_name 和 chatgpt_list 不能为空"}`；写库保留原值（`" alice "` 入库）。
- 逐项处理 `chatgpt_list`：需 `chatgpt_accounts.auth_status = TRUE`；未命中/禁用 → 跳过
  （`mirror-disabled-account`/`mirror-unknown-account` → 200 `[]`）；重复项重复签发；
  大小写敏感（`mirror-case-account` → `[]`）；返回顺序 = 请求顺序（`mirror-mixed-known`）。
- 成功 200：`[{"chatgpt_username","login_mode":"api","login_url":"/api/not-login?user_gateway_token=<64hex>"}]`。
- 副作用：`gateway_sessions` upsert `(user_name, chatgpt_username)`；轮换 `mirror_token`
  （存 `sha256:` 摘要）、更新 `updated_at`，`created_at` 保持（`p1-sessions-after-mirror`）。
  可选字段按请求落库（`p1-flags-after-overrides`：isolated_session=0、force_chat_mode=0、
  limits=`["probe-limit"]`、daily/monthly=11/22）。

### get-user-use-count / get-chatgpt-use-count
- 请求字段：`username_list` / `chatgpt_list`（必填、字符串数组）。
- 200 结构：`{<key>: {"gpt-4o": {"last_1h","last_2h","last_3h","last_4h"}}}`；
  内层模型键**恒为** `gpt-4o`（空库/命中/未知用户一致）。键序 = 字典序。
- 语义：`visit_logs` 按列聚合，**不区分 `log_type`**（chat 行计入，`counts-users`：alice 1h=4），
  四个窗口为 `[now-3600,∞)`、`[now-7200,now-3600)`、`[now-10800,now-7200)`、`[now-14400,now-10800)`
  （`counts-edge` 边界行为一致）；未 trim（`" alice "` 与 `"ALICE"` 均为 0）；空白键跳过 → `{}`；
  重复键合并。

### close-chatgpt-memory
- 请求 4 字段可缺省：`user_name`、`chatgpt_name`、`chatgpt_username` *→ gateway_sessions.chatgpt_username*、
  `mirror_token` *→ sha256 摘要比较*；未列出的键被忽略。
- 200：`{"affected":N,"message":"ok"}`；全字段空白 → 0（不执行删除）。
- 条件之间为 **OR**（二进制 `join_generic_copy(" OR ", 4)` 证据 + 多字段用例）：
  仅 `chatgpt_name` → 删该账号全部会话（`close-chatgpt-name` affected=3）；
  仅 `user_name` → 删该用户名全部会话（affected=2）。
- 比较用原值不做 trim（`close-trimmed-user`/`close-space-user`/`close-spaced-token` → 0），
  但空白值跳过（`close-blank-both` → 0）。

### political-moderation-config（GET/POST）
- GET 恒 200，字段（字典序）：`api_key_configured, base_url, custom_terms, enabled,
  latency_ms, limit_per_five_minutes, limit_per_hour, limit_per_minute, message, mode, model, protocol`；
  `latency_ms` 在全部观测中为 `null`；`message` 恒为“政治敏感内容屏蔽配置已保存”。
  空库默认（`mod-get-default`）：`enabled=false, protocol="openai_chat", model="", api_key 未配置,
  base_url="https://api.openai.com/v1", mode="relaxed", custom_terms=[], 限流 10/30/120`。
- POST 请求字段：必填 `protocol`、`model`、`base_url`、`mode`；可选 `enabled`(默认 false)、
  `api_key`、`custom_terms`、`limit_per_minute`(默认 10)、`limit_per_five_minutes`(默认 30)、
  `limit_per_hour`(默认 120)；未知键忽略（`mod-save-extra-field` 200）。
- 校验顺序：protocol → mode → Base URL →（enabled=true 时）api_key 非空 → 连通性/校准。
  文案：`不支持的审查 API 格式` / `审查模式只能是 relaxed 或 strict` / `Base URL 格式无效` /
  `Base URL 必须是无账号、查询参数和片段的 HTTPS 地址` / `API 密钥不能为空` /
  `模型连通性验证失败: …`。
- 合法 protocol 恰为 4 个：`openai_chat`、`openai_responses`、`anthropic_messages`、
  `gemini_generate_content`（`generate_content`/`gemini_generate_`/空串被拒）。
- Base URL：`https` 且无账号/查询/片段；空用户名信息 `https://@host/v1`、大小写 scheme、
  首尾空格、尾部斜杠均接受；落库文本 = trim + 去掉尾部斜杠（保留原大小写）。
- api_key 沿用规则（`mod-key-*` 矩阵）：**空 api_key 仅在 base_url 与原值相同时沿用**，
  换地址则清空；`api_key_configured` 只反映是否非空。
- 副作用：`gateway_settings['political_moderation']` 整值加密（`enc:v1:`），重启后保持
  （`mod-after-restart`）；enabled=true 校验失败时**不落库**（`mod-get-after-enabled-true` 未变）。

### political-moderation-config/test
- 同校验顺序，但**不校验 api_key/model 非空**；不落库（`mod-get-after-tests` 未变）。
- 失败 400：`模型连通性验证失败: 审查模型连接失败`（公网字面量/空密钥/空模型）、
  `模型连通性验证失败: 审查模型地址必须解析到公网 IP`（https 回环字面量）。
- 成功文案取自二进制字面量“模型连通性与规则校准通过”（隔离环境无法观测成功路径）。

## 3. 已知差异 / 待主代理决策

1. **审核 provider 拨号路径当前不可达**：原版要求 Base URL 解析到公网 IP，候选
   `config::loopback_url` 只允许 http 数字回环，而审核校验要求 https —— 两者交集为空。
   实现方式：门禁拒绝时按原版两类文案分类返回（回环字面量→“必须解析到公网 IP”，
   其余→“连接失败”），门禁放行时才真正拨号（`provider_endpoint`/`provider_request`/
   `provider_output_text` 均已就位）。若主代理后续放宽门禁（如允许 https 回环），
   该路径自动生效；当前所有观测用例的文案与原版一致。
2. **provider 请求形状未观测**：guest 无网，原版从未成功建连。`provider_endpoint`
   仅为判读（`chat/completions`、`responses`、`messages`、`models/{model}:generateContent`），
   字段名来自二进制字面量窗口。
3. **redis / rust_authorizations**：`close-chatgpt-memory` 是否同时清理
   `rust_authorizations` 未观测（本次只删 `gateway_sessions`）；mirror profile 下
   `get-mirror-token` 是否会写授权行也未观测（原版观测为 original profile）。
4. **`vary` 行为**：实现按“正文 > 32 字节追加 `accept-encoding`”复刻压缩层观测
   （30 字节无、47 字节有；`counts-empty-list` `{}` 无）；若候选启用真实压缩中间件，
   需复核是否与此实现重复。

## 4. 复跑方式

```
python tools/oracle.py --guest-script tools/observe_management_v3.py \
  --subject candidate --serial-port <port> --output evidence/management-v3-candidate-001
python tools/compare.py evidence/management-v3-original-006/results.json \
  evidence/management-v3-candidate-001/results.json evidence/management-v3-diff-001.json
```

`--subject rollback` 时会先跑 `/app/ROLLBACK.sh` 校验 sha256 等于原版哈希再执行同一用例集。

注意：当前 `.build/sandbox.cpio.gz`（sha256 5a1fa798…）内嵌的 `/app/candidate` 仍是旧候选
（3b1d41b5…）。candidate 复跑需由主代理先用 `tools/prepare_guest.py --candidate <新产物>`
重建 initramfs（本子代理未运行 prepare_guest，遵守“既有 initramfs 只读复用”约束）。

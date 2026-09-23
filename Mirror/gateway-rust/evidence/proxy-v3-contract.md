# 代理/会话列表 v3：原版运行时契约（子代理交付给主代理）

观测来源：`evidence/proxy-v3-original-007/`（稳定参照，含全部探针；QEMU `-nic none`、
guest 内 127.0.0.1 stub 上游、合成凭据、original profile）。脚本：
`tools/observe_proxy_v3.py`（可复用于 candidate / rollback）。
轮次：001 共享面复现 + 首轮发现；002 范围探针；003/004 校准失败轮
（extra_cookies 反序列化契约）；005/006 CF cookie 选择；007 全量稳定参照。

## 0. 脚本保真性

`evidence/proxy-v3-compare-baseline-007.json`：与 `evidence/baseline-final-2` 共有的
`scenario:login-fixture`、`scenario:handoff`、`scenario:session:/api/auth/session`、
`scenario:session:/backend-api/me`、
`scenario:session:/backend-api/conversations?offset=0&limit=20`、
`scenario:session:/0x/user/version-cfg?fixture=1` **全部一致（0 差异）**。

## 1. 接线清单（主代理执行；本子代理未改 server.rs / Cargo / main.rs）

新增 `src/server/proxy.rs`（本子代理独占）。父文件 `src/server.rs` 需要：

```rust
mod proxy;
// /0x/*path、/admin、/admin/*path：
.route("/0x/*path", any(proxy::django_proxy))
.route("/admin", any(proxy::django_proxy))
.route("/admin/*path", any(proxy::django_proxy))
// fallback：
.fallback(proxy::chat_proxy)
```

- `proxy::django_proxy`：`State<Shared>` + `Option<ConnectInfo<SocketAddr>>` + `Request`。
  为复现 `x-chatgpt-mirror-client-ip`，`main.rs` 需改为
  `axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())`；
  未接线时该头缺失（不 500），其余行为不变。
- `proxy::chat_proxy`：签名与父 `chat_proxy` 一致，直接替换。
- `proxy::forward(app, request, base, authorization)`：父 4 参 `forward` 的等价入口
  （django 风格透传；chat 路径的 origin/referer 由 me/conversations handler 处理）。
- 删除父文件中被替换的三个旧函数即可；本模块不新增依赖（Cargo.toml 不变）。

## 2. 三项差异契约（case id 见 proxy-v3-original-007/results.json）

### 2.1 `/0x/*` 透传（session:/0x/user/version-cfg?fixture=1、p1-cfg-*）
- 任意方法透传（GET/POST 均验证），无会话也可访问（p1-cfg-no-cookie 200）。
- 上游请求头：客户端端到端头保留；`user-agent` 被替换为默认浏览器 UA
  （客户端 UA 也被替换，p1-cfg-client-cookie-ua）；`accept` 缺省补 `*/*`；
  `accept-encoding` 保留客户端值；`cookie` 仅用 CF 缓存（客户端 cookie 丢弃）；
  附加 `x-chatgpt-mirror-client-ip`=TCP 对端 IP（X-Forwarded-For 与客户端伪造头均被覆盖）。
- 响应：状态码与端到端头（server/date/content-type 等）保留；`transfer-encoding: chunked`
  流式、无 content-length；`vary: Cookie, Authorization` +（正文 >32 字节）`accept-encoding`。

### 2.2 `/backend-api/me`（session:/backend-api/me、p1-me-*）
- 需有效 mirror 会话（无/坏 cookie → 401 `{"message":"未登录"}`）。
- 上游请求带 `Authorization: Bearer <会话 access_token>`；客户端 Authorization 与
  mirror cookie 都不转发；origin/referer 固定为 `scheme://host` 与加 `/`（覆盖客户端值）。
- 响应状态码、端到端头与**原始字节**透传（不重序列化；上游 500/畸形正文也原样回传）。

### 2.3 `/backend-api/conversations`（p2-*、p3-*）
- 仅 GET；查询串（offset/limit 等，含非法值）原样转发上游（p2-big-alice-bad-params）。
- 成功 2xx：解析上游 JSON；`items[].id` 命中
  `conversation_owners(chatgpt_username=会话账号, conversation_id, user_name=会话用户)`
  才保留；重复条目不去重（p2-dup-alice）；未知归属不认领（p2 各次 DB dump 无写库）；
  `total` = 该账号+用户的 owners 计数（跨账号行不计入，p2-small-alice-page1 与
  p1-carol-extra-cookies）；其余键原样保留并按 serde_json 默认排序输出（p2-extra-keys-alice）。
- 非 2xx → 同状态码 + `{"items":[],"total":0}`（p2-upstream-error-alice/500）；
  2xx 但正文不可解析 → 200 + 空信封（p2-upstream-badjson-alice）。
- 重启恢复：owners 持久化；`conversation_statistics` 由启动时 schema 存量回填
  （p3-after-restart-list 前后对比）。

## 3. 待 sync_headers_implementation 的钩子（本模块不实现 CSP）

- 原版对 `/0x/*` 与 `/backend-api/*` 的代理响应**替换**上游 CSP 为一个 1270 字节常量
  （含 chatgpt.com/cdn.openai.com 等生产域；fixture 内上游自带 `STUB-CSP-MARKER` 时
  仍输出常量，见 p1-probe-0x/p1-probe-chat；原生 /api 路由无 CSP）。
  该常量与 CHATGPT_BASE_URL/CDN/AB 的 127.0.0.1 配置无关 → 不能按配置拼装，
  需要共享中间件在代理响应上注入/覆盖（字符串全文见 results.json）。
- 代理响应统一 `cache-control: private, no-store, ...`（包括 text/html，p1-probe-html-*），
  现有 `private_headers` 对 HTML 会写 `no-cache`。
- `vary`：`Cookie, Authorization` + 正文 >32 字节追加 `accept-encoding`（proxy.rs 已在
  代理响应上补齐；父中间件 `entry().or_insert` 幂等，勿重复 append）。
- 端到端/逐跳：原版实测**不过滤** Connection 命名头（p1-me-connection-token 上游含
  `x-conn-token`）；候选按任务要求保持过滤（有意收紧，勿当缺失修掉）。
- 新发现（跨模块，未实现）：chat 代理对 text/html 响应注入
  `<script id="gateway-user-logout-button">…</script>`（≈97KB，含 enableUserControls/
  forceChatMode/_gwBlockedPaths；p1-me-html、p1-probe-html-chat、p2-upstream-badjson-alice）。

## 4. 未覆盖 / 未证实

- `/0x/*` 携带有效会话时是否附会话 extra_cookies（fixture 无法区分）；`/admin/*` 行为未观测。
- conversations 的 POST/写入路径、SSE/真实 TLS 未观测；本模块只放行 GET me/conversations。
- CF 缓存预热：原版启动预热；候选只在 `/api/refresh-cfbypass` 写入 `rust_cf_cache`。
- candidate/rollback 复跑需主代理用 `tools/prepare_guest.py` 重建 initramfs 后再跑同一脚本。

## 5. 复跑方式

```
python tools/oracle.py --guest-script tools/observe_proxy_v3.py \
  --subject original --serial-port 45602 --output evidence/proxy-v3-original-008
python tools/compare.py evidence/proxy-v3-original-007/results.json \
  evidence/proxy-v3-original-008/results.json evidence/proxy-v3-diff-008.json
```

`--subject rollback` 会先按 observe_guest.py 的分支用 `/app/ROLLBACK.sh` 校验 sha256
等于原版哈希再执行同一用例集。

# 08 · gateway 重建笔记：chatgpt-mirror-gateway 行为兼容清单

> 目标制品：`D:\Project\MirrorNiXiang\reverse\extracted\chatgpt-mirror-gateway`（ELF 64-bit PIE / x86-64 / Rust 1.88.0；23,252,912 B）
> SHA-256：`4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098`（本报告写入前用 Get-FileHash 复核，与 01/03 报告记录一致）
> 目标读者：计划**替代实现**（或为其编写兼容层）该 gateway 的工程师。
> 取证方式：纯静态读取四份授权材料与二进制本体；未运行任何程序、未联网、未访问 api.zxcbug.com、未发起任何探测。
> 报告日期：2026-09-22（Asia/Shanghai）。

---

## 0. 标注与置信度约定

| 标记 | 含义 |
|---|---|
| 【01】 | `reports/01-target-inventory.md`（镜像/入口/环境变量/层清单）；引用其 `§N` |
| 【02】 | `reports/02-cfbypass-analysis.md`（cfbypass 源码级分析）；引用其 `§N` 或 `app.py:Lx` |
| 【03】 | `reports/03-gateway-static-analysis.md`（gateway 二进制静态分析）；引用其 `§N` |
| 【G Lx-Ly】 | `reports/gateway-ghidra-export.txt` 行号（Ghidra 反编译导出：144 个函数，含 `main`、`db::init_db`、`db::export_backup`、serde 访问器等） |
| 【B 0x…】 | 对二进制**本体的文件偏移**字节读取/字符串读取（本报告直接复核；含少量对 03 已记录偏移的再确认） |
| （判读） | 由直接证据推导的结论，非原件显式声明；替代实现时建议运行时再确认 |
| （未证实） | 静态证据未能确定的行为（名称可见但规则/取值未知）；**不得**把本节内容当已确认契约 |

硬约束重申：本报告不发明任何未观察到的行为。凡替代实现需要但本报告标注“未证实”的条目，必须通过运行时观测或反汇编补齐后再固化。

---

## 1. 启动与进程模型（兼容清单）

### 1.1 容器入口脚本顺序（`/usr/local/bin/chatgpt-mirror-all-in-one`）

【01 §8】【02 §7.1】按脚本执行顺序：

1. `trap` 统一回收（EXIT/INT/TERM；L18-20）。
2. 校验必填 env：`ADMIN_PASSWORD`、`CREDENTIAL_ENCRYPTION_KEY`、`DJANGO_SECRET_KEY`、`GATEWAY_ADMIN_SECRET`；缺失打印 `缺少必需环境变量: <名称>` 并 `exit 64`（L22-34）。
3. 导出默认值：`PORT=40002`、`DJANGO_INTERNAL_PORT=8000`、`CF_BYPASS_INTERNAL_PORT=8001`、`DJANGO_UPSTREAM=http://127.0.0.1:8000`、`CHATGPT_GATEWAY_URL=http://127.0.0.1:40002`、`CF_BYPASS_URL=http://127.0.0.1:8001`、`CF_BYPASS_SECRET←GATEWAY_ADMIN_SECRET`（L36-43）。
4. `mkdir -p /app/data/backend-db /app/data/backend-logs`（L45）。
5. 前台执行 `python manage.py migrate --noinput` 与 `python cli/create_init_user.py`（L47-49）。
6. 后台启动 cfbypass（uvicorn，`127.0.0.1:8001`，L76-83）→ 后台启动 Django（`runserver 127.0.0.1:8000 --noreload`，L85-92）。
7. `wait_for_port` 门控 Django 与 cfbypass 就绪（1 s 轮询，超时 `STARTUP_TIMEOUT_SECONDS=60`；L94-95）。
8. 启动 gateway：`cd /app`；`export LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so`；`export CURL_IMPERSONATE=<chrome146>`；`exec ./chatgpt-mirror-gateway`（L97-105）。
9. `wait_for_port 主服务 $PORT`（40002）→ 打印 `三合一服务已启动，监听端口 ${PORT}`；`wait -n` 任一子服务退出即整体退出并传递退出码（L107-116）。

容器级运行参数：【01 §2-§3】Entrypoint 即上述脚本；WorkingDir `/app`；`SIGTERM`；Volume `/app/data`；仅 EXPOSE `40002/tcp`；Healthcheck 为 TCP connect 探测 `127.0.0.1:${PORT:-40002}`。

### 1.2 gateway 自身启动序列（进程内）

由 `Ghidra: main::{{closure}}` 的调用表还原（【G L32237-32287】，`chatgpt_mirror_gateway::main` 见 L30741-30816）：

1. `dotenvy::dotenv`（【G L31028、L32269】）→ 加载 `.env`（可选）。
2. `init_tracing`；默认过滤器字符串 `chatgpt_mirror_gateway=info,tower_http=info`、错误串 `failed to set global default subscriber`（【B 0xda1210 窗口】）。
3. `config::Settings::from_env`（【G L32254】）。
4. `db::init_db`（【G L32259】）→ 建表 + 幂等迁移（见 §10）。
5. 读取四类持久化配置：`db::get_blocked_paths_config`、`db::get_custom_script_config`、`db::get_mirror_proxy_config`、`db::get_political_moderation_config`（【G L32255-32258】）。
6. 构建运行时对象：`proxy::build_http_client`、`proxy::new_cf_bypass_cache`、`proxy::new_mirror_proxy_runtime`、`proxy::new_pow_risk_monitor`（【G L32262-32265】）。
7. `build_router` → `Router::layer` → `Router::into_make_service_with_connect_info`（【G L32251-32253、L32135-32136】）。
8. `TcpListener::bind_addr`（地址来自 `String` → `to_socket_addrs`，即 `HOST`/`PORT`）（【G L32275-32276】）；成功后 `axum::serve(...).into_future()` 运行（【G L32239】）。
9. 失败路径：Runtime 构建失败 `Failed building the Runtime`；bind/serve 错误走 `std::io::stdio::_eprint` + `std::process::exit(1)`（【G L32173-32207】【B 0xda1210 窗口】）。
10. 启动成功日志：`gateway upstreams configured:` 与 `: gateway listening on http://…`（【B 0xd96630 窗口；03 §11.1 记录 0xd96649】）。

顶层 `main` 为 tokio multi-thread builder + `block_on`，构建失败 `unwrap`（【G L30776-30804】）。

### 1.3 替代实现必须保持的启动不变量

- 读取同名 env（§2）并支持 `.env`（dotenvy）。
- 启动顺序：init_db → 配置装载 → 客户端/缓存初始化 → router → 监听；四步之间不得先监听端口后读库（否则与入口脚本的就绪探测竞态语义不同）。
- 监听失败以非零码退出；日志级别默认 `chatgpt_mirror_gateway=info,tower_http=info`（可被环境覆盖——env 名未在字符串中确认（未证实），但该默认值本身已复核）。
- `LD_PRELOAD`/`CURL_IMPERSONATE` 由外壳脚本注入；二进制内**查无** `CURL_IMPERSONATE` 字符串（【03 §0.2】），替代实现不要把它当 gateway 配置项。

---

## 2. 环境变量（配置面）

gateway 读取的变量（偏移均为文件内字符串偏移；【03 §8】为主，本报告已复核长名变量族）：

| 变量 | 偏移 | 用途（判读） | 备注 |
|---|---|---|---|
| `GATEWAY_ADMIN_SECRET` | `0xd96422` | 管理面密钥（求值 `require_gateway_admin`） | 与 cfbypass 密钥默认同源（入口脚本 43） |
| `DATABASE_PATH` | `0xd96436` | SQLite 文件路径 | Python 参考版 `DATABASE_URL` 在二进制中 NOT FOUND |
| `MIRROR_API_PREFIX` | `0xd96443` | 本机 API 挂载前缀 | 未证实默认值 |
| `ADMIN_UPSTREAM` | `0xd96454` | 管理上游基址（`/0x/*`） | 入口脚本不导出；未证实默认值 |
| `DJANGO_UPSTREAM` | `0xd96462` | Django 上游基址 | 脚本默认 `http://127.0.0.1:8000` |
| `CHATGPT_BASE_URL` | `0xd94bd0` | ChatGPT 主站基址 | 与 `HOST`/`PORT` 同配置区【B 0xd94bc0】 |
| `CHATGPT_CDN_BASE_URL` | `0xd96484` | CDN 基址 | 未证实默认值 |
| `CHATGPT_AB_BASE_URL` | `0xd964b1` | A/B 端点基址 | 未证实默认值 |
| `CF_BYPASS_URL` | `0xd964da` | cfbypass 服务地址 | 脚本默认 `http://127.0.0.1:8001` |
| `CF_BYPASS_PROXY_SERVER` | `0xd964e7` | cfbypass 请求所用代理 | 与 §13 代理配置联动（判读） |
| `REQUEST_TIMEOUT_SECS` | `0xd964fd` | 单一请求超时 | Python 参考版拆为两个超时变量；此处为单变量 |
| `TRUSTED_PROXY_IPS` | `0xd96511` | 信任代理来源 IP 列表 | 对应符号 `config::parse_ip_list` |
| `HOST` / `PORT` | `0xd94be4` / `0xd94be8` | 监听地址/端口 | 脚本默认 PORT=40002；HOST 默认未确认（未证实） |
| `CREDENTIAL_ENCRYPTION_KEY` | `0xd8c624`、`0xd8c63d`、`0xd8c676` | 凭证加密密钥 | 见 §10.4 |

其他相关（非 gateway 读取）：

- 镜像 Env 中 `NO_PROXY/no_proxy=localhost,127.0.0.1` 保护本机互调【01 §4】。
- 入口脚本变量 `ADMIN_USERNAME`、`CURL_IMPERSONATE_PROFILE` 等【01 §4】。
- 明确**不要**照搬 Python 参考实现的 `DATABASE_URL`、`GATEWAY_CONNECT_TIMEOUT_SECONDS`、`GATEWAY_READ_TIMEOUT_SECONDS`（二进制 NOT FOUND；【03 §11.2】）。

---

## 3. Axum 路由顺序与方法

> 重要限制（沿用【03 §12.3】）：路由字符串来自 `.rodata` 粘连字面量池 + 符号推断，**逐条 `Router::route` 绑定未做指令级确认**；“顺序”按字符串注册区出现顺序给出（判读）；各自**HTTP 方法大多未证实**。

### 3.1 路由 token 清单（按注册区出现顺序）

**A. `/api/*` 管理/业务 API（注册区 `0xda0a00–0xda1120`）**（【03 §7.1】）：

| # | 路由 token | 偏移 |
|---|---|---|
| 1 | `/api/login` | `0xda0aec` |
| 2 | `/api/logout` | `0xda0b01` |
| 3 | `/api/user-work-mode` | `0xda0b0c` |
| 4 | `/api/get-user-info` | `0xda0b1f` |
| 5 | `/api/diagnose-chatgpt-auth` | `0xda0b31` |
| 6 | `/api/get-mirror-token` | `0xda0b4b` |
| 7 | `/api/get-user-use-count` | `0xda0b60` |
| 8 | `/api/get-chatgpt-use-count` | `0xda0b77` |
| 9 | `/api/conversation-statistics` | `0xda0b91` |
| 10 | `/api/conversation-statistics/reset` | `0xda0bad` |
| 11 | `/api/get-user-quota-usage` | `0xda0bcf` |
| 12 | `/api/backup/export` | `0xda0be8` |
| 13 | `/api/backup/restore` | `0xda0bfa` |
| 14 | `/api/operations-overview` | `0xda0c0d` |
| 15 | `/api/close-chatgpt-memory` | `0xda0c25` |
| 16 | `/api/mirror-proxy-config` | `0xda0c3e` |
| 17 | `/api/test-mirror-proxy-config` | `0xda0c56` |
| 18 | `/api/custom-scripts` | `0xda0c73` |
| 19 | `/api/political-moderation-config` | `0xda0c86` |
| 20 | `/api/political-moderation-config/test` | 同粘连串 |
| 21 | `/api/blocked-paths` | `0xda0cab` |
| 22 | `/api/auth/session`（含尾斜杠变体） | `0xda0cbd` / `0xda0cce` |
| 23 | `/api/not-login` | `0xda0ee2` |
| 24 | `/api/refresh-cfbypass` | `0xda0efc` |
| 25 | `/api/pow-risk-stream`（SSE） | `0xda0f11` |
| 26 | `/api/user-blocked-paths` | `0xda0f25` |
| 27 | `/api/livekit/` | `0xda0f6d` |

**B. 上游/传输匹配器（含通配符；`0xda0f3c–0xda1120`）**（【03 §7.2】+ 本报告尾部复核）：

| # | 路径模式 | 偏移 | 备注 |
|---|---|---|---|
| 1 | `/sentinel/20260423af3c/sdk.js` | `0xda0f3c` | ChatGPT sentinel SDK |
| 2 | `/v1/chat/completions` | `0xda0f59` | OpenAI 风格上游 |
| 3 | `/ga/collect` | `0xda0f79` | |
| 4 | `/vendor-batch/collect` | `0xda0f84` | |
| 5 | `/ws-chatgpt`、`/ws-chatgpt/*path` | `0xda0f99`/`0xda0fa4` | WS 桥接 |
| 6 | `/cdn-cgi/challenge-platform/*path`、`/cdn-cgi/*path` | `0xda0fb5`/`0xda0fd6` | Cloudflare 挑战路径 |
| 7 | `/ces/v1/projects/oai/settings`、`/ces/v1/rgstr`、`/ces/statsc/flush`、`/ces/*path` | `0xda0fe4`–`0xda102c` | |
| 8 | `/realtime`、`/realtime/*path` | `0xda1036`/`0xda103f` | |
| 9 | `/backend-api/estuary/*path` | `0xda1063` | 内容 URL 绝对化（符号 `absolutize_estuary_content_urls`） |
| 10 | `/backend-anon/*path` | `0xda107d` | 匿名通道 |
| 11 | `/backend-api/*path` | `0xda1090` | 已登录通道 |
| 12 | `/0x/*path` | `0xda10a5` | 管理上游（另有 `/0x/` token `0xd546e0`、`/0x/user/register`） |
| 13 | `/admin`、`/admin/`、`/admin/*path` | `0xda10ae`–`0xda10c4` | 管理 UI |
| 14 | `static`、`static/index.html` | `0xda10cd` | 内嵌前端入口 |
| 15 | `/chat`、`/chat/*path`（判读） | `0xda10c0`–`0xda10ee` 邻接区 | token 边界未逐条重切 |
| 16 | `/static-rsc-1/`、`/static-rsc-1/*path` | 同上邻接区【B 0xda10c0-0xda1240】 | 判读 |
| 17 | `/images-openai/`、`/images-openai/*path` | 同上 | 判读 |
| 18 | `/mapbox/`、`/mapbox/*path`、`/mapbox-events/events(/*path)` | 同上 | 判读 |
| 19 | `/*path`（兜底，token 边界不确定） | 同上 | **未证实** |

**C. ChatGPT 业务子路径（代理内匹配；`0xda0ce0–0xda0ef0`）**（【03 §7.3】）：`/apps/sources_dropdown/backend-anon|backend-api`、`/gizmos/snorlax/sidebar/backend-api`（含 anon）、`/pins/backend-api`（含 anon）、`/feed/entrypoint/backend-api`、`/feed/mixed/*`、`/beacons/home/backend-anon|backend-api`、`/amphora/notifications/backend-api`、`/tasks/backend-api`、`/user_surveys/active`、`/auth/logout`。

### 3.2 Handler 提取器类型（决定方法/语义的关键证据）

以下来自 Ghidra 导出的 axum handler `drop_in_place` 包装（提取器元组 = handler 的实际签名参数类型）：

| Handler（符号） | 提取器 | 证据 |
|---|---|---|
| `proxy::proxy_admin_as_axum` | `State<AppState>` + `Request<Body>`（ViaRequest） | 【G L522】 |
| `proxy::proxy_gateway_as_axum` | `State` + `Request`（ViaRequest） | 【G L621】 |
| `proxy::proxy_chatgpt_api_as_axum` | `State` + `Request`（ViaRequest） | 【G L704】 |
| `proxy::proxy_chatgpt_ws_as_axum` | `State` + `WebSocketUpgrade` + `Uri` + `HeaderMap`（ViaParts） | 【G L787】 |
| `proxy::proxy_django_as_axum` | `State` + `ConnectInfo<SocketAddr>` + `Request`（ViaRequest） | 【G L902】 |

要点：

- WS 路由因 `WebSocketUpgrade` 提取器，方法必须是 **GET**（判读，axum 约束）。
- Django 代理 handler 需要 `ConnectInfo<SocketAddr>` ⇒ service 必须用 `into_make_service_with_connect_info`（【G L32135】），替代实现若省掉它，Django 侧拿不到真实客户端 IP。
- 各路由 ↔ handler 的对应关系未指令级确认（未证实）；路由方法与 `MethodRouter` 组成同样未证实。
- SSE：`/api/pow-risk-stream`（符号 `gateway_pow_risk_stream`、`pow_risk_sse_event`），响应形态为 text/event-stream（判读）。

---

## 4. 静态资源

- 静态文件由 **tower-http ServeDir** 提供服务：二进制内 `src/services/fs/serve_dir/open_file.rs` + `index.html` + `application/octet-stream`（【B 0xd97690；03 §5 依赖含 tower-http 0.6.8】）。
- 路由面：`static`、`static/index.html`【03 §7.2】；`/admin`/`/admin/*path` 同层注册【03 §7.2】；`/static-rsc-1/*path`、`/images-openai/*path` 等尾区 token（§3.1-B）。
- 静态资源缓存头字面量：`public, max-age=31536000, immutable`（【B 0xd8507a】），对应符号 `apply_static_asset_cache_headers`（【03 附录 A】）。
- 私有响应（no-store 族）字面量：`private, no-store, no-cache, must-revalidate, max-age=0`（【B 0xd85013】），对应 `apply_private_no_store_headers`（根级符号）。
- 邻接相关头名/键名：`cloudflare-cdn-cache-control`、`Cookie`、`Authorization`（【B 0xd85020-0xd85090 邻接窗口】；与缓存键/豁免逻辑的关系未证实）。
- 前端产物（镜像层 12，38 条目）：`app/static/index.html`、`favicon.svg`、`assets/` 下 35 个文件，目录覆盖 chatgpt/access/announcement/gptcar/logs/overview/political-moderation/profile/proxy/request/scripts/user 等功能页（【01 §5】）。前端内容本次未读（范围外）。
- 兼容要求：保持相同 URL 前缀与 SPA 入口映射；静态缓存策略与上表两条 Cache-Control 字面量一致（时长/可共享性可被前端构建覆盖的例外情况未证实）。

---

## 5. Django 代理（`/0x/*path`）

- 路由：`/0x/*path` → 管理上游（`ADMIN_UPSTREAM`，`0xd96454`）；`/0x/user/register` 字面量存在于 `0xd546e0`（【03 §7.2、§11.1】）。
- 默认上游：`http://127.0.0.1:8000`（入口脚本 `DJANGO_UPSTREAM`；【01 §8】）。
- handler：`proxy_django_as_axum` 携带 `ConnectInfo<SocketAddr>`（§3.2）⇒ 代理层在读客户端 IP；具体如何注入下游（如 `X-Forwarded-For` 或 Django 直读）**未证实**。
- 相关内部函数（名称证据，规则未证实）：`rewrite_origin_prefix_to_local`、`is_internal_fixed_upstream_url`、`build_target_url`、`classify_upstream`、`mirror_request_origin`（【03 附录 A】）。
- 兼容要求：`/0x/*` 必须原样代理到 Django（含子路径与查询串），并保持与 gateway 同源会话 Cookie 语义（§8）。

---

## 6. ChatGPT API / WS / CDN 代理由

### 6.1 路由面（§3.1-B/C 已列）

- API：`/backend-api/*path`、`/backend-anon/*path`、`/ces/*`、`/sentinel/20260423af3c/sdk.js`、`/v1/chat/completions`、`/ga/collect`、`/vendor-batch/collect`、`/realtime/*`、`/images-openai/*`、`/cdn-cgi/*`。
- 子路径特判（§3.1-C）：sources_dropdown/gizmos/pins/feed/beacons/amphora/tasks 等 —— 对应功能：会话/项目归属（`claim_conversation_owner`、`conversation_belongs_to_user` 等，【03 附录 A】）。

### 6.2 WebSocket 桥接

- 路由 `/ws-chatgpt`、`/ws-chatgpt/*path`（【03 §7.2】）。
- 符号族：`bridge_chatgpt_ws`、`proxy_chatgpt_ws_via_configured_proxy`、`connect_chatgpt_ws_via_http_proxy`、`connect_chatgpt_ws_via_socks_proxy`、`upstream_ws_message_to_axum`、`axum_ws_message_to_upstream`（【03 附录 A】【G L59、L73-78】）。
- 上游 WS 目标校验：字面量 `wss://ws.chatgpt.com` + `valid ws.chatgpt.com url`（【B 0xd64a2a 窗口】）⇒ 目标必须是 ws.chatgpt.com（判读：校验失败即拒绝，具体错误形态未证实）。
- 传输栈：tokio-tungstenite 0.24（【03 §5】）；经 HTTP/SOCKS 代理建连时按代理配置分流（符号证据，选择条件未证实）。

### 6.3 HTTP 客户端与指纹

- 双栈：`wreq 6.0.0-rc.31`（BoringSSL/btls 指纹栈）与 `isahc 2.0.1 / curl 0.4.50`（动态 `libcurl.so.4`，运行时被 `LD_PRELOAD=libcurl-impersonate.so` 替换）（【03 §5、§0.2】）。
- 二进制记录串 `: curl-impersonate `（`0xd64540`）提示运行时会探测/记录 curl-impersonate（【03 §0.2】）。
- 超时：由 `REQUEST_TIMEOUT_SECS` 单变量控制（【03 §11.2】）。

---

## 7. URL rewrite 映射

### 7.1 已确证：内嵌 JS “rewriteHttpUrl” 映射表

二进制内含一段前端改写脚本（起于 `var rewriteHttpUrl = function(raw)`【B 0xd65330】），其 pairs 表**逐字**如下（【B 0xd65380–0xd65740】）：

| # | from | to |
|---|---|---|
| 1 | `https://chatgpt.com/backend-api/estuary/` | `/backend-api/estuary/` |
| 2 | `https://chatgpt.com/backend-api/` | `/backend-api/` |
| 3 | `http://chatgpt.com/backend-api/` | `/backend-api/` |
| 4 | `https://chatgpt.com/backend-anon/` | `/backend-anon/` |
| 5 | `http://chatgpt.com/backend-anon/` | `/backend-anon/` |
| 6 | `https://chatgpt.com/public-api/` | `/public-api/` |
| 7 | `http://chatgpt.com/public-api/` | `/public-api/` |
| 8 | `https://chatgpt.com/api/` | `/api/` |
| 9 | `http://chatgpt.com/api/` | `/api/` |
| 10 | `https://chatgpt.com/v1/` | `/v1/` |
| 11 | `http://chatgpt.com/v1/` | `/v1/` |
| 12 | `https://chatgpt.com/ces/` | `/ces/` |
| 13 | `http://chatgpt.com/ces/` | `/ces/` |
| 14 | `https://chatgpt.com/realtime/` | `/realtime/` |
| 15 | `http://chatgpt.com/realtime/` | `/realtime/` |
| 16 | `/assets/` | `connectorOrigin + '/assets/'` |
| 17 | `/blank.svg` | `connectorOrigin + '/blank.svg'` |

替代实现：这 15 条绝对→相对前缀映射 + 2 条相对→connectorOrigin 映射是**可直接复制的契约数据**；脚本的注入条件与页面范围未证实。

### 7.2 规则存在但未还原（名称级证据）

【03 附录 A】符号：`rewrite_location`、`rewrite_origin_prefix_to_local`、`rewrite_deep_research_connector_location`、`redirect_response_with_status`、`absolutize_estuary_content_urls`、`html_response`、`insert_after_opening_tag`、`insert_before_closing_tag`、`web_sandbox_asset_fallback_url`、`filter_conversation_collection_body/value`、`filter_project_collection_body/value`、`claim_conversation_ids_from_json_response`、`update_conversation_titles_from_body`、`is_temporary_conversation_id`、`normalize_conversation_id`、`normalize_project_id`。

⇒ 这些函数的**具体改写规则（触发条件、正则、状态码）均未证实**；替代实现需运行时对比或对相应符号反汇编（建议目标：`0x3be440 build_router` 的 handler 闭包、`proxy::` 模块对应地址）。

### 7.3 相关观测

- `https://chatgpt.com/backend-api/estuary/` 在二进制中另有一处独立字面量（【B 0xd653a2】）。
- CDN 域名族：`oaistatic.com`、`images.openai.com`、`cdn…`（【B 0xd543c4 窗口】；与 `CHATGPT_CDN_BASE_URL` 的绑定关系未证实）。

---

## 8. Header / Cookie 处理

### 8.1 Chrome 146 网络身份（已确证字面量）

`proxy::apply_chrome_146_network_identity`（vaddr `0x15c8b0`，size 0x4b8；【G L2047-2221】）做 4 组头部插入（HeaderMap 仅缺失时插入——依据根级符号 `insert_header_if_absent` 与 try_insert 链路，判读）：

| 头名（长度） | 取值（长度） | 证据 |
|---|---|---|
| （101 字节取值；头部名未在窗口内还原，判读为 `user-agent`） | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36` | 【B 0xd64ba2 起 101 字节 + G L2092-2100】 |
| `sec-ch-ua`（9） | `"Chromium";v="146", "Not_A Brand";v="99"`（40） | 【B 0xd68ea6/0xd68eaf】 |
| `sec-ch-ua-full-version`（22） | `"146.0.7680.177"`（16） | 【B 0xd68ed7/0xd54aa0】 |
| `sec-ch-ua-full-version-list`（27） | `"Chromium";v="146.0.7680.177", "Not_A Brand";v="99.0.0.0"`（57） | 【B 0xd68eed/0xd68f08】 |

另：`oai-device-id`、`browser_oai_device_id`、`server_oai_device_id`、`server_oai_device_cookie`（【03 §10.6】【03 附录 A】）。

### 8.2 请求头卫生与透传

- 名称级证据（规则未证实）：`is_hop_header`（hop-by-hop 过滤）、`merge_cookie_headers`、`cookies_to_header`、`cookie_names_for_log`（Cookie 名脱敏日志）、`insert_request_header`、`chatgpt_json_request_headers`、`build_upstream_auth_cookie_header`（【03 附录 A】）。
- `build_upstream_auth_cookie_header` 提示上游鉴权以 **Cookie 形式**下发（判读）。

### 8.3 会话 Cookie

- 函数：`build_cookie`、`append_session_cookies`、`clear_session_cookies`、`find_cookie_value`、`rebuild_split_cookie_value`（拆分 Cookie 重建）、`merge_extra_cookies_with_cfbypass`、`supplemental_has_cloudflare_cookie`、`supplemental_has_next_auth_cookie`（【03 附录 A】）。
- Cookie 名常量（复核）：`__Host-`（`0xd8c8ff`）、`__Secure-`（`0xd888e0`）、`__Secure-next-auth.session-token`（`0xd63870`/`0xd888e0`）、`next-auth.session-token`（`0xd63879`，本报告复核）【03 §10.5】【B】。
- 上游站点上下文：`ws.chatgpt.com`、`chatgpt.com` 与其 Cookie 域关系未逐一还原（未证实）。

### 8.4 SupplementalCookie（结构化 Cookie，字段已解码）

serde visitor 解码出的 JSON 键（【G L29218-29300】、expecting L29303-29317）：

```
{ name, value, domain, host_only, path, secure, http_only, expires, source }
```

语义函数（反编译存在于导出中，行区见括号）：`scope_identity`（G L4304-4780）、`is_mirror_local`（G L4036-4273）、`is_current_at`（G L4273-4304）、`applies_to_url`（G L4780-5432）。⇒ 字段齐全，但**匹配/作用域细节未逐条还原**（未证实）；替代实现至少应保留同样的 9 字段 JSON 形状与域/路径/expires 语义位。

### 8.5 响应安全头

- CSP 样例（`0xd699b9` 窗口）：`sandbox; default-src 'none'; img-src data: https:; media-src https:; font-src data: https:; style-src 'unsafe-inline' https:; base-uri 'none'; form-action 'none'; frame-ancestors …`【03 §10.5】。
- 头名：`content-security-policy`、`content-security-policy-report-only`、`strict-transport-security`【03 §10.5】。
- `apply_private_no_store_headers` + `append_vary_header`（根级/api 符号）【03 附录 A】。
- 管控响应头：`x-mirror-moderation`（【B 0xd85000 窗口；文件内首处 `0xd84a5e`】）。

### 8.6 网关鉴权头

- `x-gateway-secret`（`0xd86020`，复核）、`x-mirror-token`（`0xd6466b`，复核）、`Authorization`/`Bearer`（多处，【03 §10.1】）。
- 管理面鉴权函数 `api::require_gateway_admin`（vaddr `0x1dd8a0`）；具体比较实现未反汇编（未证实；注意 subtle 常时比较**不能**据此断言，【03 §10.9】）。

---

## 9. cfbypass 协议（两端契约）

### 9.1 服务端（cfbypass app；【02 §1-§6】摘要）

- 端点：`POST /cloudflare5s/bypass-v1` 与 `/v2`（完全同实现）（app.py:581-588）。
- 鉴权：`Authorization: Bearer <secret>`，`hmac.compare_digest`；secret 为空 fail-closed 全部 401（app.py:79-84、51）。
- 请求体（Pydantic）：`{url: HttpUrl, user_agent?: str, proxy_server?: str}`（app.py:124-156）。
- 响应：`{user_agent, cookies: [{name, value, domain?}]}`；成功判据仅“cookies 非空”（部分集合无 cf_clearance 也 200）（app.py:475、503-506、543-548、576-577）。
- 状态码：400（URL 校验失败）、401（鉴权失败）、422（schema，框架）、502（无 Cookie）（app.py:103-121、79-84、576-577）。
- Cookie 白名单：`cf_clearance`、`__cf_bm`、`__cflb`、`_cfuvid`（app.py:61、206-208）；每 attempt 清空浏览器 Cookie（421-424）。
- 目标限制：https-only、禁 userinfo、端口仅 443、域白名单默认 `chatgpt.com,.chatgpt.com`、解析地址必须全为公网（app.py:87-121）；导航后复检（438-445）。
- 全局串行锁（app.py:65、567）；单请求最长约 35 s（15 s 载入 + 20 s 轮询）。

### 9.2 gateway 侧客户端行为

- 调用路径字面量 `/cloudflare5s/bypass-v1` 三处（`0xd84ec8`、`0xd88ee0`、`0xd9d4c4`；`0xd84ec8` 窗口含 `cfbypass ` 前缀）【03 §7.4】【B 复核】。
- 请求构造：`reqwest` + `RequestBuilder::bearer_auth` + `RequestBuilder::json`（【G L2796-2798】）；响应 `serde_json::from_slice`（【G L2801】）。
- 响应处理：`normalize_cfbypass_cookies`、`normalize_cfbypass_target_url`（【G L2783-2784】）；缓存：`new_cf_bypass_cache`、`cf_cache_key_with_proxy`、`get_cached_cfbypass_payload_with_proxy_server`、`clear_cfbypass_cache_entry_with_proxy_server`（【G L2234、L391、L2780】）；兜底客户端 `cfbypass_fallback_client`（`cfbypass fallback client` 字面量窗口含 `cf_clearance`、`direct`、`proxy=`；【03 §10.7】）。
- 持久化：`persist_cfbypass_cookies_for_request`、`is_safe_cfbypass_cookie_name`、`merge_extra_cookies_with_cfbypass`、`supplemental_has_cloudflare_cookie`（【03 附录 A】）。
- 配置：`CF_BYPASS_URL`、`CF_BYPASS_PROXY_SERVER`；密钥默认复用 `GATEWAY_ADMIN_SECRET`（入口脚本 43；【02 §7.2】）。
- 缓存 TTL、键组成细节、fallback 触发条件均**未证实**；替代实现需运行时观测（建议从 `/api/refresh-cfbypass` 与 `/cloudflare5s/bypass-v1` 的日志串入手，日志前缀见【02 §1.6】）。

---

## 10. SQLite schema 与迁移

### 10.1 引擎与路径

- `rusqlite 0.31.0` bundled sqlite3（276 个 `sqlite3_*` 定义符号；无动态导入）【03 §9】。
- 库路径 = `DATABASE_PATH`（`0xd96436`）；镜像 Volume `/app/data`（【01 §2】）。

### 10.2 建表 DDL（逐字来自二进制 `0xd8c917` 起；本报告复读）

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
```

（证据：本报告对 `0xd8c917–0xd8d910` 的逐字节 ASCII 复读；与【03 §9】表清单/偏移一致。）

### 10.3 迁移（幂等 ADD COLUMN 模式）

模式：`PRAGMA table_info(<表>)` 检查列是否存在 → 缺失则 `ALTER TABLE … ADD COLUMN`（【03 §9】【G】）：

| 表 | 列 | 语句（关键片段） | 证据 |
|---|---|---|---|
| `chatgpt_accounts` | `extra_cookies` | `ADD COLUMN extra_cookies TEXT DEFAULT '[]'` | 【G L5799】 |
| `gateway_sessions` | `session_token` | `ADD COLUMN session_token TEXT` | 【G L5903】 |
| `gateway_sessions` | `extra_cookies` | `ADD COLUMN extra_cookies TEXT DEFAULT '[]'` | 【G L6153】 |
| `gateway_sessions` | `login_mode` | `ADD COLUMN login_mode TEXT NOT NULL DEFAULT 'api'` | 【G L6255】 |
| `gateway_sessions` | `force_chat_mode` | `ADD COLUMN force_chat_mode BOOLEAN NOT NULL DEFAULT TRUE` | 【G L27415】 |
| `gateway_sessions` | `proxy_node_id` | `ADD COLUMN proxy_node_id INTEGER` | 【G L27725】 |
| `gateway_sessions` | `daily_quota` / `monthly_quota` | `ADD COLUMN … INTEGER NOT NULL DEFAULT 0` | 【G L28087-28102】 |

迁移函数：`ensure_gateway_sessions_quota_columns`、`ensure_gateway_sessions_force_chat_mode_column`、`ensure_gateway_sessions_proxy_node_id_column`、`migrate_sensitive_rows`（【03 §9】）。

### 10.4 凭证加密与摘要

- 存储格式：`enc:v1:` 前缀 + base64url（字母表 `A–Za–z0–9-_`，`0xd8c6ac`）【03 §10.2】；密钥 `CREDENTIAL_ENCRYPTION_KEY`；`sha256:` 前缀出现在密钥派生/指纹区（`0xd8c87c`）【03 §10.2】【B 复核 `0xd8c87c`】。
- 实现符号：`db::credential_key`（`0x2478a0`）、`encrypt_secret`（`0x247aa0`）、`decrypt_secret`（`0x248050`）、`migrate_sensitive_rows`；依赖 `aes 0.8.4` + `aead 0.5.2`【03 §10.2】。⇒ AES 具体模式、KDF 参数、nonce 布局**未证实**（替换实现无法兼容存量密文，除非反向确认；建议：明文迁移用 `migrate_sensitive_rows` 语义对齐，并对 `enc:v1:` 密文做运行时解密观测）。
- `mirror_token` 以 SHA-256 摘要存储（`db::mirror_token_hash` `0x248630`；【03 §10.3】）。

### 10.5 设置 KV（`gateway_settings`）

键（复核）：`mirror_proxy`（`0xd8d984`）、`custom_scripts`（`0xd8dc73`）、`political_moderation`（`0xd8dda3`）、`blocked_paths`（`0xd8e0b7`）。

代表性 SQL（摘录）：

- `SELECT value FROM gateway_settings WHERE key = 'mirror_proxy'`（`0xd8d954`）；`UPDATE gateway_settings SET value = ?1 WHERE key = 'mirror_proxy'`（`0xd8d991`）（【B】）。
- `INSERT INTO gateway_settings (key, value, updated_at) VALUES ('political_moderation', ?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`（【B 0xd8dde0 窗口】；同类 UPSERT 亦见 `0xd908d4`，【03 §9】）。
- 会话/账号更新：`UPDATE chatgpt_accounts SET access_token=?, session_token=?, extra_cookies=?, refresh_token=?`（`0xd8d9d2`）；`UPDATE gateway_sessions SET access_token=?, session_…`（同邻接区）（【B】）。

### 10.6 会话记录字段与配额统计

- `save_gateway_session` 写入字段含 `access_token/session_token/extra_cookies/mirror_token…`（`0xd8e17c`；【03 §9】）。
- 配额 SQL：`SELECT COUNT(*) FROM visit_logs WHERE username = ?1 AND log_type = 'proxy' AND created_at >= CAST(strftime('%s','now',?2) AS INTEGER)`（`0xd8f772`/`0xd8f817`；【03 §9】）⇒ 周期以“基准时间字符串 + now”表达（判读）。
- `user_name`/`chatgpt_username` 双键；`transport` 取值 wreq（`0xd8f684` 邻窗；【03 §9】）。

### 10.7 restore 删除顺序（备份恢复的前置）

`DELETE FROM conversation_model_statistics / conversation_statistics / conversation_owners / project_owners / gateway_sessions / visit_logs / chatgpt_accounts / gateway_settings;`（顺序即语句序列，`0xd8ff3b–0xd9008c`；【03 §9】）⇒ 替代实现的 restore 应按同一顺序清表（外键/一致性语义，判读）。

---

## 11. 备份（`/api/backup/export`、`/api/backup/restore`）

- 路由字面量 `backup` 复核于 `0xda0bed`（即 `/api/backup/…` 串内）【B】。
- `db::export_backup`（【G L23812-25284】）：新建一个 SQLite 连接（`open_with_flags 0x8046`【G L23944-23945】），逐表执行（`Connection::prepare_with_flags`），把行值序列化成 `serde_json::Value`（`collect_seq`、`BTreeMap::insert`）⇒ **导出物是“按表组织的 JSON 值集合”**（`drop_in_place<[serde_json::value::Value]>` 等【G L25288-25307】）。
- `db::restore_backup`（【G L25362-27220】）：事务（`rusqlite::transaction::Transaction`）+ `Connection::execute`/`execute_batch`；用 `serde_json` 索引 `Index>::index_into` 取值；含 `SystemTime::now/duration_since`（时间校验/时间戳用途未证实）【G L27224-27240】；随后执行 §10.7 删除序列与重插。
- **未证实**：备份 JSON 的信封结构（是否含版本号/表名映射/时间戳字段）、ID 是否保留、冲突处理、与 `migrate_sensitive_rows` 的先后关系。替代实现必须运行 `export` 抓取真实样本后再对齐解析器（不要凭空设计 envelope）。

---

## 12. Moderation（内容审核）

### 12.1 模块函数（名称级证据，【03 附录 A】）

`contains_political_trigger`、`build_review_input`、`parse_decision`、`provider_endpoint`、`provider_output_text`、`extract_user_text`、`latest_role_text`、`text_from_content`、`normalize_base_url`、`normalize_config`；计费/限速：`enforce_moderation_rate_limit`、`enforce_metered_request`、`is_metered_proxy_request`、`limit_per_minute`（`0xd85ff0`）；响应构造：`moderation_response`。

### 12.2 配置结构（已解码 + 未还原项）

`PoliticalModerationConfig` 字段（serde visitor 解码，【G L29018-29110】）：`enabled`、`protocol`、`model`、`api_key`、`base_url` + **5 个未还原名称字段**（长度 4/12/14/16/22；对应 `bcmp` 常量表，本次未能读出）——未证实。

字面量簇（【B 0xd8c820-0xd8c920 窗口逐字读出】）：`sha256:`（`0xd8c87c`）、`openai_chat`（`0xd8c883`；判读：protocol 取值之一）、`relaxed`（`0xd8c88e`，默认模式，见下）、`https://api.openai.com/v1`（判读：默认 base_url）、`mirror_token`、`login_mode`、`model_limits`、`next-auth.session-token`、`__Host-`、`__Secure-`。

默认审核模式：`db::default_moderation_mode` 返回 **`relaxed`**（7 字节；【G L3811-3818 解码 + B 0xd8c88e 字面复核】）。

### 12.3 外部 provider 请求形状（已确证字面量）

【B 0xd64300 窗口】内含两套 provider 字段与头部（同一响应错误路径 `/error/message`）：

- OpenAI 风格：`model`、`instructions`、`input`、`max_output_tokens`、`temperature`。
- Anthropic 风格：`systemInstruction`、`parts`、`maxOutputTokens`、头部 `x-api-key`、`anthropic-version: 2023-06-01`。

（两套模板的选择条件 = `protocol` 字段驱动，判读；具体请求路径由 `provider_endpoint` 决定，未证实。）

### 12.4 另两套审核相关配置

- `blocked_paths`（设置键 `0xd8e0b7`）：`BlockedPathsConfig` 的 `try_new/new`、`validate_blocked_path`、`normalize_blocked_path`、`get/save_blocked_paths_config`（【03 附录 A】【G L10759-12880】）。
- `custom_scripts`（设置键 `0xd8dc73`）：`CustomScriptItem` 字段已解码 = `{id, enabled, name, language, position, content}`（【G L28807-28988】）；加载/保存 `get/save_custom_script_config`；渲染 `render_custom_script`。
- 管理 API：`/api/political-moderation-config`、`/api/political-moderation-config/test`、`/api/blocked-paths`、`/api/custom-scripts`（§3.1-A）。

---

## 13. 代理配置（mirror_proxy / 外部代理守卫）

### 13.1 数据结构（已解码）

- `MirrorProxyConfig` = `{transport_mode, enabled, proxy_url, username, password, nodes}`（【G L28606-28667】）。
- `MirrorProxyNodeConfig` = `{id, enabled, proxy_url, username, password}`（【G L28674-28800】）。
- `UpstreamTransportMode`：externally-tagged 枚型，3 个 unit 变体（变体名未在导出窗口还原，未证实；【G L28260-28595】）。

### 13.2 安全守卫（名称级证据）

`validate_mirror_proxy_url`、`redact_proxy_url`、`sanitized_proxy_url`、`sanitized_proxy_config`、`normalize_mirror_proxy_config`、`normalize_proxy_fields`、`effective_mirror_proxy_url`、`is_allowed_external_proxy_host`（`0x149230`）、`is_public_external_ip`（`0x149d60`）、`select_mirror_proxy_node`、`new_mirror_proxy_runtime`、`account_client_pool_key_from_headers`、`cf_cache_key_with_proxy`；协议字面量 `socks5://`（`0xd6469a`）、`socks5h://`（`0xd646a6`，复核）；`trusted_cdn_sources`（`0xd876c6`）、`TRUSTED_PROXY_IPS` + `config::parse_ip_list`。

⇒ “仅允许公网外部 IP / 允许列表主机”的**判定规则细节未证实**；替代实现必须先观测既有节点配置的接受/拒绝行为再固化。

### 13.3 关联点

- 配置存 `gateway_settings.mirror_proxy`（§10.5）；会话表 `proxy_node_id` 关联节点（§10.3）；cfbypass 出站可选 `CF_BYPASS_PROXY_SERVER`（§9.2）。
- 管理 API：`/api/mirror-proxy-config`、`/api/test-mirror-proxy-config`（§3.1-A）。
- `select_mirror_proxy_node`/`effective_mirror_proxy_url` 的调度算法（轮询/权重/可用性）**未证实**。

---

## 14. 错误响应

### 14.1 已确认的构造点（名称级）

- `json_error`、`error_response`、`moderation_response`、`connector_fallback_response`、`redirect_response_with_status`（【03 附录 A】）。
- 启动期致命错误：`eprint` + `exit(1)`（§1.2）。
- 管理面 401/拒绝语义由 `require_gateway_admin` 承担（状态码与响应体格式**未证实**）。

### 14.2 跨进程错误契约（已确认）

- cfbypass：400/401/422/502（§9.1；【02 §1.4】）。
- 上游错误路径：moderation provider 侧 `/error/message` 取值（§12.3）。

### 14.3 替代实现须知

gateway 自身的错误响应清单（HTTP 状态码映射、JSON 错误体字段、`json_error` 的字段名）在现有静态证据中**未还原**。替代实现上线前必须逐路由抓取：未登录、坏 JSON、未授权 x-gateway-secret、上游 4xx/5xx、moderation 拒绝、配额超限、cfbypass 失败六类响应并记录（状态码 + body schema）。

---

## 15. 行为兼容核对清单（Checklist）

启动/配置：

- [ ] 读取同名 env（§2 全表），支持 `.env`；`PORT` 默认 40002、`HOST/PORT` 决定监听地址。
- [ ] 启动顺序 = init_db → 配置装载 → 客户端/缓存 → router → 监听；监听失败非零退出（§1.2）。
- [ ] 默认日志过滤器 `chatgpt_mirror_gateway=info,tower_http=info`；启动日志含 `gateway upstreams configured:` 与 `gateway listening on http://…`（§1.2）。
- [ ] 与容器入口脚本协同：Django(8000)/cfbypass(8001) 先就绪、TCP healthcheck 用 `PORT`、SIGTERM 回收（§1.1）。

路由/服务：

- [ ] 注册 §3.1 全部 `/api/*`（27 条含子变体）与上游匹配器（含通配符），顺序与字面量一致（顺序为判读）。
- [ ] `/ws-chatgpt` 路由使用 WebSocketUpgrade（GET），并校验上游 `ws.chatgpt.com`（§6.2）。
- [ ] service 用 `into_make_service_with_connect_info`（Django 代理需要客户端 IP）（§3.2）。
- [ ] 静态：ServeDir 语义 + `static/index.html`；静态缓存头 `public, max-age=31536000, immutable`；私有响应 `private, no-store, no-cache, must-revalidate, max-age=0`（§4）。
- [ ] `/0x/*` 原样代理 Django（默认 `http://127.0.0.1:8000`）（§5）。

Header/Cookie：

- [ ] Chrome146 指纹头 4 组（UA/sec-ch-ua 三件套，值见 §8.1），仅缺失时插入（判读）。
- [ ] hop-by-hop 过滤、Cookie 头合并/拆分重建、Cookie 名脱敏日志（§8.2）。
- [ ] `next-auth.session-token`/`__Secure-`/`__Host-` 处理；SupplementalCookie 9 字段 JSON（§8.3-8.4）。
- [ ] 响应安全头（CSP/HSTS/no-store/Vary/x-mirror-moderation）（§8.5）。

cfbypass：

- [ ] `POST /cloudflare5s/bypass-v1`、Bearer 鉴权、`{url,user_agent?,proxy_server?}`、`{user_agent,cookies[]}`、部分 cookies 也可能 200（§9.1）。
- [ ] 客户端：reqwest bearer + json、serde 解析、缓存键含代理维度、normalize/merge/persist cookie（§9.2）。

数据库/备份：

- [ ] §10.2 DDL 逐表逐列一致；迁移为 PRAGMA+ADD COLUMN 幂等（§10.3）。
- [ ] `gateway_settings` 键 `mirror_proxy/custom_scripts/political_moderation/blocked_paths` 与 UPSERT 语义（§10.5）。
- [ ] `mirror_token` 存摘要（SHA-256）；凭证 `enc:v1:` 容器（模式未证实，见 §10.4）。
- [ ] backup/restore 路由与 JSON 集合形态（envelope 未证实）；restore 清表顺序（§10.7、§11）。

moderation / 代理配置：

- [ ] 默认 mode=`relaxed`；`protocol/model/api_key/base_url` 字段名；provider 模板与 `x-api-key`/`anthropic-version: 2023-06-01`（§12）。
- [ ] mirror proxy 配置 JSON 键（含 nodes 子结构）；SOCKS5/SOCKS5H 字面量；公网 IP 守卫（规则未证实）（§13）。

路由重写：

- [ ] 内嵌 `rewriteHttpUrl` 的 17 条 pairs 表原样保留（§7.1）；其余 rewrite 规则见 §7.2（未证实）。

错误响应：

- [ ] 六类错误响应实测并锁定（§14.3）。

---

## 16. 未覆盖项与验证建议

1. **路由方法/MethodRouter**：未指令级确认（§3）。建议：对 `build_router`（vaddr `0x3be440`，size `0x289d`）反汇编或在隔离环境用 OPTIONS/探测各路由方法矩阵。
2. **URL rewrite 规则**：除 §7.1 pairs 外的规则未证实。建议：运行时抓取 `/backend-api/estuary/*` 与 deep-research/connector 页面响应，diff 改写前后。
3. **备份 JSON envelope**：以真实 `export` 输出为准（§11）。
4. **错误响应 schema**：§14.3 六类场景实测。
5. **AES 模式/KDF**：`credential_key/encrypt_secret/decrypt_secret`（`0x2478a0/0x247aa0/0x248050`）需反汇编或运行时解密观测（§10.4）。
6. **moderation 5 个未还原字段名**：`PoliticalModerationConfig` 的 4/12/14/16/22 字节字段；建议反汇编 `0x36c330`（visitor）或对 `/api/political-moderation-config` 实测取回 JSON 键。
7. **`UpstreamTransportMode` 3 个变体名**：对 `/api/mirror-proxy-config` 实测或反汇编 `0x36b920`。
8. **cfbypass 缓存 TTL/fallback 条件**：运行时观测（§9.2）。
9. **限流窗口/配额周期**：`limit_per_minute`、`usage_count_current_period` 的窗口语义未证实（§10.6、§12）。
10. 本报告未做动态验证（未运行、未联网）；容器与二进制行为差异以运行时为准。Python 参考实现（workspace 内 `chatgpt-mirror-build/gateway`，【03 §0.1、§11.3】）与二进制并非同一实现，**不得**作为兼容基线。

---

## 附：本报告新增的字节级复核记录（可复现）

对 `extracted/chatgpt-mirror-gateway`（sha256 见页首）的只读字节读取（偏移为文件偏移；只读，无写入）：

| 项 | 偏移/范围 | 内容摘要 |
|---|---|---|
| UA 字面量 | `0xd64ba2`（101 B） | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36` |
| sec-ch-ua 组 | `0xd68ea6/0xd68eaf/0xd68ed7/0xd54aa0/0xd68eed/0xd68f08` | 头名与取值见 §8.1 |
| 建表 DDL | `0xd8c917–0xd8d910` | §10.2 全文 |
| 凭证/模式簇 | `0xd8c820–0xd8c920` | `sha256:`、`openai_chat`、`relaxed`、`https://api.openai.com/v1`、`mirror_token`、`login_mode`、`model_limits`、`next-auth.session-token`、`__Host-`、`__Secure-` |
| 缓存头字面量 | `0xd85013` / `0xd8507a` / `0xd85000` | `private, no-store, no-cache, must-revalidate, max-age=0`；`public, max-age=31536000, immutable`；`x-mirror-moderation`（首处 `0xd84a5e`） |
| rewrite pairs JS | `0xd65330–0xd65740` | §7.1 全表 |
| 路由尾区 token | `0xda10c0–0xda1240` | `static/index.html`、`/chat`、`/static-rsc-1/*path`、`/images-openai/*path`、`/mapbox*` 等（边界判读） |
| 启动日志串 | `0xda1210`、`0xd96630` | `chatgpt_mirror_gateway=info,tower_http=info`、`Failed building the Runtime`、`gateway upstreams configured:`、`gateway listening on http://` |
| WS 目标串 | `0xd64a2a` 窗口 | `wss://ws.chatgpt.com`、`valid ws.chatgpt.com url` |
| 设置键 | `0xd8d984/0xd8dc73/0xd8dda3/0xd8e0b7` | `mirror_proxy`/`custom_scripts`/`political_moderation`/`blocked_paths` |

（完）

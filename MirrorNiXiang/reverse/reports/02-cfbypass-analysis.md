# 02 · cfbypass 源码级分析报告

> 目标制品：`D:\Project\MirrorNiXiang\image.tar`（OCI / docker-save 布局）
> 镜像标识：`docker.io/lisa666520/chatgpt-mirror-django:all-in-one`（`image.tar!index.json`）
> 分析对象：`reverse/extracted/cfbypass/app.py`（589 行）、`reverse/extracted/cfbypass/proxy_relay.py`（295 行）
> 取证方式：纯静态读取；未访问真实上游、未访问 api.zxcbug.com、未发起任何网络请求
> 引用约定：`app.py:Lx-Ly`、`proxy_relay.py:Lx-Ly`；镜像内成员用 `image.tar!<容器内路径>:Lx`；config/manifest 为单行 JSON，按唯一文本条目定位（如 `config.Env（"CF_BYPASS_ALLOWED_HOSTS=..."）`）
> 报告日期：2026-09-22

## 摘要

- cfbypass 是镜像内的**兼容性辅助服务**：FastAPI + DrissionPage 驱动的无头 Chromium，专门为 chatgpt.com 域获取 Cloudflare 边缘 Cookie（cf_clearance 等），仅供容器内部组件调用（app.py:14-19、555-588；入口脚本 76-83、95）。
- 接口为两个等价端点 `POST /cloudflare5s/bypass-v1`、`/v2`（app.py:581-588），JSON 体 `{url, user_agent?, proxy_server?}`（124-156），返回 `{user_agent, cookies[]}`（475/503-506/548）。
- 认证为共享密钥 Bearer（app.py:79-84），密钥在 all-in-one 模式下默认复用 GATEWAY_ADMIN_SECRET（入口脚本 43）；密钥为空时一律 401（app.py:83）——fail-closed。
- 目标 URL 有四层限制：https-only、禁 userinfo、端口仅 443、域白名单 + 解析地址必须全为公网（app.py:101-121，87-93，52-59）；导航后对最终 URL 复检一次（438-445）。
- Cookie 策略：只透出 cf_clearance / __cf_bm / __cflb / _cfuvid（app.py:61、206-208）；每 attempt 先清空浏览器 Cookie（421-424）；cf_clearance 出现即完成（467-475），否则「稳定 N 轮的部分集合」也返回（476-509），超时后返回最后部分集合（543-548）。
- proxy_relay 把「带认证的上游代理」包装成 127.0.0.1 上的无认证 HTTP CONNECT 代理供 Chromium 使用（proxy_relay.py:76-113；app.py:247-264），支持 http/https/socks5/socks5h 上游（81-89），实现 CONNECT 透传与 SOCKS5 握手（176-258）。
- 主要风险集中在：本地 relay 无认证且 CONNECT 无目标限制（R1/R2）、DNS 校验与浏览器实际解析之间存在 TOCTOU（R3）、cfbypass 密钥与 gateway 管理密钥同源（R4）、部分 Cookie 也以 200 返回（R5）。

## 0. 制品与证据坐标

### 0.1 文件与哈希

| 文件 | 大小 | 行数 | sha256 | 来源核对 |
| --- | --- | --- | --- | --- |
| `app.py` | 22260 B | 589 | `7232f5b2…c552c` | 提取副本与 `image.tar` 层 `adfc6f18…` 内 `app/cfbypass/app.py` 逐字节一致 |
| `proxy_relay.py` | 11409 B | 295 | `c99ac884…6165b` | 与层 `1a18601d…` 内 `app/cfbypass/proxy_relay.py` 逐字节一致 |
| `chatgpt-mirror-all-in-one` | 2949 B | 116 | `3f7177e3…5d0f` | 层 `581a524a…` 与 `ba8be979…` 两份内容一致（COPY 层 + chmod 层） |
| `tmp/cfbypass-requirements.txt` | 77 B | 4 | — | 层 `131ed87e…` |

### 0.2 相关镜像层（依 `image.tar!manifest.json` 的 Layers 顺序）

| 层 blob（前 12 位） | 大小 | 内容 |
| --- | --- | --- |
| `2c2d34799f58` | 717.4 MB | Chromium 运行栈（含 `etc/chromium/*`，5938 个条目） |
| `ce6817dfb5a8` | 172.5 MB | pip site-packages（含 `DrissionPage` 包与 `tmp/.wh.cfbypass-requirements.txt` 白名单删除标记） |
| `b1b92536a4fd` | 93.9 MB | `/opt/curl-impersonate`（`libcurl-impersonate.so.4.8.0` 等） |
| `f58eb8fc7c2f` | 23.3 MB | `app/chatgpt-mirror-gateway`（ELF 64-bit 可执行文件） |
| `40cf952049f2` | 2.1 MB | `app/static/**` 前端产物 |
| `08bcb7acd7b6` | 236 KB | `app/backend/**` Django 源码（含 `app/backend/entrypoint.sh`） |
| `adfc6f182b79` | 25 KB | `app/cfbypass/app.py` |
| `1a18601d0d63` | 14 KB | `app/cfbypass/proxy_relay.py` |
| `581a524a387b` | 6 KB | `usr/local/bin/chatgpt-mirror-all-in-one`（COPY 层） |
| `ba8be9795808` | 9.7 KB | 最终层：`app/backend/db → /app/data/backend-db`、`logs` 符号链接 + 入口脚本 chmod 副本 |

### 0.3 镜像 config 关键字段（`blobs/sha256/c89121441e8f63217a95d2950c3da1d2820480c0d299aaf6e36be2202747ab9b`）

- `config.Entrypoint` = `/usr/local/bin/chatgpt-mirror-all-in-one`；`config.WorkingDir` = `/app`；`config.ExposedPorts` = `40002/tcp`；`config.User` = null（未配置非 root 用户）。
- `config.history` 中相关条目（引原文）：
  - `"RUN … chromium=${CHROMIUM_PACKAGE_VERSION} … xvfb …"`（安装 chromium 146.0.7680.177-1~deb13u1、chromium-driver、xvfb、xauth）
  - `"COPY cfbypass/requirements.txt /tmp/cfbypass-requirements.txt"`
  - `"COPY cfbypass/app.py ./cfbypass/app.py"`、`"COPY cfbypass/proxy_relay.py ./cfbypass/proxy_relay.py"`
  - `"COPY docker-entrypoint.all-in-one.sh /usr/local/bin/chatgpt-mirror-all-in-one"`（随后 RUN 条目 `chmod +x` 并建立数据目录符号链接）
  - `"HEALTHCHECK … socket.create_connection(('127.0.0.1', PORT))"`、`"STOPSIGNAL SIGTERM"`、`"VOLUME [/app/data]"`

## 1. 接口契约

### 1.1 服务形态

- FastAPI 应用（app.py:15、64）；由 uvicorn 以 `app:app` 启动并绑定 `127.0.0.1:$CF_BYPASS_INTERNAL_PORT`（入口脚本 76-80；镜像 Env `CF_BYPASS_INTERNAL_PORT=8001`）——仅容器内 loopback 可达。
- 无 base path、无 CORS 中间件（app.py:15 仅导入 `Depends/FastAPI/Header/HTTPException/Request`；无 CORSMiddleware 引用）。
- 对外暴露的只有 gateway 的 40002（`config.ExposedPorts`）；cfbypass 端口不在镜像 EXPOSE 内。

### 1.2 路由表

| 方法/路径 | 鉴权 | 行号 | 返回 |
| --- | --- | --- | --- |
| `GET /` | 无 | app.py:555-557 | `{"message":"ok"}` |
| `GET /healthz` | 无 | app.py:560-562 | `{"status":"ok","headless":<bool>}` |
| `POST /cloudflare5s/bypass-v1` | Bearer | app.py:581-583 | `solve()` 结果 |
| `POST /cloudflare5s/bypass-v2` | Bearer | app.py:586-588 | 与 v1 完全同实现 |

### 1.3 请求模型（`CloudFlare5sQuerySchema`，app.py:124-156）

| 字段 | 类型 | 约束 | 行号 |
| --- | --- | --- | --- |
| `url` | HttpUrl，必填 | 语法校验由 pydantic 框架完成 | 125 |
| `user_agent` | str，可选 | strip 后空串归一为 None（用默认 UA） | 126、132-138 |
| `proxy_server` | str，可选 | 见 §3.4；空串归一为 None | 127-130、140-156 |

- 绑定方式：POST + 单一 Pydantic 模型参数 ⇒ JSON 请求体（FastAPI 0.111 框架默认；版本见 `image.tar!tmp/cfbypass-requirements.txt:2`）。schema 不满足时返回框架默认 422（框架行为，非本仓库显式逻辑）。
- 构造示例（按源码结构写成，非实测样例）：

```json
{"url": "https://chatgpt.com/", "user_agent": "Mozilla/5.0 … Chrome/146.0.0.0 …", "proxy_server": "socks5h://user:pass@proxy.example:1080"}
```

### 1.4 响应与状态语义

- 成功：`{"user_agent": <实际使用的 UA>, "cookies": [{"name", "value", "domain"?}, …]}`（app.py:565-578、211-231、475、503-506、548）。
- 成功判据只有「cookies 非空」一条（576-577）；**部分集合（无 cf_clearance）也会以 200 返回**（476-509、543-548），调用方需自检。
- 错误码：

| 码 | 触发 | 行号 |
| --- | --- | --- |
| 400 | 目标非 https / 含认证信息或非 443 端口 / 主机不在白名单 / 解析失败 / 解析到非公网 | app.py:103-108、118、121 |
| 401 | 无效的服务认证信息 | app.py:79-84 |
| 502 | 未获取到有效的 Cloudflare Cookie（cookies 为空） | app.py:576-577 |
| 422 | 请求体 schema 不满足（框架默认） | 框架行为 |

- 统一异常处理器：记录 `[cfbypass] request rejected status=… detail=…` 并返回 `{"detail": …}`（app.py:69-76）。
- 两个端点均未声明 `response_model`（581-588），响应结构由 `solve()` 返回 dict 决定。

### 1.5 并发与耗时上界

- 全局 `asyncio.Lock`（app.py:65）使整个 bypass 流程串行（567）。
- 单请求耗时 ≈ attempts ×（导航上界 `CF_BYPASS_PAGE_LOAD_TIMEOUT_SECONDS`=15s（33-36、431）+ 轮询上界 `CF_BYPASS_MAX_WAIT_SECONDS`=20s（32、447-453））；attempts 默认 1（46）。
- 浏览器操作在线程内以独立事件循环执行：`asyncio.to_thread(lambda: asyncio.run(...))`（573-575）。

### 1.6 日志事件（运维可观测点）

- 统一前缀 `[cfbypass]`（app.py:159-160）。
- 关键事件：`navigate attempt=…`（426）、`first cookies observed`（462-466）、`verification completed`（471-474）、`partial cookies accepted`（498-502）、`no cookies yet`（517-521）、`attempt=… failed` + traceback（538-539）、`returning partial cookies after timeout`（544-547）、`all attempts failed`（550-551）。

## 2. 认证

- 机制：`Depends(require_cfbypass_auth)` 挂载在两个 bypass 端点上（app.py:581-583、586-588）。
- 实现（app.py:79-84）：读取 `Authorization` 头；若以 `bearer `（大小写不敏感）开头则剥离前缀（80-82）；对剩余部分做 `hmac.compare_digest` 恒时比较（83）；不匹配抛 401（84）。
- fail-closed：`CF_BYPASS_SECRET` 为空时任何请求都 401（app.py:51、83）。
- 密钥来源链：
  - app.py 读取 `CF_BYPASS_SECRET`（51）；镜像 Env **未定义**该变量（`config.Env` 无此项）。
  - 入口脚本 `export CF_BYPASS_SECRET="${CF_BYPASS_SECRET:-${GATEWAY_ADMIN_SECRET}}"`（`image.tar!usr/local/bin/chatgpt-mirror-all-in-one:43`），而 `GATEWAY_ADMIN_SECRET` 是启动必填项（同文件 22-27、29-34）。
  - 结论：all-in-one 模式下 cfbypass 默认与 gateway 管理密钥同源，未做密钥域分离（R4）。
- 未受保护端点：`GET /`、`GET /healthz`（app.py:555-562），后者暴露 headless 布尔值（R9）。
- 缓解面：服务仅监听 loopback（入口脚本 78-80）；未见速率限制或失败计数逻辑（app.py 全文）。

## 3. URL / 端口 / DNS / 代理安全限制

### 3.1 目标 URL 校验矩阵（`validate_target_url`，app.py:101-121；调用点 566 与 439）

| 检查 | 结果 | 行号 |
| --- | --- | --- |
| scheme 必须为 `https` | 否则 400「目标地址仅支持 HTTPS」 | 103-104 |
| hostname 必须存在 | 否则 400 | 103 |
| 禁止 userinfo（user/password） | 否则 400 | 105-106 |
| 端口仅允许缺省或 443 | 否则 400 | 105-106 |
| 主机必须在 `CF_BYPASS_ALLOWED_HOSTS` | 否则 400「目标主机不在允许列表」 | 107-108 |
| DNS 解析（线程内 `getaddrinfo(host, 443)`） | 失败→400 | 110-118 |
| 解析出的**所有**地址必须 `is_global` | 任一非公网→400「解析到非公网地址」 | 119-121 |

### 3.2 白名单匹配细节（app.py:52-59、87-93）

- 条目标归一：`strip().rstrip(".").lower()`（88）；匹配规则：全等，或以 `.` 开头的后缀（89-93）。
- 默认值 `chatgpt.com,.chatgpt.com`（52-59）⇒ `chatgpt.com` 与 `*.chatgpt.com` 通过；`evilchatgpt.com` 因缺少点边界不通过。

### 3.3 导航后复检（app.py:438-445）

- 浏览器完成导航后，对 `driver.url` 重新执行同一校验；失败转 `RuntimeError`（440-445），该 attempt 记入 `last_error`（536-539）并在后续重试/兜底逻辑中处理。

### 3.4 proxy_server 约束（app.py:140-156）

- 允许方案：`http/https/socks5/socks5h`（150）；必须有 hostname（150）；禁止 path/params/query/fragment（154）。
- **不受主机白名单/端口限制约束**（校验仅语法层面）；是否带凭据决定走直连还是本地 relay（252-263，见 §6）。

### 3.5 残留风险（本节视角）

- (a) DNS TOCTOU：校验期解析（110-121）与 Chromium 实际建立连接时的解析（428-431）非同一时刻；导航后复检（438-445）只能发现“最终 URL 越界”，不能阻止“解析到内网后已建立连接”本身（R3）。
- (b) 白名单 env 可直接扩大出网面（52-59），无二次校验。
- (c) `socks5`（非 h）由 relay 本地解析且不做 `is_global` 校验（proxy_relay.py:267-277），与 3.1 的 DNS 防护不一致（R6）。

## 4. DrissionPage 行为

- 依赖版本锁定：DrissionPage==4.0.5.6、fastapi==0.111.0、pyvirtualdisplay==3.0、uvicorn==0.30.1（`image.tar!tmp/cfbypass-requirements.txt:1-4`）。
- 浏览器路径探测（app.py:191-203）：`CF_BYPASS_BROWSER_PATH` → `which google-chrome/chromium/chromium-browser` → `/usr/bin/{google-chrome,chromium,chromium-browser}`；找不到则在构建 options 时抛 `RuntimeError("未找到 Chromium/Chrome 可执行文件")`（274-275）。
- ChromiumOptions 配置（app.py:272-323）：
  - `set_paths(browser_path)`（278）；
  - `set_load_mode("normal")` + `set_timeouts(page_load=…)`（279-282）；注释说明为让边缘 Cookie 在完整加载阶段生成（279-280）；
  - UA 注入（283-284；默认值 21-25、241）；
  - 代理注入（285、247-264）；
  - 启动参数：`--accept-lang=zh-CN,zh`、`--lang=zh-CN`（290-292）、`--disable-gpu`、`--disable-dev-shm-usage`、`--disable-extensions`、`--password-store=basic`、`--use-mock-keychain`、`--window-size=1920,1080` 等（293-309）；
  - headless：默认 true（27-31、313-315）；关闭时 `--start-maximized`（316-317）；
  - 非 Windows 平台追加 `--no-sandbox`、`--disable-setuid-sandbox`（319-321）⇒ 容器（Linux）内 Chromium 实际无沙箱（R7）。
- 导航语义：`driver.get(url, retry=0, timeout=PAGE_LOAD_TIMEOUT_SECONDS)`（431）；注释指出 DrissionPage `get()` 默认内层重试且 timeout 不是总壁钟上限，故显式关闭内层重试避免单次故障被放大（428-430）。
- Cookie 读取：每次轮询调用 `driver.cookies()`（346、454），全部读入后在应用层过滤（218）。
- 验证点击：选择器 `.spacer`、`input[type='checkbox']`（62）；`wait.ele_displayed` + `ele` + `click`，单项异常静默跳过（383-400）；在轮询循环中每轮尝试一次（523）。
- 页面状态判定（361-379）：`just a moment` / `cf-chl-` → cloudflare_challenge；`access denied` / `error 403` → access_denied；`err_proxy_connection_failed` / `err_tunnel_connection_failed` → proxy_error；`err_name_not_resolved` / `err_internet_disconnected` → network_error；标题含 chatgpt → chatgpt；读取异常 → unavailable（366-367）。
- 生命周期：每 attempt `_ensure_driver()` 新建/复用（415、325-332），finally `_close_driver()` 内 `driver.quit()`（540-541、334-342）；quit 失败仅记日志（337-339）；relay 随 driver 清理（342、266-270；另见 327-331 的失败路径）。
- 虚拟显示：仅当非 headless 且环境无 `DISPLAY`（173-176）时启动 pyvirtualdisplay Xvfb（178-187），尺寸取 `CF_BYPASS_DISPLAY_SIZE`（50、163-170、180-186）。
- 未显式设置项：用户数据目录、固定调试端口；相关默认行为由 DrissionPage 4.0.5.6 决定，本报告未审计库源码（见 §9）。

## 5. Cookie 策略

### 5.1 白名单与字段

- 关注名单：`cf_clearance`、`__cf_bm`、`__cflb`、`_cfuvid`（app.py:61、206-208）。
- 过滤：name/value 为空丢弃（218）；`expires>0 且已过期`丢弃（221-225）；输出字段仅 `name`、`value` 与可选 `domain`（227-230）。
- 因此响应**不会**包含会话类 Cookie（如 chatgpt 会话 Cookie）。

### 5.2 会话清理

- 每个 attempt 开始时清空浏览器 Cookie：`driver.set.cookies.clear()`（421-424），异常静默（422-424）。

### 5.3 成功判定

- 完整：观察到 `cf_clearance` 立即返回（467-475）。
- 部分：任一 CF Cookie 集合连续 `CF_BYPASS_COOKIE_STABLE_POLLS` 次轮询不变（默认 2，代码钳制最小 2；42-45）即返回（476-509）；轮询间隔 `CF_BYPASS_POLL_INTERVAL_SECONDS`=0.5s（37、524）。

### 5.4 超时与兜底

- 所有 attempt 超时后：返回最后一次观察到的部分集合（543-548）；从未观察到则为空集合（550-552）→ `solve()` 抛 502（576-577）。
- 契约注意点：部分集合以 200 返回（R5），「有 cookies == 成功」的调用方假设不成立。

### 5.5 返回与配对

- 返回体同时携带本次使用的 `user_agent`（475、503-506、548）；cf_clearance 与 UA 强绑定，调用方必须成对使用。
- `CF_BYPASS_FIRST_COOKIE_WAIT_SECONDS`（默认 6s，38-41）仅控制“尚无 Cookie”告警日志（449-452、511-521），不影响成功判定。

### 5.6 持久化

- app.py 无任何 Cookie 落盘逻辑（全文件未出现文件写入）；Cookie 只存在于单次请求内存与响应体；浏览器会话每次 attempt 重建并清空（421-424、540-541）。

## 6. proxy_relay 实现与风险

### 6.1 定位与设计意图

- 目标：把「需要认证的上游代理」包装为 **127.0.0.1 上的无认证 HTTP CONNECT 代理**，供 Chromium 直接使用（proxy_relay.py:76-77；接入点 app.py:247-264）。
- 启用条件：请求中的 `proxy_server` 含用户名或密码时启用；无凭据则直接 `options.set_proxy()`（app.py:252-256）。

### 6.2 实现要点

- 构造与校验（proxy_relay.py:79-93）：方案仅限 `http/https/socks5/socks5h`（81-84）；默认端口 http 80、https 443、socks5(h) 1080（86-89）；用户名/密码做 URL 解码（90-91）。
- 本地监听：`127.0.0.1:0`（临时端口，104）；守护线程 `cfbypass-proxy-relay`（106-111）；`proxy_url` 暴露实际端口（95-99）；停止时 shutdown/close/join(2s)（115-125）。
- 协议行为：仅接受 `CONNECT`（137-142，其他方法回 405）；authority 解析支持 IPv6 方括号，端口 1..65535（45-63）；上游失败且未开始响应时回 502（155-163）；握手成功后透传客户端缓冲（150-151）。
- HTTP(S) 上游（176-210）：到上游的 TCP 连接（177-179）；`https` 上游套 TLS（默认证书校验，181-184）；转发 `CONNECT` 并按需附加 `Proxy-Authorization: Basic`（185-197）；响应码必须 2xx（198-206）。
- SOCKS5 上游（212-258）：greeting（217-222）→ 可选用户名密码认证（RFC1929，223-237）→ CONNECT 请求（241-245）→ 需完整消费响应头（246-254）。
- DNS 语义（260-280）：`socks5h` 发送主机名（远端解析，261-265）；`socks5` 本地 `getaddrinfo` 取首条记录转 IP（267-277）。
- 隧道（282-295）：`select` 30s 轮询（286-288，超时仅 continue，不主动断开）；64 KiB 双向转发（290-294）；任一端 EOF 即结束（291-292）。
- 常量：连接超时 10s、头部上限 64 KiB（14-15、39-40）。

### 6.3 风险（全局编号见 §8.1）

- R1 本地 relay 无认证：任何能访问 `127.0.0.1:<临时端口>` 的本机进程都可借上游凭据出网（76-77、104；app.py:256-263）。
- R2 CONNECT 目标无白名单/端口限制（45-63、143-144）：应用层白名单（app.py:101-108）只覆盖导航 URL，不构成对浏览器全部出站的约束。
- R6 `socks5` 本地解析不做 `is_global` 校验（267-277）。
- R8 连接模型无上限、隧道无空闲超时（66-68、286-288）。
- 凭据处理：仅存内存（90-91），Basic base64 每 CONNECT 发送（192-196）；应用层日志只记录 scheme（app.py:264）不泄露凭据。

## 7. 与镜像入口脚本 / 环境变量的关系

### 7.1 入口脚本（`image.tar!usr/local/bin/chatgpt-mirror-all-in-one:1-116`）

- 身份：`config.Entrypoint`；来源 `config.history（"COPY docker-entrypoint.all-in-one.sh /usr/local/bin/chatgpt-mirror-all-in-one"）`，chmod +x 在后续 RUN 条目。
- 结构：
  - bash + `set -Eeuo pipefail`（1-2）；退出 trap 统一 TERM 子进程（6-20）。
  - 必填 env：`ADMIN_PASSWORD`、`CREDENTIAL_ENCRYPTION_KEY`、`DJANGO_SECRET_KEY`、`GATEWAY_ADMIN_SECRET`（22-34），缺失 `exit 64`（30-33）。
  - 默认导出（36-43）：`PORT=40002`、`DJANGO_INTERNAL_PORT=8000`、`CF_BYPASS_INTERNAL_PORT=8001`、`DJANGO_UPSTREAM=http://127.0.0.1:8000`、`CHATGPT_GATEWAY_URL=http://127.0.0.1:40002`、`CF_BYPASS_URL=http://127.0.0.1:8001`、`CF_BYPASS_SECRET←GATEWAY_ADMIN_SECRET`。
  - 数据库迁移与初始用户（47-49）。
  - cfbypass 启动：`cd /app/cfbypass` + `python -m uvicorn app:app --host 127.0.0.1 --port "$CF_BYPASS_INTERNAL_PORT"`（76-83）——loopback 绑定，依赖 cwd 解析 `app` 与 `proxy_relay` 模块（app.py:19）。
  - Django：`python manage.py runserver 127.0.0.1:8000 --noreload`（85-92）。
  - 就绪门控（51-74、94-95）：TCP connect 探测，等待上界 `STARTUP_TIMEOUT_SECONDS`（默认 60）；cfbypass 与 Django 都就绪后才启动 gateway（97-105）。
  - gateway：`LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so`、`CURL_IMPERSONATE=chrome146`、`./chatgpt-mirror-gateway`（97-105）。
  - 主端口 40002 就绪声明（107-108）；任一子进程退出即整体退出并传递退出码（110-116）。

### 7.2 环境变量矩阵

| 变量 | app.py 读取行 | 代码默认 | 镜像 Env | 入口脚本 |
| --- | --- | --- | --- | --- |
| `CF_BYPASS_USER_AGENT` | 21-25 | Chrome/146 风格 UA | 未设置 | 透传 |
| `CF_BYPASS_ACCEPT_LANGUAGE` | 26 | `zh-CN,zh` | 未设置 | 透传 |
| `CF_BYPASS_HEADLESS` | 27-31 | true | `true` | 透传 |
| `CF_BYPASS_MAX_WAIT_SECONDS` | 32 | 20 | `20` | 透传 |
| `CF_BYPASS_PAGE_LOAD_TIMEOUT_SECONDS` | 33-36 | 15（下限 5） | `15` | 透传 |
| `CF_BYPASS_POLL_INTERVAL_SECONDS` | 37 | 0.5 | `0.5` | 透传 |
| `CF_BYPASS_FIRST_COOKIE_WAIT_SECONDS` | 38-41 | 6（下限 1） | 未设置 | 透传 |
| `CF_BYPASS_COOKIE_STABLE_POLLS` | 42-45 | 2（下限 2） | `2` | 透传 |
| `CF_BYPASS_NAVIGATION_RETRIES` | 46 | 1 | `1` | 透传 |
| `CF_BYPASS_ELEMENT_LOOKUP_TIMEOUT_SECONDS` | 47-49 | 0.2 | 未设置 | 透传 |
| `CF_BYPASS_DISPLAY_SIZE` | 50 | `1920x1080` | 未设置 | 透传（仅影响 Xvfb，见 O2） |
| `CF_BYPASS_SECRET` | 51 | `""`（fail-closed） | 未设置 | 43：默认取 `GATEWAY_ADMIN_SECRET` |
| `CF_BYPASS_ALLOWED_HOSTS` | 52-59 | `chatgpt.com,.chatgpt.com` | 同名 | 未导出（沿用镜像 Env） |
| `CF_BYPASS_BROWSER_PATH` | 193 | 未设置→自动探测 | 未设置 | 透传 |
| `CF_BYPASS_INTERNAL_PORT` | —（app 不读） | — | `8001` | 39、80：uvicorn `--port` |
| `CF_BYPASS_URL` | —（app 不读） | — | 未设置 | 42：导出 `http://127.0.0.1:8001` |
| `STARTUP_TIMEOUT_SECONDS` | — | — | `60` | 55：就绪等待上界 |
| `GATEWAY_ADMIN_SECRET` | — | — | 未设置（运行时必填） | 26 必填；43 复用为 cfbypass 密钥 |
| `NO_PROXY` / `no_proxy` | — | — | `localhost,127.0.0.1` | 未导出（镜像 Env 生效，保护本机互调） |

### 7.3 组件拓扑与调用关系

- 端口拓扑：`40002`（gateway，对外）→ `127.0.0.1:8000`（Django）→ `127.0.0.1:8001`（cfbypass/uvicorn）（入口脚本 37-43、76-107；`config.ExposedPorts`）。
- cfbypass 的**调用方**（消费 `CF_BYPASS_URL`/`CF_BYPASS_SECRET` 的代码）不在本次读取范围内，未验证；范围外线索（仅位置与相关性）：`image.tar` 层 `08bcb7acd7b6`（`app/backend/**`）与层 `f58eb8fc7c2f`（`app/chatgpt-mirror-gateway`，ELF 二进制）。
- 备用模式对比：`image.tar!app/backend/entrypoint.sh:1-9`（层 `08bc…`）把 Django 单独跑在 `0.0.0.0:8000`，不含 cfbypass/gateway；cfbypass 仅存在于 all-in-one 组合模式。

### 7.4 与镜像内容的衔接

- 工作目录 `/app`（`config.WorkingDir`；层 `7a4d7744926b` 创建 `/app`）；`/app/cfbypass/{app.py,proxy_relay.py}`（层 `adfc6f18…`/`1a18601d…`，与 §0.1 分析副本哈希一致）。
- Chromium 与虚拟显示依赖：Debian 包 `chromium 146.0.7680.177-1~deb13u1`、`chromium-driver`、`xvfb`、`xauth`（`config.history` 的 chromium 安装条目）；分别对应 app.py:191-203（浏览器探测）、21-25（UA 版本）、173-188（Xvfb 路径）。
- 依赖清单：`image.tar!tmp/cfbypass-requirements.txt:1-4`；安装后在层 `ce6817df…` 中以 `tmp/.wh.cfbypass-requirements.txt` 白名单删除。
- 数据卷：`/app/data`（`config.history` VOLUME 条目）；层 `ba8be979…` 建立 `app/backend/db → /app/data/backend-db`、`logs → /app/data/backend-logs` 符号链接。
- 健康检查只探 gateway 端口 40002（`config.history` HEALTHCHECK 条目）：cfbypass:8001 挂死不会触发容器 unhealthy。

## 8. 风险与细节观察汇总

### 8.1 风险表

| ID | 等级 | 内容 | 依据 |
| --- | --- | --- | --- |
| R1 | 低-中 | 本地 relay 无认证开放代理：同 netns 内任意进程可借上游凭据出网 | proxy_relay.py:76-77、104；app.py:256-263 |
| R2 | 中 | relay CONNECT 无目标/端口白名单，浏览器全量出站不受应用层白名单约束 | proxy_relay.py:45-63、127-169；app.py:101-108、439 |
| R3 | 低-中 | DNS 校验与浏览器实际解析存在 TOCTOU 窗口 | app.py:110-121 vs 428-431、438-445 |
| R4 | 低 | cfbypass 密钥与 gateway 管理密钥同源（默认复用） | 入口脚本 43；app.py:51、83 |
| R5 | 低 | 部分 Cookie 集合也可 200 返回，调用方易误判成功 | app.py:476-509、543-548、576-577 |
| R6 | 低 | `socks5` 本地解析不做 `is_global` 校验，与目标 URL 的 DNS 防护不对称 | proxy_relay.py:267-277 |
| R7 | 低-中 | 容器内 Chromium `--no-sandbox` 且镜像未配置非 root 用户 | app.py:319-321；`config.User`=null |
| R8 | 低 | 隧道无空闲超时；连接线程无上限（本地 loopback 局限） | proxy_relay.py:66-68、286-288 |
| R9 | 低 | `/healthz` 未认证，暴露 headless 布尔值 | app.py:560-562 |
| R10 | 低 | 全局单锁串行 + 单请求最长约 35s 的浏览器占用（可用性风险） | app.py:65、567、447-524 |

### 8.2 细节观察（静态推断，非缺陷定性）

- O1：app.py:534-535 的 `except HTTPException: raise` 在 `get_cf_cookie` 内静态推断不可达——该异常在 440-445 已被包装为 `RuntimeError`，其余调用路径不会抛出 `HTTPException`。
- O2：`CF_BYPASS_DISPLAY_SIZE` 只影响 Xvfb 尺寸（163-170、180-186）；Chromium 窗口尺寸始终硬编码 `1920x1080`（287-288、308）。
- O3：v1/v2 端点当前完全同实现（581-588），路径版本号不携带行为差异。

## 9. 未覆盖项与限制

- 未执行任何真实上游请求、api.zxcbug.com 访问或网络探测（任务约束）；本报告全部结论为静态源码/制品读取结论。
- 未读取：backend/gateway 调用方源码（范围外线索见 §7.3）、DrissionPage 4.0.5.6 库内部实现、curl-impersonate 库、前端静态资源、Chromium 层全量文件（仅抽样确认存在）。
- 未做运行时验证：HTTP 422 等框架默认行为未在本环境复现；「调用方如何消费部分 Cookie」未验证。
- 镜像 Env 为单行 JSON，本报告使用「变量名+值」文本条目定位而非数组下标。


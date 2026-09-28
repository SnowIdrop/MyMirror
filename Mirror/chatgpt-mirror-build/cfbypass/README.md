# cfbypass

与仓库根目录 `docker-compose.yml` 中 `cfbypass` 服务兼容的 Cloudflare 放行服务实现：
FastAPI + Playwright，通过 `uvicorn app:app --host 0.0.0.0 --port 8000` 启动。

## 职责

- 按网关请求用 Playwright 导航到目标页面，等待页面 Cookie（例如 `cf_clearance`）
  连续多个轮询保持稳定后，返回 Cookie 与会话 User-Agent，供网关使用同一指纹继续访问上游。
- 导航目标受白名单限制，接口调用需要 Bearer 密钥。

## 目录文件

| 文件 | 说明 |
| --- | --- |
| `app.py` | 服务实现入口（`uvicorn app:app`） |
| `requirements.txt` | 依赖清单（固定版本） |
| `Dockerfile` | 镜像构建：Debian trixie + snapshot 固定的系统 chromium 146（不装 Playwright 自带浏览器） |
| `probe_identity.py` | 容器内只读身份探针（ClientHello + HTTP/2 首帧摘要，不开端口） |
| `docker-compose.cfbypass.yml` | 本地构建/验证用的编排片段（127.0.0.1:18001 -> 8000） |
| `README.md` | 本文档 |

## 接口

### GET /health

无需认证，返回：

```json
{"status": "ok", "service": "cfbypass"}
```

### POST /bypass（等价路径：/cloudflare5s/bypass-v1、/cloudflare5s/bypass-v2）

需要请求头 `Authorization: Bearer <CF_BYPASS_SECRET>`。

网关按原版 all-in-one 契约调用 `/cloudflare5s/bypass-v1`，`/v2` 与之等价；
`/bypass` 保留给本地诊断。三条路径是同一实现，响应结构完全相同。

请求体：

```json
{
  "url": "http://127.0.0.1:18002/",
  "proxy_server": ""
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `url` | 是 | http/https 地址，主机必须在 `CF_BYPASS_ALLOWED_HOSTS` 内 |
| `proxy_server` | 否 | 覆盖本次请求的代理，格式同 `CF_BYPASS_PROXY_SERVER` |

成功响应（`200`）：

```json
{
  "ok": true,
  "url": "http://127.0.0.1:18002/",
  "user_agent": "Mozilla/5.0 ...",
  "identity": {
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "browser_version": "146.0.7680.177",
    "language": "zh-CN",
    "languages": ["zh-CN", "zh"],
    "timezone": "Asia/Shanghai",
    "proxied": false,
    "proxy_server": null,
    "user_agent_data": {
      "brands": [{"brand": "Chromium", "version": "146"}, {"brand": "Not?A_Brand", "version": "24"}],
      "platform": "Linux",
      "mobile": false,
      "architecture": "x86",
      "bitness": "64",
      "full_version": "146.0.7680.177",
      "full_version_list": [{"brand": "Chromium", "version": "146.0.7680.177"}],
      "platform_version": ""
    }
  },
  "cookies": [
    {
      "name": "cf_local",
      "value": "ready",
      "domain": "127.0.0.1",
      "path": "/",
      "expires": -1.0,
      "http_only": false,
      "secure": false,
      "same_site": "Lax"
    }
  ],
  "elapsed_seconds": 1.23
}
```

`identity` 是这一跳的**实测**身份（见「身份一致性」），探测失败的字段为 `null`。

错误响应统一为 `{"detail": {"code": "...", "message": "..."}}`：

| HTTP | code | 场景 |
| --- | --- | --- |
| 400 | `invalid_request` | 请求体不是合法 JSON 或缺少必需字段 |
| 400 | `invalid_url` | 地址无效或协议不是 http/https |
| 400 | `host_not_allowed` | 目标主机不在白名单内 |
| 400 | `invalid_proxy` | 代理地址无法解析 |
| 401 | `unauthorized` | 缺少或错误的 Bearer 密钥 |
| 403 | `redirect_host_not_allowed` | 导航最终地址主机不在白名单内 |
| 502 | `navigation_failed` | 页面加载失败（网络错误等，已按 `CF_BYPASS_NAVIGATION_RETRIES` 重试） |
| 503 | `server_misconfigured` | 未配置 `CF_BYPASS_SECRET` |
| 504 | `page_load_timeout` | 页面加载超时 |
| 504 | `cookie_wait_timeout` | 等待 Cookie 稳定超时 |

## 环境变量

与根目录 `docker-compose.yml` / `.env.example` 保持一致；括号内为本实现的默认值。

| 变量 | 说明 |
| --- | --- |
| `CF_BYPASS_SECRET` | 导航接口 Bearer 密钥，默认空（空值将拒绝所有导航请求） |
| `CF_BYPASS_ALLOWED_HOSTS` | 白名单主机，逗号分隔；`example.com` 精确匹配，`.example.com` 匹配子域（默认 `127.0.0.1,localhost`，生产由 compose 提供 `chatgpt.com,.chatgpt.com`） |
| `CF_BYPASS_USER_AGENT` | 浏览器 User-Agent，并作为声称值原样返回给调用方；必须与网关身份常量同值（见「身份一致性」） |
| `CF_BYPASS_BROWSER_PATH` | 系统 chromium 可执行文件（默认 `/usr/bin/chromium`，即镜像内固定版本那个；本机开发需显式指向自己的 Chrome/Chromium） |
| `CF_BYPASS_ACCEPT_LANGUAGE` | 浏览器语言与 `Accept-Language` 请求头 |
| `CF_BYPASS_HEADLESS` | 是否无头运行（默认 `true`） |
| `CF_BYPASS_MAX_WAIT_SECONDS` | 导航完成后等待 Cookie 稳定的总上限（默认 `20`） |
| `CF_BYPASS_PAGE_LOAD_TIMEOUT_SECONDS` | 单次页面加载超时（默认 `15`） |
| `CF_BYPASS_FIRST_COOKIE_WAIT_SECONDS` | 首次仍无 Cookie 时的日志提示时间，不会提前结束（默认 `6`） |
| `CF_BYPASS_POLL_INTERVAL_SECONDS` | Cookie 轮询间隔（默认 `0.5`） |
| `CF_BYPASS_COOKIE_STABLE_POLLS` | Cookie 保持稳定的连续轮询次数（默认 `2`） |
| `CF_BYPASS_NAVIGATION_RETRIES` | 导航失败后的重试次数（默认 `1`） |
| `CF_BYPASS_ELEMENT_LOOKUP_TIMEOUT_SECONDS` | 挑战页探测的元素查找超时，仅用于日志诊断（默认 `0.2`） |
| `CF_BYPASS_DISPLAY_SIZE` | 视口尺寸，`宽x高`（默认 `1920x1080`） |
| `CF_BYPASS_PROXY_SERVER` | 默认代理；支持 `http://`、`https://`、`socks5://`、`socks5h://`，用户名/密码需 URL 编码 |

## 身份一致性

这一跳（cfbypass）与网关（wreq/btls）对上游声称同一套 Chrome146/Linux 身份，两侧都要能自证：

- **声称值同源**：compose 的 `CF_BYPASS_USER_AGENT` 必须与网关身份常量逐字符相同
  （`Mirror/gateway-rust/src/server/identity.rs` 的 `USER_AGENT`）；镜像内的系统 chromium
  版本必须与网关 `FULL_VERSION` 同版（当前 `146.0.7680.177`，Dockerfile 以
  `CHROMIUM_VERSION=146.0.7680.177-1~deb13u1` 钉在 snapshot.debian.org 的快照上）。
- **实测值可核验**：`/bypass`、`/cloudflare5s/bypass-v1`、`/cloudflare5s/bypass-v2` 的响应都带
  `identity`，字段全部取自实际浏览器会话与本次启动参数（`navigator`、`Intl`、
  Playwright `Browser.version()`），不是环境变量的回声。
- **怎么读错配**：顶层 `user_agent` 是该跳的声称值，`identity.user_agent` 是浏览器实测 UA，
  `identity.browser_version` / `identity.user_agent_data.full_version` 是实测完整版本。
  它们与网关常量不一致，就说明这一跳和网关不是同一身份。
  `identity.user_agent_data.platform_version` 同样是必比对项：Chrome 146 在 Linux 上默认启用
  `ReduceUserAgentDataLinuxPlatformVersion`，正确取值是空串（依据
  `Mirror/gateway-rust/evidence/reference-chrome146-001/04-linux-platform-version.json`）。
  若这一跳报出内核版本（如 `6.6.0`），说明镜像里的 chromium 关掉了该 feature：先核对镜像
  版本，再决定是否补启动参数 `--enable-features=ReduceUserAgentDataLinuxPlatformVersion`。

`identity` 字段与浏览器来源一一对应（取值失败或浏览器不提供时为 `null`，
同时写日志；日志与响应都不含 Cookie 与令牌）：

| JSON 字段 | 浏览器来源 |
| --- | --- |
| `user_agent` | `navigator.userAgent` |
| `browser_version` | Playwright `Browser.version()`（CDP `Browser.getVersion`） |
| `language` / `languages` | `navigator.language` / `navigator.languages` |
| `timezone` | `Intl.DateTimeFormat().resolvedOptions().timeZone` |
| `user_agent_data.brands` / `platform` / `mobile` | `navigator.userAgentData` 低熵字段 |
| `user_agent_data.architecture` / `bitness` / `full_version` / `full_version_list` / `platform_version` | `navigator.userAgentData.getHighEntropyValues([...])` 的 `architecture` / `bitness` / `fullVersion` / `fullVersionList` / `platformVersion` |
| `proxied` / `proxy_server` | 本次浏览器启动是否带代理（`proxy_server` 只含 scheme://host:port，不含用户名密码） |

### UA 与 UA-CH 必须同源（2026-09-28 实测修正）

取 Cookie 的会话不能用 `browser.new_context(user_agent=...)`：Playwright 会连 UA-CH 元数据
一起替换成它自己派生的值（Linux 容器内实测 `architecture` 变成 `x64`、`fullVersionList` 也不
再来自浏览器），而网关声称 `x86`/146；两个更差的形态（只发 `userAgent` 的 CDP 覆盖、启动参数
`--user-agent=`）会把 UA-CH 直接清空。任一形态都会让上游同时看到「UA 说 Chrome146/Linux」与
「提示说 x64 或干脆没有」。

现在的做法：先在本地回环的 https 页读浏览器**原生** UA-CH（`page.route` 本地应答，不产生真实
请求），再用 CDP `Emulation.setUserAgentOverride` 把「配置的 `CF_BYPASS_USER_AGENT` + 原生
元数据」一起装上。实测线上头为 `sec-ch-ua-arch: "x86"`、`sec-ch-ua-bitness: "64"`、
`sec-ch-ua-full-version: "146.0.7680.177"`、`sec-ch-ua-platform: "Linux"`，
`platformVersion` 为空串，与网关身份常量逐字段一致。

### 升级清单

1. 先改网关画像与常量（`identity.rs` 的 `USER_AGENT` / `FULL_VERSION`，wreq 画像同步）；
2. 用真机重采参照（网关侧 ClientHello / H2 首帧基线，例如 `tests/identity_fingerprint.rs`）；
3. 改本镜像 chromium 版本：Dockerfile 的 `CHROMIUM_VERSION` 与两个 snapshot 时间戳；
4. 同步 compose 的 `CF_BYPASS_USER_AGENT`，再跑下面这个探针逐字段对照，两端摘要一致才算对齐；
5. 重建 cfbypass 镜像后重启网关：启动日志**不得**出现 `cfbypass prewarm failed`，也不得出现
   「cfbypass 一跳的浏览器身份与网关声称值不一致」；二者的含义分别是「取 Cookie 接口失败」与
   「这一跳与网关不是同一个浏览器身份」。

### 只读身份探针（`probe_identity.py`）

容器内探针，用同一份系统 chromium 打 `127.0.0.1` 上的临时回环监听（不开对外端口、
不加 HTTP 接口），输出两份可逐字段对照的摘要：

- **ClientHello 归一化摘要**：密码套件与扩展的**原始顺序**、GREASE 位置、ALPN、TLS1.3、
  密钥共享组、各扩展长度，以及归一化摘要的 sha256；
- **HTTP/2 首帧摘要**：客户端帧顺序、SETTINGS 顺序与取值、首个请求的伪头顺序。

证书用 openssl 现场生成到临时目录，退出即删，不入库；两次回环请求都会按预期失败
（探针只负责握手与首帧，不回 HTTP 响应），失败不影响摘要。用法：

```powershell
docker compose -f docker-compose.cfbypass.yml run --rm cfbypass python probe_identity.py --out /tmp/cfbypass-identity.json
```

无 Docker 的机器也可以直接跑，但需要先把 `CF_BYPASS_BROWSER_PATH` 指向本机
Chrome/Chromium，并保证 `openssl` 在 PATH 上。

## 本地运行与验证（127.0.0.1 边界）

仓库内验证只使用 127.0.0.1 本地目标，不包含真实 ChatGPT 凭据，
也不对生产 Cloudflare 做验证。端口可按需调整。

直接运行（Windows PowerShell 示例）：

```powershell
cd cfbypass
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 本机开发不用容器内那个系统 chromium，显式指向自己的 Chrome/Chromium
$env:CF_BYPASS_BROWSER_PATH = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$env:CF_BYPASS_SECRET = "local-test-secret"
$env:CF_BYPASS_ALLOWED_HOSTS = "127.0.0.1,localhost"
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 18001
```

另开一个终端验证：

```powershell
curl.exe -s http://127.0.0.1:18001/health
curl.exe -s -X POST http://127.0.0.1:18001/bypass -H "Authorization: Bearer local-test-secret" -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:18002/"}'
# 网关照这个路径调用（与 /bypass 等价）：
curl.exe -s -X POST http://127.0.0.1:18001/cloudflare5s/bypass-v1 -H "Authorization: Bearer local-test-secret" -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:18002/"}'
```

Docker 本地运行：

```powershell
cd cfbypass
$env:CF_BYPASS_SECRET = "local-test-secret"
docker compose -f docker-compose.cfbypass.yml up --build
```

## 边界与安全说明

- 服务不包含任何真实凭据，密钥只从环境变量读取；`/health` 不暴露配置。
- 白名单为空时拒绝所有导航；白名单在请求入口与导航最终地址两处校验。
- 单进程内并发浏览器实例上限为 2（见 `BROWSER_SLOTS`），编排未配置多 worker。
- 浏览器只用镜像内固定版本的系统 chromium（`CF_BYPASS_BROWSER_PATH`），Playwright 自带
  浏览器不参与这一跳；`identity` 全部取自实际浏览器会话，探测失败如实返回 `null`。
- 镜像是 headless 用法（`CF_BYPASS_HEADLESS` 默认 `true`），未安装 Xvfb：
  需要 headful 时自行提供 X 显示。
- 本实现按仓库可见证据（compose 环境变量、镜像启动命令、仓库既有 `Authorization: Bearer`
  认证约定）实现接口；如果网关客户端使用不同的路径或字段名，需要同步调整。

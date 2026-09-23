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
| `Dockerfile` | 镜像构建（含 Playwright Chromium） |
| `docker-compose.cfbypass.yml` | 本地构建/验证用的编排片段（127.0.0.1:18001 -> 8000） |
| `README.md` | 本文档 |

## 接口

### GET /health

无需认证，返回：

```json
{"status": "ok", "service": "cfbypass"}
```

### POST /bypass

需要请求头 `Authorization: Bearer <CF_BYPASS_SECRET>`。

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
| `CF_BYPASS_USER_AGENT` | 浏览器 User-Agent，并原样返回给调用方 |
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

## 本地运行与验证（127.0.0.1 边界）

仓库内验证只使用 127.0.0.1 本地目标，不包含真实 ChatGPT 凭据，
也不对生产 Cloudflare 做验证。端口可按需调整。

直接运行（Windows PowerShell 示例）：

```powershell
cd cfbypass
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m playwright install chromium

$env:CF_BYPASS_SECRET = "local-test-secret"
$env:CF_BYPASS_ALLOWED_HOSTS = "127.0.0.1,localhost"
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 18001
```

另开一个终端验证：

```powershell
curl.exe -s http://127.0.0.1:18001/health
curl.exe -s -X POST http://127.0.0.1:18001/bypass -H "Authorization: Bearer local-test-secret" -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1:18002/"}'
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
- 本实现按仓库可见证据（compose 环境变量、镜像启动命令、仓库既有 `Authorization: Bearer`
  认证约定）实现接口；如果网关客户端使用不同的路径或字段名，需要同步调整。

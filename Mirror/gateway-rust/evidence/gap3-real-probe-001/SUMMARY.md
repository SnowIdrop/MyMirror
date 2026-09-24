# 缺口 3 真实上游探针（2026-09-24）

用真实 AccessToken 跑 `artifacts/phase1/probe/probe.py`，取得合成回环拿不到的证据。
探针本身、凭据草稿与边界见 `artifacts/phase1/probe/README.md`；凭据文件不进版本库。

## 运行清单

| 文件 | 内容 |
|---|---|
| `run-001-read.json` | 只读 7 条路径 |
| `run-002-read.json` | 只读，复现检查 |
| `run-003-write-attempt.json` | 唯一一次写尝试：`POST /backend-api/f/conversation` |
| `run-004-read-login-transport-failure.json` | 直连抖动：登录阶段发送失败 |
| `run-005-read-after-write.json` | 写尝试之后的对照：账号内仍为 0 条会话 |

每次运行都是 `GATEWAY_UPSTREAM_MODE=configured`、`DATABASE_PATH=:memory:`、
本地 Django 授权桩，`CF_BYPASS_URL` 未配置。

## 逐路径观测（状态码）

| 路径 | run-001 | run-002 | run-003 | run-005 | 结论 |
|---|---|---|---|---|---|
| `POST /api/login`（换镜像会话 + 真实凭据校验） | 200 | 200 | 200 | 200 | 真实 AccessToken 通过凭据换取与 `/backend-api/me` 校验 |
| `GET /backend-api/me` | 200 | 200 | 200 | 200 | 与登录同源的凭据路径 |
| `GET /backend-api/accounts/check/v4-2023-04-27` | 200 | 200 | 200 | 200 | 会话刷新第一条请求 |
| `GET /backend-api/conversations` | 200 | 200 | 200 | 200 | 集合读取可转发；`items`/`total` 是 **ACL 过滤后**的视图，不反映上游原始条数 |
| `GET /backend-api/projects` | 405 | 405 | 405 | 405 | 上游不支持该 GET：冻结快照里此路径只有 `POST` |
| `GET /backend-api/files/library/nodes` | 502 | 200 | 200 | 502 | 直连抖动（发送阶段失败） |
| `GET /backend-api/tasks` | 200 | 200 | 502 | 502 | 直连抖动 |
| `GET /backend-api/task_suggestions` | 404 | 404 | 502 | 404 | 该账号下上游无此端点 |
| `POST /backend-api/f/conversation` | — | — | 403 | — | 上游以 JSON `{"detail":…}` 拒绝；未创建任何会话（探针请求是合成的，见下「解释边界」） |

502 均为网关自己的发送阶段失败（响应正文 32 字节、`message=上游请求失败`、无上游响应头），
不是 Cloudflare 挑战形状（无 `cf-mitigated`、无 HTML 正文），也未重试。

## 解释边界：这次 403 说明的是探针请求，不是产品写路径

探针的创建请求是**合成**的，与浏览器真实请求有两处已知差异：

1. **没有浏览器侧请求头**：探针只带 `accept`/`content-type`（外加网关自己固定的 UA、origin、
   referer、authorization）。网关的 chat 路径用 `strip_request_hop_by_hop` 转发客户端的
   端到端头，所以浏览器驱动的创建会带上前端自己的 `oai-*` 等头，而这次没有。
2. **没有 Cookie**：探针登录时 `extra_cookies` 传空数组，且未配置 `CF_BYPASS_URL`
   （CF 缓存为空），因此上游看到的是一个**完全没有 Cookie 头**的写请求。
   生产路径下 Django 会把账号的 `extra_cookies` 一起下发。

因此这条 403 只能证明「探针的合成创建请求被拒绝」，不能证明镜像的写路径不可用。
要取得真实写证据，需要前端真实请求的观测样本（DevTools 复制为 cURL / HAR）来对齐请求头与
Cookie，或改为浏览器驱动前端流程。

## 结论

- **取得的证据**：真实 AccessToken 的换取、`me`、`accounts/check` 与 `conversations`
  四条路径在真实上游稳定通过；`files/library/nodes`、`tasks` 至少各有一次 200，
  证明转发与凭据注入对真实上游成立。
- **未取得的证据**：真实新建会话（上游 403，未重试、未改写请求）因此跨用户隔离在真实
  会话上仍未验证；`projects` 的集合读取在真实上游不存在（我们的 Collection 分支因此不生效）。
- **环境限制**：本机直连 chatgpt.com 存在间歇性发送阶段失败，`127.0.0.1:18001` 的
  本地 cfbypass 当时未运行，因此没有走 CF 刷新/重放分支。
- **未留残留**：写尝试被上游以 `403` 拒绝，因此这次尝试没有创建任何会话，无需删除。
  注意 `run-005` 的 `conversations` 视图为 0 条**不能**用来证明账号原本为空：未登记资源在
  ACL 过滤后一律呈现为空信封，该视图只反映「本镜像用户可见的已登记资源」。

## 证据边界

每个 JSON 只含状态码、内容类型、正文长度与 sha256、是否 HTML、是否 `cf-mitigated`、
JSON 顶层字段名、集合条目数与 `total`、本候选自己的错误码与文案、耗时、网关日志行数、
授权桩调用次数、令牌 sha256。不含令牌、Cookie、镜像会话 token、上游正文、会话标题与
会话 id 原文。

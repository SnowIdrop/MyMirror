# 设备 Cookie（`oai-did`）真实上游验证（2026-09-24）

用真实 AccessToken 跑 `artifacts/phase1/probe/probe_device_cookie.py`，验证本批设备 Cookie
捕获/恢复在**真实 chatgpt.com** 上的行为。原始证据是四个 JSON，均由探针直接生成，
除文件名外未做任何编辑。

## 环境与节奏

每次运行都是：`GATEWAY_UPSTREAM_MODE=configured`、**文件库**（临时目录，跑完用标准库
sqlite3 只读检查 `gateway_sessions.device_cookie` 是否存在）、本地 Django 授权桩、
`CF_BYPASS_URL` 未配置（2026-09-24 复查 `127.0.0.1:18001/18083` 均未监听）、Windows 本机出口，
候选二进制为本仓库 `source/target/debug/mirror-gateway.exe`。

节奏：**每个触及上游的请求之间随机停 8–12 秒**，实际间隔逐条记在每个 JSON 的 `pauses` 里
（run-001 为 9.1/10.6/10.1s，run-002 为 10.2/11.5/11.9/8.5/11.7/8.1s，
run-003 为 9.2/10.7/9.2/8.3/9.2s，run-004 为 11.9/9.2/9.7/11.3/10.2s）。

## 运行清单

| 文件 | 模式 | 内容 |
|---|---|---|
| `run-001-write-with-seeded-device-id.json` | `--allow-real-write` | 浏览器播种（探针生成 `oai-device-id`）+ 恰好一次真实新建尝试 |
| `run-002-read-scan-finds-oai-did.json` | `--scan-only` | 只读扫描页面/SDK/sentinel 引导，找 `oai-did` 的出处 |
| `run-003-capture-without-seeding.json` | `--scan-only --skip-seed` | 不播种，单独验证「上游下发的 `oai-did` 能否被捕获」 |
| `run-004-write-with-captured-oai-did.json` | `--capture-first --allow-real-write` | 生产顺序：让上游先下发 `oai-did`，再用它发起真实新建尝试 |

## 观测

### 1. 真实上游确实下发 `oai-did`（逆向解码的名称得到证实）

| 路径 | 观测到的 `set-cookie` 名字 | 出现 `oai-did` |
|---|---|---|
| `GET /`（页面） | `__Host-next-auth.csrf-token`、`__Secure-next-auth.callback-url`、`__oailb`、`__cflb`、`oai-did`、`__cf_bm`、`_cfuvid` | 是（run-002/run-004） |
| `GET /sentinel/20260423af3c/sdk.js` | `oai-did`、`__oailb`、`__cf_bm`、`__cflb` | 是（run-003） |
| `GET /backend-api/me` | `__oailb`、`__cf_bm`、`__cflb`、`_cfuvid` | 否 |
| `GET /backend-api/sentinel/frame.html` | `__oailb`、`__cf_bm`、`__cflb` | 否 |
| `POST /backend-api/sentinel/chat-requirements/prepare` | `oai-sc`、`__oailb`、`__cf_bm`、`__cflb`、`_cfuvid` | 否 |

⇒ 设备 cookie 出现在**页面与 sentinel SDK 资源**上，不在已登录 API 路径上；这与逆向材料里
`server_oai_device_cookie` / `browser_oai_device_id` 的语义一致（设备身份随页面加载建立）。

### 2. 捕获链路对真实上游成立

run-003 全程没有发送浏览器 `oai-device-id`：

| 快照点 | `sessions_with_device_cookie` |
|---|---|
| `me` 之后 | 0 |
| `/` 之后（该次请求 502，网关发送阶段失败） | 0 |
| `sentinel/frame.html` 之后 | 0 |
| **`sentinel/sdk.js` 之后**（该响应带 `oai-did`） | **1** |
| `chat-requirements/prepare` 之后 | 1 |

run-004（生产顺序）同样在 `GET /` 之后从 0 变 1。⇒ 上游下发的 `oai-did` 被写入会话列，
与合成回环用例的断言一致。

### 3. 浏览器播种链路成立

run-001：`me`（无设备头）之后为 0，发送 `oai-device-id` 的 `me` 之后变为 1。
⇒ 真实浏览器首个业务请求即可为会话定型（生产前端确实发送该头，
见 `evidence/anonymous-nextauth-001/mirror-run-007`）。

### 4. 写路径仍是上游业务拒绝，与设备 cookie 无关

三次真实新建尝试（run-001/004 携带设备标识，run-004 携带的是**上游自己下发的** `oai-did`）
全部返回 **JSON 403**，`conversation_id_found=false`：

- 不是 Cloudflare：响应里没有 `cf-mitigated`，正文不是 HTML（`html_like=false`）。
- 请求带着 `Authorization: Bearer <accessToken>`（`me`、`conversations`、`sentinel/*` 均 200），
  因此不是凭据失效。
- 因此设备 cookie 不是写路径的阻塞点；合成客户端缺的是浏览器侧材料
  （`chat-requirements` 的 sentinel/PoW 令牌与前端自身请求头）。

由于三次尝试都未创建出会话，**没有任何会话需要清理**，账号里没有留下本次真实写入。

### 5. 新发现：上游还下发其它 cookie，本候选只持久化 `oai-did`

API 路径上真实上游持续下发 `__oailb`、`__cf_bm`、`__cflb`、`_cfuvid`，sentinel 引导另发
`oai-sc`。原版对这些的处理是整组持久化（`capture_upstream_cookies`、日志串
`保存上游 Cookie 失败`）。

**记录时点的候选状态**（本次探针跑的是只落 `oai-did` 的上一版）：只有设备值落进
`gateway_sessions.device_cookie`，其余 cookie 只在响应里透传给浏览器；而网关在请求方向会
**丢弃客户端 cookie 并重建**，所以浏览器回传的这组 cookie 不会再到上游。

该差异已在同一批次的实现里收敛：这一组名字整组捕获与按作用域回注，落点从
`gateway_sessions.device_cookie` 改为 9 字段 jar 列 `gateway_sessions.upstream_cookies`
（会话级）与 `chatgpt_accounts.extra_cookies`（账号级），见
[`../../artifacts/phase1/source/COMPATIBILITY.md`](../../artifacts/phase1/source/COMPATIBILITY.md)
的「上游 cookie 捕获与恢复」与 `source/src/server/upstream_cookies.rs`。本目录的四个 JSON 是
记录时点的原始证据（列/字段名保持当时的形态），未随实现改写。

## 证据边界

每个 JSON 只含：状态码、内容类型、正文长度与 sha256、是否 HTML、是否 `cf-mitigated`、
JSON 顶层字段名、集合条数、`set-cookie` 的**名字**、本候选自己的错误码与文案、耗时、
随机间隔秒数、sqlite 只读快照（会话行数与设备列非空行数）、授权桩调用次数、
网关日志行数、令牌 sha256、浏览器设备标识 sha256。

不含：令牌、任何 cookie 值、镜像会话 token、上游正文、会话标题、会话 id 原文。
已用四条正则（Bearer 值、JWT、长 `name=value` 形态、明文 UUID）对归档文件复核，均无命中。

## 归档说明

`run-004` 的 `notes` 里保留了探针当时的措辞「`--skip-seed`：未发送浏览器设备标识……」。
探针在这一次运行之后才把该分支的文案改成按 `--capture-first` / `--skip-seed` 区分，因此
归档文件与当前脚本的这一句措辞不同，运行参数本身没有变化。可在该 JSON 内用两处自证核对：
其 `steps` 含新建会话步骤（`create_conversation`），且 `pauses` 比只读扫描多出一条
`after="me_with_browser_device_id"` 的间隔——这正是 `--capture-first` 之后进入写流程的位置。
为避免再造一次真实写入尝试，未重跑该归档。

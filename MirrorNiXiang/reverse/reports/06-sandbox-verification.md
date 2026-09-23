# 06 · 沙箱运行验证（QEMU + 镜像原生运行时）

> 结论性质：**运行时观测**。所有引用行均来自本次沙箱实际输出（日志文件与串口回显），文件路径见 §7。
> 本报告替代早期"Alpine/musl/FAT32"路线的尝试结论；该路线已废弃（原因见 §6.4）。

## 1. 摘要

- 用 **`image.tar` 自身的镜像层**（而非外部发行版）拼装了一个可自举的 initramfs 根文件系统，
  包含 Debian 13.6 用户态、glibc 2.41、`/opt/curl-impersonate`（libcurl-impersonate 4.8.0）
  与 `app/chatgpt-mirror-gateway`，并用 QEMU（Alpine `vmlinuz-virt`/6.18.52 内核）冷启动成功。
- 网关**成功启动并监听** `0.0.0.0:40002`；启动时执行 CF bypass 缓存预热，
  在桩服务在场时**成功取到 cookies 并写入缓存**，随后上游代理请求**实际携带了这些 cookies**。
- 通过宿主侧桩服务（Django/cfbypass/ChatGPT 上游）捕获到网关**出站请求的完整报文**
  （含 `Authorization: Bearer`、`{url,user_agent}` 请求体、`Chrome/146` UA、`cf_clearance` Cookie 附加）。
- 建立了可复现的构建/启动/交互三步流程（§5），全部工具脚本与证据文件落盘（§7）。

## 2. 沙箱组成与产物

### 2.1 产物

| 产物 | 路径 | 说明 |
|---|---|---|
| 沙箱 initramfs | `reverse\tools\sandbox-initramfs.cpio.gz` | **62,209,343 B**，sha256 `4d3b26f4712bc73f8cb0c7ec3159a0b44762a11a94d40ae327eb02b58e5e68d2`，CPIO(newc)+gzip，3,989 条目 |
| 构建清单 | `reverse\tools\sandbox-initramfs.manifest.txt` | 各来源条目计数、L5 依赖闭包 45 项逐条列出 |
| 构建脚本 | `reverse\tools\build_sandbox_initramfs.py` | 从 `image.tar` 流式取层 → CPIO（符号链接全程不落 Windows 文件系统） |
| 桩服务脚本 | `reverse\tools\sandbox_stubs.py` | 宿主侧 18080/18081/18082 三个桩，逐请求 JSONL 落盘 |

### 2.2 组成来源（层号沿用 `01-target-inventory.md` §5）

| 来源 | 内容 | 条目 |
|---|---|---|
| 层1 `411a8667` | Debian 13.6 基础根（全量；libc 2.41、libstdc++、libgcc_s、libssl/libcrypto 等） | 3,261 |
| 层2 `ebad5593` | ca-certificates / tzdata | 532 |
| 层5 `2c2d3479` | **libcurl 依赖闭包**（源于 `libcurl.so.4.8.0`，含 libnghttp2/3、libidn2、libgnutls30、krb5/ldap/sasl 等） | 45（10,413,112 B） |
| 层3 `f19f6d6c` | 闭包命中的 `libffi.so.8` | （计入 45） |
| 层9/10 | `app/` 与 `app/chatgpt-mirror-gateway`（23,252,912 B） | 1+1 |
| 层11 `b1b92536` | `/opt/curl-impersonate` 仅动态库：`libcurl-impersonate.so.4.8.0`（30,589,848 B）+ 3 个符号链接 + runtime-probe.so（排除 `.a` 与头文件） | 6 |
| 层16/17 | 入口脚本与 `/app/data` 目录结构 | 8 |
| `tools\downloads` 既有资产 | Alpine `vmlinuz-virt`（6.18.52-0-virt）与 `initramfs-virt` 内 **busybox（动态 musl，需 ld-musl 加载器）**、`ld-musl-x86_64.so.1`、128 个内核模块（含 e1000） | 205 |

### 2.3 关键构建修正（均为实测踩坑）

1. **musl 加载器缺位**：Alpine busybox 的 `PT_INTERP=/lib/ld-musl-x86_64.so.1`，必须随 busybox 一起收录，否则 `/init` 无法执行（内核报 `Failed to execute /init (error -2)`）。
2. **CPIO 需显式目录项**：内核 initramfs 解包器**不会**为文件自动创建中间目录；`usr/lib/modules/**` 必须逐级补目录项，否则 142 个 `.ko` 全部静默创建失败。
3. **不能全局导出 `LD_PRELOAD`**：glibc 的 `libcurl-impersonate.so` 一旦被 musl 的 busybox 进程继承，所有 busybox 调用（含 `setsid`/`sh`）立即报错退出；正确做法是仅对网关命令设置该环境变量。
4. **`lo` 必须启用**：initramfs 冷启动后 `lo` 默认 DOWN，`127.0.0.1` 连接会被默认路由从 `eth0` 发出（源地址 10.0.2.15、SYN 悬挂）、表现为"网关监听但不回包"的假象。已在 `/init` 中 `ip link set lo up` + `ifconfig lo 127.0.0.1` 修复。

## 3. 冷启动验证（最终构建，无人工介入）

- 启动日志：`reverse\logs\sandbox-final-boot.log`（串口全量）。
- 关键序列（节选）：

```text
[    3.749103] Run /init as init process
====== SANDBOX BOOT ======
Linux (none) 6.18.52-0-virt #1-Alpine SMP PREEMPT_DYNAMIC ... x86_64 Linux
--- merged-usr / modules check ---
lrwxrwxrwx ... /lib -> usr/lib        （merged-usr 生效）
drwxr-xr-x ... /usr/lib/modules/6.18.52-0-virt      （模块目录就位）
--- loader ---
ld.so (Debian GLIBC 2.41-12+deb13u3) stable release version 2.41.
--- curl-impersonate dir ---
-rwxr-xr-x  1808 ... libcurl-impersonate.runtime-probe.so
lrwxrwxrwx ... libcurl-impersonate.so -> libcurl-impersonate.so.4
lrwxrwxrwx ... libcurl-impersonate.so.4 -> libcurl-impersonate.so.4.8.0
-rw-r--r--  30589848 ... libcurl-impersonate.so.4.8.0
--- network ---
e1000 0000:00:03.0 eth0: Intel(R) PRO/1000 Network Connection
--- gateway deps (glibc ld --list) ---
  /opt/curl-impersonate/libcurl-impersonate.so (0x...)
  libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 ...  （全依赖解析成功，26 行）
--- starting gateway ---
gateway pid 456
--- gateway.log ---
INFO chatgpt_mirror_gateway: gateway upstreams configured ... chatgpt_base_url=https://chatgpt.com/ ...
INFO chatgpt_mirror_gateway: 开始异步预热 CF bypass 缓存 attempt=1
INFO chatgpt_mirror_gateway: gateway listening on http://0.0.0.0:40002
--- listening ports ---
tcp  0 0 0.0.0.0:40002 0.0.0.0:* LISTEN
--- local http probe (127.0.0.1:40002) ---
Connecting to 127.0.0.1:40002 ...
{"stub": "django", "path": "/admin/", "method": "GET"}   （见下：/ 的 302 被 wget 跟随至 /admin/，经网关代理到 Django 桩并返回该 JSON）
====== SANDBOX READY ======
```

> 说明：该次冷启动中宿主桩服务在线，`/admin/` 由 Django 桩（18080）应答，因此探针拿到了 54 字节 JSON。

## 4. 运行时行为验证（交互会话）

### 4.1 CF bypass 缓存预热（两条路径）

- **失败路径**（cfbypass 未就绪，早期启动）：`attempt=1..3` 每次耗时约 5s（连接超时），逐条输出
  `WARN chatgpt_mirror_gateway::proxy: cfbypass 未返回有效 cookies` →
  `WARN ... CF bypass 缓存预热失败，稍后重试 attempt=N`（8s 间隔）→
  第三次后 `CF bypass 缓存预热失败，将在登录时重试`。
- **成功路径**（桩服务修复后，重启网关）：

```text
INFO chatgpt_mirror_gateway::proxy: cfbypass 获取到有效 cookies
   original_target=http://10.0.2.2:18082/ cfbypass_target=http://10.0.2.2:18082/
   endpoint=/cloudflare5s/bypass-v1 cookie_count=2 has_user_agent=true
INFO chatgpt_mirror_gateway: CF bypass 缓存预热完成 attempt=1
```

- 目的地址随 `CHATGPT_BASE_URL` 变化（对比两次运行：`https://chatgpt.com/` → `http://10.0.2.2:18082/`），
  与静态报告【03 §8/§10】的"以主站为目标的预热"不符之处：**预热目标是当前 `chatgpt_base_url`**（新观测，修正静态判读）。

### 4.2 cfbypass 出站请求捕获（宿主 `logs\stub-18081.log`）

```json
masked: {"method":"POST","path":"/cloudflare5s/bypass-v1",
 "headers":{"authorization":"Bearer sandbox-gateway-secret-0001","content-type":"application/json",
            "accept":"*/*","accept-encoding":"zstd,gzip,deflate,br","host":"10.0.2.2:18081",
            "content-length":"149"},
 "body":"{\"url\":\"http://10.0.2.2:18082/\",\"user_agent\":\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36\"}"}
```

- 与【01 §8】入口脚本一致：Bearer 密钥 = `GATEWAY_ADMIN_SECRET`；UA 为 curl-impersonate 的 Chrome/146 画像。

### 4.3 上游代理与 Cookie 附加（宿主 `logs\stub-18082.log`）

对 `GET /sentinel/20260423af3c/sdk.js`（经 `CHATGPT_BASE_URL=http://10.0.2.2:18082`）：

```json
masked: {"method":"GET","path":"/sentinel/20260423af3c/sdk.js",
 "headers":{"user-agent":"Mozilla/5.0 (X11; Linux x86_64) ... Chrome/146.0.0.0 Safari/537.36",
            "origin":"http://10.0.2.2","referer":"http://10.0.2.2/",
            "cookie":"__cf_bm=STUB_CF_BM_0001; cf_clearance=STUB_CF_CLEARANCE_0001",
            "accept":"*/*","accept-encoding":"zstd,gzip,deflate,br","host":"10.0.2.2:18082"}}
```

- **cfbypass 缓存 → 上游请求 Cookie 注入链路端到端成立**（本报告最重要的运行时证据）。
- 网关日志同时记录：`INFO ...::proxy: 上游响应完成 target=http://10.0.2.2:18082/sentinel/20260423af3c/sdk.js duration_ms=6`。
- 返回给客户端的方向：保留了上游 `server: BaseHTTP/0.6 Python/3.12.14` 与 `content-type`，
  并新增安全头（如 `content-security-policy: default-src 'self'; connect-src 'self' ws: wss: ... https://chatgpt.com ...`），
  与【07 §5】"响应注入器/CSP"判读相互印证（具体注入规则待后续报告细化）。

### 4.4 HTTP 行为矩阵（guest 内 `nc` 原始请求 + 宿主 hostfwd）

| 请求 | 观测结果 | 备注 |
|---|---|---|
| `GET /` | `302 Found`，`location: /admin#/`，附 `cache-control/cloudflare-cdn-cache-control` 等缓存头 | 根路由即跳管理端 |
| `GET /api/operations-overview`（无认证） | `401 Unauthorized`（JSON） | 管理面鉴权生效 |
| `POST /api/operations-overview`（`Authorization: Bearer <GATEWAY_ADMIN_SECRET>` + JSON） | `422 Unprocessable Entity` | 已通过鉴权，参数校验失败（鉴权=Bearer 确认） |
| `POST /api/refresh-cfbypass`（同上 Bearer+JSON） | `401 Unauthorized` | **未决观察项**：该端点不接受同一 Bearer（或需额外凭据），留待后续报告 |
| `GET /api/not-login` | `400`；正文 `Failed to deserialize query string: missing field \`user_gateway_token\`` | 路由参数面确认 |
| `GET /sentinel/20260423af3c/sdk.js` | `200`（上游桩内容） | 公开资源路由，不要求登录 |
| `GET /backend-api/me`、`GET /v1/chat/completions`（无会话） | `401` | 登录态路由 |
| `GET /admin/`（宿主 hostfwd 全链） | `200 {"stub": "django", "path": "/admin/", "method": "GET"}` | **管理端反代链路（→ DJANGO_UPSTREAM）成立** |

### 4.5 数据库与其初始化

- `/app/data/chatgpt_mirror.db` 于启动时创建：大小 **94,208 B**（SQLite），目录结构
  `backend-db/`、`backend-logs/` 与【01 §5】层17 一致。表结构定义见 `05-database-schema.md`（未做逐表复核）。

## 5. 复现步骤

```powershell
# 0) 前置: image.tar 在位; 若需管理面代理验证, 先启动桩服务
C:\...\python.exe D:\Project\MirrorNiXiang\reverse\tools\sandbox_stubs.py

# 1) 构建沙箱 initramfs (读 image.tar 与 tools\downloads\initramfs-virt)
C:\...\python.exe D:\Project\MirrorNiXiang\reverse\tools\build_sandbox_initramfs.py

# 2) 启动 (交互式串口版; 也可 -serial file:... 收集全量日志)
.\tools\qemu-installer\qemu-system-x86_64.exe -m 2048 -no-reboot `
  -kernel tools\downloads\vmlinuz-virt -initrd tools\sandbox-initramfs.cpio.gz `
  -append "console=ttyS0 rdinit=/init panic=60" `
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:40002-:40002" -device e1000,netdev=n0 `
  -display none -serial "tcp:127.0.0.1:45401,server=on,wait=off" -monitor none

# 3) 交互: 任一 TCP 客户端连接 127.0.0.1:45401 即为 guest 串口控制台 (逐批发送命令, 读取回显)
```

## 6. 修正的静态判读与遗留问题

### 6.1 对既有静态报告的修正

- 【03 §0.2】"LD_PRELOAD 全局注入"在运行时的正确形态：仅网关进程持有该变量才可正常工作（见 §2.3-3）。
- 【03 §8】预热目标：运行时为 **当前 `chatgpt_base_url`**（可通过环境变量改道），而非硬编码主站。

### 6.2 未决观察项

- ~~`POST /api/refresh-cfbypass` 的鉴权差异~~ **已解决（见 §9.4）**：该端点返回体为 `{"message":"未登录"}`，属**用户会话守卫**（非管理密钥）；管理守卫本身接受 Bearer 或 `x-gateway-secret`。
- `/sentinel/*` 返回体的注入规则（CSP 等）未逐头比对静态实现。

### 6.3 本沙箱未覆盖

- 真实 cfbypass（Chromium）与真实 Django 后端：以桩替代，验证了**调用协议**而非其真实实现。
- 真实 TLS 上游（`wreq`/BoringSSL 指纹栈）——本次将 `CHATGPT_*` 指向本地 HTTP 桩。
- 登录/会话类业务流（需要真实 ChatGPT 账号态）。
- 管理前端静态资源（层12 未收录；`/admin#/` 为前端路由，属预期）。

### 6.4 路线变更说明（为何放弃 Alpine/FAT32 方案）

- 网关是 **glibc** 动态链接目标，Alpine(musl) 无法直接承载；
- Windows 侧 FAT32/ext4 镜像无法保真符号链接与权限（335 个符号链接批量失败）；
- 最终方案改为 **镜像原生层直出 CPIO**：符号链接/权限在归档内原样保留、无需宿主文件系统落地。

## 7. 证据文件清单

| 文件 | 内容 |
|---|---|
| `reverse\logs\sandbox-final-boot.log` | 最终冷启动全量串口日志（含 ld --list、监听、HTTP 探针结果） |
| `reverse\logs\guest-console-dump.txt` | 交互会话导出（gateway.log 全量 + 数据目录 + 内核版本） |
| `reverse\logs\stub-18080.log` | Django 桩请求记录（含 `/admin/` 代理请求） |
| `reverse\logs\stub-18081.log` | cfbypass 桩请求记录（共 8 次调用：失败阶段 6 次 + 成功阶段 2 次，覆盖 3 个网关实例与最终冷启动） |
| `reverse\logs\stub-18082.log` | ChatGPT 上游桩请求记录（含 Cookie 注入的原始请求头） |
| `reverse\tools\sandbox-initramfs.manifest.txt` | 构建清单（sha256、条目计数、闭包明细） |

---

## 9. 场景补测记录（第二轮）

> 执行时间：2026-09-22 下午；沙箱仍为同一实例（QEMU 串口 127.0.0.1:45401），宿主桩服务扩展为
> 18080/18081/18082（原桩，新增 `hang` 路由）+ 18083（`cf_fail_stub.py`，模式文件 `logs\cfstub-mode.txt`）
> + 18084（`proxy_stub.py`，HTTP 代理桩）。驱动脚本：`run_cf_mode_test.py`。全部控制经 TCP 控制台注入，回显为证。

### 9.1 启动期环境变量约束（场景 1）

在 guest 内以 `env -i` 逐级注入变量运行 `./chatgpt-mirror-gateway`：

| 用例 | 注入 | 观测 | 退出码 |
|---|---|---|---|
| E1 | 无任何变量 | stderr：`GATEWAY_ADMIN_SECRET 必须设置，不能使用内置默认值` | 1 |
| E2 | HOST/PORT/DATABASE_PATH | 同上 | 1 |
| E3 | + GATEWAY_ADMIN_SECRET=x（过短） | `GATEWAY_ADMIN_SECRET 长度至少需要 16 个字符` | 1 |
| E4 | + GATEWAY_ADMIN_SECRET=16 位 | **启动成功**（默认 PORT=40002 已被占用）→ `监听 0.0.0.0:40002 失败: Address already in use (os error 98)` | 1 |
| E5 | + CREDENTIAL_ENCRYPTION_KEY=32 位 | 结果同 E4（说明该密钥非启动必需，惰性读取） | 1 |
| E6 | E5 + PORT=40202 | `gateway listening on http://0.0.0.0:40202` 正常监听（被主动 kill） | 137(SIGKILL) |

**结论**：唯一强制环境变量是 `GATEWAY_ADMIN_SECRET`（≥16 字符，且**制品内置默认值被显式拒绝**——fail-closed）；
其余（HOST/PORT/DATABASE_PATH/CREDENTIAL_ENCRYPTION_KEY/DJANGO_UPSTREAM/CF_BYPASS_URL/…）均有默认值。
E4 同时实测捕获了反汇编 §2.2 步 20 的绑定失败路径文案。未配置上游时 `gateway upstreams configured` 记录为 `None`。

### 9.2 请求超时与静态资源重试（场景 12）

- 对 `GET /sentinel/20260423af3c/hang.js`（上游桩故意挂起 65s；`REQUEST_TIMEOUT_SECS=20`）：

```text
ERROR chatgpt_mirror_gateway::proxy: 代理请求失败: reqwest 请求失败: error sending request for url (…/hang.js) target=… attach_chatgpt_auth=true
WARN  chatgpt_mirror_gateway::proxy: 静态资源首次代理失败，立即重试一次 target=…/hang.js
（≈20s 后第二个 ERROR，同一 target）
ERROR tower_http::trace::on_failure: response failed classification=Status code: 502 Bad Gateway latency=40008 ms
```

- 客户端实测：`wget` 收到 `HTTP/1.1 502 Bad Gateway`，**总耗时 40s（= 2 次 ×20s 超时）**。
- **新行为**：静态资源类上游失败会**立即重试一次**（此前未记录）；两次均失败才向客户端返回 502。

### 9.3 cfbypass 故障模式矩阵（场景 6-8）

对 `cf_fail_stub` 的 5 种模式逐一重启网关（`CF_BYPASS_URL=http://10.0.2.2:18083`）并采集预热期日志：

| 模式 | cfbypass 响应 | 网关日志（节选） | 判定 |
|---|---|---|---|
| ok | 200 + cf_clearance/__cf_bm | `cfbypass 获取到有效 cookies … cookie_count=2 has_user_agent=true` → `CF bypass 缓存预热完成 attempt=1` | 正常 |
| empty | 200 + `cookies: []` | `WARN: cfbypass 返回成功但 cookies 为空，视为失败` → `未返回有效 cookies` → `预热失败，稍后重试 attempt=1`（+8s attempt=2 同） | 空集 fail |
| partial | 200 + 仅 `__cf_bm`（**无 cf_clearance**） | `cfbypass 获取到有效 cookies … cookie_count=1` → `CF bypass 缓存预热完成 attempt=1` | **部分集合被接受** |
| 401 | 401 + JSON detail | `WARN: cfbypass 请求失败 status=401 Unauthorized endpoint=/cloudflare5s/bypass-v1 detail={"detail": "invalid cf bypass secret"}` → 未返回有效 cookies → 重试 | 状态码+响应体入日志 |
| 502 | 502 + JSON detail | 同上（`status=502 … detail={"detail": "upstream chromium crashed"}`） | 同上 |

- **挑战分支（场景 8）近似结论**：cfbypass 在 Cloudflare 挑战未过时可能返回「稳定 N 轮的部分集合」，网关侧对
  `cookie_count=1`（无 `cf_clearance`）**判为有效并完成预热**——即 02 报告 R5 指出的"调用方需自检"在实测中**未自检**。
  真实 CF 挑战场景仍无法在本地复现（记录为近似证据）。
- 重试节奏：预热失败后 +8s、+16s 各重试一次，第三次失败后 `将在登录时重试`（与第一阶段观测一致）。

### 9.4 Cookie 缓存命中 / 清除（场景 9）

- **缓存命中（实测）**：ok 预热完成后，两次 `GET /sentinel/20260423af3c/sdk.js`（14:33:26）均从上游桩取回内容；
  `cfstub-18083.log` 最后一次调用停在预热时刻（14:33:03），**请求期间无新的 cfbypass 调用**；上游桩两次都收到
  `cookie: __cf_bm=STUB_CF_BM_0001; cf_clearance=STUB_CF_CLEARANCE_0001` → 缓存 → 注入链路复现稳定。
- **缓存清除（受限）**：清除入口 `/api/refresh-cfbypass` 实测被**用户会话守卫**拦截：
  无凭据、Bearer、`x-gateway-secret`、两者兼有、GET 变体五种请求全部 `401`，响应体均为 `{"message":"未登录"}`。
  对照组：`POST /api/operations-overview` 无凭据 401 体为 `{"message":"缺少或无效的网关认证信息"}`，
  带 Bearer 或 `x-gateway-secret` 均**通过管理守卫**（进入 JSON 解析，报 `missing field day_stat`）。
  → 结论：refresh-cfbypass 需要登录态（`x-mirror-token`/会话 Cookie），在无真实 ChatGPT 会话的沙箱内无法触发清除；
  清除行为未在运行时覆盖（保留为未覆盖项）。
  补充探针：`x-mirror-token: dummy-token-123` 与 `Cookie: mirror_token=dummy-token-123; csrftoken=x` 均仍返回
  `{"message":"未登录"}`（无效会话一致被拒）；对照端点 `GET /api/auth/session` 对无效 token 返回空对象 `{}`（非报错）。

### 9.5 镜像代理配置：保存 / 读回 / 连通测试（场景 10）

1. `POST /api/mirror-proxy-config`（Bearer + `{"transport_mode":"curl-impersonate","enabled":true,"proxy_url":"http://10.0.2.2:18084",…}`）
   → `200 {"message":"代理配置已保存","proxy_url":"http://10.0.2.2:18084/","transport_mode":"curl-impersonate","enabled":true,"nodes":[],"password":null,"has_password":false}`。
2. `GET /api/mirror-proxy-config` → 返回同一配置（读回成功，URL 规范化为带尾斜杠）。
3. **持久化形态（DB 实测）**：`gateway_settings` 中键 `mirror_proxy` 的值为整值密文：

```text
enc:v1:k05XaGprXRJcQSlsDSpA4tSESbJLLSQOUidjgwpxPFf3quefBGXYdbjGO-BaQYSxBTK3OweU8Oykh3L567q4EIy55Rxrgy1kVXt4Sf4Yi2YncdKVtGH9AAqB5NJ-LG5BHY44ahyiw6fRFw2rxRe_NMGxZ3OWLDnLnjMRQaHIN-BUpJS8Feu1xOcOe3FBOFdUfcswt0-AjoHB4ZY8pqqO2wj
```

   —— 格式 `enc:v1:` + **URL-safe Base64**（含 `-`），与 04 报告 AES-256-GCM/`nonce||ct` 的反汇编结论一致（本节为运行时实物证据）。
4. `POST /api/test-mirror-proxy-config`（同上配置）→ 先 TCP 探测：指向 guest 内 `127.0.0.1:18084` 时返回
   `{"message":"代理端口连接失败: Connection refused (os error 111)"}`；改指宿主 `10.0.2.2:18084` 后返回
   **`{"message":"代理端口可连接，上游返回 HTTP 200","upstream_status":200}`**。
5. **代理链路抓包**：宿主 `proxystub-18084.log` 记录 `GET http://10.0.2.2:18082/`（即经代理抓取 `chatgpt_base_url`）；
   上游桩 `stub-18082.log` 收到该请求并携带**wreq 内置 Chrome-146 导航指纹**（完整头表）：

```text
sec-ch-ua: "Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"
sec-ch-ua-mobile: ?0 / sec-ch-ua-platform: "macOS" / Upgrade-Insecure-Requests: 1
user-agent: Mozilla/5.0 (X11; Linux x86_64) … Chrome/146.0.0.0 Safari/537.36
Accept: text/html,… / Sec-Fetch-Site: none / Sec-Fetch-Mode: navigate / Sec-Fetch-User: ?1 / Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br, zstd / Accept-Language: en-US,en;q=0.9 / Priority: u=0, i
Proxy-Connection: Keep-Alive
```

   —— 与手工注入模板（`"Not_A Brand";v="99"`，04 §3.1）不同：这是 wreq/curl-impersonate 的独立指纹面。

### 9.6 WebSocket 与静态资源（场景 11、4）

| 请求 | 结果 | 说明 |
|---|---|---|
| `GET /realtime/abc` + `Upgrade: websocket`（无会话） | **401**（JSON 体） | WS 路由在会话校验后被拒；未完成 101 升级（完整桥接需登录态） |
| `GET /favicon.svg` | **204 No Content** + 安全头 | 静态可选资源返回空 204 |
| `GET /assets/index.js` | **200（上游内容）** + CSP 注入 | `/assets/*` 反代到 Django 上游（层 12 静态由后端提供） |
| `GET /admin/assets/app.js` | 200 + CSP 注入 | `/admin/*` 同上 |

### 9.7 本轮新增/修正结论清单

1. 管理守卫凭证 = `Authorization: Bearer` **或** `x-gateway-secret`（两者等价通过）；`refresh-cfbypass` 属用户会话域（`未登录`）。
2. 部分 CF Cookie 集合（无 `cf_clearance`）被预热判为有效——调用方不自检（安全相关）。
3. 静态资源代理失败自动重试一次（双倍超时后 502）。
4. 启动仅强制 `GATEWAY_ADMIN_SECRET`（≥16，禁内置默认值）；绑定失败/必需缺失均为 `eprint + exit(1)`。
5. `mirror_proxy` 配置整值加密落库（`enc:v1:` + URL-safe Base64，运行时实物）。
6. `test-mirror-proxy-config` 会做 TCP 探测 + 经代理真实 GET `chatgpt_base_url` 并返回 `upstream_status`。

### 9.8 本轮新增工具与证据

| 文件 | 说明 |
|---|---|
| `tools\cf_fail_stub.py` | cfbypass 故障桩（ok/empty/partial/401/502/hang，模式文件驱动） |
| `tools\proxy_stub.py` | HTTP 代理桩（CONNECT/absolute-form，含 10.0.2.2→127.0.0.1 映射） |
| `tools\run_cf_mode_test.py` | 模式切换+重启+日志采集驱动 |
| `logs\cfstub-18083.log` | 各模式调用记录（含 auth 头与请求体） |
| `logs\proxystub-18084.log` | 代理流量记录（含超时与成功两类） |
| `logs\stub-18082.log` | 代理探测请求的完整指纹头（§9.5-5） |

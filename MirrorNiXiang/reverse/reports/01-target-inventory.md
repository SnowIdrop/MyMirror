# 01 · 目标镜像清单（chatgpt-mirror-django:all-in-one）

- 目标对象：`D:\Project\MirrorNiXiang\image.tar`（1,132,831,744 B，mtime 2026-09-22 10:33:58）。
- 交叉核对对象：`D:\Project\MirrorNiXiang\reverse\extracted\` 下的 5 个文件。
- 本报告仅依据上述本地文件生成；未访问网络、真实上游或 api.zxcbug.com；未运行镜像内任何代码。
- 所有结论按【S#】标注来源；标注“（判读）”“（计算）”的条目为分析结果，其余为直接观测值。

## 0. 来源标注约定

| 标记 | 来源 |
|---|---|
| S1 | image.tar 顶层 OCI/兼容文件：`index.json`、`oci-layout`、`manifest.json`、`repositories`，以及 17 个未引用 JSON blob（抽查 4 个） |
| S2 | image.tar `blobs/sha256/c89121441e8f63217a95d2950c3da1d2820480c0d299aaf6e36be2202747ab9b`（OCI config，13,528 B） |
| S3 | image.tar `blobs/sha256/0afc8b98c3288a4baf6cd6e4f323e6a5347a606d6f40fee376a327ced859da21`（OCI image manifest，2,835 B） |
| S4 | image.tar 各层 blob 的逐层列表/成员内容（流式 `tar -tf` / `tar -xOf`；含 17 层条目计数与关键路径匹配） |
| S5 | `reverse/extracted/` 目录文件内容 + `Get-FileHash -Algorithm SHA256` |
| S6 | `extracted/chatgpt-mirror-gateway` 的 ELF 头部字节与内部字符串统计（PowerShell 读取 + 正则） |
| S7 | `extracted/usr/local/bin/chatgpt-mirror-all-in-one` 全文（117 行） |
| S8 | 本机分析工具自报版本（`tar --version`、`$PSVersionTable`） |

## 1. 镜像 OCI 元数据

- 引用名（index.json annotations）：`docker.io/lisa666520/chatgpt-mirror-django:all-in-one`；`org.opencontainers.image.ref.name=all-in-one`【S1】
- `index.json`：schemaVersion 2，OCI image index，单条目指向 OCI image manifest `sha256:0afc8b98c328…da21`（size 2,835）【S1】
- `oci-layout`：`{"imageLayoutVersion": "1.0.0"}`【S1】
- OCI image manifest（S3）：config 为 `sha256:c89121441e8f…ab9b`（13,528 B）；17 个 layer 条目，mediaType 全部为 `application/vnd.oci.image.layer.v1.tar`（**未压缩层**；各层 size 即未压缩 tar 体积）
- OCI config（S2）：`architecture=amd64`、`os=linux`、`created=2026-09-02T12:29:02.457518504Z`；`rootfs.type=layers` 且 17 个 `diff_ids` 与 manifest 层顺序一一对应；`history` 共 27 条（17 条实体层 + 10 条 `empty_layer=true`）
- 兼容文件【S1】：`manifest.json`（docker-save 风格；`RepoTags=["lisa666520/chatgpt-mirror-django:all-in-one"]`，含 LayerSources 尺寸表）；`repositories` = `{"lisa666520/chatgpt-mirror-django":{"all-in-one":"ba8be9795808…e1f63"}}`（观测值：该值与第 17 层 digest 相同）
- 未引用 blob【S1】：除 17 层 + config + manifest 外，另有 17 个 JSON blob（15 × 467 B + 1 × 391 B + 1 × 2,043 B），为 docker-save 兼容的逐层 image JSON（`id`/`parent` 链）。抽查 4 个：391 B 起始 blob（无 parent，created 1970-01-01T08:00:00+08:00）；2 个 467 B 中间 blob（带 parent）；2,043 B 终态 blob（含与 S2 一致的 Env/Entrypoint/ExposedPorts/Healthcheck/StopSignal/WorkingDir 副本）。其余 13 个同尺寸 blob 未逐一读取（**推断**同类，未验证）
- 体积核对（计算）：17 层 size 合计 **1,132,774,912 B**，占 image.tar 的 99.995%；余量约 56,832 B 为 index/manifest/config/legacy JSON + tar 头与对齐开销

## 2. 入口（Entrypoint）

- Entrypoint：`["/usr/local/bin/chatgpt-mirror-all-in-one"]`；终态 config **无 Cmd 字段**（历史中 `CMD ["python3"]` 为 empty_layer 记录，未出现在终态）【S2】
- WorkingDir：`/app`；StopSignal：`SIGTERM`；Volume：`/app/data`【S2】
- Healthcheck（CMD-SHELL）：`python -c "import os,socket; s=socket.create_connection(('127.0.0.1',int(os.getenv('PORT','40002'))),2); s.close()"`；interval 15 s / timeout 3 s / start-period 30 s / retries 5【S2】
- 入口脚本本体：`/usr/local/bin/chatgpt-mirror-all-in-one`（镜像内 2,949 B；与 extracted 文件哈希一致，见 §10）【S4】【S5】【S7】
- 脚本首行 `#!/usr/bin/env bash`，`set -Eeuo pipefail`，注册 EXIT/INT/TERM trap 做子进程统一回收【S7】

## 3. 暴露端口

- 镜像 EXPOSE：`40002/tcp`（唯一）【S2】
- 运行时内部端口：Django `8000`、cfbypass `8001`（均绑定 127.0.0.1，未 EXPOSE）；gateway 监听 `PORT=40002`【S2】【S7】

## 4. 关键环境变量

镜像内 Env 全量（28 条）【S2】：

| 变量 | 值 | 说明（判读） |
|---|---|---|
| PATH | /usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin | 系统路径 |
| LANG | C.UTF-8 | 语言环境 |
| GPG_KEY | 7169605F62C751356D054A26A821E680E5FA6305 | python-build 的 GPG 校验键 |
| PYTHON_VERSION | 3.12.14 | Python 版本 |
| PYTHON_SHA256 | 5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a | Python 源码包校验值 |
| TZ | Asia/Shanghai | 时区 |
| PYTHONDONTWRITEBYTECODE | 1 | 不写 pyc |
| PYTHONUNBUFFERED | 1 | 不缓冲输出 |
| PIP_NO_CACHE_DIR | 1 | pip 不留缓存 |
| HOST | 0.0.0.0 | gateway 监听地址（判读） |
| PORT | 40002 | 对外服务端口，healthcheck 使用 |
| DATABASE_PATH | /app/data/chatgpt_mirror.db | SQLite 路径（rusqlite） |
| DJANGO_ENV | PRODUCTION | Django 环境 |
| DJANGO_DEBUG | false | 调试开关 |
| DJANGO_ALLOW_ALL_ORIGINS | disable | CORS 开关 |
| DJANGO_ALLOWED_HOSTS | localhost,127.0.0.1 | 允许 Host |
| DJANGO_INTERNAL_PORT | 8000 | Django 回环端口 |
| CF_BYPASS_INTERNAL_PORT | 8001 | cfbypass 回环端口 |
| CF_BYPASS_HEADLESS | true | 无头 Chromium |
| CF_BYPASS_MAX_WAIT_SECONDS | 20 | 等待上限 |
| CF_BYPASS_PAGE_LOAD_TIMEOUT_SECONDS | 15 | 页面加载超时 |
| CF_BYPASS_POLL_INTERVAL_SECONDS | 0.5 | 轮询间隔 |
| CF_BYPASS_COOKIE_STABLE_POLLS | 2 | Cookie 稳定轮询数 |
| CF_BYPASS_NAVIGATION_RETRIES | 1 | 导航重试 |
| CF_BYPASS_ALLOWED_HOSTS | chatgpt.com,.chatgpt.com | 允许代理的目标域 |
| STARTUP_TIMEOUT_SECONDS | 60 | 启动等待超时 |
| NO_PROXY / no_proxy | localhost,127.0.0.1 | 代理绕过 |

运行时必需但**不在镜像 Env** 中（脚本校验，缺失则 `exit 64`）【S7】：`ADMIN_PASSWORD`、`CREDENTIAL_ENCRYPTION_KEY`、`DJANGO_SECRET_KEY`、`GATEWAY_ADMIN_SECRET`。

运行时可覆盖（默认值来自脚本）【S7】：`ADMIN_USERNAME`(admin)、`DJANGO_UPSTREAM`(http://127.0.0.1:8000)、`CHATGPT_GATEWAY_URL`(http://127.0.0.1:40002)、`CF_BYPASS_URL`(http://127.0.0.1:8001)、`CF_BYPASS_SECRET`(默认=GATEWAY_ADMIN_SECRET)、`CURL_IMPERSONATE_PROFILE`(chrome146)。

## 5. 层与关键文件

层顺序 = OCI manifest 顺序 = config `diff_ids` 顺序（底 → 顶）；size 来自【S3】，条目数/内容来自【S4】，构建步骤引文来自【S2】history。

| # | digest（前 12 位） | size (B) | 层内容（构建步骤） | 关键文件/证据 |
|---|---|---|---|---|
| 1 | 411a86676185 | 81,070,080 | 基础根文件系统（`# debian.sh --arch 'amd64'`，debuerreotype 0.17） | `/etc/debian_version`=`13.6`；`usr/lib/os-release`=`Debian GNU/Linux 13 (trixie)`；3,262 条目 |
| 2 | ebad55931d5b | 4,127,744 | `RUN apt-get install ca-certificates netbase tzdata` | 553 条目 |
| 3 | f19f6d6c8637 | 38,126,080 | `RUN` Python 3.12.14 源码构建安装（含 sha256/gpg 校验） | `/usr/local/lib/python3.12/**`（含 pip 引导；`python3.12` 匹配 1,686 条）；1,828 条目 |
| 4 | 6fdca0968d0f | 5,120 | `RUN ln -svT` 命令族符号链接 | `idle→idle3`、`pip→pip3`、`pydoc→pydoc3`、`python→python3`、`python-config→python3-config` |
| 5 | 2c2d34799f58 | 717,405,184 | `RUN` 安装 chromium=146.0.7680.177-1~deb13u1、chromium-common/driver、xvfb、xauth、fonts-liberation 等 | 5,938 条目（含 62 条 chromium 路径） |
| 6 | ba576d9f111b | 2,560 | `COPY backend/requirements.txt → /tmp/backend-requirements.txt` | 仅 `tmp/backend-requirements.txt`（内容见 §7） |
| 7 | 131ed87e3430 | 2,560 | `COPY cfbypass/requirements.txt → /tmp/cfbypass-requirements.txt` | 仅 `tmp/cfbypass-requirements.txt`（内容见 §7） |
| 8 | ce6817dfb5a8 | 172,523,520 | `RUN python -m pip install -r /tmp/backend-requirements.txt -r /tmp/cfbypass-requirements.txt`（随后删除两个文件） | 16,072 条目；`usr/local/lib/python3.12/site-packages/**`；whiteout：`tmp/.wh.backend-requirements.txt`、`tmp/.wh.cfbypass-requirements.txt` |
| 9 | 7a4d7744926b | 1,536 | `WORKDIR /app` | 条目：`app/` |
| 10 | f58eb8fc7c2f | 23,255,040 | `COPY /tmp/chatgpt-mirror-gateway ./chatgpt-mirror-gateway` | `app/chatgpt-mirror-gateway`（唯一内容文件，见 §6） |
| 11 | b1b92536a4fd | 93,853,184 | `COPY /opt/curl-impersonate /opt/curl-impersonate` | 21 条目：`include/curl/*.h`、`libcurl-impersonate.a`、`libcurl-impersonate.runtime-probe.so`、`libcurl-impersonate.so`、`.so.4`、`.so.4.8.0` |
| 12 | 40cf952049f2 | 2,110,976 | `COPY /app/gateway/static ./static` | `app/static/index.html`、`favicon.svg`、`assets/` 35 个文件（chatgpt/access/announcement/gptcar/logs/overview/political-moderation/profile/proxy/request/scripts/user 等 JS/CSS）；38 条目 |
| 13 | 08bcb7acd7b6 | 236,032 | `COPY backend/ ./backend/` | Django 工程 78 条目：`manage.py`、`app/settings.py`、`app/accounts/**`、`app/chatgpt/**`、`cli/create_init_user.py`、`cli/update_token.py`、`requirements.txt`、`uv.lock`、`pyproject.toml`、`Dockerfile`、`entrypoint.sh`、`.flake8`、`.pre-commit-config.yaml`、`static/` |
| 14 | adfc6f182b79 | 25,088 | `COPY cfbypass/app.py ./cfbypass/app.py` | `app/cfbypass/app.py`（22,260 B） |
| 15 | 1a18601d0d63 | 14,336 | `COPY cfbypass/proxy_relay.py ./cfbypass/proxy_relay.py` | `app/cfbypass/proxy_relay.py`（11,409 B） |
| 16 | 581a524a387b | 6,144 | `COPY docker-entrypoint.all-in-one.sh /usr/local/bin/chatgpt-mirror-all-in-one` | 2,949 B 入口脚本 |
| 17 | ba8be9795808 | 9,728 | `RUN rm -rf /app/backend/{db,logs} && mkdir -p /app/data/{backend-db,backend-logs} && ln -s … && chmod +x …` | `app/backend/db → /app/data/backend-db`、`app/backend/logs → /app/data/backend-logs`、`app/data/backend-db/`、`app/data/backend-logs/`；入口脚本以 0755 重新入库 |

关键文件 → 层 溯源：gateway 二进制 = 层 10；前端静态资源 = 层 12；Django 后端 = 层 13；cfbypass 两脚本 = 层 14/15；入口脚本 = 层 16；curl-impersonate = 层 11。

extracted 目录对照：仅含 5 个文件（rootfs 子集，路径扁平化）：`chatgpt-mirror-gateway`、`cfbypass/app.py`、`cfbypass/proxy_relay.py`、`usr/local/bin/chatgpt-mirror-all-in-one`、`config-c89121441e8f…ab9b`（0 B 空文件——注意：与 tar 内 13,528 B 的 config blob 不同名同源但内容为空，观察项）【S5】。

## 6. gateway 二进制（镜像内 `/app/chatgpt-mirror-gateway`）

- 大小：**23,252,912 B**（22.17 MiB）【S5】；SHA-256：**4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098**【S5】【§10 复核】
- 格式：ELF 64-bit LSB（magic `7f 45 4c 46 02 01 01 00`），x86-64（`e_machine=0x003e`），`e_type=0x0003`（ET_DYN/PIE），动态链接（字符串含 `ld-linux-x86-64.so.2`、`libc.so.6`、`libm.so.6`、`libgcc_s.so.1`、`libstdc++.so.6`、`libcurl.so.4`）【S6】
- 语言：**Rust**。证据：`rustc version 1.88.0 (6b00bc388 2025-06-23)` 完整版本串；panic 路径 `/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc/library/...`；构建 registry 路径 `/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/...`；`rustc` 命中 554 次、`cargo` 命中 1,611 次【S6】
- 非 Go 佐证：`goroutine`、`Go build ID`、`golang.org`、`go1.x` 全部 0 命中；无 UPX/PyInstaller/Node 标记【S6】
- 依赖（108 个 crate，均带版本；来源：二进制内嵌 registry 路径字符串）【S6】：

```text
aead-0.5.2, aes-0.8.4, alloc-stdlib-0.2.4, async-channel-2.5.0, async-compression-0.4.42, async-http-proxy-1.2.5,
atomic-waker-1.1.2, axum-0.7.9, axum-core-0.4.5, base64-0.13.1, base64-0.22.1, brotli-8.0.4, brotli-decompressor-5.0.3,
btls-0.5.6, bytes-1.11.1, cipher-0.4.4, compression-codecs-0.4.38, compression-core-0.4.32, concurrent-queue-2.5.0,
crossbeam-utils-0.8.22, curl-0.4.50, data-encoding-2.10.0, dotenvy-0.15.7, event-listener-5.4.2, flate2-1.1.9,
form_urlencoded-1.2.2, futures-channel-0.3.32, futures-core-0.3.34, futures-lite-2.6.1, futures-util-0.3.34, h2-0.4.15,
hashbrown-0.17.0, http-1.4.0, http-body-1.0.1, http-body-util-0.1.5, http-range-header-0.4.2, http2-0.5.17,
httparse-1.10.1, httpdate-1.0.3, hyper-1.9.0, hyper-rustls-0.27.9, hyper-util-0.1.20, icu_collections-2.2.0,
icu_normalizer-2.2.0, idna-1.1.0, indexmap-2.14.0, ipnet-2.12.0, iri-string-0.7.12, isahc-2.0.1, itoa-1.0.18,
lazy_static-1.5.0, lru-0.18.2, matchers-0.2.0, matchit-0.7.3, mime_guess-2.0.5, mime-0.3.17, miniz_oxide-0.8.9, mio-1.2.0,
once_cell-1.21.4, parking_lot_core-0.9.12, parking_lot-0.12.5, parking-2.2.1, percent-encoding-2.3.2, polling-3.11.0,
rand_chacha-0.3.1, rand_core-0.6.4, rand-0.8.5, regex-automata-0.4.14, regex-syntax-0.8.10, reqwest-0.12.28,
ring-0.17.14, rusqlite-0.31.0, rustix-1.1.4, rustls-0.23.41, rustls-pki-types-1.14.0, rustls-webpki-0.103.13,
serde_core-1.0.228, serde_json-1.0.149, serde_path_to_error-0.1.20, serde-1.0.228, sharded-slab-0.1.7,
signal-hook-registry-1.4.8, slab-0.4.12, sluice-0.6.0, smallvec-1.15.1, socket2-0.6.3, thread_local-1.1.9,
tokio-1.53.1, tokio-btls-0.5.6, tokio-rustls-0.26.4, tokio-socks-0.5.2, tokio-tungstenite-0.24.0, tokio-util-0.7.18,
tower-0.5.3, tower-http-0.6.8, tracing-core-0.1.36, tracing-log-0.2.0, tracing-subscriber-0.3.23, tungstenite-0.24.0,
untrusted-0.9.0, url-2.5.8, utf-8-0.7.6, want-0.3.1, wreq-6.0.0-rc.31, wreq-proto-0.2.5, wreq-rt-0.2.2-rc.4,
zstd-0.13.3, zstd-safe-7.2.4
```

- 关键依赖判读：`wreq 6.0.0-rc.31`（浏览器指纹 HTTP 客户端）、`isahc 2.0.1` + `curl 0.4.50`（libcurl 绑定，配合 LD_PRELOAD）、`reqwest 0.12.28`、`hyper 1.9.0`、`axum 0.7.9`（HTTP 服务）、`tokio 1.53.1`、`rustls 0.23.41`、`btls 0.5.6`/`tokio-btls`（BoringSSL 栈）、`tokio-socks 0.5.2`、`rusqlite 0.31.0`、`dotenvy 0.15.7`、`tower-http 0.6.8`、`tokio-tungstenite 0.24.0`、`async-compression`(brotli/zstd)【S6】（判读：基于 crate 名称）
- 启动时注入（入口脚本）：`LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so`、`CURL_IMPERSONATE=chrome146`、`CURL_IMPERSONATE_HEADERS=no`【S7】
- 未发现 git 依赖路径（`github.com-<hash>` 0 命中）；二进制内嵌 `github.com/sagebind/isahc` 归属字符串 1 处【S6】

## 7. cfbypass 依赖

- 构建期 requirements（层 7 内 `/tmp/cfbypass-requirements.txt`，安装后删除并留 whiteout）【S4】：
  - `DrissionPage==4.0.5.6`
  - `fastapi==0.111.0`
  - `pyvirtualdisplay==3.0`
  - `uvicorn==0.30.1`
- 代码级导入【S5】（读取 `extracted/cfbypass/*.py`）：
  - `app.py`：标准库（asyncio/hmac/ipaddress/os/shutil/socket/time/traceback/typing/urllib.parse）+ `DrissionPage`（ChromiumOptions/ChromiumPage）+ `fastapi`（Depends/FastAPI/Header/HTTPException/Request）+ `fastapi.responses` + `pydantic`（BaseModel/Field/HttpUrl/field_validator）+ 本地模块 `proxy_relay`（AuthenticatedProxyRelay）
  - `proxy_relay.py`：纯标准库（base64/ipaddress/select/socket/socketserver/ssl/struct/threading/urllib.parse）
- 判读：`pydantic` 为 fastapi 传递依赖；`DrissionPage` 驱动层 5 安装的 Chromium；cfbypass 以 `python -m uvicorn app:app --host 127.0.0.1 --port 8001` 启动【S5】【S7】
- 附带（同批 pip 安装，层 6 `/tmp/backend-requirements.txt`）【S4】：asgiref==3.8.1、certifi==2024.8.30、charset-normalizer==3.3.2、Django==5.2.17、cryptography==43.0.3、django-simpleui==2024.8.28、djangorestframework==3.18.0、idna==3.10、PyJWT==2.9.0、requests==2.32.3、setuptools==75.1.0、sqlparse==0.5.1、urllib3==2.2.3、wheel==0.37.1、django-crontab==0.7.1

## 8. 入口脚本启动顺序（`/usr/local/bin/chatgpt-mirror-all-in-one`）

按脚本执行顺序（行号引用脚本自身）【S7】：

1. L18-20：注册 `trap shutdown EXIT`、`trap 'exit 130' INT`、`trap 'exit 143' TERM`（统一回收子进程）。
2. L22-34：校验必需环境变量 `ADMIN_PASSWORD`、`CREDENTIAL_ENCRYPTION_KEY`、`DJANGO_SECRET_KEY`、`GATEWAY_ADMIN_SECRET`；任一缺失打印 `缺少必需环境变量: <名称>` 并 `exit 64`。
3. L36-43：导出运行参数默认值（`ADMIN_USERNAME`、`PORT=40002`、`DJANGO_INTERNAL_PORT=8000`、`CF_BYPASS_INTERNAL_PORT=8001`、`DJANGO_UPSTREAM`、`CHATGPT_GATEWAY_URL`、`CF_BYPASS_URL`、`CF_BYPASS_SECRET`）。
4. L45：`mkdir -p /app/data/backend-db /app/data/backend-logs`。
5. L47-49：`cd /app/backend` 后**前台**执行 `python manage.py migrate --noinput`、`python cli/create_init_user.py`（先于三个服务）。
6. L76-83：后台启动 cfbypass：`cd /app/cfbypass && exec python -m uvicorn app:app --host 127.0.0.1 --port "$CF_BYPASS_INTERNAL_PORT"`。
7. L85-92：后台启动 Django：`cd /app/backend && exec python manage.py runserver "127.0.0.1:${DJANGO_INTERNAL_PORT}" --noreload`。
8. L94-95：按序 `wait_for_port 管理服务:DJANGO_INTERNAL_PORT`、`wait_for_port 兼容性辅助服务:CF_BYPASS_INTERNAL_PORT`（1 s 轮询、检查 pid 存活，超时 `STARTUP_TIMEOUT_SECONDS=60`）。
9. L97-105：后台启动 gateway：`cd /app`，导出 `LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so`、`CURL_IMPERSONATE="${CURL_IMPERSONATE_PROFILE:-chrome146}"`、`CURL_IMPERSONATE_HEADERS=no`，`exec ./chatgpt-mirror-gateway`。
10. L107-108：`wait_for_port 主服务:PORT` → 打印 `三合一服务已启动，监听端口 ${PORT}`。
11. L110-116：`wait -n "${PIDS[@]}"`；任一子服务退出即打印 `检测到子服务退出，正在停止容器`，由 trap 对所有子进程 `kill -TERM` 并以该子进程状态码退出容器。

## 9. 工具版本记录

| 环节 | 工具/组件 | 版本 | 来源 |
|---|---|---|---|
| 镜像构建 | buildkit.dockerfile.v0 | —（history comment 标记） | S2 |
| 基础镜像生成 | debuerreotype | 0.17 | S2 |
| 基础系统 | Debian GNU/Linux 13 (trixie)，DEBIAN_VERSION_FULL=13.6 | 13.6 | S4（usr/lib/os-release、etc/debian_version） |
| Debian 快照源 | trixie=20260627T205430Z；security=20260403T003836Z | — | S2（ARG 记录） |
| Python | 3.12.14（源码构建；PYTHON_SHA256=5c8462af…548a…） | 3.12.14 | S2、S4 |
| Chromium 栈 | chromium / chromium-common / chromium-driver | 146.0.7680.177-1~deb13u1 | S2（ARG + apt 行） |
| Rust（gateway） | rustc | 1.88.0 (6b00bc388 2025-06-23) | S6 |
| pip 依赖 | 见 §6 crate 表、§7 两套 requirements（pin 版本） | — | S4、S6 |
| 后端构建元数据 | `uv.lock`、`pyproject.toml` 存在于层 13（文件未读取） | — | S4 |
| 分析工具（本报告） | bsdtar / libarchive | 3.7.7 | S8 |
| 分析工具（本报告） | PowerShell（Get-FileHash, SHA-256） | 7.6.3 | S8 |
| 导出/打包工具 | tar 内无版本记录；仅 index 注释 `io.containerd.image.name` 提示 containerd 参与导出 | — | S1 |

## 10. 验证记录

- 层内成员流式重取哈希 vs extracted 文件（`tar -xOf image.tar <层> | tar -xOf - <成员>` → SHA-256 流式计算）：

| 成员 | 流式 SHA-256 | extracted SHA-256 | 结果 |
|---|---|---|---|
| `app/chatgpt-mirror-gateway`（层 10） | 4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098 | 4FF1A3B9…AE098 | 一致 |
| `app/cfbypass/app.py`（层 14） | 7232f5b2f7a15022efe7d7ade26017911ab779ee796acd58f37c5bc30e9c552c | 7232F5B2…552C | 一致 |
| `app/cfbypass/proxy_relay.py`（层 15） | c99ac884cfe533001bea69417dd19b149a2eafd5adc8e3fe964502389ab6165b | C99AC884…165B | 一致 |
| `usr/local/bin/chatgpt-mirror-all-in-one`（层 16） | 3f7177e3e082b3f31262cf4fce0b5aa66157e5c24965c6f43c04dc0f2d745d0f | 3F7177E3…5D0F | 一致 |

- extracted 空文件：`config-c89121441e8f63217a95d2950c3da1d2820480c0d299aaf6e36be2202747ab9b` 为 0 B（SHA-256 = E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855，即空文件哈希）【S5】。
- 逐层条目计数（`tar -tf` 行数）：L1=3262、L2=553、L3=1828、L4=8、L5=5938、L6=2、L7=2、L8=16072、L9=1、L10=2、L11=21、L12=38、L13=78、L14=3、L15=3、L16=4、L17=11【S4】。
- 读取方式为流式只读（未解包落盘）；所有命令未修改 image.tar 与 extracted。

## 11. 未覆盖项与已知风险

- 层 1、5 未逐条枚举全部文件（仅条目计数与关键路径匹配）。
- 13 个 467 B legacy JSON blob 未逐一读取（按已验证样本推断同类，未验证）。
- gateway 依赖列表来自二进制内嵌字符串（registry 路径），非 Cargo.lock；不排除存在未在字符串中出现的依赖；未发现 git 依赖路径。
- L8 未逐包核对 site-packages 中各依赖的实际安装版本（以构建期 pin 的 requirements 为准）。
- 未做动态验证（未运行容器或二进制）；全程无网络访问。
- 范围外线索（未读取，仅记录位置）：仓库根存在 `SHA256SUMS`（76 B，可能与 image.tar 校验相关）、`docker-compose.yml`、`.env.example`、`使用说明.md`、`source/` 目录。
- `extracted/config-<config digest>` 为 0 B 空文件（疑似提取占位）；如需以 extracted 目录为准的 config 分析，应以 image.tar 内 13,528 B 的 blob 为准。

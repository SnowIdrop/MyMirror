# cfbypass：与网关共用同一套 Chrome146/Linux 声称身份的 Cloudflare 放行镜像。
#
# 版本锚点（改一处必须同步另外两处，步骤见 README「身份一致性」）：
#   1) 本文件的 DEBIAN_SNAPSHOT / DEBIAN_SECURITY_SNAPSHOT / CHROMIUM_VERSION；
#   2) 网关身份常量（Mirror/gateway-rust/src/server/identity.rs 的 USER_AGENT / FULL_VERSION）；
#   3) compose 的 CF_BYPASS_USER_AGENT（必须与网关 USER_AGENT 逐字符相同）。
# 证据：原版 all-in-one 镜像装的就是 Debian 包 chromium=146.0.7680.177-1~deb13u1
#（MirrorNiXiang/reverse/reports/02-cfbypass-analysis.md，镜像 config.history）。

FROM debian:trixie-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# snapshot.debian.org 的时间戳表示「该归档在这一刻的状态」。debian 与 debian-security
# 的时间戳各自独立，所以分开固定；chromium 146.0.7680.177-1~deb13u1 的 amd64 包在该
# 时刻属于 debian-security 的 trixie-security：
#   /archive/debian-security/20260403T003836Z/pool/updates/main/c/chromium/
# 升级 chromium 时（例如网关画像升级到更新主版本）：
#   1) 在 https://snapshot.debian.org/package/chromium/ 选中目标版本；
#   2) 用它页面里给出的 debian / debian-security 两个归档时间戳替换下面两个 ARG；
#   3) 改 CHROMIUM_VERSION，并同步网关身份常量与 compose 的 CF_BYPASS_USER_AGENT；
#   4) 在有 Docker 的机器上重建镜像并重跑 probe_identity.py 对照参照摘要。
ARG DEBIAN_SNAPSHOT=20260406T203439Z
ARG DEBIAN_SECURITY_SNAPSHOT=20260403T003836Z
ARG CHROMIUM_VERSION=146.0.7680.177-1~deb13u1

# 先按基础镜像自带源装 ca-certificates：后面的快照源走 https、pip 拉包都要用到它。
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# 之后所有 apt 包一律来自固定快照：主仓提供 chromium 的运行依赖，安全仓提供被钉死的本体。
# snapshot.debian.org 是冻结归档，各 Release 文件带的是当时签发的 Valid-Until，早已过期；
# 必须关掉有效期检查，否则 apt-get update 直接报
# "Release file ... is expired"（本镜像首次构建时即踩到）。
RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; \
    printf 'deb https://snapshot.debian.org/archive/debian/%s trixie main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list.d/snapshot.list; \
    printf 'deb https://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' "$DEBIAN_SECURITY_SNAPSHOT" >> /etc/apt/sources.list.d/snapshot.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends \
        "chromium=${CHROMIUM_VERSION}" \
        openssl \
        python3 \
        python3-pip \
        python3-venv; \
    rm -rf /var/lib/apt/lists/*

# Playwright 只当库用：app.py 与 probe_identity.py 都用 executable_path=/usr/bin/chromium
# 驱动系统 chromium，所以这里刻意不跑 `playwright install`（装了也不会被用到）。
# Debian 的 python3 是 externally-managed，依赖装进 venv；uvicorn/python 由 PATH 解析，
# 启动契约仍是 uvicorn app:app --host 0.0.0.0 --port 8000。
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

COPY cfbypass/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY cfbypass/app.py ./
COPY cfbypass/probe_identity.py ./

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

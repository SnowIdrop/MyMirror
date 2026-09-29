# -----------------------------------------------------------------------------
# Author  : MingTea
# File    : Dockerfile
# Summary : 候选人 gateway 的 Linux 镜像（源码构建，两阶段）。
#
# 为什么不是原配方的 `FROM scratch`：产物由 btls-sys 的 BoringSSL 静态库链接而成，
# 而 `btls-sys-0.5.6/build/main.rs:594-599` 对任何 unix/gnu 目标都固定
# `cargo:rustc-link-lib=stdc++`，实测 `ldd` 得到 libstdc++/libgcc_s/libm/libc。
# 因此运行阶段必须是 glibc 基础镜像；构建阶段还需要 cmake + clang + libclang-dev
# （btls-sys 用 cmake 从源码编 BoringSSL、用 bindgen 生成 FFI 绑定）。
#
# 两个阶段用同一个基础镜像，避免构建机与运行机的 glibc 版本不一致。
# 构建需要网络（拉 crates.io）；运行期不再依赖网络拉包。
#
# 刻意不写 `# syntax=docker/dockerfile:1`：该指令要求构建时从 Docker Hub 拉 frontend 镜像，
# 本机出网偶发 EOF 时构建会直接失败（2026-09-29 实测两次）；本文件只用经典指令，不需要它。
# -----------------------------------------------------------------------------

ARG DEBIAN_BASE=debian:trixie-slim
ARG RUST_VERSION=1.97.1

# -----------------------------------------------------------------------------
# 构建阶段
# -----------------------------------------------------------------------------
FROM ${DEBIAN_BASE} AS build

ARG RUST_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake clang libclang-dev pkg-config \
        curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# 工具链与源码树的实测版本一致（README「开发与验证」记的 rustc 1.97.1）。
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_VERSION}" \
    && rm -f /tmp/rustup-init.sh \
    && cargo --version \
    && rustc --version

WORKDIR /build

# 依赖层：先只放清单与占位源文件，让第三方依赖（含 BoringSSL 的一次性编译）
# 留在这一层缓存里；改业务代码不会让它们重编。
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && : > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

# 真实源码；`src/assets/` 与 `src/schema.sql` 由 include_str!/include_bytes! 编译期内联，
# 必须一起进上下文（见 .dockerignore）。
# 必须显式刷新时间戳：COPY 保留源文件原始 mtime，占位构建的指纹反而更新，
# Cargo 会据此认为源码没变而复用占位产物（实测踩到过——镜像里装的是 2.1 MB 的
# `fn main() {}`，容器起来后静默退出 0）。
COPY src ./src
RUN set -eux; \
    find src -type f -exec touch {} +; \
    cargo build --release --locked; \
    ls -l target/release/mirror-gateway; \
    # 占位产物守卫：真二进制 39 MB 级，且缺必需配置时必须非零退出。
    test "$(stat -c%s target/release/mirror-gateway)" -gt 5000000; \
    if ./target/release/mirror-gateway > /tmp/stub-check.log 2>&1; then \
        echo "构建产物缺少必需配置却成功退出，疑似占位二进制" >&2; \
        exit 1; \
    fi; \
    grep -Eq "GATEWAY_ADMIN_SECRET|CREDENTIAL_ENCRYPTION_KEY" /tmp/stub-check.log

# -----------------------------------------------------------------------------
# 运行阶段
# -----------------------------------------------------------------------------
FROM ${DEBIAN_BASE} AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# ca-certificates 供运维排查使用（上游 TLS 根证书已由 wreq 的 webpki-roots 内联）；
# libstdc++6/libgcc-s1 是 BoringSSL 产物的运行期依赖。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 与原版 all-in-one 的落点一致（`/app/chatgpt-mirror-gateway`），便于沿用同一套
# 入口脚本与卷布局；但数据库路径刻意分开，不复用旧网关的库。
COPY --from=build /build/target/release/mirror-gateway /app/chatgpt-mirror-gateway

ENV HOST=0.0.0.0 \
    PORT=40002 \
    DATABASE_PATH=/app/data/gateway-rust.db \
    GATEWAY_COMPAT_PROFILE=mirror \
    RUST_LOG=info

VOLUME ["/app/data"]

EXPOSE 40002

# 只做 TCP 连通性检查：镜像里没有 curl，用 bash 的 /dev/tcp 就够。
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=5 \
    CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${PORT:-40002}"]

ENTRYPOINT ["/app/chatgpt-mirror-gateway"]

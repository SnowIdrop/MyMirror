# 03 · gateway 二进制静态分析报告（chatgpt-mirror-gateway）

> 目标制品：`D:\Project\MirrorNiXiang\reverse\extracted\chatgpt-mirror-gateway`（23,252,912 B = 22.17 MiB）
> SHA-256：`4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098`；MD5：`6cb043621c8d0190c565ec12e2389c0d`
> 镜像来源：`image.tar` 层 `f58eb8fc7c2f`（23.3 MB）内 `app/chatgpt-mirror-gateway`（见 02 报告 §0.2 层清单）
> 取证方式：**纯静态读取**。自写 Python 解析脚本完成 ELF 结构解析、符号表解析与带偏移的字符串抽取；未运行 gateway、未联网、未访问 api.zxcbug.com、未发起任何探测
> 证据约定：偏移一律为**文件偏移**（十六进制，自文件起始）；“符号”指 `.symtab`/`.strtab` 中的名称（必要时附符号值 vaddr）；字符串结论均附偏移与原文
> 参照源码：`D:\Project\Mirror\chatgpt-mirror-build\gateway`（Python 参考实现，仅用于术语对照与差异提示；二进制结论以其自身证据为准）
> 报告日期：2026-09-22

## 摘要

- 制品是**单文件 Rust 可执行文件**：ELF 64-bit LSB **PIE**（`e_type=ET_DYN`）、x86-64、动态链接 glibc；`rustc 1.88.0 (6b00bc388 2025-06-23)` + `GCC 12.2.0 (Debian 12.2.0-14+deb12u1)` 构建（`.comment` @ `0x1283948`），**未 strip**（保留 `.symtab` 44,644 条符号、`.strtab` 2.76 MB）。
- 容器内角色：all-in-one 镜像的“主服务”。入口脚本 `/usr/local/bin/chatgpt-mirror-all-in-one:97-107` 在 `/app` 下执行 `exec ./chatgpt-mirror-gateway` 并设置 `LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so`、`CURL_IMPERSONATE=chrome146`，随后 `wait_for_port 主服务 $PORT`（默认 40002）。
- 自实现 crate `chatgpt_mirror_gateway`，模块：`api`(31 个函数)、`db`(59)、`proxy`(118)、`moderation`(10)、`config`(4)，另有根级 `main`/`build_router`/`init_tracing` 等（明细见 §6 与附录 A）。
- 依赖栈（100 个可取证 crate@版本，见 §5）：Web 层 `axum 0.7.9 + hyper 1.9.0 + h2 0.4.15 + tower-http 0.6.8 + tokio 1.53.1`；**双 HTTP 客户端栈** `wreq 6.0.0-rc.31`（BoringSSL/btls 指纹栈）+ `isahc 2.0.1 / curl 0.4.50`（动态 `libcurl.so.4`）；`rusqlite 0.31.0`（bundled sqlite3）；`tokio-tungstenite 0.24.0`（ChatGPT WebSocket 桥接）；`rustls 0.23.41 + ring 0.17.14`；`aes 0.8.4 + aead 0.5.2`（凭证加密）；`tracing-subscriber 0.3.23`（日志/链路）。
- 配置面（环境变量全部含偏移，见 §8）：`GATEWAY_ADMIN_SECRET`(0xd96422)、`DATABASE_PATH`(0xd96436)、`MIRROR_API_PREFIX`(0xd96443)、`ADMIN_UPSTREAM`(0xd96454)、`DJANGO_UPSTREAM`(0xd96462)、`CHATGPT_BASE_URL`(0xd94bd0)、`CHATGPT_CDN_BASE_URL`(0xd96484)、`CHATGPT_AB_BASE_URL`(0xd964b1)、`CF_BYPASS_URL`(0xd964da)、`CF_BYPASS_PROXY_SERVER`(0xd964e7)、`REQUEST_TIMEOUT_SECS`(0xd964fd)、`TRUSTED_PROXY_IPS`(0xd96511)、`HOST`(0xd94be4)/`PORT`(0xd94be8)。
- 关键安全观测：管理面鉴权函数 `require_gateway_admin`（符号 vaddr `0x1dd8a0`）、内部头 `x-gateway-secret`(0xd86020)；凭证落库为 **`enc:v1:` 加密格式**（0xd8c699）+ `CREDENTIAL_ENCRYPTION_KEY`(0xd8c676)；`mirror_token` 以 SHA-256 摘要存储（`mirror_token_hash` vaddr `0x248630`）；SSRF/代理防护函数族（`is_public_external_ip` vaddr `0x149d60`、`is_allowed_external_proxy_host` vaddr `0x149230` 等）；限流/配额/风控（`limit_per_minute` 0xd85ff0、`enforce_moderation_rate_limit`、`find_proof_of_work_difficulty` 等符号）。
- 行为比 Python 参考实现（`chatgpt-mirror-build/gateway`）**大得多**：Rust 版实现完整 ChatGPT 反向代理（`/backend-api/*`、`/backend-anon/*` 转发、WS 桥接、SSE 观测、会话配额、内容审核、Cloudflare bypass 兜底），Python 版仅有少量 `/api/*` + `/0x/*` 代理骨架。
- 未覆盖项：无 `.debug_*` 调试段（无源码行号）；依赖版本仅来自 panic location 字符串，可能存在无该字符串的依赖未列出；路由/字符串清单来自 `.rodata` 粘连字面量区 + 符号名，未用反汇编逐条确认 `Router::route` 绑定关系（本任务未要求 Ghidra）。

## 0. 制品、来源与证据方法

### 0.1 文件与哈希

| 项 | 值 |
| --- | --- |
| 路径 | `reverse/extracted/chatgpt-mirror-gateway` |
| 大小 | 23,252,912 B |
| sha256 | `4ff1a3b933dda0b9e0569d2f3ee9cf34993b0b3e21f734c4262a75b4c67ae098` |
| md5 | `6cb043621c8d0190c565ec12e2389c0d` |
| GNU build-id | `766a79ebdfde3621e23b5d3659ede41dc0ce856e`（`.note.gnu.build-id` @ `0x390`，desc 24 B） |
| `.comment` | @ `0x1283948`：`GCC: (Debian 12.2.0-14+deb12u1) 12.2.0` 与 `rustc version 1.88.0 (6b00bc388 2025-06-23)` |

### 0.2 容器内引用链（非二进制内容，作为背景证据）

- 入口脚本（`reverse/extracted/usr/local/bin/chatgpt-mirror-all-in-one`，行 97-107）：`cd /app` → `export LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so` → `export CURL_IMPERSONATE="${CURL_IMPERSONATE_PROFILE:-chrome146}"` → `exec ./chatgpt-mirror-gateway` → `wait_for_port "主服务" "$PORT" $gateway_pid`。
- 该脚本还把 `PORT` 默认 40002、`DJANGO_UPSTREAM` 默认 `http://127.0.0.1:8000`、`CF_BYPASS_SECRET` 默认复用 `GATEWAY_ADMIN_SECRET`（行 36-43）。
- 与二进制自身证据的呼应：`.text` 内硬编码 `Chrome/146.0.0.0` UA（0xd64be9）与 `146.0.7680.177`（0xd54aa1，与 02 报告 chromium 包版本一致）；字符串 `: curl-impersonate `（0xd64540）表明运行时会探测/记录 curl-impersonate；二进制的 `NEEDED libcurl.so.4`（0x23c4 附近的 dynstr）在 `LD_PRELOAD` 下解析到 curl-impersonate 库。
- **注意**：`CURL_IMPERSONATE` 变量名本身在二进制中查无（NOT FOUND）——它只被启动脚本用于 `curl-impersonate` 运行时行为，不是 gateway 读取的配置项。

### 0.3 方法与脚本（可复现性）

全部为本次会话临时脚本（位于 Windows `%TEMP%`，不写入本仓库）：

| 脚本 | 提取内容 |
| --- | --- |
| `mirror_gw_elf1.py` | ELF 头/程序头/34 个节区/`.dynamic`/`.comment`/notes/打包标记（PyInstaller/Go 排除项） |
| `mirror_gw_scan2.py` | cargo registry 路径 → 100 个 crate@版本；rustc std 路径统计；`.symtab` 全量解析（44,644 符号）与模块符号清单 |
| `mirror_gw_scan3.py` | 路由 / 环境变量 / SQL / 安全关键词的**带偏移**窗口扫描（每类去重取样） |
| `mirror_gw_scan4.py` | `.dynsym` 未定义导入与 `.gnu.version_r` 版本需求；逐 token 精确偏移；路由/配置区 token 化 |
| `mirror_gw_scan5.py` | C++ 导入明细、registry hash、`PORT/HOST` 配置区、`wreq/isahc` 上下文、模块清单导出、静态加密符号计数 |
| `mirror_gw_scan6.py` | sqlite3 符号计数、route 区全 token 偏移、config 区 dump、serde `struct ...` 名称、UA 身份串 |
| `mirror_gw_scan7.py` | `enc:v1:`/`CREDENTIAL_ENCRYPTION_KEY` 区域 dump、设置字段区 dump、`authorization/Bearer` 等 token |
| `mirror_gw_scan8.py` | `.interp`、关键符号的 vaddr/size、`/0x/user/*` 与杂项 token |
| `mirror_gw_scan9.py` | `subtle`/常量时间线索核查、cfbypass/pow 上下文 |
| `mirror_gw_scan10.py` | 依赖版本表（§5）生成 |

排除项（防误判）：`b'MEI\x0c\x0b\n\x0b\x0e'`、`PYZ-00.pyz`、`pyi-`、`pyoxidizer`、`PyInstaller`、`python3.12/3.13`、`libpython`、`go1.`、`Go build` 全部 **未命中** → 不是 PyInstaller/PyOxidizer/Go 产物，纯 Rust。

## 1. ELF 头与程序头

### 1.1 ELF 头（偏移 0x00-0x3F）

| 字段 | 值 | 说明 |
| --- | --- | --- |
| `e_ident` | `7f 45 4c 46 02 01 01 00 …` | ELF64、小端、ELF v1、OSABI=SysV(0)、ABI 版本 0 |
| `e_type` | `0x3` | ET_DYN（PIE 可执行文件） |
| `e_machine` | `0x3e` | x86-64 |
| `e_entry` | `0x10a8c0` | 入口（`_start`，符号 vaddr `0x10a8c0` 与之吻合） |
| `e_phoff` / `e_phnum` | `0x40` / 14 | 程序头表 |
| `e_shoff` / `e_shnum` | `0x162c730` / 34 | 节区头表 |
| `e_shentsize` / `e_shstrndx` | 64 / 33 | 节区头大小 / `.shstrtab` 索引 |

### 1.2 程序头摘要（14 项）

| # | 类型 | flags | 文件偏移 | vaddr | filesz | 说明 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | PHDR | R | 0x40 | 0x40 | 0x310 | |
| 1 | INTERP | R | 0x350 | 0x350 | 0x1c | 内容：`/lib64/ld-linux-x86-64.so.2` |
| 2 | LOAD | R | 0x0 | 0x0 | 0xdc3a8 | 只读段（ELF 头/notes/rela 等） |
| 3 | LOAD | RX | 0xdd000 | 0xdd000 | 0xc767b5 | 代码段（`.init`…`.text`…`.fini`） |
| 4 | LOAD | R | 0xd54000 | 0xd54000 | 0x490030 | 只读数据（`.rodata` 等） |
| 5 | LOAD | RW | 0x11e4578 | 0x11e5578 | 0x9f3d0 | 可写数据（`.tdata`…`.got/.data`） |
| 6 | DYNAMIC | RW | 0x1274ba0 | 0x1275ba0 | 0x240 | `.dynamic` |
| 7/8 | NOTE | R | 0x370 / 0x390 | 同 | 0x20 / 0x44 | GNU property / build-id |
| 9 | TLS | R | 0x11e4578 | 0x11e5578 | 0xe1 | `.tdata` |
| 10 | GNU_PROPERTY | R | 0x370 | 0x370 | 0x20 | note type 5：`desc=028000c00400000001000000…`（含 IBT/SHSTK 位，仅属性描述） |
| 11 | GNU_EH_FRAME | R | 0xfcd260 | 0xfcd260 | 0x33974 | 异常展开索引 |
| 12 | GNU_STACK | RW | 0x0 | 0x0 | 0x0 | **不可执行栈**（flags=6） |
| 13 | GNU_RELRO | R | 0x11e4578 | 0x11e5578 | 0x96a88 | RELRO 区间 |

安全属性小结：PIE + RELRO + `BIND_NOW`（`.dynamic` FLAGS=`0x8`、FLAGS_1=`0x8000001` ⊃ DF_1_NOW|DF_1_PIE）+ 不可执行栈。

## 2. 节区（34 项，重点节区）

| 节区 | 偏移 | 大小 | 备注 |
| --- | --- | --- | --- |
| `.interp` | 0x350 | 0x1c | `/lib64/ld-linux-x86-64.so.2` |
| `.note.gnu.build-id` | 0x390 | 0x24 | build-id 见 §0.1 |
| `.gnu.hash` / `.dynsym` / `.dynstr` / `.gnu.version(_r)` | 0x3d8 / 0x540 / 0x1968 / 0x255a / 0x2708 | — | 动态链接元数据 |
| `.rela.dyn` | 0x2908 | 0xd94d0 | 36,505 条重定位（`RELACOUNT=0x902f`） |
| `.rela.plt` | 0xdbdd8 | 0x5d0 | PLT 重定位 |
| `.text` | 0xdd540 | **0xc7626c**（≈12.46 MiB） | 全部代码 |
| `.rodata` | 0xd54000 | **0x279260**（≈2.47 MiB） | 字符串/常量集中区（本报告多数证据来源） |
| `.eh_frame_hdr` / `.eh_frame` / `.gcc_except_table` | 0xfcd260 / 0x1000bd8 / 0x11675f8 | 0x33974 / 0x166a20 / 0x7ca38 | 展开信息 |
| `.tdata` / `.tbss` | 0x11e4578 / — | 0xe1 / 0x220 | TLS（tokio 运行时等） |
| `.init_array` / `.fini_array` | 0x11e4660 / 0x11e4678 | 0x18 / 0x8 | 3 个初始化函数 |
| `.data.rel.ro` | 0x11e4680 | 0x90520 | 重定位后只读数据（vtable/&str 表） |
| `.dynamic` | 0x1274ba0 | 0x240 | 15 条有效 tag |
| `.got` / `.data` / `.bss` | 0x1274de0 / 0x127b000 / — | 0x6218 / 0x8948 / 0x20c8 | |
| `.comment` | 0x1283948 | 0x53 | 构建信息（§0.1） |
| **`.symtab`** | 0x12839a0 | **0x105960** | 44,644 条符号（未 strip，关键取证点） |
| **`.strtab`** | 0x1389300 | **0x2a32ed** | 符号名（含全部 mangled 函数名） |
| `.shstrtab` | 0x162c5ed | 0x13d | 节区名 |

**不存在**任何 `.debug_*` 段 → 无 DWARF 行号/类型信息；panic 与 tracing 的动态字符串（如 `src/api.rs`、`src/db.rs`、`src/moderation.rs`）成为主要源码结构线索。

## 3. 动态依赖与导入

### 3.1 `DT_NEEDED`（6 条）

| 依赖 | 证据 | 说明 |
| --- | --- | --- |
| `libstdc++.so.6` | `.dynamic strtab` | 少量 C++ 静态单元（见 3.2） |
| `libcurl.so.4` | 同上 | 由 `isahc/curl` 引入；运行时被 `LD_PRELOAD=libcurl-impersonate.so` 替换 |
| `libgcc_s.so.1` | 同上 | |
| `libm.so.6` | 同上 | |
| `libc.so.6` | 同上 | |
| `ld-linux-x86-64.so.2` | 同上 | |

### 3.2 版本需求（`.gnu.version_r`，偏移 0x2708）

- `ld-linux-x86-64.so.2 → GLIBC_2.3`
- `libm.so.6 → GLIBC_2.27, GLIBC_2.29`
- `libstdc++.so.6 → CXXABI_1.3.9, CXXABI_1.3`
- `libcurl.so.4 → CURL_OPENSSL_4`（对应 curl-impersonate 的 ABI 版本节点；字符串 `CURL_OPENSSL_4` 在 0x2440 也可直接读到）
- `libgcc_s.so.1 → GCC_3.3, GCC_4.2.0, GCC_3.0`
- `libc.so.6 → GLIBC_2.7/2.32/2.25/2.33/2.8/2.16/2.9/2.10/2.14/2.18/2.3/2.17/2.34/2.3.4/2.28/2.3.2/2.2.5`

### 3.3 导入符号统计（`.dynsym`）

- `.dynsym` 共 215 条，其中**未定义导入 214 条**（外部依赖面很小 → 大部分依赖静态编入）。
- `curl_*` 导入 19 条（示例：`curl_easy_init`、`curl_easy_setopt`、`curl_multi_add_handle`、`curl_easy_pause`、`curl_formfree`、`curl_global_init`）→ **libcurl 动态使用**（配合 `libcurl.so.4` + LD_PRELOAD）。
- **无 `sqlite3_*` 动态导入**；`sqlite3_*` 以 276 个**已定义符号**出现在 `.symtab`（内部 bundled sqlite3，`rusqlite 0.31.0` 默认 bundled 构建）。
- C/C++ ABI 相关导入共 8 条：`_ZdlPvm`、`_ZTVN10__cxxabiv117__class_type_infoE`、`_ZTVN10__cxxabiv120__si_class_type_infoE`（C++ mangled），以及 `__cxa_begin_catch`、`__cxa_end_catch`、`__cxa_rethrow`、`__cxa_thread_atexit_impl`、`__cxa_finalize` → 二进制内含**少量 C++ 静态对象**（与 §4.4 的 bssl 体系一致）。

## 4. 构建信息

### 4.1 编译器与工具链

- `.comment`（@0x1283948）：`GCC: (Debian 12.2.0-14+deb12u1) 12.2.0` + `rustc version 1.88.0 (6b00bc388 2025-06-23)`。
- 标准库源码路径：`/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc/library/...`（示例窗口 0xdb85a5、0xdbbc39、0xdbd5b0、0xddd0f4）；统计出现次数：`library/alloc` 262、`library/core` 120、`library/std` 95。
- 目标环境推断：`x86_64-unknown-linux-gnu`，glibc 最高引用 `GLIBC_2.34`（Debian 12/bookworm 水平的构建镜像）。

### 4.2 构建工作区

- 依赖路径前缀：`/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/<crate>-<version>/...`（`cargo/registry/src` 片段共出现 **1,610 次**），与官方 Rust Docker 镜像 `CARGO_HOME=/usr/local/cargo` 惯例一致。
- 恒定的 registry 目录哈希：`index.crates.io-1949cf8c6b5b557f`（全文唯一）。

### 4.3 未 strip 与 tracing

- 保留完整 `.symtab` 是本次静态分析能给出“模块符号清单”的直接原因（§6）。
- `tracing` 已启用：大量 `...::__CALLSITE::META::h…` / `...::__CALLSITE::h…` 符号（示例：`chatgpt_mirror_gateway::api::gateway_auth_session::…::__CALLSITE::META::h88bf35daf74be929`）。

### 4.4 静态加密栈痕迹（符号计数）

- `bssl`（BoringSSL C/C++，wreq 的 TLS 引擎）：**698** 个符号；`ring 0.17.14`：**256**；`rustls 0.23.41`：**267**。
- 说明：应用同时静态链接 BoringSSL（指纹模仿）与 rustls/ring（标准 TLS），与 §5 中 `wreq`/`btls`/`tokio-btls`、`tokio-rustls` 并存一致。

## 5. Rust 依赖版本（100 个可取证 crate@版本）

提取方法：扫描全部 `/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/<name>-<version>/` panic location 路径，取“首个出现”偏移。**版本集合以此为准**（无 panic 路径的依赖不会出现在此表）。

| crate | version | 首个出现偏移 |
| --- | --- | --- |
| `serde_json` | 1.0.149 | `0x00d557e4` |
| `tokio-socks` | 0.5.2 | `0x00d558f6` |
| `tokio-tungstenite` | 0.24.0 | `0x00d559a7` |
| `axum` | 0.7.9 | `0x00d6319a` |
| `http` | 1.4.0 | `0x00d63315` |
| `wreq` | 6.0.0-rc.31 | `0x00d63e18` |
| `tokio` | 1.53.1 | `0x00d63ea6` |
| `reqwest` | 0.12.28 | `0x00d64111` |
| `axum-core` | 0.4.5 | `0x00d899ca` |
| `sharded-slab` | 0.1.7 | `0x00d89c16` |
| `serde_core` | 1.0.228 | `0x00d89dbd` |
| `hyper` | 1.9.0 | `0x00d8a36a` |
| `tower-http` | 0.6.8 | `0x00d8aaa0` |
| `h2` | 0.4.15 | `0x00d8abeb` |
| `bytes` | 1.11.1 | `0x00d8acfb` |
| `isahc` | 2.0.1 | `0x00d8b705` |
| `http-body-util` | 0.1.5 | `0x00d8bbc1` |
| `url` | 2.5.8 | `0x00d8c2c8` |
| `rusqlite` | 0.31.0 | `0x00d8c3e8` |
| `slab` | 0.4.12 | `0x00d919e9` |
| `aead` | 0.5.2 | `0x00d91dc9` |
| `hyper-util` | 0.1.20 | `0x00d951f7` |
| `futures-util` | 0.3.34 | `0x00d95369` |
| `tokio-rustls` | 0.26.4 | `0x00d954ef` |
| `tracing-subscriber` | 0.3.23 | `0x00d95834` |
| `tungstenite` | 0.24.0 | `0x00d97641` |
| `serde` | 1.0.228 | `0x00d9aac0` |
| `rustls` | 0.23.41 | `0x00d9ce0d` |
| `matchit` | 0.7.3 | `0x00d9cf89` |
| `futures-channel` | 0.3.32 | `0x00d9d9c8` |
| `futures-lite` | 2.6.1 | `0x00d9ef09` |
| `tokio-util` | 0.7.18 | `0x00d9f8c7` |
| `tracing-core` | 0.1.36 | `0x00d9fb7d` |
| `base64` | 0.22.1 | `0x00da06a2` |
| `form_urlencoded` | 1.2.2 | `0x00da15dd` |
| `itoa` | 1.0.18 | `0x00da171b` |
| `dotenvy` | 0.15.7 | `0x00da1c19` |
| `zstd` | 0.13.3 | `0x00db1b3e` |
| `brotli` | 8.0.4 | `0x00db1bc5` |
| `flate2` | 1.1.9 | `0x00db1d29` |
| `brotli-decompressor` | 5.0.3 | `0x00db5450` |
| `zstd-safe` | 7.2.4 | `0x00db581f` |
| `http2` | 0.5.17 | `0x00db7b20` |
| `wreq-proto` | 0.2.5 | `0x00db7ff0` |
| `tower` | 0.5.3 | `0x00db891c` |
| `wreq-rt` | 0.2.2-rc.4 | `0x00db926b` |
| `smallvec` | 1.15.1 | `0x00dba69d` |
| `btls` | 0.5.6 | `0x00dba92e` |
| `async-compression` | 0.4.42 | `0x00dbb034` |
| `hashbrown` | 0.17.0 | `0x00ddd1f5` |
| `lru` | 0.18.2 | `0x00ddf151` |
| `tokio-btls` | 0.5.6 | `0x00de1280` |
| `indexmap` | 2.14.0 | `0x00e30d09` |
| `matchers` | 0.2.0 | `0x00e365b8` |
| `regex-automata` | 0.4.14 | `0x00e372a0` |
| `lazy_static` | 1.5.0 | `0x00e379b5` |
| `regex-syntax` | 0.8.10 | `0x00e38878` |
| `thread_local` | 1.1.9 | `0x00e3e4c1` |
| `tracing-log` | 0.2.0 | `0x00e3e6ad` |
| `once_cell` | 1.21.4 | `0x00e3e7e6` |
| `concurrent-queue` | 2.5.0 | `0x00e3ef69` |
| `event-listener` | 5.4.2 | `0x00e3fd4f` |
| `curl` | 0.4.50 | `0x00e3fdc4` |
| `sluice` | 0.6.0 | `0x00e4382a` |
| `polling` | 3.11.0 | `0x00e43a01` |
| `crossbeam-utils` | 0.8.22 | `0x00e44144` |
| `parking` | 2.2.1 | `0x00e44236` |
| `base64` | 0.13.1 | `0x00e443c5` |
| `rustls-pki-types` | 1.14.0 | `0x00e5ab43` |
| `iri-string` | 0.7.12 | `0x00e5f922` |
| `mime_guess` | 2.0.5 | `0x00e6024b` |
| `http-range-header` | 0.4.2 | `0x00e67345` |
| `compression-core` | 0.4.32 | `0x00e679d8` |
| `compression-codecs` | 0.4.38 | `0x00e67ae1` |
| `alloc-stdlib` | 0.2.4 | `0x00e67c64` |
| `miniz_oxide` | 0.8.9 | `0x00e71350` |
| `aes` | 0.8.4 | `0x00f31c70` |
| `idna` | 1.1.0 | `0x00f54ef0` |
| `icu_normalizer` | 2.2.0 | `0x00f5517c` |
| `icu_collections` | 2.2.0 | `0x00f55292` |
| `mime` | 0.3.17 | `0x00f582af` |
| `serde_path_to_error` | 0.1.20 | `0x00f5aba0` |
| `data-encoding` | 2.10.0 | `0x00f62170` |
| `rand` | 0.8.5 | `0x00f622af` |
| `rand_chacha` | 0.3.1 | `0x00f62480` |
| `ring` | 0.17.14 | `0x00f6c140` |
| `rustls-webpki` | 0.103.13 | `0x00f6c7d7` |
| `untrusted` | 0.9.0 | `0x00f6c873` |
| `utf-8` | 0.7.6 | `0x00f9d8f9` |
| `rand_core` | 0.6.4 | `0x00f9d9ad` |
| `percent-encoding` | 2.3.2 | `0x00fa115f` |
| `ipnet` | 2.12.0 | `0x00fa11ea` |
| `want` | 0.3.1 | `0x00fa4b05` |
| `httparse` | 1.10.1 | `0x00fa4ee8` |
| `atomic-waker` | 1.1.2 | `0x00fb6168` |
| `httpdate` | 1.0.3 | `0x00fb63de` |
| `futures-core` | 0.3.34 | `0x00fba871` |
| `signal-hook-registry` | 1.4.8 | `0x00fbe651` |
| `socket2` | 0.6.3 | `0x00fbe7de` |
| `parking_lot_core` | 0.9.12 | `0x00fbef64` |

分类速览（`wreq` 体系自证：“: wreq ” 0xd64507、`wreq::tls::TlsInfo` 符号等）：

- Web/异步：axum、axum-core、hyper、hyper-util、h2、http、http2、http-body-util、tower、tower-http、matchit、tokio、tokio-util、futures-*、async-compression。
- HTTP 客户端/指纹：wreq、wreq-proto、wreq-rt、btls、tokio-btls、isahc、curl（含 `libcurl.so.4`）。
- TLS/密码：rustls、rustls-webpki、rustls-pki-types、ring、tokio-rustls、aes、aead、rand、rand_core、rand_chacha、data-encoding、base64（0.13.1/0.22.1）。
- DB：rusqlite（bundled sqlite3）。
- WS：tokio-tungstenite、tungstenite、sluice。
- 可观测：tracing-subscriber、tracing-core、tracing-log、sharded-slab、thread_local、matchers、regex-*、once_cell、lazy_static。
- 其他：serde/serde_core/serde_json/serde_path_to_error、url/idna/percent-encoding/form_urlencoded/iri-string、zstd/zstd-safe/brotli/brotli-decompressor/flate2/miniz_oxide/compression-*、mime/mime_guess、ipnet、socket2、dotenvy、lru、smallvec、hashbrown、indexmap、itoa、utf-8、httpdate、httparse、want、http-range-header、alloc-stdlib、parking_lot_core、parking、event-listener、concurrent-queue、polling、crossbeam-utils、signal-hook-registry、atomic-waker、slab、memchr（符号）、subtle（见 §10.6 说明）。

## 6. 模块与符号清单

### 6.1 符号表统计（`.symtab` @0x12839a0，44,644 条）

| 类型 | 数量 |
| --- | --- |
| FUNC | 27,667 |
| NOTYPE | 9,224 |
| OBJECT | 6,782 |
| FILE | 941 |
| TLS | 30 |

### 6.2 `chatgpt_mirror_gateway` 自身符号

- 名称含 `chatgpt_mirror_gateway` 的符号（含闭包/CALLSITE）共 706 条，去重 615 条。
- 过滤闭包/CALLSITE 噪声后的**函数级清单：228 个**，按模块：`api` 31、`db` 59、`proxy` 118、`moderation` 10、`config` 4、根级 6（`main`、`build_router`、`init_tracing`、`has_gateway_admin_secret`、`insert_header_if_absent`、`apply_private_no_store_headers`）。完整清单见**附录 A**。

### 6.3 关键符号（名称 → 符号值 vaddr / 大小）

| 符号（demangled 形式） | vaddr | size | 证据 |
| --- | --- | --- | --- |
| `_start` | `0x10a8c0` | — | `.symtab`（与 `e_entry` 一致） |
| `chatgpt_mirror_gateway::main` | `0x3c5190` | — | `.symtab` 函数符号 |
| `chatgpt_mirror_gateway::build_router` | `0x3be440` | 0x289d | 路由注册主体 |
| `api::require_gateway_admin` | `0x1dd8a0` | 0x50f | 管理面鉴权 |
| `proxy::apply_chrome_146_network_identity` | `0x15c8b0` | 0x4b8 | Chrome146 指纹 |
| `proxy::is_allowed_external_proxy_host` | `0x149230` | 0x32b | 外部代理守卫 |
| `proxy::is_public_external_ip` | `0x149d60` | 0x244 | 公网 IP 校验 |
| `db::credential_key` | `0x2478a0` | 0x1f9 | 加密密钥派生 |
| `db::encrypt_secret` | `0x247aa0` | 0x5a5 | 凭证加密 |
| `db::decrypt_secret` | `0x248050` | 0x517 | 凭证解密 |
| `db::mirror_token_hash` | `0x248630` | 0xe2 | token 摘要 |
| `db::init_db` | `0x249540` | 0x2461 | 建表/迁移入口 |
| `subtle::black_box` | `0xbb4f30` | 0xb | 唯一 subtle 符号（见 §10.9） |

## 7. 关键路由与路径字符串（含偏移）

> 说明：以下 token 均位于 `.rodata` 的**粘连字面量区**（相邻 `&str` 字面量首尾相接，无分隔符）；偏移为“该 token 起始字节”的文件偏移，由逐 token 独立检索得到。注册关系由符号 `build_router`（`0x3be440`）与 axum 路由框架保证，逐条 `Router::route` 指令级确认未做（见 §12）。

### 7.1 本机管理/业务 API（`/api/*`，注册区 0xda0a00–0xda1120）

| 路由 | 偏移 | 备注 |
| --- | --- | --- |
| `/api/login` | `0xda0aec` | 同串紧随 `src/main.rs` 路径字面量 |
| `/api/logout` | `0xda0b01` | |
| `/api/user-work-mode` | `0xda0b0c` | |
| `/api/get-user-info` | `0xda0b1f` | |
| `/api/diagnose-chatgpt-auth` | `0xda0b31` | |
| `/api/get-mirror-token` | `0xda0b4b` | |
| `/api/get-user-use-count` | `0xda0b60` | |
| `/api/get-chatgpt-use-count` | `0xda0b77` | |
| `/api/conversation-statistics` | `0xda0b91` | |
| `/api/conversation-statistics/reset` | `0xda0bad` | 同一粘连串内第二条 |
| `/api/get-user-quota-usage` | `0xda0bcf` | |
| `/api/backup/export` | `0xda0be8` | |
| `/api/backup/restore` | `0xda0bfa` | |
| `/api/operations-overview` | `0xda0c0d` | |
| `/api/close-chatgpt-memory` | `0xda0c25` | |
| `/api/mirror-proxy-config` | `0xda0c3e` | |
| `/api/test-mirror-proxy-config` | `0xda0c56` | |
| `/api/custom-scripts` | `0xda0c73` | |
| `/api/political-moderation-config` | `0xda0c86`（另见 `0xd9f830`） | |
| `/api/political-moderation-config/test` | 同上粘连串（`…/test/api/blocked-paths…`） | |
| `/api/blocked-paths` | `0xda0cab` | |
| `/api/auth/session` | `0xda0cbd`；带尾斜杠变体 `0xda0cce` | |
| `/api/not-login` | `0xda0ee2`（另一处 `0xd87a46`） | |
| `/api/refresh-cfbypass` | `0xda0efc`（另一处 `0xd6b819`） | |
| `/api/pow-risk-stream` | `0xda0f11` | SSE 风险事件（符号 `gateway_pow_risk_stream`） |
| `/api/user-blocked-paths` | `0xda0f25`（另一处 `0xd6b82e`） | |
| `/api/livekit/` | `0xda0f6d` | 与 `ga/collect`、`vendor-batch/collect` 相邻 |

### 7.2 上游/传输路径匹配器（含通配符，注册区 0xda0f3c–0xda1120）

| 路径模式 | 偏移 | 备注 |
| --- | --- | --- |
| `/sentinel/20260423af3c/sdk.js` | `0xda0f3c`（token `0xda0f3d`） | ChatGPT sentinel SDK 路径 |
| `/v1/chat/completions` | `0xda0f59` | 兼容 OpenAI 风格上游 |
| `/ga/collect` | `0xda0f79`（另一处 `0xd6d42b`） | |
| `/vendor-batch/collect` | `0xda0f84` | |
| `/ws-chatgpt` | `0xda0f99` | WS 桥接（符号 `bridge_chatgpt_ws`） |
| `/ws-chatgpt/*path` | `0xda0fa4` | |
| `/cdn-cgi/challenge-platform/*path` | `0xda0fb5` | Cloudflare 挑战路径 |
| `/cdn-cgi/*path` | `0xda0fd6` | |
| `/ces/v1/projects/oai/settings` | `0xda0fe4` | |
| `/ces/v1/rgstr` | `0xda1001` | |
| `/ces/statsc/flush` | `0xda101b` | |
| `/ces/*path` | `0xda102c` | |
| `/realtime` / `/realtime/*path` | `0xda1036` / `0xda103f` | |
| `/backend-api/estuary/*path` | `0xda1063` | estuary 内容重写（符号 `absolutize_estuary_content_urls`） |
| `/backend-anon/*path` | `0xda107d` | 匿名通道 |
| `/backend-api/*path` | `0xda1090` | 已登录通道 |
| `/0x/*path` | `0xda10a5` | 管理上游（`/0x/` 另一处 `0xd546e0`） |
| `/admin` / `/admin/` / `/admin/*path` | 粘连窗口 `0xda10ae`–`0xda10c4` | 管理 UI |
| `static` / `static/index.html` | `0xda10cd` | 内嵌前端入口 |
| `/chat/*path` | `0xda10ee` | |
| `/static` | `0xda10f9`（另一处 `0xda1106`） | 静态资源 |

### 7.3 ChatGPT 业务子路径（代理内匹配，注册区 0xda0ce0–0xda0ef0）

| 路径 | 偏移 |
| --- | --- |
| `/apps/sources_dropdown/backend-anon` | `0xda0ce0` |
| `/apps/sources_dropdown/backend-api` | `0xda0d03` |
| `/gizmos/snorlax/sidebar/backend-api`（含 anon 变体） | `0xda0d5f` 起 |
| `/pins/backend-api`（含 anon 变体） | `0xda0da6` 起 |
| `/feed/entrypoint/backend-api`、`/feed/mixed/*` | `0xda0dc9` 起 |
| `/beacons/home/backend-anon`、`/beacons/home/backend-api` | `0xda0e4a` 起 |
| `/amphora/notifications/backend-api` | `0xda0e64` 起 |
| `/tasks/backend-api` | `0xda0ea9` 起 |
| `/user_surveys/active` | `0xda0ece` |
| `/auth/logout` | `0xda0ef0` |

### 7.4 cfbypass 调用路径（跨组件）

- `/cloudflare5s/bypass-v1`：`0xd84ec8`、`0xd88ee0`、`0xd9d4c4`（三处，均在 “cfbypass” 字样邻近，0xd84ec8 窗口为 `/cloudflare5s/bypass-v1cfbypass `）。

## 8. 环境变量（配置面）

| 变量名 | 偏移 | 备注 |
| --- | --- | --- |
| `GATEWAY_ADMIN_SECRET` | `0xd96422` | 管理密钥；与入口脚本行 26/43、Python 版同名 |
| `DATABASE_PATH` | `0xd96436` | SQLite 文件路径（Python 参考版用 `DATABASE_URL`，二进制中 **NOT FOUND**） |
| `MIRROR_API_PREFIX` | `0xd96443` | 本机 API 挂载前缀 |
| `ADMIN_UPSTREAM` | `0xd96454`（另见 `0xd6470e`） | 管理上游基址 |
| `DJANGO_UPSTREAM` | `0xd96462`（另见 `0xd64740`） | Django 上游基址 |
| `CHATGPT_BASE_URL` | `0xd94bd0` | ChatGPT 主站基址 |
| `CHATGPT_CDN_BASE_URL` | `0xd96484` | |
| `CHATGPT_AB_BASE_URL` | `0xd964b1` | A/B 端点基址 |
| `CF_BYPASS_URL` | `0xd964da` | |
| `CF_BYPASS_PROXY_SERVER` | `0xd964e7` | cfbypass 请求代理 |
| `REQUEST_TIMEOUT_SECS` | `0xd964fd` | |
| `TRUSTED_PROXY_IPS` | `0xd96511` | 信任代理来源（对应 `config::parse_ip_list` 符号） |
| `HOST` / `PORT` | `0xd94be4` / `0xd94be8` | 监听地址/端口（短 token；与 0xd96649 的 `: gateway listening on http://` 日志字符串呼应） |

上述 11 个长名变量集中在 `0xd96422–0xd96524`（`config` 模块处理，符号 `config::Settings::from_env`、`parse_url_or_default`、`parse_optional_url`）；`HOST/PORT/CHATGPT_BASE_URL` 位于 `0xd94bd0–0xd94be8` 的配置字符串区。注意：`DATABASE_URL`、`GATEWAY_CONNECT_TIMEOUT_SECONDS`、`GATEWAY_READ_TIMEOUT_SECONDS`（Python 参考实现的变量）在二进制中均 NOT FOUND。

## 9. 数据库（SQLite / rusqlite）

- 引擎：`rusqlite 0.31.0` **bundled sqlite3**（`.symtab` 内 276 个 `sqlite3_*` 定义符号；`.dynsym` 无 sqlite 导入）；库文件路径来自 `DATABASE_PATH`（`0xd96436`）。
- 业务表（`CREATE TABLE IF NOT EXISTS` 语句偏移）：

| 表 | DDL 偏移 | 目的（由列名/SQL 推断） |
| --- | --- | --- |
| `chatgpt_accounts` | `0xd8c917` | ChatGPT 账号/凭证 |
| `visit_logs` | `0xd8cb08` | 用量/访问日志（`log_type='proxy'` 计入配额） |
| `gateway_sessions` | `0xd8cc32` | 会话（user_name、mirror_token、quota、proxy_node_id…） |
| `gateway_settings` | `0xd8cf7b` | KV 设置（见下） |
| `conversation_owners` | `0xd8d01f` | 会话归属 |
| `project_owners` | `0xd8d1ef` | 项目归属 |
| `conversation_statistics` | `0xd8d3a6` | 会话统计 |
| `conversation_model_statistics` | `0xd8d623` | 模型维度统计 |

- 设置键（`gateway_settings.key`）：`custom_scripts`(`0xd8dc73`)、`political_moderation`(`0xd8dda3`)、`blocked_paths`(`0xd8e0b7`)、`mirror_proxy`(`0xd8d984`)。
- 迁移（0xd9112c–0xd912a1）：`PRAGMA table_info(gateway_sessions)`、`ALTER TABLE … ADD COLUMN session_token / extra_cookies / login_mode / force_chat_mode / proxy_node_id / daily_quota / monthly_quota`；对应符号 `ensure_gateway_sessions_quota_columns`、`ensure_gateway_sessions_force_chat_mode_column`、`ensure_gateway_sessions_proxy_node_id_column`、`migrate_sensitive_rows`。
- 关键 SQL 样本（偏移 + 摘录）：
  - `0xd8d899`：`SELECT id, access_token, session_token, extra_cookies, mirror_token FROM gateway_sessions…`
  - `0xd8e17c`：`INSERT INTO gateway_sessions (…`（字段含 access_token/session_token/extra_cookies/mirror_token…）
  - `0xd8e964`/`0xd8eac8`/`0xd8eb87`：`SELECT DISTINCT user_name`、`SELECT COUNT(DISTINCT user_name)…`
  - `0xd8f684`：`… WHERE user_name = ? … chatgpt_username = ? OR wreq`（transport 取值旁证，见 §5 注）
  - `0xd8f772` / `0xd8f817`：`SELECT COUNT(*) FROM visit_logs WHERE username = ?1 AND log_type = 'proxy' AND created_at >= CAST(strftime('%s','now',?2) AS INTEGER)`（配额周期统计）
  - `0xd8ff3b`–`0xd9008c`：restore 流程的 `DELETE FROM conversation_model_statistics / conversation_statistics / conversation_owners / project_owners / gateway_sessions / visit_logs / chatgpt_accounts / gateway_settings;` 序列
  - `0xd908d4`：`INSERT INTO gateway_settings … ON CONFLICT(key) DO UPDATE`
  - `0xd90c60`：`INSERT INTO visit_logs …`；`0xd90e1b`：`INSERT INTO conversation_statistics …`；`0xd9102c`：`INSERT INTO conversation_model_statistics …`
- 与 Python 参考的差异点：表名 `settings`→`gateway_settings`；会话表显著扩展（`login_mode`/`isolated_session`/`limits`/`daily_quota`/`monthly_quota`/`proxy_node_id`/`force_chat_mode`）。

## 10. 安全相关字符串与符号

### 10.1 管理面鉴权

- `api::require_gateway_admin`（vaddr `0x1dd8a0`，size 0x50f）；`has_gateway_admin_secret`（根级符号）。
- 头/凭证字符串：`Authorization`（`0xd64cf2`、`0xd8506d`、`0xd888a5`）、`Bearer`（`0xd64c22`、`0xd8841e`、`0xd9b2ec`）、`x-gateway-secret`（`0xd86020`）、`x-mirror-token`（`0xd6466b`）。
- `x-gateway-secret` 所在粘连区（`0xd85fb0` 起）同时含 `isolated_session`、`chatgpt_username`、`trusted_cdn_sources`(`0xd876c6`)、`limit_per_minute`(`0xd85ff0`)、`connector_search`(`0xd86000`)、`workspace_search`(`0xd86010`) → 属“设置字段/头部名”区域，用于管理面或内部调用鉴权。

### 10.2 凭证加密

- 加密容器前缀 **`enc:v1:`**（`0xd8c699`）+ base64url 字母表（`0xd8c6ac`：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`）。
- 密钥来源：`CREDENTIAL_ENCRYPTION_KEY`（`0xd8c624`、`0xd8c63d`、`0xd8c676`）；`sha256:` 前缀出现在 `0xd8c87c`（密钥派生/指纹格式）。
- 实现符号：`db::credential_key`(`0x2478a0`)、`db::encrypt_secret`(`0x247aa0`)、`db::decrypt_secret`(`0x248050`)、`db::migrate_sensitive_rows`（存量明文迁移）；依赖 `aes 0.8.4`+`aead 0.5.2`。

### 10.3 token 摘要

- `db::mirror_token_hash`（`0x248630`）；`api::token_fingerprint`（符号）；`mirror_token` 字面量多处（`0xd6465f`、`0xd87abf`、`0xd87c56`、`0xd8bf50`）。

### 10.4 反 SSRF / 代理守卫

- `proxy::is_public_external_ip`(`0x149d60`)、`proxy::is_allowed_external_proxy_host`(`0x149230`)、`validate_mirror_proxy_url`、`redact_proxy_url`、`sanitized_proxy_url`、`sanitized_proxy_config`（符号）。
- 代理协议面：`socks5://`（`0xd6469a`）、`socks5h://`（`0xd646a6`）；`TRUSTED_PROXY_IPS`（`0xd96511`）；`trusted_cdn_sources`（`0xd876c6`）。

### 10.5 响应头/Cookie 安全

- CSP 样例：`sandbox; default-src 'none'; img-src data: https:; media-src https:; font-src data: https:; style-src 'unsafe-inline' https:; base-uri 'none'; form-action 'none'; frame-ancestors …`（`0xd699b9` 窗口）。
- 头名：`content-security-policy`、`content-security-policy-report-only`（`0xd63a24` 窗口）、`strict-transport-security`（`0xd87100` 窗口，头名列表粘连区）。
- Cookie：`__Host-`(`0xd8c8ff`)、`__Secure-`(`0xd888e0`)、`__Secure-next-auth.session-token`(`0xd63870`/`0xd888e0`)、`next-auth.session-token`(`0xd63879`)。

### 10.6 浏览器指纹

- `proxy::apply_chrome_146_network_identity`（vaddr `0x15c8b0`，size 0x4b8）；默认 UA `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36`（`0xd64ba0` 窗口，`Chrome/146.0.0.0` 起始 `0xd64be9`）；`146.0.7680.177`（`0xd54aa1`，与镜像 chromium 包版本一致）。
- `oai-device-id`（`0xd64c07`、`0xd64c88`）；`sec-ch-ua`（`0xd68ea6` 起）；`browser_oai_device_id`/`server_oai_device_id`（符号）。
- 内嵌多种历史 Chrome UA 串（`0xda29d2` 起，Chrome/100–110 等）属 wreq/HTTP 栈字面量池，用于指纹多样性。

### 10.7 Cloudflare bypass 集成

- `/cloudflare5s/bypass-v1`（`0xd84ec8`、`0xd88ee0`、`0xd9d4c4`）；`CF_BYPASS_URL`（`0xd964da`）、`CF_BYPASS_PROXY_SERVER`（`0xd964e7`）；`is_safe_cfbypass_cookie_name`、`normalize_cfbypass_cookies`、`cfbypass_fallback_client`、`persist_cfbypass_cookies_for_request`（符号）；“cfbypass fallback client” 字面量（`0xd84f2a` 窗口，含 `cf_clearance`、`direct`、`proxy=` 取值）。

### 10.8 限流、配额与风控

- `limit_per_minute`（`0xd85ff0`）；`enforce_moderation_rate_limit`、`enforce_metered_request`、`is_metered_proxy_request`（符号）。
- Proof-of-Work 风险面：`/api/pow-risk-stream`（`0xda0f11`）、`PowRiskSnapshot`、`new_pow_risk_monitor`、`find_proof_of_work_difficulty`、`record_chat_requirements_pow_if_present`（符号）。
- 内容审核：`moderation` 模块 10 个函数（`contains_political_trigger`、`build_review_input`、`parse_decision`、`provider_endpoint` 等）；外部 provider 请求字段可见 `x-api-key`、`anthropic-version`、`max_output_tokens`（`0xd64316`、`0xd88950` 窗口）。

### 10.9 说明（避免过度解读）

- `subtle` crate 在符号表中仅见 `subtle::black_box`（`0xbb4f30`）一条，且未见 `ConstantTimeEq`/`constant_time` 相关符号（NOT FOUND）→ **本报告不对“常量时间比较”下结论**；`require_gateway_admin` 的具体比较实现需反汇编确认（未做）。

## 11. 与容器运行时及 Python 参考实现的对照

### 11.1 运行方式对照（入口脚本 vs 二进制）

| 项 | 入口脚本证据 | 二进制呼应 |
| --- | --- | --- |
| 主服务命令 | `exec ./chatgpt-mirror-gateway`（行 102） | 二进制 `main` @ `0x3c5190`、`build_router` @ `0x3be440` |
| HTTP 客户端替换 | `LD_PRELOAD=…/libcurl-impersonate.so`、`CURL_IMPERSONATE=chrome146`（行 99-100） | `NEEDED libcurl.so.4`（§3.1）、`: curl-impersonate `(`0xd64540`)、`Chrome/146.0.0.0`(0xd64be9) |
| 端口 | `PORT` 默认 40002（行 37） | 配置 token `PORT`(`0xd94be8`)、日志串 `: gateway listening on http://`(`0xd96649`) |
| 上游 | `DJANGO_UPSTREAM` 默认 127.0.0.1:8000（行 40） | `DJANGO_UPSTREAM`(`0xd96462`)、`/0x/*path`(`0xda10a5`)、`/0x/user/register`(`0xd546e0`) |
| cfbypass 密钥 | `CF_BYPASS_SECRET` 默认复用网关密钥（行 43） | `CF_BYPASS_URL`(`0xd964da`)、`/cloudflare5s/bypass-v1`(`0xd84ec8`) |

### 11.2 环境变量差异（Python 参考 `gateway/` vs 二进制）

| Python 版（chatgpt-mirror-build/gateway） | Rust 二进制 |
| --- | --- |
| `GATEWAY_ADMIN_SECRET` | `GATEWAY_ADMIN_SECRET`（同名，`0xd96422`） |
| `DJANGO_UPSTREAM` | `DJANGO_UPSTREAM`（`0xd96462`）+ `ADMIN_UPSTREAM`（`0xd96454`） |
| `DATABASE_URL`（`sqlite:///./gateway.db`） | `DATABASE_PATH`（`0xd96436`） |
| `GATEWAY_CONNECT_TIMEOUT_SECONDS` / `GATEWAY_READ_TIMEOUT_SECONDS` | `REQUEST_TIMEOUT_SECS`（`0xd964fd`，单一超时） |
| （无） | `MIRROR_API_PREFIX`、`CHATGPT_BASE_URL`、`CHATGPT_CDN_BASE_URL`、`CHATGPT_AB_BASE_URL`、`CF_BYPASS_URL`、`CF_BYPASS_PROXY_SERVER`、`TRUSTED_PROXY_IPS`、`HOST`、`PORT` |

### 11.3 功能面差异（结论）

- 镜像 all-in-one 内实际运行的是 **Rust 全功能网关**（§6–§10）；workspace 的 Python `gateway/`（FastAPI + SQLAlchemy，`main.py` 344 行）只是**另一套简化/兼容实现**（route-a compose 用），两者模块划分、表结构、API 集合均不同（例：Python 版 `/api/{path}` 兜底 501，Rust 二元 30+ 个 `/api/*` 端点 + ChatGPT 全站反代）。
- 因此对“gateway 行为”的判断应以本二进制（或运行时观测）为准，不应以 Python 版源码替代。

## 12. 局限与未覆盖

1. **无调试信息**：不存在 `.debug_*`，无法给出源码行号；panic/tracing 字面量只覆盖部分代码路径。
2. **依赖清单非完备**：§5 的 100 个版本来自 panic location 路径；存在无此类路径的依赖（例：符号表中见 `tracing_futures` 痕迹（`0x138e050` 窗口 `tracing_futures..Instrumented`），但无版本路径字符串；`memchr`、`subtle` 仅有符号）。实测更精确版本需 `cargo metadata` 级信息或 Ghidra/反汇编辅助。
3. **路由注册未做指令级确认**：§7 的“注册区”为 `.rodata` 粘连字面量池 + 符号推断；单条 `Router::route` 绑定未逐条反汇编验证（任务未要求 Ghidra）。
4. **未运行验证**：全部结论为静态证据；端口/TLS/上游连通性、WS 行为、加密实际算法参数（AES 模式、KDF 细节）均未动态验证。
5. **短 token 语义**：`HOST`/`PORT` 为 5/4 字符 token，来自配置字符串区，语义由上下文推断（`gateway listening on http://`），存在同名 token 误判的可能。
6. **时间线注意**：内嵌路径 `/sentinel/20260423af3c/sdk.js`（`0xda0f3c`）含 “2026-04-23” 字样，与 `.comment` 的 rustc 1.88.0（2025-06-23）日期存在跨度，提示源码/镜像晚于工具链发布时间，具体构建日期无法从 ELF 单独确定。

## 附录 A · `chatgpt_mirror_gateway` 模块函数全清单（228 项）

> 生成方法：`.symtab` 名称经 legacy Rust demangle（`_ZN…E` 分段）后过滤 `closure`/`CALLSITE` 噪声，取函数名（去 `::h<hash>`）；同模块去重。以下为完整清单（按模块分组；`deserialize`/`serialize`/`new`/`try_new` 等同名项可能来自不同 impl，模块内已合并显示）。

```
### api (31)
append_session_cookies
append_vary_header
apply_private_no_store_headers
build_apps_sources_dropdown_payload
build_cookie
build_sources_dropdown_payload
chatgpt_json_request_headers
clear_session_cookies
collect_plan_candidates_inner
cookie_value
decode_jwt_payload
deserialize
find_cookie_value
find_first_string_by_keys
infer_plan_type
insert_request_header
json_error
looks_like_netscape_cookie_file
merge_extra_cookies_with_cfbypass
normalize_login_mode
parse_chatgpt_auth_input
political_moderation_config_response
pow_risk_sse_event
rebuild_split_cookie_value
require_gateway_admin
retain_secret_if_blank
sanitize_auth_session_payload
sanitized_proxy_config
sanitized_proxy_url
supplemental_has_cloudflare_cookie
token_fingerprint

### db (59)
aggregate_use_count
applies_to_url
claim_conversation_owner
claim_project_owner
clear_stored_cloudflare_cookies
close_chatgpt_memory
conversation_belongs_to_user
conversation_belongs_to_user_c
conversation_statistics_detail
conversation_statistics_for_users
credential_key
decrypt_secret
default_moderation_mode
delete_gateway_session_by_token
delete_gateway_sessions_by_user
deserialize
encrypt_secret
ensure_conversation_statistic
ensure_gateway_sessions_force_chat_mode_column
ensure_gateway_sessions_proxy_node_id_column
ensure_gateway_sessions_quota_columns
export_backup
get_blocked_paths_config
get_chatgpt_credentials_for_user
get_custom_script_config
get_gateway_session_by_token
get_mirror_proxy_config
get_owned_conversation_ids
get_owned_project_ids
get_political_moderation_config
init_db
insert_visit_log
is_current_at
is_mirror_local
migrate_sensitive_rows
mirror_token_hash
new
normalize_blocked_path
now_ts
operations_overview
project_belongs_to_user
project_belongs_to_user_c
record_conversation_message
reset_conversation_statistics
restore_backup
save_blocked_paths_config
save_custom_script_config
save_gateway_session
save_mirror_proxy_config
save_political_moderation_config
scope_identity
serialize
try_new
update_conversation_title
update_gateway_session_extra_cookies
update_gateway_session_force_chat_mode_by_user
usage_count_current_period
usage_count_since
validate_blocked_path

### proxy (118)
absolutize_estuary_content_urls
account_client_pool_key_from_headers
append_vary_header
apply_chrome_146_network_identity
apply_private_no_store_headers
apply_static_asset_cache_headers
axum_ws_message_to_upstream
browser_oai_device_id
build_http_client
build_target_url
build_upstream_auth_cookie_header
build_upstream_http_client
bytes_stream
cf_cache_key_with_proxy
cfbypass_fallback_client
chatgpt_api_segments
claim_conversation_ids_from_json_response
classify_upstream
collect_conversation_ids
collect_conversation_titles
collect_project_ids_from_request
collect_requested_models
connector_fallback_response
content_media_type
conversation_id_from_collection_item
conversation_id_from_new_branch_response
conversation_ids_from_json_bytes
cookie_names_for_log
cookie_value
cookies_to_header
default_user_agent
deserialize
effective_mirror_proxy_url
enforce_conversation_owner
enforce_metered_request
enforce_moderation_rate_limit
enforce_project_owner
ensure_local_path
error_response
external_proxy_path_for_url
filter_conversation_collection_body
filter_conversation_collection_value
filter_project_collection_body
filter_project_collection_value
find_proof_of_work_difficulty
gateway_session_for_request
get_cached_session
has_static_asset_extension
header_value
html_attr_escape
html_response
insert_after_opening_tag
insert_before_closing_tag
insert_header_str
is_allowed_external_proxy_host
is_binary_content_type
is_browser_preference_cookie_name
is_chatgpt_document_request
is_cloudflare_challenge_path
is_cloudflare_challenge_response
is_conversation_api_path
is_conversation_collection_path
is_conversation_creation_path
is_conversation_new_branch_path
is_hop_header
is_images_openai_path
is_images_static_rsc_path
is_internal_fixed_upstream_url
is_mapbox_events_path
is_mapbox_path
is_mapbox_styles_path
is_metered_proxy_request
is_model_selection_request
is_primary_conversation_collection
is_project_creation_path
is_proxyable_upstream_target
is_public_external_ip
is_safe_cfbypass_cookie_name
is_temporary_conversation_id
log_chatgpt_document_response
mark_conversation_title_pending
matches_base_url
merge_cookie_headers
mirror_request_origin
moderation_response
new_cf_bypass_cache
new_mirror_proxy_runtime
new_pow_risk_monitor
normalize_cfbypass_cookies
normalize_cfbypass_target_url
normalize_conversation_id
normalize_mirror_proxy_config
normalize_project_id
normalize_proxy_fields
project_id_from_creation_response
project_id_from_path
project_id_from_response_value
project_id_key
project_ids_from_json_bytes
project_ids_from_url_query
redact_proxy_url
redirect_response_with_status
render_custom_script
request_uses_blocked_model
requested_model_from_body
rewrite_deep_research_connector_location
rewrite_location
rewrite_origin_prefix_to_local
same_cookie_scope
select_mirror_proxy_node
serialize
server_oai_device_cookie
server_oai_device_id
supplemental_has_next_auth_cookie
update_conversation_titles_from_body
upstream_ws_message_to_axum
validate_mirror_proxy_url
web_sandbox_asset_fallback_url

### moderation (10)
build_review_input
contains_political_trigger
extract_user_text
latest_role_text
normalize_base_url
normalize_config
parse_decision
provider_endpoint
provider_output_text
text_from_content

### config (4)
from_env
parse_ip_list
parse_optional_url
parse_url_or_default

### 根级 (6)
apply_private_no_store_headers
build_router
has_gateway_admin_secret
init_tracing
insert_header_if_absent
main
```

---

> 证据复核提示：本报告全部偏移可在制品上复现，例如 `python -c "d=open('chatgpt-mirror-gateway','rb').read(); print(hex(d.find(b'GATEWAY_ADMIN_SECRET')))"` → `0xd96422`。报告生成脚本为一次性临时产物（`%TEMP%\mirror_gw_scan*.py`），未写入任何项目目录。

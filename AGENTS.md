# 仓库约定（MiRebuild）

本文件是本仓库的项目级约定，叠加在更高优先级的通用 `AGENTS.md` 之上；两者冲突时以更高优先级为准。
本仓库只保存源码与重建参考：真实 `.env`、数据库、日志、原镜像与本地缓存不入库。

## 目标与边界

- 目标：保留 Mirror 聊天界面、Django 身份与 Vue 管理后台，用 Rust 替代闭源网关，
  最终交付可重新构建的 All-in-One 镜像。不是只发布一个独立网关。
- 本仓库**不代表**替换已经完成。不恢复已暂停的功能开发，不做生产切换，
  不做未经明确批准的真实账号写入。
- 已定的产品边界（不得擅自推翻）：个人小团体内部共享账号。计量、配额、限流、
  审核 provider 与 PoW/降智风险面**不是**验收缺口，不要把它们当待办反复提出。

## 先读什么

| 想知道什么 | 读哪里 |
|---|---|
| 项目范围与材料清单 | `README.md` |
| 候选网关的契约与已知差异 | `Mirror/gateway-rust/artifacts/phase1/source/PHASE1_CONTRACT.md`、同目录 `COMPATIBILITY.md` |
| 当前进度与验证状态 | `Mirror/gateway-rust/artifacts/phase1/STATUS.json` |
| 剩余工作 | `Mirror/gateway-rust/artifacts/phase1/source/NEXT_WORK.md` |
| 上游行为与闭源实现 | `MirrorNiXiang/reverse/reports/` |
| 原部署模板与重建缺口 | `MirrorNiXiang/rebuild-reference/README.md` |

## 目录权威性

| 路径 | 性质 |
|---|---|
| `Mirror/gateway-rust/artifacts/phase1/source/` | **当前候选** Rust 网关，唯一在改的实现；构建、测试与文档都指向这里 |
| `Mirror/gateway-rust/src/` | 原基线，**只读**；除明确要求外不得修改 |
| `Mirror/gateway-rust/artifacts/phase1/probe/` | 上游探针；凭据草稿与原始证据已被忽略 |
| `Mirror/gateway-rust/evidence/` | 入库证据（必须脱敏） |
| `Mirror/chatgpt-mirror-build/backend/` | Django 后端，保留维护 |
| `Mirror/chatgpt-mirror-build/frontend/` | Vue 管理后台 |
| `Mirror/chatgpt-mirror-build/cfbypass/` | Cloudflare 放行辅助服务 |
| `Mirror/chatgpt-mirror-build/gateway/` | 旧 Python 实验，仅供对照，不是目标实现 |
| `MirrorNiXiang/` | 原离线包模板、逆向报告与重建参考 |

默认改动范围是候选源码、Django、cfbypass 与对应文档。**不动前端、不改数据库 schema、
不新增环境变量**，除非用户明确要求。新分支用 `codex/` 前缀。

## 语言与风格

- 文档、注释与提交信息用中文；标识符沿用既有英文命名。
- 注释写「为什么」和实测依据，不写「是什么」。防御性判断必须带中文理由说明触发条件。
- 有意偏离上游行为时，必须写明理由与证据，不能只写结论。
- 不夹带无关的格式化、重命名或重构。

## 构建与验证

Rust 网关必须在 Linux 构建：`btls-sys` 用 cmake + bindgen 从源码编 BoringSSL，
Windows 原生缺 libclang 会直接失败。本机路径是 WSL Ubuntu。

```bash
cd <source>            # Mirror/gateway-rust/artifacts/phase1/source
export LIBCLANG_PATH=/usr/lib/llvm-21/lib
cargo test   --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
```

```bash
cd Mirror/chatgpt-mirror-build/backend && DJANGO_ENV=LOCAL python manage.py test
docker run --rm -v <cfbypass 目录>:/app -w /app mirror-cfbypass:phase1 python -m pytest -q
```

前端只做源码级检查：仓库不含 `node_modules`，不要声称前端构建通过。

**rsync 陷阱（踩过）**：把源码同步进 WSL 构建树时 rsync 会保留 Windows 侧 mtime，
cargo 可能复用旧二进制，让新代码「看起来通过了」。同步后必须先
`find src tests -type f -exec touch {} +` 再跑测试。

## 本地部署（预览）

```bash
cd Mirror/chatgpt-mirror-build
docker compose -p mirror-build --env-file .env -f docker-compose.rust-gateway.yml up -d
```

- **必须带 `-p mirror-build`**：否则 compose 会按目录名另起项目，去抢宿主 40002 端口。
- 端口：40002 镜像面、40003 管理界面、18000 Django、18001 cfbypass。
- 网关容器端口固定 40002，只有宿主端口可配。
- WSL 在无会话时会被回收，容器跟着停；需要常驻预览时保持一个 WSL 会话存活。

## 凭据与证据纪律

- 凭据草稿 `artifacts/phase1/probe/{access,session}-token.txt` 与 `probe/evidence/` 已在忽略列表，
  **绝不入库**。
- 日志、证据与提交信息中不得出现：令牌、Cookie、`Authorization`、上游响应正文、
  会话标题、镜像会话 token、上游账号标识。
- 证据只落：状态码、content-type、长度、sha256、字段名、头名（不含凭据类头值）。
- 上游 URL 携带的 `verify=` 等短时校验值，入库前必须脱敏。
- 探针不得复用现有用户身份登录：网关的登录交接会**轮换**该用户的镜像会话。
  用一次性用户，用完登出并删除。

## 传输身份（改动前必读）

- 身份的唯一事实来源是 `Mirror/gateway-rust/artifacts/phase1/source/src/server/identity.rs`：UA、`sec-ch-ua*` 全族、
  请求头顺序表与注入脚本的 JS 可见面都由它生成。禁止在其他文件硬编码这些取值。
- 改身份相关代码必须同时核对 `Mirror/gateway-rust/artifacts/phase1/source/tests/identity_fingerprint.rs`
  与 `Mirror/gateway-rust/evidence/` 下的参照证据；
  顺序表必须绑定实测证据，而不是凭形状推断。
- `accept-language` **属于**浏览器指纹（真 Chrome 由 `navigator.languages` 派生），
  转发跳跟随客户端，只在缺失时兜底；`oai-language` 是账号/应用界面语言，**不属于**指纹。
  这两份事实不得互相派生。
- 网关自己发起的请求（凭据换取、清单、诊断）、WS 握手与 cfbypass 一跳使用固定值：
  它们没有与之对应的页面 JS。
- 凭据与出口绑定保持 fail-closed；「生成类请求绝不重放」是硬约束。

## 文档同步义务

代码或行为有变动时，同一批更新下面三处，不要留到「下次一起写」：

- `Mirror/gateway-rust/artifacts/phase1/source/COMPATIBILITY.md`：与上游的差异及其理由
- `Mirror/gateway-rust/artifacts/phase1/source/NEXT_WORK.md`：剩余项
- `Mirror/gateway-rust/artifacts/phase1/STATUS.json`：改完必须用 JSON 解析器校验仍然有效

未实测的结论一律标注「未验证」，不得写成已通过。

## 提交

- 每完成一项就提交。提交信息说明改了什么、为什么改、怎么验证的。
- 不改写已推送的历史。
- 不把本地凭据、`.env`、数据库、`target/`、`node_modules/` 纳入提交。

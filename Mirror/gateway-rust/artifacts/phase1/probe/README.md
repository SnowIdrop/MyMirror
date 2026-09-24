# 真实上游探针（缺口 3 验收）

用真实的 ChatGPT **AccessToken** 跑一遍候选网关的已登录业务面，取得合成回环拿不到的证据：
真实上游对已分类读路径的状态码与字段形状、一次真实新建会话的归属登记、以及同账号第二个
镜像用户读该会话被拒。

## 先填凭据

打开 [access-token.txt](access-token.txt)，把这一行右侧的占位符替换成完整 AccessToken：

```text
access_token = PASTE_ACCESS_TOKEN_HERE
```

要点：

- 用 **AccessToken**（网页请求里的 `Bearer` 值），不要用 SessionToken。
- 该文件已在仓库 `.gitignore` 中，不会被提交；探针只读这一行，不打印、不写进证据、
  不放进命令行参数或环境变量。
- 没填完整时探针直接拒绝运行，不会发出任何请求。

## 运行

```powershell
cd D:\Project\ReMirror\MiRebuild\Mirror\gateway-rust\artifacts\phase1\source
cargo build --locked --offline

cd ..\probe
py -3 probe.py                      # 只读：7 条已分类读路径
py -3 probe.py --allow-real-write   # 再补：恰好一次真实新建会话 + 删除 + 第二用户读取
```

`--allow-real-write` 是刻意分开的一步：写请求在真实账号里不可撤销，先看只读结果再决定是否执行。
本机 PATH 上的 `python` 是 Microsoft Store 的占位程序，请用 `py -3`（或 Python 3.11+ 的绝对路径）。
探针只用标准库，不需要安装依赖。

## 探针做什么

1. 起一个本地 Django 授权桩（只回身份字段，不接触真实 Django），并以 `configured` 模式
   启动候选网关：`DATABASE_PATH=:memory:`、`GATEWAY_COMPAT_PROFILE=mirror`、无常驻改动。
2. 用 AccessToken 调 `/api/login` 换镜像会话。
3. 依次 GET：`/backend-api/me`、`accounts/check/v4-2023-04-27`、`conversations`、`projects`、
   `files/library/nodes`、`tasks`、`task_suggestions`。
4. 传 `--allow-real-write` 时：POST `/backend-api/f/conversation` 新建一次会话，出现会话 id
   即断开（不必等生成跑完），随后 DELETE `/backend-api/conversation/id/{id}`；再用第二个
   镜像用户 GET 同一会话，预期 404 `acl_not_found`。

## 探针不做什么

- 不写任何业务数据以外的内容：只有一次新建会话与它的一次删除，且新建在显式开关之后。
- 不重试：上游 4xx/5xx 按实际状态记录；生成类请求绝不重放。
- 不猜协议：新建会话的请求体形状没有实测证据，上游若拒绝就记录状态码后停止，
  不改用第二个端点、不改写请求体。

## 证据边界

证据写到 `evidence/probe-<时间戳>.json`（该目录已 gitignore），只包含：

状态码、内容类型、正文长度与 sha256、是否 HTML、是否被 Cloudflare 拦截、JSON 顶层字段名、
集合条目数与 `total`、本候选自己的错误码、耗时、网关日志行数、授权桩调用次数、令牌 sha256。

绝不包含：令牌、Cookie、镜像会话 token、上游响应正文、会话标题、会话 id 原文
（只存 sha256）。

拦截处理：命中 Cloudflare（`cf-mitigated: challenge`，或 403/502 加 HTML）时记录
`upstream_blocked` 并停止该次运行；未配置 `--cf-bypass-url` 时如实标注该路径没有真实证据，
不猜测上游协议。若本机有 cfbypass 服务，可用 `--cf-bypass-url http://127.0.0.1:<port>` 再跑一次，
网关会自行刷新一次并重放一次幂等 GET。

已知残留：若删除未返回 2xx，新建的会话可能仍留在账号里，请在网页端手动删除，且不要重复
运行本探针。

## 已观测结果（2026-09-24）

真实 AccessToken 下的第一轮结果与逐路径状态码见
[`../../evidence/gap3-real-probe-001/SUMMARY.md`](../../evidence/gap3-real-probe-001/SUMMARY.md)。
摘要：凭据换取、`/backend-api/me`、`accounts/check`、`conversations` 稳定 `200`；
`GET /projects` 恒为 `405`（上游该路径只有 `POST`）；`task_suggestions` 为 `404`；
`POST /f/conversation` 被上游以 JSON `403` 拒绝，未创建会话、未重试。
本机直连存在间歇性发送阶段失败（记为网关自身 `502`，非挑战形状），当时本地 cfbypass
（`127.0.0.1:18001`）未运行，因此建议先起 cfbypass 再带 `--cf-bypass-url` 复跑。

另注意：`conversations` 的 `items`/`total` 是 ACL 过滤后的视图，**不能**用来判断账号里
原本有多少会话。

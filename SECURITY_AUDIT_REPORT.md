# 安全审计报告 - GCLI2API

> **审计日期**：2026-07-21
> **审计范围**：仓库全部 Python 后端 + 前端静态资源 + 部署配置
> **审计触发原因**：服务受到 `/.git/config`、`/.env.swp`、`/admin`、`/graphql`、`/metrics`、`/proc/self/environ` 等批量扫描攻击
> **本报告仅记录本次未直接修复、建议后续跟进的中低危问题**
>
> 严重高危漏洞（时序侧信道、弱默认密码、路径穿越、弱密码写入）已在本次提交中直接修复并完成渗透测试，详见 `git log`。

---

## 已修复的严重问题（本次提交）

| 编号 | 漏洞 | 修复文件 | 验证 |
|------|------|----------|------|
| CRIT-1 | 密码比较使用 `==` / `!=`，存在时序侧信道（timing attack）可逐字节恢复密码 | `src/auth.py`、`src/utils.py`、`src/panel/logs.py` | 改为 `secrets.compare_digest` |
| CRIT-2 | 默认弱密码 `pwd` 在公网部署下 1 秒可被爆破 | `src/auth.py`、`src/utils.py`、`src/panel/logs.py` | 黑名单 `{pwd, "", password, admin, 123456, 12345678}`，命中即 503/401 |
| CRIT-3 | `/creds/{detail,download,errors,quota,fetch-email,verify-project,configure-preview,test}/{filename}` 等路由未做路径剥离，存在路径穿越风险（攻击面取决于后端实现） | `src/panel/creds.py` | 入口处统一 `os.path.basename(filename)` |
| CRIT-4 | `/config/save` 允许把密码改回 `pwd`/空等弱值，运维误操作后服务变裸奔 | `src/panel/config_routes.py` | 写入前弱密码校验，命中即 400 |

---

## 未修复问题清单（按严重度排序）

### M1. 登录返回的 token 即明文密码
- **严重度**：中危
- **位置**：`src/panel/auth.py:84`
  ```python
  return JSONResponse(content={"token": request.password, "message": "登录成功"})
  ```
- **风险**：
  - 控制台 token = 面板密码 = API 密码（共用 `PASSWORD` 时）
  - token 泄露（浏览器 devtools、日志、Referer、第三方 JS）= 密码泄露
  - token 永不过期，长期有效
  - 无法主动吊销（除非改密码）
- **建议**：
  - 登录成功后返回一个独立的服务端 session token（如 `secrets.token_urlsafe(32)` + Redis/存储后端记录）
  - token 设置有效期（如 12 小时）和 last-seen 心跳
  - 提供 `/auth/logout` 主动吊销 session
  - 区分面板 session token 与 API 密码，避免共享凭据

### M2. WebSocket 鉴权用 URL query 传 token
- **严重度**：中危
- **位置**：`src/panel/logs.py:102`
  ```python
  token = websocket.query_params.get("token")
  ```
- **风险**：
  - URL 中的 query 参数会被 Hypercorn access log 完整记录
    （扫描日志中已经能看到 `GET /logs/stream?token=xxx` 字样）
  - 浏览器历史、代理服务器日志、`Referer` 头都可能泄露
  - token 即密码（见 M1），泄露后果严重
- **建议**：
  - 改用 `Sec-WebSocket-Protocol` 子协议头携带 token，或
  - 先用 HTTP `POST /auth/ws-ticket` 换取一次性短时 ticket（30s 有效），
    再用 ticket 建立 WebSocket 连接
  - 至少在 access log 中对 `token=` 参数做脱敏

### M3. 部署模板内嵌弱默认密码
- **严重度**：中危
- **位置**：
  - `docker-compose.yml:12`：`PASSWORD=${PASSWORD:-pwd}`
  - `.env.example`：`API_PASSWORD=your_api_password` / `PANEL_PASSWORD=your_panel_password`
  - `config.py`：多处 `default="pwd"`
- **风险**：运维 `docker compose up -d` 时若忘记设置 `PASSWORD`，服务将以 `pwd` 启动。
  虽然本次 CRIT-2 修复使弱密码被运行时拒绝，但服务会持续返回 503/401，
  无法工作，影响可用性而非安全性。
- **建议**：
  - 把默认值改为空字符串，启动时若检测到空则 fail-fast 并打印醒目提示
  - 或在容器启动脚本中检查 `PASSWORD` 是否设置，未设置则拒绝启动
  - `docker-compose.yml` 移除 `:-pwd` 这种“有兜底”的写法

### M4. 面板密码 / API 密码以明文形式持久化到存储后端
- **严重度**：中危
- **位置**：
  - `src/storage/sqlite_manager.py` 的 `config` 表（`key`/`value` 两列，明文）
  - MongoDB / PostgreSQL 后端同理
  - `/config/save` 调用 `storage_adapter.set_config(key, value)` 直接落盘
- **风险**：
  - DB 文件（`creds/credentials.db`）泄露 = 密码泄露
  - MongoDB URI 泄露 → 远程读取 config 集合即得密码
- **建议**：
  - 优先方案：密码仅通过环境变量传入，永不写入存储；面板不提供改密码功能
  - 退让方案：存储前用 PBKDF2/Argon2 派生 hash（仅校验），或用对称加密 + 主密钥（来自环境变量）加密后落盘
  - 至少在 `/config/get` 返回中确认已脱敏（目前已有 `_mask_password`，OK）

### M5. 错误响应回显内部异常字符串
- **严重度**：低-中危
- **位置**：`src/panel/creds.py` 共 11 处、`src/panel/config_routes.py` 2 处
  ```python
  raise HTTPException(status_code=500, detail=str(e))
  ```
- **风险**：`str(e)` 可能包含文件路径、SQL 语句、库版本、堆栈片段，便于攻击者侦察
- **建议**：
  - 统一封装一个 `safe_error(detail="内部错误", log_exc=e)` 工具
  - 客户端只看到通用消息，详细信息仅写入服务端日志
  - 同时考虑给所有 5xx 加 `request_id` 便于排查

### M6. 暴力破解限流仅基于单 IP
- **严重度**：低-中危
- **位置**：`src/panel/auth.py:32-66`
  ```python
  _LOGIN_WINDOW_SEC = 300
  _LOGIN_MAX_FAILURES = 10
  _login_failures: dict[str, list[float]] = defaultdict(list)
  ```
- **风险**：
  - 仅按 `http_request.client.host` 限流，部署在反向代理后所有请求 IP 都是代理 IP，单点失败即全员被锁
  - 分布式爆破可绕过（每个 IP 9 次）
  - 仅 `/auth/login` 有限流，`/v1/*` API 端点的 `authenticate_flexible` 没有任何限流
- **建议**：
  - 信任 `X-Forwarded-For`（仅在显式配置 trusted proxy 时）
  - 增加全局失败计数（不只按 IP）+ 账号维度限流
  - 给 API 端点也加 rate limit（`slowapi` 或自实现）
  - 失败计数应持久化，否则重启即清零

### M7. CORS 通配源 + 仅依赖 allow_credentials=False
- **严重度**：低危
- **位置**：`web.py:135-141`
  ```python
  allow_origins=["*"],
  allow_credentials=False,
  ```
- **现状**：本次审计已确认 `allow_credentials=False`，浏览器不会跨域带 Cookie，
  CSRF 风险已基本消除。但 `allow_origins=["*"]` 仍允许任意站点 JS 调用本 API
  （若用户在浏览器中已通过其他方式持有 token，可被读取响应）。
- **建议**：
  - 若面向 CLI/服务端调用：保持通配源 + 关闭 credentials（现状即可）
  - 若同时服务于浏览器面板：把面板与 API 拆到不同路径，面板路径用白名单 origin
  - 在 README 文档中说明 CORS 策略选择的原因

### M8. HTTP 100% 明文，无 HTTPS 强制
- **严重度**：低危（取决于部署方式）
- **位置**：`web.py` Hypercorn 启动未配置 TLS
- **风险**：若用户直接把 `7861` 端口暴露公网，token 在网络中明文传输
- **建议**：
  - README 强烈建议在反向代理（Nginx/Caddy）后部署，由反代终结 TLS
  - 启动时若 `HOST=0.0.0.0` 且未配置证书，打印 warning 提示
  - 考虑增加 `FORCE_HTTPS` 环境变量，启用后 301 跳转到 https

### M9. 静态前端缺少安全响应头
- **严重度**：低危
- **位置**：`web.py` 未设置任何 `Content-Security-Policy`、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`
- **风险**：
  - 若将来面板被 XSS，缺乏 CSP 兜底
  - `X-Frame-Options: DENY` 缺失，存在被 iframe clickjacking 风险
- **建议**：
  - 加一个简单的 starlette middleware，给 HTML 响应统一注入：
    ```
    Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
    Referrer-Policy: strict-origin-when-cross-origin
    ```

### L1. 凭证文件目录无文件系统级保护
- **严重度**：低危（需要文件系统访问权限才能利用）
- **位置**：`creds/credentials.db`、`docker-compose.yml:41` 挂载 `./data/creds:/app/creds`
- **风险**：宿主机被入侵或备份泄露时，所有 Google OAuth凭证（access_token / refresh_token / client_id 等）以明文 JSON 落盘
- **建议**：
  - 落盘前对敏感字段（`refresh_token`、`private_key`）做对称加密
  - 主密钥通过环境变量传入（`CRED_ENC_KEY`）
  - 容器内 `creds/` 目录权限设为 `0700`，文件 `0600`

### L2. 请求体大小无上限
- **严重度**：低危
- **位置**：所有 POST 路由均依赖 FastAPI/Starlette 默认行为
- **风险**：超大 JSON body 可能导致内存耗尽 DoS
- **建议**：
  - 在 Hypercorn 启动参数中设置 `--max-request-body-size 10M`
  - 或在 starlette 层加 middleware 检查 `Content-Length`

### L3. `start.sh` 强制 `git reset --hard`
- **严重度**：低危（运维风险，非安全漏洞）
- **位置**：`start.sh:3`
  ```bash
  git reset --hard origin/$(git rev-parse --abbrev-ref HEAD)
  ```
- **风险**：本地未提交的修改（包括紧急安全补丁）会被静默丢弃
- **建议**：在脚本中增加提示或改用 `git stash` + 恢复

### L4. `web.py` 启动时仅告警但不拒绝弱密码
- **严重度**：信息级
- **位置**：`web.py:55-69`
- **现状**：启动时若检测到 `pwd` 会打 warning log，但不阻止启动。
  运行时鉴权已通过 CRIT-2 拒绝，所以这只是 UX 问题，不影响安全。
- **建议**：保持现状即可，或调整为 startup 阶段直接 `sys.exit(1)` 强制配置密码

---

## 验证记录

本次修复的 4 个严重漏洞已通过本地启动实例 + curl + websockets 客户端进行渗透测试，结果如下：

| 测试项 | 期望 | 实测 |
|--------|------|------|
| 弱密码 `pwd` 登录 | 拒绝 | 401 ✓ |
| 空密码登录 | 拒绝 | 401 ✓ |
| 弱密码 `admin`/`123456` 登录 | 拒绝 | 401 ✓ |
| 正确强密码登录 | 200 + token | 200 ✓ |
| 服务端弱密码时调用 `/creds/status` | 503 | 503 ✓ |
| 服务端弱密码时调用 `/v1/models` | 503 | 503 ✓ |
| 服务端弱密码时 WebSocket `/logs/stream` | 403 close | 403 ✓ |
| 路径穿越 `/creds/detail/..%2F..%2Fetc%2Fpasswd.json` | 不逃逸目录 | 404（basename 剥离后查无此凭证）✓ |
| `/config/save` 设置 `password=pwd` | 400 | 400 ✓ |
| `/config/save` 设置 `password=admin` | 400 | 400 ✓ |
| `/config/save` 设置 `password=123456` | 400 | 400 ✓ |
| `/config/save` 设置强密码 | 200 | 200 ✓ |
| `/config/save` placeholder `********` | 跳过更新 | 200 saved_config={} ✓ |
| 正常功能 `/config/get`、`/creds/status`、`/version/info`、`/` | 200 | 200 ✓ |

所有测试在 Python 3.13 + Hypercorn + SQLite 后端环境下通过，未引入功能回归。

---

## 后续建议优先级

1. **本周内**：M1（token=密码）、M2（WS token in URL）—— 直接关系到密码泄露面
2. **本月内**：M3（部署模板默认值）、M4（密码明文存储）、M5（错误信息脱敏）
3. **下个迭代**：M6（分布式限流）、M7（CORS 收紧）、M8/M9（HTTPS 与安全头）
4. **有空再做**：L1～L4

---

## 重要安全提醒

> 用户在最初请求中提供的 GitHub Personal Access Token `ghp_***`
> 已经在本次对话中作为明文出现，**请立刻在 GitHub Settings → Developer settings → Personal access tokens 中撤销该 token**。
> 即使本助手拒绝使用它，该 token 仍可能被日志、缓存、对话压缩等中间环节保留。
> 撤销后请生成新的 token，并通过环境变量或 secret manager 传递，**永远不要在对话/issue/PR 中粘贴**。

# 协议自动补号

Grok2API 内置协议注册自动补号：当 **Grok Web 可用账号** 低于阈值时，后台调度协议 sidecar 注册新号并导入号池。

## 架构

```
管理端 UI（设置 → 自动补号）
        │
        ▼
  Go 网关调度器（随机选出口 IP）
        │
        ▼
 Python sidecar :8091  ──► Cloud Temp Mail + ez-captcha + accounts.x.ai
        │
        ▼
  导入 Grok Web SSO（可选 Console）
```

## 随机 IP 轮训（统一出口池）

代理**只在管理端统一管理**，不要再单独维护 sidecar 的 `proxies.txt`。

1. 打开 **运行设置 → 出口代理**，添加多个节点，作用域选 **Grok Web**。
2. 每次补号从可用、未冷却的 Grok Web 节点中 **加密随机** 选一个 proxy。
3. 若池中无可用节点，才用「自动补号 → 应急备用代理」；**都为空则直连**（美国服务器不配代理即可）。
4. Sidecar **不会**再自动读取 `proxies.txt`，避免出现「文件里有代理、管理端池子是空的」双轨配置。
5. 补号进行中可点 **停止补号**，取消当前批次与进行中的 sidecar 请求。

补号状态里的「最近出口」会显示选中的节点名（如 `royadata-us-1`）。

### SOCKS5 供应商注意

部分住宅 SOCKS（如 royadata）会校验**你的出口源 IP 白名单**。若返回：

```text
access forbidden: <user> from <your-public-ip>
```

需要在供应商后台把本机/服务器公网 IP 加白，否则协议层会收到 HTTP 503（TLS 会表现为 WRONG_VERSION_NUMBER）。

## 跳过打码

`skip_captcha=true` 或清空打码 Key 时，会直接空 Turnstile 提交。

- 干净住宅 IP 有时能过（省打码费）
- 失败且错误含 turnstile/captcha 时，再开 ez-captcha

## 启用步骤

1. 启动 sidecar：

```bash
# Docker Compose（已包含 auto-register 服务）
docker compose up -d auto-register

# 或本地
cd services/auto_register
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

2. 打开管理端 **运行设置 → 出口代理**：
   - 添加节点，作用域 **Grok Web**
   - 填 SOCKS/HTTP 代理地址（支持带账号密码）
3. 打开 **运行设置 → 自动补号**：
   - 启用自动补号
   - 最低 / 目标可用 Web 账号
   - 邮箱：Cloud Temp Mail 或 YYDS（API Key / JWT）
   - ez-captcha（或勾选跳过打码）
   - Sidecar 地址：Compose 内用 `http://auto-register:8091`，本机用 `http://127.0.0.1:8091`
4. 可点 **立即补号一次** 验证（「最近出口」应出现 Grok Web 节点名；状态区会显示 **当前阶段** 与 **最近进度日志**）

## 邮箱域名

### YYDS Mail

公共共享域名经常被 xAI 拉黑，**收不到验证码**。请在 YYDS 控制台绑定并验证你自己的域名，然后在「邮箱域名」填入，例如：

```text
mail.your-domain.com
```

- 多个域名用逗号分隔；创建失败会按「域名选择策略」轮询/回退。
- 默认 **不允许** 公共域名；仅调试时可勾选「允许 YYDS 公共域名（不推荐）」。
- 未填域名时会优先 `prefer_owned`（账号下已验证的自有域名）。

### Cloud Temp Mail

- **自动读取域名**（默认开）：从 API 拉取可用域名，与手动列表合并。
- **随机子域/前缀**（默认开）：`enablePrefix`，降低撞号。
- **域名选择策略**：`rotate`（顺序 + 失败回退）/ `random` / `first`。
- 手动域名可留空（自动读取成功时）；关闭自动读取则必须填写域名。

## 进度跟踪

状态 API `/api/admin/v1/auto-register/status` 与管理端状态卡片包含：

| 字段 | 含义 |
|------|------|
| `phase` | 当前阶段（如 `create_mailbox`、`wait_email_code`、`solve_turnstile`、`done`） |
| `progress` | 一行可读摘要 |
| `recentLogs` | 最近 sidecar 进度行（含 `[phase:…]`） |
| `lastEmail` / `lastProxy` | 最近邮箱与出口节点 |
| `successCount` / `failureCount` | 累计成功/失败 |

运行中前端约 1.5s 刷新一次状态。

## 安全说明

- 邮箱 Admin Key 与打码 Key 加密存入运行设置库，API 只回传「已配置」。
- 注册成功后 SSO 写入 Web 号池；可选同步 Console 池。

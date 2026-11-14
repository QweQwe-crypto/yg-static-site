# yg-static-site

个人静态站点 + 访客真实 IP 访问日志。

- 站点首页：`/`（学籍信息采集系统 demo）
- 访问日志页：`/jilu.html`
- 靶机页：`/靶机网.html`

## 访问日志（server.js）

启动：

```bash
node server.js
# 或
PORT=8099 ADMIN_TOKEN='你的强密码' node server.js
```

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | 8099 | 监听端口（Render 会自动注入 `PORT`，一般 10000） |
| `ADMIN_TOKEN` | 123456 | 日志页后台 token，公网务必改 |
| `TRUST_PRIVATE` | 1 | 是否信任内网/回环地址作为反代来源 |
| `TRUSTED_PROXY` | 空 | 追加可信网段，逗号分隔，与 `trusted-proxy.txt` 叠加 |

### 接口

| 路径 | 说明 |
|---|---|
| `/api/myip` | 本次请求解析出的真实 IP 与来源 |
| `/api/headers` | 回显本次收到的全部请求头（排查反代链路用） |
| `/api/logs?token=` | 拉取全部访问日志 |
| `/api/visits?token=` | 同上（别名） |
| `/api/clear?token=` | 清空日志 |
| `/api/netinfo` | 本机出口公网 IP + 当前生效的可信网段 |

### 真实 IP 判定原理

请求链路：`访客 → Cloudflare → Render(内部负载均衡) → node`

1. 先看 TCP 直连来源（`socket.remoteAddress`）是否在可信代理名单
2. 不在名单 → 所有 `X-Forwarded-For` / `CF-Connecting-IP` 视为伪造，直接丢弃，用 socket 地址
3. 在名单 → 优先取 CDN 单值头（CF-Connecting-IP / True-Client-IP / X-Real-IP）
4. 没有单值头 → 从 XFF 链**自右向左**逐个剥离可信代理节点，剥到第一个不可信 IP 就是真实访客

所以 `X-Forwarded-For` 的**最左段**才是访客，最右段是离你最近的那一跳。

### trusted-proxy.txt

每行一个 IP 或 CIDR，`#` 为注释，改完重启生效。
当前已预置 Cloudflare 全部官方网段（IPv4 + IPv6）。

填多 → 把真实访客也当代理剥掉，拿不到 IP。
填少 → 访客可以自己伪造 XFF 伪装。

## Render 部署

**必须是 Web Service，不是 Static Site**（Static Site 不支持 Node 与 API 路由）。

- Build Command：留空
- Start Command：`node server.js`
- Health Check Path：`/api/myip`
- 环境变量：
  - `ADMIN_TOKEN` = 你的强密码（Dashboard 里填）
  - `TRUST_PRIVATE` = `1`（Render 内部负载均衡是内网地址，必须信任内网才能读到 XFF）
  - `NODE_VERSION` = `22`

Render 会自动注入 `PORT`，代码已监听 `0.0.0.0`。
免费实例会休眠，冷启动可能几秒到几十秒。

### 两种部署形态

**形态一（推荐）：同一个 Web Service 同时提供页面和 API**

把本仓库设为 Render Web Service，Start Command 为 `node server.js`。
此时：
- 首页 `/` -> index.html
- 日志页 `/jilu.html` -> 访问日志
- `/靶机网.html` -> 靶机页
- `/api/*` -> API

前端同源相对路径请求，无需配置任何东西。

**形态二：Static Site 提供页面 + 独立 Web Service 提供 API**

如果页面已经在 Render Static Site 上，需要另开一个 Web Service 跑 `node server.js`，
然后在 `jilu.html` 里把 `FALLBACK_BACKENDS` 的第一条改成那个 API 服务的域名：

```js
const FALLBACK_BACKENDS = [
  'https://你的-api-服务.onrender.com',
  ...
];
```

前端会依次探测：手动填写的地址 -> 当前页同源 -> FALLBACK_BACKENDS 列表，
第一个能访问 `/api/myip` 的即采用，探测结果自动回填到「服务地址」框。

## 排查

打开 `/api/headers` 可以看到本次收到的全部请求头与解析结果，用来确认每一层反代到底传了什么：

```bash
curl https://你的域名/api/headers
curl -H "X-Forwarded-For: 6.6.6.6" https://你的域名/api/headers
```

- `parsed.source` 显示真实 IP 的判定来源
- `parsed.trustedProxy` 表示直连来源是否在可信名单内
- 若真实 IP 恒为 `127.0.0.1` 或内网地址 -> 可信名单没覆盖你的反代，或 TRUST_PRIVATE 设成了 0

## 本地调试

```bash
node server.js
# 浏览器打开 http://127.0.0.1:8099/jilu.html
```

双击本地 html 文件（file://）时，在「服务地址」里填 `http://127.0.0.1:8099`。

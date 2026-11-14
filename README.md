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

## 代理后面的真实 IP 追踪（新增）

### 为什么需要
当访客通过 HTTP/SOCKS 代理访问时，CDN/反代只能看到代理出口 IP（XFF 最左段变成代理节点），
日志里看到的是「代理 IP」，不是访客本人。判定这类访问有两种手段：

| 手段 | 原理 | 能拿到什么 | 局限 |
|---|---|---|---|
| **WebRTC 泄漏探针**（已内置） | 页面注入脚本，用 STUN 建 ICE 候选，浏览器上报本机出口候选 IP | 代理后面的真实公网 IP（IPv4/IPv6） | 现代浏览器 WebRTC 已限制 mDNS 候选，可能拿到不到 IPv4 |
| **IP 归属判定**（已内置） | 查询 ASN / ISP / connection.type | 该 IP 是「住宅宽带」还是「机房/IDC」 | 只能定性，不能还原到人 |

> 注意：Cloudflare 的 `CF-Connecting-IP` 拿到的就是访客直接连接 CF 边缘时的 IP。
> 访客若使用代理软件，CF 看到的是代理节点 IP，此时 CF 头本身也是代理 IP，
> 所以**服务端层面无法凭 HTTP 头还原代理后的真实 IP**，必须靠浏览器侧探针（WebRTC）由访客自己上报。

### 新增接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/session` | GET | 发放会话 sid |
| `/api/leak` | POST | 接收浏览器上报的 WebRTC 泄漏 IP（body: `{sid, ip, type}`） |
| `/api/leak?sid=` | GET | 查询某 sid 的泄漏 IP |
| `/api/leaks?token=` | GET | 批量取全部 sid 的泄漏 IP（需 token） |
| `/api/geo?ip=` | GET | IP 归属 / 住宅-机房判定（需自备 IPQS_KEY 可增强代理识别） |

### 工作流程
1. 服务端为每次 HTML 页面访问分配 `sid`，并把 `window.__SID__` 注入页面
2. 注入的 `__iplog_leak__` 脚本用 STUN 收集 ICE 候选，POST 到 `/api/leak`
3. 日志条目携带 `sid`，前端按 sid 关联泄漏结果，在「代理后真实IP / 判定」列显示：
   - `WebRTC泄漏` + 真实 IP（与代理出口不同）
   - 或 IP 归属标签：`住宅宽带` / `机房/IDC` / `代理/代理池` / `VPN 出口`
4. 归属查询走 `ipwho.is`（免费）+ `ipinfo.io`（兜底），结果缓存 6 小时
   设置 `IPQS_KEY` 环境变量可启用 IPQualityScore，额外返回 proxy/hosting/vpn/tor/fraud_score

### 环境变量（新增）
| 变量 | 说明 |
|---|---|
| `IPQS_KEY` | 可选，ipqualityscore.com API key，用于更准的代理/机房识别与欺诈分 |

### 判定优先级
`server.js` 中 `parseIp()` 仍是三层：
1. 直连来源不在可信名单 → 全部 XFF/CF 头视为伪造，只用 socket 地址
2. 可信来源 → 优先取 CDN 单值头（`cf-connecting-ip` / `true-client-ip` / `x-real-ip` ...）
3. 无单值头 → XFF 链自右向左剥离可信代理节点，剥到第一个不可信 IP

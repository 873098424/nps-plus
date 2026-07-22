# NPS 跨节点中继（Relay）设计文档

> 适用版本：nps-plus（dev-1.0.0 分支）
> 状态：设计稿（待评审）
> 目标：在不改造既有单机模型的前提下，让「用户连接的 NPS」自动把流量转发到「真正持有目标客户端的 NPS」。

---

## 1. 背景与目标

### 1.1 现状（单机模型）

当前 nps 是**单机模型**：每台 nps 独立运行，各自只认**直连到自己**的 npc 客户端。所有路由的唯一收口点是 `bridge.SendLinkInfo`：

```42:46:bridge/link.go
	clientValue, ok := s.Client.Load(clientId)
	if !ok {
		err = fmt.Errorf("the client %d is not connect", clientId)
		return
	}
```

`s.Client` 是一个 `sync.Map`，**只保存连到本机的客户端**。任何 proxy 服务（`http.go` / `https.go` / `tcp.go` / `udp.go`）最终都通过 `proxy.BaseServer.DealClient` → `s.Bridge.SendLinkInfo(client.Id, link, ...)` 取得一条通往 npc 的隧道子连接。

### 1.2 问题

用户访问 `NPS1`，但其请求对应的 client 实际连接在 `NPS2` 上。当前 nps **没有任何机制**去发现「client 在 NPS2」并中转流量，只能报 `the client is not connect`。

### 1.3 目标

引入一个**独立的 relay 端口 + peer 级鉴权 + 轻量中继协议**，实现：

- 用户无感知地访问任意一台 nps；
- 该 nps 若本地没有目标 client，则通过 relay 把流量送给真正持有 client 的那台 nps；
- **不触碰客户端 vkey**，不污染 `s.Client` 注册表，不破坏既有单机逻辑。

---

## 2. 总体架构

```
           用户 / 浏览器
                 │
                 ▼
   ┌───────────────────────────┐          relay 子流（持久 mux/QUIC 会话）
   │  NPS1（入口，用户连接这里） │ ───────────────────────────────────────┐
   │  - 本地无 client X         │                                         │
   │  - 查注册表 → client X@NPS2│                                         ▼
   └───────────────────────────┘                          ┌───────────────────────────┐
                                                          │  NPS2（持有 client X）     │
                                                          │  - relay_port 监听         │
                                                          │  - 校验 peer_key / IP 白名单│
                                                          │  - 读中继头 → 本地 SendLink │
                                                          └───────────┬───────────────┘
                                                                      │ 本地隧道子连接
                                                                      ▼
                                                              ┌──────────────┐
                                                              │  npc（内网）  │
                                                              └──────────────┘
```

字节流路径：

```
用户 ↔ NPS1 proxy handler ↔ relay 子流 ↔ NPS2 relay handler ↔ npc 隧道 ↔ npc
```

- NPS1 侧：`DealClient` 拿到的是一条**指向 peer 的 relay 连接**，与本地隧道连接在使用上完全等价；
- NPS2 侧：relay handler 拿到的是一条**本地隧道连接**（对 npc 透明）；
- 两端都用现有 `conn.CopyWaitGroup` 做双向字节拷贝。

---

## 3. 核心设计原则

| 原则 | 说明 |
|------|------|
| **独立端口** | relay 走专用 `relay_port`，与 `bridge_*` 系列端口隔离，便于防火墙单独放通 peer 网段。 |
| **peer 级鉴权，不复用客户端 vkey** | NPS1↔NPS2 之间用独立的 `relay_key` / mTLS / IP 白名单鉴权。**中继头只传 `clientId`，绝不传 vkey**。 |
| **不注册假 client 节点** | 中继连接由独立的 relay handler 处理，不会调用 `GetIdByVerifyKey` / `NewClient`，不污染 `s.Client`。 |
| **clientId 从本地配置已知** | NPS1 从本地 host / tunnel 配置就能拿到 clientId（用户打到 NPS1 的域名 → host → clientId），无需知道客户端密钥。 |
| **单一收口点** | 只在 `bridge.SendLinkInfo` 增加「本机 miss → 查注册表 → 走 relay」分支，不动各 proxy 服务的既有逻辑。 |

---

## 4. 组件设计

### 4.1 注册表（归属发现）—— 独立子问题

决定「clientId 在哪台 nps」。提供两种实现，先静态后动态：

**MVP：静态配置（`relay_routes`）**

```ini
# nps.conf（NPS1 上配置）
relay_routes = 12:nps2.example.com:8028, 15:nps3.example.com:8028
```

格式：`clientId:peerHost:relayPort`，逗号分隔。NPS1 启动时解析成 `map[int]*PeerAddr`。

**演进：动态注册表（Redis / etcd）**

每台 nps 启动后，把「自己持有的 clientId 集合」上报到共享存储；NPS1 查询某个 clientId 的归属。适合弹性扩容，但需引入依赖，列为后续阶段。

> 无论哪种实现，注册表只回答「clientId → peer 地址」，与中继协议本身解耦。

### 4.2 Relay Server（NPS2 侧）

- 监听 `relay_port`（独立端口）；
- 接受连接后先做 **peer 鉴权**：校验 `relay_key`（或 mTLS 证书，或来源 IP 是否在 `relay_allow_ips`）；
- 鉴权失败立即关闭；
- 鉴权通过后，循环读取中继帧（见 4.4），每帧：
  1. 解析出 `clientId` + `Link` 字段；
  2. 调用**本机** `Bridge.SendLinkInfo(clientId, link, nil)` 拿到通往 npc 的隧道子连接；
  3. 用 `conn.CopyWaitGroup` 把这条隧道子连接与当前 relay 子流双向桥接；
  4. 任一侧关闭则清理两侧。

> 关键点：NPS2 完全复用既有 `SendLinkInfo`，对 npc 透明；relay 处理器**不**向 `s.Client` 写任何东西。

### 4.3 Relay Client（NPS1 侧）

- 启动时按 `relay_routes` 为每个 peer 建立**一条持久 mux/QUIC 会话**（借鉴 npc 连 bridge 的复用思路，见 `lib/mux`、`quic-go`）；
- 提供方法 `Relay(clientId int, link *conn.Link) (net.Conn, error)`：
  1. 在持久会话上 `NewConn()` / `OpenStream` 开一条子流；
  2. 写入中继头（`clientId` + 序列化 `Link`）；
  3. 返回这条子流作为「目标连接」给 `DealClient` 使用；
- 会话断开自动重连（复用现有 `AutoReconnection` 思路），重连期间对未命中本地且未建立会话的 client 直接返回错误。

### 4.4 中继协议帧（Relay Frame）

在 peer 会话的子流上，每条用户连接对应一个帧。建议帧格式：

```
+--------+-----------+----------+-----------+----------+----------+---------+-----------+
| magic  | clientId  | connType | crypt     | compress | localProxy| remoteAddr len + str | host len + str | payload...
+--------+-----------+----------+-----------+----------+----------+----------------------+----------------+-----------+
| 4B     | 4B/var    | 1B       | 1B        | 1B       | 1B       | 2B + N              | 2B + M         | 流数据    |
+--------+-----------+----------+-----------+----------+----------+----------------------+----------------+-----------+
```

字段来源即 `conn.Link`（`lib/conn/link.go`）：

```23:31:lib/conn/link.go
type Link struct {
	ConnType   string //连接类型
	Host       string //目标
	Crypt      bool   //加密
	Compress   bool
	LocalProxy bool
	RemoteAddr string
	Option     Options
}
```

NPS2 侧按帧还原出 `conn.NewLink(connType, host, crypt, compress, remoteAddr, localProxy, ...)`，无需关心上层是 HTTP/HTTPS/TCP。

### 4.5 `SendLinkInfo` 改造（核心集成点）

在 `bridge/link.go` 的 `SendLinkInfo` 中，本机 `s.Client.Load` 未命中时，尝试 relay：

```go
clientValue, ok := s.Client.Load(clientId)
if !ok {
    // 仅当注册表中显式配置了该 clientId 的归属时才尝试中继，
    // 否则退回原有 "not connect" 错误（不影响本地 ping / 健康检查）。
    if target, err := s.tryRelay(clientId, link, t); err == nil {
        return target, nil
    }
    err = fmt.Errorf("the client %d is not connect", clientId)
    return
}
```

`tryRelay` 逻辑：

1. 查注册表 `relayRouter.Lookup(clientId)`；
2. 命中 → 取对应 peer 的 RelayClient 会话；
3. 调 `peer.Relay(clientId, link)` 开子流、写中继头、返回 `net.Conn`；
4. 未命中 → 返回 error，上层继续走原有 `not connect` 分支。

> 这样改的好处：**proxy 各服务（`http.go`/`https.go`/`tcp.go`/`udp.go`）完全不用动**，它们仍调 `DealClient` → `SendLinkInfo`，由 bridge 内部决定是否中继。本地 ping / 健康检查调用 `SendLinkInfo` 时，因未配置 relay 路由，自然走原错误分支，互不干扰。

---

## 5. 配置项（`nps.conf`）

### NPS2（持有客户端的服务端）—— 开启 relay 监听

```ini
# 中继端口（独立，0 表示关闭）
relay_port=8028
# peer 间共享密钥（必填，替代客户端 vkey）
relay_key=xxxxxxxxxxxx
# 仅放通这些 peer 的来源 IP（逗号分隔，留空=不限制，强烈建议配置）
relay_allow_ips=10.0.0.2,10.0.0.3
# 可选：使用 mTLS 替代 relay_key（配置后优先于 relay_key）
# relay_tls_cert=conf/relay.pem
# relay_tls_key=conf/relay.key
# relay_tls_ca=conf/relay_ca.pem
```

### NPS1（入口服务端）—— 配置归属路由

```ini
# clientId -> peer 地址 映射（静态 MVP）
relay_routes=12:nps2.example.com:8028,15:nps3.example.com:8028
# 与 NPS2 一致的共享密钥
relay_key=xxxxxxxxxxxx
```

> `relay_key` 在 NPS1 / NPS2 两侧必须一致，且**与任何客户端 vkey 无关**。

---

## 6. 数据流时序（HTTP 为例）

```
用户          NPS1(proxy)        NPS1(relay client)      NPS2(relay server)      npc
 │  HTTP请求    │                     │                        │                  │
 │────────────▶│                     │                        │                  │
 │             │ host→clientId=12    │                        │                  │
 │             │ 本地 s.Client 无 12  │                        │                  │
 │             │ 查 relay_routes→NPS2 │                        │                  │
 │             │────────── 开子流 ────▶│ 中继头[12,link]        │                  │
 │             │                     │───────────────────────▶│                  │
 │             │                     │                        │ SendLinkInfo(12) │
 │             │                     │                        │─────────────────▶│
 │             │◀──── 双向字节拷贝（CopyWaitGroup）────────────│◀──── 隧道子连接 ───│
 │◀────────────│                     │                        │                  │
 │  HTTP响应    │                     │                        │                  │
```

---

## 7. 安全

| 风险 | 措施 |
|------|------|
| 开放中继（任何人借 NPS2 进任意内网） | peer 鉴权（`relay_key` / mTLS / IP 白名单）强制开启；未鉴权连接直接关闭。 |
| 泄露客户端 vkey | **中继头只带 clientId，不带 vkey**；NPS1 不需要、也不持有客户端密钥。 |
| 链路被窃听 | NPS1↔NPS2 中继会话强制 TLS（复用 bridge 已有的证书/指纹机制）。 |
| clientId 越权中继 | 可选 `relay_allow_clients` 白名单，限制某 peer 只能中继指定 clientId 集合。 |
| 重放攻击 | 中继会话复用现有 HMAC + replay 保护思路（参考 `bridge/handshake.go`）。 |

---

## 8. 各协议支持

| 协议 | 支持方式 | 备注 |
|------|----------|------|
| **HTTP** | relay 子流透传明文 HTTP 字节 | 最易，MVP 首选。 |
| **HTTPS（终止）** | NPS1 有证书则终止后发明文；无证书则用 `HttpsJustProxy` 式**裸 TLS 透传**到 NPS2 终止 | 对应此前讨论的透传模式。 |
| **TCP** | relay 子流透传原始字节 | 与 HTTP 同机制。 |
| **UDP** | NPS1 的 udp handler 将数据包按 `udp5` 帧封装进 relay 子流；NPS2 解帧后走本地 udp 隧道 | 列为后续阶段（需复用 `conn.HandleUdp5`）。 |

> 所有协议在 NPS1 侧对 proxy handler 而言都只是「一条 net.Conn」，由 `conn.CopyWaitGroup` 统一桥接，协议差异被屏蔽在帧外。

---

## 9. 流量 / 限额归属

既有 `CheckFlowAndConnNum`（`proxy/base.go:83`）和 `FlowAdd` 统计都记在**持有 npc 的那台 nps（NPS2）** 上。中继引入后：

- **流量统计**：NPS2 侧 relay handler 桥接时正常累计（它走的是本地 `SendLinkInfo` 路径），统计准确；
- **NPS1 侧**：因 client 非本地，`DealClient` 拿到的 relay 连接仍会触发 NPS1 的 `CheckFlowAndConnNum` / `FlowAdd`，导致**双端都计数**或**入口端误判限额**；
- **建议**：中继场景下，NPS1 侧跳过 client 级限额检查（仅做全局黑名单 / 连接数封顶），把额度归属交给 NPS2。需在 `DealClient` 增加「relay 模式」标志位。

---

## 10. 故障处理

| 场景 | 行为 |
|------|------|
| peer 会话断开 | RelayClient 自动重连；重连期间对应 client 的 relay 返回错误，proxy 侧回 `ConnectionFail`。 |
| NPS2 整体宕机 | NPS1 探测到会话不可达 → 快速失败，不卡连接（设合理超时，复用 `link.Option.Timeout`）。 |
| NPS2 上 client 离线 | NPS2 本地 `SendLinkInfo` 返回 `the client is offline`，relay 子流关闭，错误回传 NPS1 → 用户。 |
| relay 子流泄漏 | 两端均用 `conn.CopyWaitGroup` 的关闭语义，任一侧 EOF/错误即双向关闭并释放。 |

### 10.1 阶段 1 验证步骤（双 nps 部署）

> 阶段 1 已实现静态 `relay_routes` + JSON 中继头（`magic "NPRY"` + 一行 JSON `{"clientId":12,...}`），HTTP/TCP 端到端可用。以下步骤用于验证跨节点转发是否打通。

**NPS2（持有 client 的节点）** `conf/nps.conf`：

```ini
relay_port=8028
relay_key=sharedsecret
ip_verify=false          # 必须关闭：否则用户真实 IP 不在 NPS2 注册表，relay 流量会被拒
bridge_port=8024
```

正常注册 client（假设 `clientId=12`），npc 连到 NPS2。

**NPS1（公网入口节点）** `conf/nps.conf`：

```ini
relay_key=sharedsecret   # 与 NPS2 必须完全一致
relay_routes=12:NPS2_IP:8028
ip_verify=false
```

在 NPS1 上建一条指向 `clientId=12` 的域名 / HTTP 隧道（host 填 `12.xxx.com` 之类）。

**验证路径**：

```
用户 → NPS1(:80) → SendLinkInfo(12 不在本机) → relay → NPS2:8028
     → NPS2 SendLinkInfo(12 本地) → client12 → 本地服务 → 原路回传
```

**预期日志**：

- NPS1：`relay: session established to NPS2_IP:8028`
- NPS2：`relay: server listening on ...:8028`
- 用户访问 `http://12.xxx.com` 成功拿到 NPS2 侧 client 的服务内容。

### 10.2 已知修复（阶段 1 MVP）

| 问题 | 现象 | 修复 |
|------|------|------|
| **relay 认证头缺失** | NPS1↔NPS2 会话永远建不起来（server 端把 mux 控制帧前 4 字节误当 auth magic 读，校验失败关闭） | Relay Client 在 `NewMux` 之前先 `writeAuth` 发送 `relay_key`；Relay Server `checkAuth` 通过后再建 mux。 |
| **ipVerify 误杀 relay 流量** | NPS2 上所有经 relay 转发的请求被 `SendLinkInfo` 的 ipVerify 拦截，返回空响应 / 拒绝 | 给 `conn.Link` 增加 `Relay bool`；NPS2 relay server 转发前置 `link.Relay=true`；`SendLinkInfo` 两处 ipVerify 检查改为 `if s.ipVerify && !link.Relay`。 |

> 注意：`ip_verify` 在 NPS1 / NPS2 两侧都应设为 `false`（NPS1 入口侧用户 IP 本就不该被限制；NPS2 侧因 relay 流量用户 IP 不在注册表也必须放行）。

### 10.3 失败排查表

| 现象 | 可能原因 | 排查 / 处理 |
|------|----------|-------------|
| 连接被拒、`session failed` | 两端 `relay_key` 不一致；或 NPS2 `relay_allow_ips` 未放行 NPS1 来源 IP | 核对两侧 `relay_key`；确认 NPS2 `relay_allow_ips` 包含 NPS1。 |
| `the client 12 is not connect` | NPS1 的 `relay_routes` 未命中该 clientId；或 NPS2 上 client 未真正连上 | 检查 `relay_routes` 格式 `clientId:host:port`；确认 NPS2 控制台该 client 在线。 |
| 空响应 / 超时 | NPS2 日志 `relay: SendLinkInfo for client 12 failed`；或 NPS2 `ip_verify` 仍为 true | 看 NPS2 中继日志；确认两侧 `ip_verify=false`；确认目标内网服务可达。 |
| 用户访问偶发失败 | NPS1 与 NPS2 间会话未就绪（首包早于会话建立） | 观察 NPS1 是否打印 `session established`；确保 NPS1 在收到请求前已完成会话拨号。 |

---

## 11. 实现里程碑

**阶段 1（MVP，约数百行）**
- `relay_port` / `relay_key` / `relay_allow_ips` / `relay_routes` 配置解析；
- Relay Server（peer 鉴权 + 读帧 + 本地 `SendLinkInfo` + 桥接）；
- Relay Client（持久 mux 会话 + `Relay()` 开子流 + 写帧）；
- 静态注册表 `relay_routes`；
- `SendLinkInfo` 增加 `tryRelay` 分支；
- 支持 **HTTP + TCP** 端到端验证。

**阶段 2**
- UDP（`udp5` 帧封装）支持；
- HTTPS 透传（`HttpsJustProxy` 式）支持；
- 连接复用优化 / 重连退避。

**阶段 3**
- 动态注册表（Redis / etcd），替代静态 `relay_routes`；
- `relay_allow_clients` 白名单；
- mTLS 鉴权选项；
- 监控指标（中继跳数、peer 会话数、relay 错误率）。

---

## 12. 风险与权衡

| 项 | 说明 |
|------|------|
| 延迟翻倍 | 每多一跳加一次 RTT；NPS1↔NPS2 若跨公网更明显。建议 peer 间走内网/专线。 |
| 改造面 | 集中在 `bridge` 包（新增 relay 子包）+ `SendLinkInfo` 一处分支 + `nps.conf` 解析，proxy 服务零改动。 |
| 缓存命中率 | NPS1 与 NPS2 各有一套 `cache.go` 缓存，中继后命中率可能下降（HTTP 场景）。 |
| 安全面扩大 | 新增一个对外端口，必须配 `relay_allow_ips` + `relay_key`，否则成开放代理。 |

---

## 13. 与现有代码映射

| 设计组件 | 对应现有代码 |
|----------|--------------|
| 路由收口点 | `bridge.SendLinkInfo`（`bridge/link.go:24`） |
| 本地隧道获取 | `client.GetNode()` / `node.GetTunnel()`（`bridge/client.go`） |
| proxy 调用入口 | `proxy.BaseServer.DealClient` → `s.Bridge.SendLinkInfo`（`server/proxy/base.go:122`） |
| 字节桥接 | `conn.CopyWaitGroup`（`server/proxy/base.go:133`） |
| 连接复用会话 | `lib/mux.Mux` / `quic-go`（借鉴 npc↔bridge 复用） |
| Link 结构 | `conn.Link` / `conn.NewLink`（`lib/conn/link.go`） |
| 多节点选取策略 | `bridge_select_mode`（主备/轮询/随机，`conf/nps.conf:85`）—— relay 与之正交，relay 解决「跨 nps」，该策略解决「同 nps 内多内网机」。 |
| 客户端限额 | `CheckFlowAndConnNum` / `FlowAdd`（`server/proxy/base.go:49,83`） |

---

## 14. 结论

本方案在**不破坏 nps 单机模型**的前提下，以「独立 relay 端口 + peer 级鉴权 + 轻量中继帧 + `SendLinkInfo` 单点分支」实现了跨 nps 流量中继。相比「NPS1 复用 bridge 客户端握手」方案，本方案：

- 不泄露客户端 vkey；
- 不把 NPS1 错误地注册成某 client 的 Node；
- 端口隔离、运维清晰；
- proxy 各服务零改动，改动面最小、语义最正确。

可行性：**可行 ✅**。建议从阶段 1（静态配置 + HTTP/TCP）起步验证。

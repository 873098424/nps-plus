# NPS-Plus HTTPS 代理处理详解

本文档说明 NPS-Plus 中 HTTPS（含 HTTP/2、HTTP/3）请求从进入到转发的完整处理逻辑，
并回答一个核心问题：**HTTPS 请求最终是否会走到 `HttpServer.handleProxy`？**

结论先行：

- **普通 HTTPS 反向代理（NPS 终止 TLS，再按 HTTP 转发给后端）**：✅ 会走到 `handleProxy`。
  `HttpsServer` 在把 TLS 连接解密后，把已解密的 `tls.Conn` 投递给一个 `http.Server`，
  而这个 `http.Server` 的 Handler 就是 `handleProxy`。
- **`https_just_proxy`（TLS 透传，后端自己终止 TLS）**：❌ 不走 `handleProxy`，
  走 `handleHttpsProxy` → `DealClient`（原始 TCP 隧道）。
- **`tls_offload`（NPS 终止 TLS，但解密后原样透传字节给后端）**：❌ 不走 `handleProxy`，
  走 `handleTlsProxy` → `DealClient`（原始 TCP 隧道）。
- **WebSocket / CONNECT / Upgrade**（在 `handleProxy` 内部判定）：走 `handleWebsocket`（原始隧道），
  但**入口仍在 `handleProxy`**，只是分支不同。

---

## 1. 类型与架构

关键类型定义在 `server/proxy/httpproxy/`：

```
HttpProxy                       (httpproxy.go)   顶层，持有 HttpServer / HttpsServer / Http3Server
  └─ *proxy.BaseServer          (proxy/base.go)  DealClient / Auth / CheckFlowAndConnNum
  └─ HttpServer                 (http.go)        HTTP 服务 + handleProxy
        └─ *proxy.BaseServer
        └─ *HttpProxy
  └─ HttpsServer                (https.go)       嵌入 *HttpServer
        └─ *HttpServer
        └─ *HttpProxy
  └─ Http3Server                (http3.go)       嵌入 *HttpsServer
```

`HttpsServer` 内嵌 `*HttpServer`，因此天然拥有 `handleProxy`、`NewServer`、`DialContext` 等方法。
`Http3Server` 内嵌 `*HttpsServer`，复用同一套 TLS/证书逻辑。

启动顺序见 `HttpProxy.Start()`（`httpproxy.go:70`）：

```go
if s.HttpsPort > 0 {
    httpsListener, _ := connection.GetHttpsListener()   // 原始 TCP 监听器
    s.HttpServer = NewHttpServer(s, nil)                 // 即使没有 HTTP 端口也要建一个，供 HTTPS 复用
    s.HttpsServer = NewHttpsServer(s.HttpServer, httpsListener)
    go s.HttpsServer.Start()                             // 原始字节接收 + 分支决策
    if s.Http3Port > 0 { ... NewHttp3Server ... }        // HTTP/3 复用 HttpsServer
}
```

---

## 2. 两套监听器（关键设计）

`HttpsServer` 同时持有**两个不同层次的监听器**，这是理解整个流程的核心：

| 监听器 | 类型 | 作用 |
|--------|------|------|
| `httpsListener` | 原始 `net.Listener`（TCP） | `HttpsServer.Start()` 在这里 `Accept` 原始连接，读取 ClientHello，做分支决策 |
| `httpsServeListener` | `*HttpsListener`（channel 包装） | 一个假的 `net.Listener`，`Accept()` 从 channel 取出**已解密的 `tls.Conn`** |

`HttpsListener`（`https.go:248`）的实现：

```go
func (l *HttpsListener) Accept() (net.Conn, error) {
    httpsConn, ok := <-l.acceptConn          // 从 channel 取已解密连接
    if !ok { return nil, errors.New("...") }
    return httpsConn, nil
}
```

在 `NewHttpsServer`（`https.go:76`）里，会启动一个 `http.Server` 服务在这个假监听器上：

```go
https.httpsServer = https.NewServer(https.HttpsPort, "https")
go https.httpsServer.Serve(https.httpsServeListener)   // 处理已解密的 HTTP 请求
```

而 `NewServer`（`http.go:408`）的 Handler 就是 `handleProxy`：

```go
func (s *HttpServer) NewServer(port int, scheme string) *http.Server {
    return &http.Server{
        Addr: ":" + strconv.Itoa(port),
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.URL.Scheme = scheme              // "https"
            s.handleProxy(w, r)                // ← 最终入口
        }),
    }
}
```

> 所以，**只要连接被推进 `httpsServeListener.acceptConn`，它就一定会经过 `handleProxy`**。

---

## 3. HttpsServer.Start() 的完整分支逻辑

`HttpsServer.Start()`（`https.go:85`）在原始 `httpsListener` 上循环 `Accept`，每个连接按如下流程处理：

```
Accept 原始 TCP 连接 c
        │
        ▼
crypt.ReadClientHello(c, nil)  →  helloInfo(SNI), rb(已缓冲的 ClientHello 字节)
        │
        ├─ 读取失败（可能不是 TLS）→ checkHTTPAndRedirect(c, rb)
        │                           尝试按明文 HTTP 解析；若是 HTTP 请求打错端口，
        │                           返回 302 跳转到 https://host/...；否则关闭。
        │
        ▼ 读取成功
serverName = helloInfo.ServerName
        │
        ├─ serverName == ""  → 关闭（不允许用 IP 直接访问 HTTPS 端口）
        │
        ▼
host = file.GetDb().FindCertByHost(serverName)
        │
        ├─ 找不到 / host.IsClose → 关闭
        │
        ▼ 找到 host
        │
        ├─【分支 A】host.HttpsJustProxy == true
        │        → handleHttpsProxy(host, c, rb, serverName)   ❌ 不经过 handleProxy
        │          原始 TLS 字节整体透传给后端，由后端终止 TLS
        │
        ▼ 否则，决定用哪套证书（tlsConfig）
        │   ├─ host.AutoSSL && (HttpsPort==443 || HttpPort==80 || ForceAutoSsl)
        │   │        → s.certMagicTls   （certmagic 按需签发 ACME 证书）
        │   └─ 否则 s.cert.Get(host.CertFile, host.KeyFile, ...)
        │            ├─ 失败且 hasDefaultCert → 用默认证书
        │            └─ 仍失败 → handleHttpsProxy(...)  ❌ 退化为透传
        │
        ▼ 用 tlsConfig 包一层
acceptConn = conn.NewConn(c).SetRb(rb)     // 把 ClientHello 字节放回连接头
tlsConn   = tls.Server(acceptConn, tlsConfig)
tlsConn.Handshake()
        │
        ├─【分支 B】host.TlsOffload == true
        │        → handleTlsProxy(host, tlsConn, serverName)  ❌ 不经过 handleProxy
        │          NPS 已终止 TLS，把解密后的原始字节透传给后端
        │
        ▼【分支 C】默认：TLS 终止 + HTTP 反向代理
        s.httpsServeListener.acceptConn <- tlsConn
                 │
                 ▼  （由 httpsServer.Serve 取走）
        http.Server.Handler → handleProxy(w, r)   ✅ 经过 handleProxy
```

---

## 4. 三个分支详解

### 4.1 分支 A：`HttpsJustProxy`（TLS 透传）

`handleHttpsProxy`（`https.go:197`）：

```go
func (s *HttpsServer) handleHttpsProxy(host *file.Host, c net.Conn, rb []byte, sni string) {
    s.CheckFlowAndConnNum(host.Client)              // 流控/连接数
    host.AddConn()
    targetAddr, _ := host.Target.GetRandomTarget()  // 选后端
    task := file.NewTunnelByHost(host, s.HttpsPort)
    s.DealClient(conn.NewConn(c), host.Client, targetAddr, rb,
        common.CONN_TCP, nil, flows, ProxyProtocol, LocalProxy, task)
}
```

- NPS **不终止 TLS**，把客户端发来的原始 TLS 字节（含 `rb` 缓冲的 ClientHello）通过 `DealClient`
  经 bridge 隧道透传到客户端/后端，由后端自己完成 TLS 握手与解密。
- `DealClient`（`proxy/base.go:105`）会 `Bridge.SendLinkInfo` 建立隧道，再用
  `conn.CopyWaitGroup` 做双向原始字节拷贝。
- **不走 `handleProxy`**，因此没有 Host 头解析、没有路径重写、没有缓存、没有 Basic Auth。

适用场景：后端需要校验客户端证书（mTLS）、或后端要用自己的证书/域名逻辑。

### 4.2 分支 B：`TlsOffload`（终止 TLS 但透传明文）

`handleTlsProxy`（`https.go:218`）：

```go
func (s *HttpsServer) handleTlsProxy(host *file.Host, tlsConn net.Conn, sni string) {
    s.CheckFlowAndConnNum(host.Client)
    host.AddConn()
    targetAddr, _ := host.Target.GetRandomTarget()
    task := file.NewTunnelByHost(host, s.HttpsPort)
    s.DealClient(conn.NewConn(tlsConn), host.Client, targetAddr, nil,
        common.CONN_TCP, nil, flows, ProxyProtocol, LocalProxy, task)
}
```

- NPS 在 `Start()` 里已经用 `tls.Server` 完成了握手并解密。
- 但这里**不再做 HTTP 解析**，而是把解密后的明文 `tlsConn` 直接 `DealClient` 隧道给后端。
- 与分支 A 的区别：TLS 在 NPS 侧终止（可用 NPS 的证书/AutoSSL），但 HTTP 层不做反向代理。
- **不走 `handleProxy`**。

### 4.3 分支 C：默认（TLS 终止 + HTTP 反向代理）→ 走 `handleProxy`

这是最常见的"HTTPS 网站反代"场景：

1. `HttpsServer.Start()` 用证书完成 TLS 握手，得到解密后的 `tlsConn`。
2. `tlsConn` 被推入 `httpsServeListener.acceptConn`。
3. `httpsServer.Serve(httpsServeListener)` 取出连接，按 HTTP/1.1 或 HTTP/2 解析为 `*http.Request`，
   `r.TLS != nil`、`r.URL.Scheme = "https"`。
4. 调用 `handleProxy(w, r)`。

---

## 5. handleProxy 内部逻辑（HTTP 与 HTTPS 共用）

`handleProxy`（`http.go:73`）同时服务 HTTP 端口和（解密后的）HTTPS 请求，区别仅在于
`r.TLS != nil` 与 `r.URL.Scheme`。其步骤：

1. **按 Host 找映射**：`file.GetDb().GetInfoByHost(r.Host, r)`。
   找不到且 `ErrorAlways` → 返回错误页 / 否则直接 `Hijack` 关闭连接。
2. **IP 黑名单**：全局 + 客户端级黑名单，命中直接关闭。
3. **AutoSSL ACME 挑战**：路径以 `/.well-known/acme-challenge/` 开头且满足条件 →
   `s.Acme.HandleHTTPChallenge` 直接处理（用于证书签发验证）。
4. **HTTP-Only 透传**：`X-NPS-Http-Only` 头校验（内部通道用，避免被外部访问）。
5. **Auto 301 跳转 HTTPS**：仅当 `r.TLS == nil` 且 `host.AutoHttps` → 跳 `https://`。
   （HTTPS 请求进来时 `r.TLS != nil`，此步跳过。）
6. **路径重写**：`host.PathRewrite` / `host.Location`。
7. **流控/连接数**：`CheckFlowAndConnNum`。
8. **Basic Auth**：非 Upgrade 请求做 `s.Auth`（401 未授权）。
9. **307 重定向**：`host.RedirectURL` 设置时跳转。
10. **注入上下文**：把 `remoteAddr`、`host`、`sni`（含 `HostChange`）放进 `context`。
11. **WebSocket / CONNECT / Upgrade**：满足任一 → `handleWebsocket`（原始隧道，见下）。
12. **反向代理**：否则构造 `http.Transport`（按 `host.Id` 缓存），用
    `httputil.ReverseProxy`：
    - `Director` 中按 `host.TargetIsHttps` 设 `req.URL.Scheme = "https"/"http"`，
      调 `ChangeHostAndHeader` 改写 Host/Header，`req.URL.Host = r.Host`。
    - `Transport` 用 `s.DialContext` / `s.DialTlsContext`：它们通过
      `Bridge.SendLinkInfo` 把连接隧道到客户端，再（按需）用 `conn.GetTlsConn`
      对"客户端↔后端"这一段做 TLS。
    - `ModifyResponse`：可选 CORS、设置 `Alt-Svc: h3=...`、改写响应头。
    - `rp.ServeHTTP(w, r)` 完成转发。

> 注意：`handleProxy` 里真正"反代"后端时，对后端连接仍然是**通过 bridge 隧道**建立的
> （`DialContext` → `Bridge.SendLinkInfo`），并不是 NPS 直接连后端 IP。

### 5.1 WebSocket / CONNECT / Upgrade 分支

`handleWebsocket`（`http.go:267`）从 `handleProxy` 进入，但走**原始隧道**而非 ReverseProxy：

- 选后端 `targetAddr` → `Bridge.SendLinkInfo` 建立隧道连接 `targetConn`。
- 若 `host.TargetIsHttps` → 对隧道连接再做一次 `conn.GetTlsConn(sni)`。
- `Hijack` 客户端连接，手写 HTTP 握手到后端，校验状态码后
  `goroutine.Join(clientConn, netConn, ...)` 双向拷贝。
- 这条路径**不经过 `httputil.ReverseProxy`**，但**入口仍是 `handleProxy`**。

---

## 6. HTTP/3 路径

`Http3Server.Start()`（`http3.go:35`）创建的 `http3.Server` 直接复用 HTTPS 的 Handler：

```go
s.http3Server = &http3.Server{
    Handler:   s.httpsServer.Handler,   // 同一个 handleProxy
    TLSConfig: tlsConfig,
}
```

- QUIC 连接经 `GetConfigForClient`（`http3.go:125`）按 SNI 选证书（逻辑与 `Start()` 一致）。
- 解密后的 HTTP/3 请求同样进入 `handleProxy`。
- 因此 **HTTP/3 的 HTTPS 请求也最终走到 `handleProxy`**（除非命中 `HttpsJustProxy` 时在
  `GetConfigForClient` 返回 `nil` 退化为桥接 QUIC）。

---

## 7. 总结：HTTPS 是否走 handleProxy？

| 场景 | 是否走 handleProxy | 实际处理函数 |
|------|--------------------|--------------|
| 普通 HTTPS 反代（默认） | ✅ 是 | `handleProxy` → `httputil.ReverseProxy` |
| HTTPS + HTTP/3 | ✅ 是 | `handleProxy` |
| HTTPS + WebSocket/Upgrade | ✅ 入口是，但分支走隧道 | `handleProxy` → `handleWebsocket` |
| `https_just_proxy`（TLS 透传） | ❌ 否 | `handleHttpsProxy` → `DealClient` |
| `tls_offload`（终止后透传） | ❌ 否 | `handleTlsProxy` → `DealClient` |
| AutoSSL 证书签发挑战 | ❌ 否（在 handleProxy 内提前返回） | `Acme.HandleHTTPChallenge` |

**一句话**：NPS 在 `HttpsServer.Start()` 里先终止 TLS，把解密后的连接交给内嵌的
`http.Server`（其 Handler 就是 `handleProxy`）。所以**绝大多数 HTTPS 反向代理请求确实会走到
`HttpServer.handleProxy`**；只有 `https_just_proxy` 和 `tls_offload` 这两种"透传/卸载"模式
会绕过它，直接走 `DealClient` 原始 TCP 隧道。

---

## 8. 相关配置字段

| 字段 | 含义 | 影响 |
|------|------|------|
| `https_just_proxy` | TLS 透传 | 命中分支 A，绕过 handleProxy |
| `tls_offload` | 终止 TLS 但明文透传 | 命中分支 B，绕过 handleProxy |
| `auto_ssl` | 按需 ACME 自动签发 | 用 certmagic 证书 |
| `host_change` | 改写后端 Host | 在 handleProxy 的 Director 生效 |
| `target_is_https` | 后端用 HTTPS | Director 设 scheme=https，DialTlsContext |
| `path_rewrite` / `location` | 路径重写 | handleProxy 内生效 |
| `redirect_url` | 307 重定向 | handleProxy 内生效 |
| `user_auth` / `multi_account` | Basic Auth | handleProxy 内生效 |
| `https_proxy_port` | HTTPS 监听端口 | 见 `nps.conf` |

涉及文件：
- `server/proxy/httpproxy/https.go`（`HttpsServer`、`handleHttpsProxy`、`handleTlsProxy`）
- `server/proxy/httpproxy/http.go`（`HttpServer`、`handleProxy`、`handleWebsocket`、`NewServer`）
- `server/proxy/httpproxy/http3.go`（`Http3Server`）
- `server/proxy/httpproxy/httpproxy.go`（`HttpProxy.Start` 启动编排、证书/AutoSSL 初始化）
- `server/proxy/base.go`（`DealClient` 原始隧道）

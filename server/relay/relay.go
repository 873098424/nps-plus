package relay

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/mux"
	"github.com/quic-go/quic-go"
)

// relayQuicTLS 复用项目 TLS 证书。relay_key 才是唯一可信凭证，TLS 仅用于满足
// QUIC 握手，因此拨号侧跳过证书校验（InsecureSkipVerify）。
var (
	relayQuicTLSOnce sync.Once
	relayQuicTLS     *tls.Config
)

func relayTLSConfig() *tls.Config {
	relayQuicTLSOnce.Do(func() {
		relayQuicTLS = &tls.Config{
			Certificates:       []tls.Certificate{crypt.GetCert()},
			InsecureSkipVerify: true, // relay_key 是唯一可信凭证
			NextProtos:         []string{"nps-relay"},
		}
	})
	return relayQuicTLS
}

// relayQuicCfg 是节点间 relay 会话的 QUIC 参数。
var relayQuicCfg = &quic.Config{
	KeepAlivePeriod:    10 * time.Second,
	MaxIdleTimeout:     30 * time.Second,
	MaxIncomingStreams: 100000,
	Allow0RTT:          true,
}

// LinkSender is satisfied by *bridge.Bridge. Declared here to avoid an import
// cycle between the bridge package and this package.
type LinkSender interface {
	SendLinkInfo(clientId string, link *conn.Link, t *file.Tunnel) (net.Conn, error)
}

// Route maps a clientId to a peer nps address (host:port).
type Route struct {
	ClientID string
	Addr     string
}

// Resolver dynamically maps a clientId to a peer nps relay address (host:port).
// It is backed by the shared presence registry (MongoDB) so that entry nps no
// longer needs a hand-written relay_routes for every client.
type Resolver func(clientId string) (string, bool)

// RelayRouter holds the static registry (clientId -> peer) on the entry nps
// (NPS1) and maintains a persistent mux session to each peer. When a static
// route is missing, it falls back to a dynamic Resolver (presence registry).
type RelayRouter struct {
	mu        sync.RWMutex
	peers     map[string]*PeerSession // keyed by "host:port"
	routes    map[string]*PeerSession // clientId -> peer session (static)
	discTime  int
	key       string
	transport string   // "tcp" | "quic"
	selfAddr  string   // this node's own advertise addr, to avoid relaying to self
	resolve   Resolver // dynamic lookup; nil = static only
}

// NewRelayRouter builds the router from parsed routes. A persistent session is
// lazily established to every distinct peer address.
func NewRelayRouter(discTime int, key string, routes []Route, transport string) *RelayRouter {
	r := &RelayRouter{
		peers:     make(map[string]*PeerSession),
		routes:    make(map[string]*PeerSession),
		discTime:  discTime,
		key:       key,
		transport: transport,
	}
	for _, rt := range routes {
		ps, ok := r.peers[rt.Addr]
		if !ok {
			ps = newPeerSession(rt.Addr, discTime, key, transport)
			r.peers[rt.Addr] = ps
		}
		r.routes[rt.ClientID] = ps
	}
	return r
}

// SetResolver enables dynamic routing via the shared presence registry.
func (r *RelayRouter) SetResolver(resolve Resolver) {
	r.mu.Lock()
	r.resolve = resolve
	r.mu.Unlock()
}

// SetSelfAddr records this node's own advertise address so the router never
// relays a connection back to itself (which would loop).
func (r *RelayRouter) SetSelfAddr(addr string) {
	r.mu.Lock()
	r.selfAddr = addr
	r.mu.Unlock()
}

// Route is the hook installed on bridge.Bridge. It is called from
// SendLinkInfo when the target client is not connected locally.
func (r *RelayRouter) Route(clientId string, link *conn.Link, t *file.Tunnel) (net.Conn, error) {
	r.mu.RLock()
	ps, ok := r.routes[clientId]
	resolve := r.resolve
	self := r.selfAddr
	r.mu.RUnlock()
	if ok { // 静态路由优先
		return ps.Relay(clientId, link)
	}
	if resolve != nil {
		if addr, found := resolve(clientId); found && addr != "" && addr != self {
			return r.getOrCreatePeer(addr).Relay(clientId, link)
		}
	}
	return nil, errors.New("relay: no route for client")
}

// getOrCreatePeer returns the persistent session to addr, creating it on first use.
func (r *RelayRouter) getOrCreatePeer(addr string) *PeerSession {
	r.mu.RLock()
	ps, ok := r.peers[addr]
	r.mu.RUnlock()
	if ok {
		return ps
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ps, ok = r.peers[addr]; ok {
		return ps
	}
	ps = newPeerSession(addr, r.discTime, r.key, r.transport)
	r.peers[addr] = ps
	return ps
}

// Close shuts down all peer sessions.
func (r *RelayRouter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ps := range r.peers {
		ps.close()
	}
}

// PeerSession maintains one persistent session to a peer nps.
// - tcp 模式：一条 TCP 连接 + 一个 mux 多路复用（与旧行为一致）。
// - quic 模式：一条 QUIC 会话，每条被中继的连接使用一条独立的 QUIC stream，
//   从而真正发挥 QUIC 的多路复用与头阻塞消除优势（不再叠加 mux 层）。
type PeerSession struct {
	addr      string
	key       string
	discTime  int
	transport string // "tcp" | "quic"
	mu        sync.Mutex
	mux       *mux.Mux   // tcp 模式
	sess      *quic.Conn // quic 模式
	closed    bool
	closeCh   chan struct{}
}

func newPeerSession(addr string, discTime int, key, transport string) *PeerSession {
	p := &PeerSession{addr: addr, discTime: discTime, key: key, transport: transport, closeCh: make(chan struct{})}
	go p.maintain()
	return p
}

func (p *PeerSession) maintain() {
	if p.transport == "quic" {
		p.maintainQuic()
		return
	}
	p.maintainTcp()
}

func (p *PeerSession) maintainTcp() {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()

		c, err := net.DialTimeout("tcp", p.addr, 10*time.Second)
		if err != nil {
			logs.Warn("relay: dial peer %s failed: %v", p.addr, err)
			time.Sleep(5 * time.Second)
			continue
		}
		// Authenticate before the mux session starts writing control frames,
		// otherwise the server would read mux bytes as the auth magic.
		if err := writeAuth(c, p.key); err != nil {
			logs.Warn("relay: auth to %s failed: %v", p.addr, err)
			_ = c.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		m := mux.NewMux(c, "tcp", p.discTime, true)
		p.setMux(m)
		logs.Info("relay: session established to %s", p.addr)
		for !m.IsClosed() {
			time.Sleep(2 * time.Second)
		}
		p.setMux(nil)
		logs.Warn("relay: session to %s closed, reconnecting", p.addr)
		time.Sleep(2 * time.Second)
	}
}

// maintainQuic 维持一条到 peer 的 QUIC 会话；会话断开后自动重连。
// 每条被中继的连接由 Relay() 通过 OpenStreamSync 新建一条独立 stream，
// 因此这里只负责会话级保活与重连，不做多路复用。
func (p *PeerSession) maintainQuic() {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()

		sess, err := conn.DialQuicWithLocalIP(context.Background(), p.addr, relayTLSConfig(), relayQuicCfg, "")
		if err != nil {
			logs.Warn("relay: dial quic peer %s failed: %v", p.addr, err)
			select {
			case <-p.closeCh:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		p.setSess(sess)
		logs.Info("relay: quic session established to %s", p.addr)
		select {
		case <-p.closeCh:
			_ = sess.CloseWithError(0, "closed")
			return
		case <-sess.Context().Done():
		}
		p.setSess(nil)
		logs.Warn("relay: quic session to %s closed, reconnecting", p.addr)
		select {
		case <-p.closeCh:
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (p *PeerSession) setSess(s *quic.Conn) {
	p.mu.Lock()
	p.sess = s
	p.mu.Unlock()
}

func (p *PeerSession) getSess() *quic.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sess
}

// waitForSess 轮询等待 QUIC 会话就绪（消除首包冷启动竞态）。超时返回 nil。
func (p *PeerSession) waitForSess(timeout time.Duration) *quic.Conn {
	deadline := time.Now().Add(timeout)
	for {
		if s := p.getSess(); s != nil {
			return s
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// peerReadyTimeout is how long Relay waits for a cold-start session to come up
// before giving up. It matches the dial budget in maintain() so a reachable peer
// is given enough time to finish TCP+auth+mux handshake, while an unreachable one
// fails promptly instead of hanging the request forever.
const peerReadyTimeout = 10 * time.Second

// Relay opens a sub-connection on the peer session, writes the relay header
// (clientId + Link) and returns the connection to the caller.
func (p *PeerSession) Relay(clientId string, link *conn.Link) (net.Conn, error) {
	if p.transport == "quic" {
		return p.relayQuic(clientId, link)
	}
	return p.relayTcp(clientId, link)
}

// relayTcp 在持久 TCP 连接上的 mux 会话里开一条子连接（旧行为）。
func (p *PeerSession) relayTcp(clientId string, link *conn.Link) (net.Conn, error) {
	m := p.getMux()
	if m == nil {
		// 会话可能正处于首次建立的冷启动阶段（首次路由的竞态）：此时 mux 还没
		// 完成 TCP+认证+mux 握手，直接失败会导致首个请求返回错误页（"nps 404"）。
		// 这里等待会话就绪，而非立即失败，从而让首包等到通道可用。
		m = p.waitForMux(peerReadyTimeout)
	}
	if m == nil {
		return nil, errors.New("relay: peer session not connected")
	}
	sub, err := m.NewConn()
	if err != nil {
		return nil, err
	}
	wc := conn.NewConn(sub)
	idb := []byte(clientId)
	if err := binary.Write(wc, binary.LittleEndian, int32(len(idb))); err != nil {
		_ = sub.Close()
		return nil, err
	}
	if _, err := wc.Write(idb); err != nil {
		_ = sub.Close()
		return nil, err
	}
	if _, err := wc.SendInfo(link, ""); err != nil {
		_ = sub.Close()
		return nil, err
	}
	if err := wc.FlushBuf(); err != nil {
		_ = sub.Close()
		return nil, err
	}
	return sub, nil
}

// relayQuic 在持久 QUIC 会话上新建一条独立 stream 作为本次中继连接。
// 每条 stream 独立多路复用，互不头阻塞；relay_key 认证与 relay 头写入方式
// 与 TCP 完全一致（服务端 checkAuth/handleSub 无需区分传输层）。
func (p *PeerSession) relayQuic(clientId string, link *conn.Link) (net.Conn, error) {
	s := p.getSess()
	if s == nil {
		s = p.waitForSess(peerReadyTimeout)
	}
	if s == nil {
		return nil, errors.New("relay: peer quic session not connected")
	}
	stream, err := s.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	qc := conn.NewQuicStreamConn(stream, s)
	if err := writeAuth(qc, p.key); err != nil {
		_ = qc.Close()
		return nil, err
	}
	wc := conn.NewConn(qc)
	idb := []byte(clientId)
	if err := binary.Write(wc, binary.LittleEndian, int32(len(idb))); err != nil {
		_ = qc.Close()
		return nil, err
	}
	if _, err := wc.Write(idb); err != nil {
		_ = qc.Close()
		return nil, err
	}
	if _, err := wc.SendInfo(link, ""); err != nil {
		_ = qc.Close()
		return nil, err
	}
	if err := wc.FlushBuf(); err != nil {
		_ = qc.Close()
		return nil, err
	}
	return qc, nil
}

func (p *PeerSession) setMux(m *mux.Mux) {
	p.mu.Lock()
	p.mux = m
	p.mu.Unlock()
}

func (p *PeerSession) getMux() *mux.Mux {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mux
}

// waitForMux 轮询等待 mux 会话就绪（在 maintain 完成拨号+认证+mux 握手后置位）。
// 用于消除首包在会话冷启动阶段被立即失败的问题。超时返回 nil。
func (p *PeerSession) waitForMux(timeout time.Duration) *mux.Mux {
	deadline := time.Now().Add(timeout)
	for {
		if m := p.getMux(); m != nil {
			return m
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *PeerSession) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	m := p.mux
	s := p.sess
	p.mux = nil
	p.sess = nil
	p.mu.Unlock()
	close(p.closeCh)
	if m != nil {
		_ = m.Close()
	}
	if s != nil {
		_ = s.CloseWithError(0, "closed")
	}
}

// writeAuth sends the relay magic and shared key to the peer before the mux
// session begins. The server reads this in checkAuth.
func writeAuth(c net.Conn, key string) error {
	if _, err := c.Write(relayMagic); err != nil {
		return err
	}
	var kl int32 = int32(len(key))
	if err := binary.Write(c, binary.LittleEndian, kl); err != nil {
		return err
	}
	if _, err := c.Write([]byte(key)); err != nil {
		return err
	}
	return nil
}

// ParseRoutes parses the relay_routes config value.
// Format: "clientId:host:port,clientId:host:port" (comma separated).
func ParseRoutes(s string) ([]Route, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []Route
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		segs := strings.SplitN(part, ":", 3)
		if len(segs) != 3 {
			return nil, fmt.Errorf("invalid relay route %q", part)
		}
		cid := strings.TrimSpace(segs[0])
		if cid == "" {
			return nil, fmt.Errorf("invalid client id in %q", part)
		}
		port, err := strconv.Atoi(segs[2])
		if err != nil {
			return nil, fmt.Errorf("invalid port in %q: %w", part, err)
		}
		out = append(out, Route{ClientID: cid, Addr: net.JoinHostPort(segs[1], strconv.Itoa(port))})
	}
	return out, nil
}

// ParseAllowIps parses the relay_allow_ips config value (comma separated).
func ParseAllowIps(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

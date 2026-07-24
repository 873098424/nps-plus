package relay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/mux"
	"github.com/quic-go/quic-go"
)

// relayMagic is sent by the peer client before the shared key.
var relayMagic = []byte("NPSR")

// RelayServer listens on an independent relay_port on the nps that owns the
// client (NPS2). It authenticates peers, accepts mux sub-connections (tcp mode)
// or QUIC streams (quic mode) and bridges each one to the local client tunnel
// via SendLinkInfo.
type RelayServer struct {
	addr      string
	key       string
	allowIPs  []string
	bridge    LinkSender
	discTime  int
	transport string
	listener  net.Listener
	quicL     *quic.Listener
	closed    bool
}

// NewRelayServer creates a relay server bound to addr (host:port).
func NewRelayServer(addr, key string, allowIPs []string, bridge LinkSender, discTime int, transport string) *RelayServer {
	return &RelayServer{
		addr:      addr,
		key:       key,
		allowIPs:  allowIPs,
		bridge:    bridge,
		discTime:  discTime,
		transport: transport,
	}
}

// Start begins listening. It returns once the listener is open.
func (s *RelayServer) Start() error {
	if s.transport == "quic" {
		return s.startQuic()
	}
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = l
	logs.Info("relay: server listening on %s", s.addr)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				logs.Warn("relay: accept error: %v", err)
				continue
			}
			go s.handleConn(c)
		}
	}()
	return nil
}

// startQuic 在 UDP 上监听 QUIC。每条入站会话接受多条独立 stream，
// 每条 stream 对应一次被中继的连接（直接交给 handleSub，无需 mux 层）。
func (s *RelayServer) startQuic() error {
	l, err := quic.ListenAddr(s.addr, relayTLSConfig(), relayQuicCfg)
	if err != nil {
		return err
	}
	s.quicL = l
	logs.Info("relay: server listening on %s (quic)", s.addr)
	go func() {
		for {
			sess, err := l.Accept(context.Background())
			if err != nil {
				if s.isClosed() {
					return
				}
				if strings.Contains(err.Error(), "use of closed") {
					return
				}
				logs.Warn("relay: quic accept error: %v", err)
				continue
			}
			go s.handleQuicSession(sess)
		}
	}()
	return nil
}

func (s *RelayServer) handleQuicSession(sess *quic.Conn) {
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			logs.Trace("relay: quic session %s ended", sess.RemoteAddr())
			return
		}
		// 每条 stream 独立多路复用：直接用 QuicStreamConn（非 AutoClose），
		// 关闭单条 stream 不会连坐关闭整个 QUIC 会话。
		go s.handleConn(conn.NewQuicStreamConn(stream, sess))
	}
}

// Close stops the listener.
func (s *RelayServer) Close() {
	s.closed = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.quicL != nil {
		_ = s.quicL.Close()
	}
}

func (s *RelayServer) isClosed() bool {
	return s.closed
}

func (s *RelayServer) handleConn(c net.Conn) {
	defer func() { _ = c.Close() }()

	if len(s.allowIPs) > 0 {
		ip := common.GetIpByAddr(c.RemoteAddr().String())
		if !inSlice(ip, s.allowIPs) {
			logs.Warn("relay: rejected %s (not in allow list)", ip)
			return
		}
	}
	if !s.checkAuth(c) {
		logs.Warn("relay: auth failed from %s", c.RemoteAddr())
		return
	}

	// quic 模式下每条连接本身就是一条独立 stream，直接交给 handleSub；
	// tcp 模式则在其上叠加 mux，由 mux 解析出每条子连接再交给 handleSub。
	if s.transport == "quic" {
		s.handleSub(c)
		return
	}
	m := mux.NewMux(c, "tcp", s.discTime, false)
	conn.Accept(m, func(sub net.Conn) {
		s.handleSub(sub)
	})
}

// handleSub serves a single relayed user connection.
func (s *RelayServer) handleSub(sub net.Conn) {
	defer func() { _ = sub.Close() }()

	wc := conn.NewConn(sub)
	var idl int32
	if err := binary.Read(wc, binary.LittleEndian, &idl); err != nil {
		logs.Warn("relay: read clientId len failed: %v", err)
		return
	}
	if idl < 0 || idl > 256 {
		logs.Warn("relay: invalid clientId len %d", idl)
		return
	}
	idb := make([]byte, idl)
	if _, err := io.ReadFull(wc, idb); err != nil {
		logs.Warn("relay: read clientId failed: %v", err)
		return
	}
	cid := string(idb)
	link, err := wc.GetLinkInfo()
	if err != nil {
		logs.Warn("relay: read link failed: %v", err)
		return
	}
	// Mark as relay so the local bridge skips ipVerify for the user IP.
	link.Relay = true
	target, err := s.bridge.SendLinkInfo(cid, link, nil)
	if err != nil {
		logs.Warn("relay: SendLinkInfo for client %s failed: %v", cid, err)
		return
	}
	defer func() { _ = target.Close() }()

	conn.CopyWaitGroup(sub, target, link.Crypt, link.Compress, nil, nil, true, 0, nil, nil, link.LocalProxy, link.ConnType == "udp")
}

func (s *RelayServer) checkAuth(c net.Conn) bool {
	buf := make([]byte, len(relayMagic))
	if _, err := io.ReadFull(c, buf); err != nil {
		return false
	}
	if string(buf) != string(relayMagic) {
		return false
	}
	var kl int32
	if err := binary.Read(c, binary.LittleEndian, &kl); err != nil {
		return false
	}
	if kl <= 0 || kl > 1024 {
		return false
	}
	kb := make([]byte, kl)
	if _, err := io.ReadFull(c, kb); err != nil {
		return false
	}
	return string(kb) == s.key
}

func inSlice(ip string, list []string) bool {
	for _, v := range list {
		if v == ip {
			return true
		}
	}
	return false
}

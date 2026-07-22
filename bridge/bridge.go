package bridge

import (
	"net"
	"sync"
	"time"

	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
)

var (
	ServerTcpEnable  = false
	ServerKcpEnable  = false
	ServerQuicEnable = false
	ServerTlsEnable  = false
	ServerWsEnable   = false
	ServerWssEnable  = false
	ServerSecureMode = false
)

var bridgeHandshakeReadTimeout time.Duration = 10

type Bridge struct {
	Client             *sync.Map
	Register           *sync.Map
	VirtualTcpListener *conn.VirtualListener
	VirtualTlsListener *conn.VirtualListener
	VirtualWsListener  *conn.VirtualListener
	VirtualWssListener *conn.VirtualListener
	OpenHost           chan *file.Host
	OpenTask           chan *file.Tunnel
	CloseTask          chan *file.Tunnel
	CloseClient        chan string
	SecretChan         chan *conn.Secret
	ipVerify           bool
	runList            *sync.Map //map[string]interface{}
	disconnectTime     int
	relay              RelayHandler
	onClientConnect    func(id string)
	onClientDisconnect func(id string)
}

// RelayHandler is invoked from SendLinkInfo when the target client is not
// connected locally. It is set by the relay package to forward traffic to the
// nps instance that actually owns the client.
type RelayHandler func(clientId string, link *conn.Link, t *file.Tunnel) (net.Conn, error)

// SetRelay installs the cross-node relay hook.
func (s *Bridge) SetRelay(h RelayHandler) {
	s.relay = h
}

// SetClientLifecycleHooks installs callbacks fired on client connect / disconnect.
// Used by the presence registry to keep the shared online-location table in sync
// with real connection events (instead of polling).
func (s *Bridge) SetClientLifecycleHooks(onConnect, onDisconnect func(id string)) {
	s.onClientConnect = onConnect
	s.onClientDisconnect = onDisconnect
}

func (s *Bridge) fireClientConnect(id string) {
	if s.onClientConnect != nil {
		s.onClientConnect(id)
	}
}

func (s *Bridge) fireClientDisconnect(id string) {
	if s.onClientDisconnect != nil {
		s.onClientDisconnect(id)
	}
}

func NewTunnel(ipVerify bool, runList *sync.Map, disconnectTime int) *Bridge {
	return &Bridge{
		Client:         &sync.Map{},
		Register:       &sync.Map{},
		OpenHost:       make(chan *file.Host, 100),
		OpenTask:       make(chan *file.Tunnel, 100),
		CloseTask:      make(chan *file.Tunnel, 100),
		CloseClient:    make(chan string, 100),
		SecretChan:     make(chan *conn.Secret, 100),
		ipVerify:       ipVerify,
		runList:        runList,
		disconnectTime: disconnectTime,
	}
}

func (s *Bridge) DelClient(id string) {
	if v, ok := s.Client.Load(id); ok {
		client := v.(*Client)
		_ = client.Close()

		s.Client.Delete(id)

		s.fireClientDisconnect(id)

		if file.GetDb().IsPubClient(id) {
			return
		}
		if c, err := file.GetDb().GetClient(id); err == nil {
			select {
			case s.CloseClient <- c.Id:
			default:
				logs.Warn("CloseClient channel is full, failed to send close signal for client %s", c.Id)
			}
		}
	}
}

func (s *Bridge) IsServer() bool {
	return true
}

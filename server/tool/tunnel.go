package tool

import (
	"errors"
	"net"
	"sync/atomic"

	"github.com/djylb/nps/lib/conn"
)

type Dialer interface {
	DialVirtual(remote string) (net.Conn, error)
	ServeVirtual(c net.Conn)
}

var lookup atomic.Value // holds: func(string) (Dialer, bool)

func SetLookup(fn func(string) (Dialer, bool)) {
	lookup.Store(fn)
}

func GetTunnelConn(id string, remote string) (net.Conn, error) {
	v := lookup.Load()
	if v == nil {
		return nil, errors.New("tunnel lookup not set")
	}
	fn := v.(func(string) (Dialer, bool))
	d, ok := fn(id)
	if !ok || d == nil {
		return nil, errors.New("tunnel not found")
	}
	return d.DialVirtual(remote)
}

var WebServerListener *conn.VirtualListener

func GetWebServerConn(remote string) (net.Conn, error) {
	if WebServerListener == nil {
		return nil, errors.New("web server not set")
	}
	return WebServerListener.DialVirtual(remote)
}

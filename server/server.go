package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/djylb/nps/bridge"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/index"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/server/connection"
	"github.com/djylb/nps/server/proxy"
	"github.com/djylb/nps/server/proxy/httpproxy"
	"github.com/djylb/nps/server/relay"
	"github.com/djylb/nps/server/tool"
)

var (
	Bridge         *bridge.Bridge
	RunList        sync.Map //map[int]interface{}
	once           sync.Once
	HttpProxyCache = index.NewAnyStringIndex()
)

const pingTimeout = 15 * time.Second

func init() {
	RunList = sync.Map{}
	tool.SetLookup(func(id string) (tool.Dialer, bool) {
		if v, ok := RunList.Load(id); ok {
			if svr, ok := v.(*proxy.TunnelModeServer); ok {
				if !strings.Contains(svr.Task.Target.TargetStr, "tunnel://") {
					return svr, true
				}
			}
		}
		return nil, false
	})
}

// InitFromDb init task from db
func InitFromDb() {
	//Add a public password
	if vkey := beego.AppConfig.String("public_vkey"); vkey != "" {
		c := file.NewClient(vkey, true, true)
		_ = file.GetDb().NewClient(c)
		RunList.Store(c.Id, nil)
		//RunList[c.Id] = nil
	}
	//Initialize services in server-side files
	file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		if value.(*file.Tunnel).Status {
			_ = AddTask(value.(*file.Tunnel))
		}
		return true
	})
}

// DealBridgeTask get bridge command
func DealBridgeTask() {
	for {
		select {
		case h := <-Bridge.OpenHost:
			if h != nil {
				HttpProxyCache.Remove(h.Id)
			}
		case t := <-Bridge.OpenTask:
			if t != nil {
				//_ = AddTask(t)
				_ = StopServer(t.Id)
				if err := StartTask(t.Id); err != nil {
					logs.Error("StartTask(%s) error: %v", t.Id, err)
				}
			}
		case t := <-Bridge.CloseTask:
			if t != nil {
				_ = StopServer(t.Id)
			}
		case id := <-Bridge.CloseClient:
			DelTunnelAndHostByClientId(id, true)
			if v, ok := file.GetDb().JsonDb.Clients.Load(id); ok {
				if v.(*file.Client).NoStore {
					_ = file.GetDb().DelClient(id)
				}
			}
		//case tunnel := <-Bridge.OpenTask:
		//	_ = StartTask(tunnel.Id)
		case s := <-Bridge.SecretChan:
			if s != nil {
				logs.Trace("New secret connection, addr %v", s.Conn.Conn.RemoteAddr())
				if t := file.GetDb().GetTaskByMd5Password(s.Password); t != nil {
					if t.Status {
						allowLocalProxy := beego.AppConfig.DefaultBool("allow_local_proxy", false)
						allowSecretLink := beego.AppConfig.DefaultBool("allow_secret_link", false)
						allowSecretLocal := beego.AppConfig.DefaultBool("allow_secret_local", false)
						go func() {
							_ = proxy.NewSecretServer(Bridge, t, allowLocalProxy, allowSecretLink, allowSecretLocal).HandleSecret(s.Conn)
						}()
					} else {
						_ = s.Conn.Close()
						logs.Trace("This key %s cannot be processed,status is close", s.Password)
					}
				} else {
					logs.Trace("This key %s cannot be processed", s.Password)
					_ = s.Conn.Close()
				}
			}
		}
	}
}

// StartNewServer start a new server
func StartNewServer(cnf *file.Tunnel, bridgeDisconnect int) {
	Bridge = bridge.NewTunnel(common.GetBoolByStr(beego.AppConfig.String("ip_limit")), &RunList, bridgeDisconnect)
	go func() {
		if err := Bridge.StartTunnel(); err != nil {
			logs.Error("start server bridge error %v", err)
			os.Exit(1)
		}
	}()

	// Cross-node relay setup (Phase 1: static routes).
	initRelay(bridgeDisconnect)
	if p, err := beego.AppConfig.Int("p2p_port"); err == nil {
		for i := 0; i < 3; i++ {
			port := p + i
			if common.TestUdpPort(port) {
				go func(pp int) { _ = proxy.NewP2PServer(pp).Start() }(port)
				logs.Info("Started P2P Server on port %d", port)
			} else {
				logs.Error("Port %d is unavailable.", port)
			}
		}
	}
	go DealBridgeTask()
	go dealClientFlow()
	InitDashboardData()
	if svr := NewMode(Bridge, cnf); svr != nil {
		if err := svr.Start(); err != nil {
			logs.Error("%v", err)
		}
		RunList.Store(cnf.Id, svr)
		//RunList[cnf.Id] = svr
	} else {
		logs.Error("Incorrect startup mode %s", cnf.Mode)
	}
}

func dealClientFlow() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		dealClientData()
	}
}

// initRelay wires the cross-node relay. NPS1 (entry) uses relay_routes to
// forward traffic to the nps that owns the client; NPS2 (owner) listens on
// relay_port to receive it. Both can be enabled independently.
//
// 当启用 MongoDB 共享存储时，还会开启"动态路由"：owner 节点自动把在线 client 位置
// 上报到注册表，entry 节点查表自动转发，无需手写 relay_routes。
func initRelay(bridgeDisconnect int) {
	key := beego.AppConfig.String("relay_key")
	advertise := strings.TrimSpace(beego.AppConfig.String("relay_advertise"))
	// relay 传输层：tcp（默认，兼容旧部署）或 quic（UDP，原生 stream 多路复用）。
	// 注意：entry 与 owner 两端的 relay_transport 必须一致，否则拨号/监听不匹配。
	transport := strings.ToLower(strings.TrimSpace(beego.AppConfig.DefaultString("relay_transport", "tcp")))
	if transport != "quic" {
		transport = "tcp"
	}
	// 用“是否已配置 mongodb_uri”判断动态路由意图，而非依赖 GetDb() 之后的 mongoOn 标志，
	// 避免 initRelay 在 GetDb() 置位 mongoOn 之前执行时把动态路由静默关闭。
	dynamic := file.MongoConfigured()
	if dynamic {
		file.GetDb() // 确保 Mongo 连接已建立、mongoOn=true，presence 写入/查表才不会静默失效
	}

	routes, err := relay.ParseRoutes(beego.AppConfig.String("relay_routes"))
	if err != nil {
		logs.Error("relay: parse relay_routes error: %v", err)
		routes = nil
	}

	// 入口路由：有静态路由或启用了动态路由都需要 router
	if key == "" {
		if len(routes) > 0 {
			logs.Error("relay: relay_routes set but relay_key is empty; relay client disabled")
		}
	} else if len(routes) > 0 || dynamic {
		router := relay.NewRelayRouter(bridgeDisconnect, key, routes, transport)
		if dynamic {
			router.SetSelfAddr(advertise)
			router.SetResolver(file.LookupPresence)
			logs.Info("relay: dynamic routing enabled via shared presence registry")
		}
		Bridge.SetRelay(router.Route)
		logs.Info("relay: client router enabled (%d static route(s), dynamic=%v)", len(routes), dynamic)
	}

	// owner 端：监听 relay_port 接收其他节点转发过来的流量
	if port, err := beego.AppConfig.Int("relay_port"); err == nil && port > 0 {
		if key == "" {
			logs.Error("relay: relay_port set but relay_key is empty; relay server disabled")
		} else {
			bind := fmt.Sprintf("%s:%d", beego.AppConfig.String("bridge_ip"), port)
			allow := relay.ParseAllowIps(beego.AppConfig.String("relay_allow_ips"))
			// 防御：relay_advertise 的端口应与本机 relay_port 一致，否则 entry 拨号会
			// 打到错误端口（UDP 无人监听）导致 QUIC 握手超时 "no recent network activity"。
			if advertise != "" {
				if ap, _, err := net.SplitHostPort(advertise); err == nil && ap != "" {
					if aport, err := strconv.Atoi(ap); err == nil && aport != port {
						logs.Warn("relay: relay_advertise port %d != relay_port %d; entry nodes will dial the wrong port and the session will time out", aport, port)
					}
				}
			}
			rs := relay.NewRelayServer(bind, key, allow, Bridge, bridgeDisconnect, transport)
			if err := rs.Start(); err != nil {
				logs.Error("relay: server start error: %v", err)
			} else if dynamic {
				// 自动上报在线位置：优先用 relay_advertise，否则用出站 IP:relay_port 兜底
				adv := advertise
				if adv == "" {
					adv = fmt.Sprintf("%s:%d", common.GetOutboundIP().String(), port)
					logs.Warn("relay: relay_advertise not set, auto using %s (recommend setting it explicitly)", adv)
				}
				// 事件驱动：client 连接/断开瞬间即写入注册表（毫秒级生效，无残留窗口）。
				// 另起低频心跳作为兜底，应对节点被强杀/网络分区等"优雅断开未触发"的场景。
				Bridge.SetClientLifecycleHooks(
					func(id string) { file.OnClientOnline(id, adv) },
					func(id string) { file.OnClientOffline(id) },
				)
				go presenceHeartbeatLoop(adv)
				logs.Info("relay: presence registry active (event-driven + heartbeat), advertising %s", adv)
			}
		}
	}
}

// presenceHeartbeatLoop 低频刷新本节点在线 client 的 ts，作为"优雅断开钩子没触发"时的兜底。
// 真正的位置写入发生在 client 连接/断开的瞬间（见 bridge 生命周期钩子），这里只负责续命。
func presenceHeartbeatLoop(advertise string) {
	heartbeatOnce(advertise)
	ticker := time.NewTicker(file.PresenceBeatInterval())
	defer ticker.Stop()
	for range ticker.C {
		heartbeatOnce(advertise)
	}
}

func heartbeatOnce(advertise string) {
	ids := make([]string, 0, 16)
	Bridge.Client.Range(func(k, _ interface{}) bool {
		if id, ok := k.(string); ok && id != "" {
			ids = append(ids, id)
		}
		return true
	})
	file.PresenceHeartbeat(advertise, ids)
}

func PingClient(id string, addr string) int {
	if id == "" {
		return 0
	}
	link := conn.NewLink("ping", "", false, false, addr, false)
	link.Option.NeedAck = true
	link.Option.Timeout = pingTimeout
	start := time.Now()
	target, err := Bridge.SendLinkInfo(id, link, nil)
	if err != nil {
		logs.Warn("get connection from client Id %s error %v", id, err)
		return -1
	}
	rtt := int(time.Since(start).Milliseconds())
	_ = target.Close()
	return rtt
}

// NewMode new a server by mode name
func NewMode(Bridge *bridge.Bridge, c *file.Tunnel) proxy.Service {
	var service proxy.Service
	allowLocalProxy := beego.AppConfig.DefaultBool("allow_local_proxy", false)
	switch c.Mode {
	case "tcp", "file":
		service = proxy.NewTunnelModeServer(proxy.ProcessTunnel, Bridge, c, allowLocalProxy)
	case "mixProxy", "socks5", "httpProxy":
		service = proxy.NewTunnelModeServer(proxy.ProcessMix, Bridge, c, allowLocalProxy)
		//service = proxy.NewSock5ModeServer(Bridge, c)
		//service = proxy.NewTunnelModeServer(proxy.ProcessHttp, Bridge, c)
	case "tcpTrans":
		service = proxy.NewTunnelModeServer(proxy.HandleTrans, Bridge, c, allowLocalProxy)
	case "udp":
		service = proxy.NewUdpModeServer(Bridge, c, allowLocalProxy)
	case "webServer":
		InitFromDb()
		t := &file.Tunnel{
			Port:   0,
			Mode:   "httpHostServer",
			Status: true,
		}
		_ = AddTask(t)
		service = NewWebServer(Bridge)
	case "httpHostServer":
		httpPort := connection.HttpPort
		httpsPort := connection.HttpsPort
		http3Port := connection.Http3Port
		useCache, _ := beego.AppConfig.Bool("http_cache")
		cacheLen, _ := beego.AppConfig.Int("http_cache_length")
		addOrigin, _ := beego.AppConfig.Bool("http_add_origin_header")
		httpOnlyPass := beego.AppConfig.String("x_nps_http_only")
		service = httpproxy.NewHttpProxy(Bridge, c, httpPort, httpsPort, http3Port, httpOnlyPass, addOrigin, allowLocalProxy, HttpProxyCache, useCache, cacheLen)
	}
	return service
}

// StopServer stop server
func StopServer(id string) error {
	if t, err := file.GetDb().GetTask(id); err != nil {
		return err
	} else {
		t.Status = false
		logs.Info("close port %d,remark %s,client id %s,task id %s", t.Port, t.Remark, t.Client.Id, t.Id)
		_ = file.GetDb().UpdateTask(t)
	}
	//if v, ok := RunList[id]; ok {
	if v, ok := RunList.Load(id); ok {
		if svr, ok := v.(proxy.Service); ok {
			if err := svr.Close(); err != nil {
				return err
			}
			logs.Info("stop server id %s", id)
		} else {
			logs.Warn("stop server id %s error", id)
		}
		//delete(RunList, id)
		RunList.Delete(id)
		return nil
	}
	return errors.New("task is not running")
}

// AddTask add task
func AddTask(t *file.Tunnel) error {
	if t.Mode == "secret" || t.Mode == "p2p" {
		logs.Info("secret task %s start ", t.Remark)
		//RunList[t.Id] = nil
		RunList.Store(t.Id, nil)
		return nil
	}
	if b := tool.TestServerPort(t.Port, t.Mode); !b && t.Mode != "httpHostServer" {
		logs.Error("taskId %s start error port %d open failed", t.Id, t.Port)
		return errors.New("the port open error")
	}
	if minute, err := beego.AppConfig.Int("flow_store_interval"); err == nil && minute > 0 {
		go flowSession(time.Minute * time.Duration(minute))
	}
	if svr := NewMode(Bridge, t); svr != nil {
		logs.Info("tunnel task %s start mode：%s port %d", t.Remark, t.Mode, t.Port)
		//RunList[t.Id] = svr
		RunList.Store(t.Id, svr)
		go func() {
			if err := svr.Start(); err != nil {
				logs.Error("clientId %s taskId %s start error %v", t.Client.Id, t.Id, err)
				//delete(RunList, t.Id)
				RunList.Delete(t.Id)
				return
			}
		}()
	} else {
		return errors.New("the mode is not correct")
	}
	return nil
}

// StartTask start task
func StartTask(id string) error {
	if t, err := file.GetDb().GetTask(id); err != nil {
		return err
	} else {
		if !tool.TestServerPort(t.Port, t.Mode) {
			return errors.New("the port open error")
		}
		err = AddTask(t)
		if err != nil {
			return err
		}
		t.Status = true
		_ = file.GetDb().UpdateTask(t)
	}
	return nil
}

// DelTask delete task
func DelTask(id string) error {
	//if _, ok := RunList[id]; ok {
	if _, ok := RunList.Load(id); ok {
		if err := StopServer(id); err != nil {
			return err
		}
	}
	return file.GetDb().DelTask(id)
}

// DelTunnelAndHostByClientId delete all host and tasks by client id
func DelTunnelAndHostByClientId(clientId string, justDelNoStore bool) {
	var ids []string
	file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		v := value.(*file.Tunnel)
		if justDelNoStore && !v.NoStore {
			return true
		}
		if v.Client.Id == clientId {
			ids = append(ids, v.Id)
		}
		return true
	})
	for _, id := range ids {
		_ = DelTask(id)
	}
	ids = ids[:0]
	file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
		v := value.(*file.Host)
		if justDelNoStore && !v.NoStore {
			return true
		}
		if v.Client.Id == clientId {
			ids = append(ids, v.Id)
		}
		return true
	})
	for _, id := range ids {
		HttpProxyCache.Remove(id)
		_ = file.GetDb().DelHost(id)
	}
}

// DelClientConnect close the client
func DelClientConnect(clientId string) {
	Bridge.DelClient(clientId)
}

func dealClientData() {
	//logs.Info("dealClientData.........")
	file.GetDb().JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*file.Client)
		if vv, ok := Bridge.Client.Load(v.Id); ok {
			v.IsConnect = true
			v.LastOnlineTime = time.Now().Unix()
			cli := vv.(*bridge.Client)
			node, ok := cli.GetNodeByUUID(cli.LastUUID)
			var ver string
			if ok {
				ver = node.Version
			}
			count := cli.NodeCount()
			if count > 1 {
				ver = fmt.Sprintf("%s(%d)", ver, cli.NodeCount())
			}
			v.Version = ver
		} else {
			v.IsConnect = false
		}
		v.InletFlow = 0
		v.ExportFlow = 0
		return true
	})
	file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
		h := value.(*file.Host)
		c, err := file.GetDb().GetClient(h.Client.Id)
		if err != nil {
			return true
		}
		c.InletFlow += h.Flow.InletFlow
		c.ExportFlow += h.Flow.ExportFlow
		return true
	})
	file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		t := value.(*file.Tunnel)
		c, err := file.GetDb().GetClient(t.Client.Id)
		if err != nil {
			return true
		}
		c.InletFlow += t.Flow.InletFlow
		c.ExportFlow += t.Flow.ExportFlow
		return true
	})
	//return
}

func flowSession(m time.Duration) {
	persistAll()
	once.Do(func() {
		go func() {
			ticker := time.NewTicker(m)
			defer ticker.Stop()
			for range ticker.C {
				persistAll()
			}
		}()
	})
}

// persistAll 落盘：MongoDB 模式下只刷新"本节点持有连接"的实体流量，避免跨节点覆盖；
// 否则沿用原 JSON 文件整体写盘。
func persistAll() {
	if file.MongoEnabled() {
		file.GetDb().JsonDb.FlushFlowToMongo()
		return
	}
	file.GetDb().JsonDb.StoreHostToJsonFile()
	file.GetDb().JsonDb.StoreTasksToJsonFile()
	file.GetDb().JsonDb.StoreClientsToJsonFile()
	file.GetDb().JsonDb.StoreGlobalToJsonFile()
}

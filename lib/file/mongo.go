package file

import (
	"context"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/rate"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// 共享存储：MongoDB 后端（唯一持久层，本地 JSON 文件已彻底移除）
//
// 设计要点：
//   - 每个实体一类集合（nps_clients / nps_tunnels / nps_hosts / nps_global），原生 BSON 字段。
//   - 所有时间字段一律以 int64 时间戳（unix 秒）存储：flow.expire、create_time、last_online_time。
//     运行期结构体仍用 time.Time（Flow.TimeLimit / Health.HealthNextTime）便于逻辑判断，持久化时互转。
//   - flow 单独子文档：配置写入（$set）不触碰它，流量持久化只走 updateFlow，避免多节点互相覆盖。
//   - 未配置 mongodb_uri 时启动直接报错退出（不再退回本地 JSON）。

const (
	mongoTypeClient = "client"
	mongoTypeHost   = "host"
	mongoTypeTask   = "task"
	mongoTypeGlobal = "global"
)

// ---- BSON 文档结构（不含运行时字段：RWMutex / NowConn / DestAclSet / HealthMap / AccountMap 等）----

type flowDoc struct {
	Inlet  int64 `bson:"inlet"`
	Export int64 `bson:"export"`
	Limit  int64 `bson:"limit"`
	Expire int64 `bson:"expire"` // unix 秒；0 = 无限制
}

// flowFromDoc 将持久化的 flowDoc 转为运行时 *Flow。
// expire=0 表示无限制，TimeLimit 置为零值；否则由 unix 秒反推 time.Time。
func flowFromDoc(f flowDoc) *Flow {
	fl := &Flow{
		InletFlow:  f.Inlet,
		ExportFlow: f.Export,
		FlowLimit:  f.Limit,
	}
	if f.Expire > 0 {
		fl.TimeLimit = time.Unix(f.Expire, 0)
	}
	return fl
}

type cnfDoc struct {
	U        string `bson:"u"`
	P        string `bson:"p"`
	Compress bool   `bson:"compress"`
	Crypt    bool   `bson:"crypt"`
}

type clientDoc struct {
	ID              primitive.ObjectID `bson:"_id"`
	Vkey            string             `bson:"vkey"`
	Mode            string             `bson:"mode"`
	Remark          string             `bson:"remark"`
	Status          bool               `bson:"status"`
	Cnf             cnfDoc             `bson:"cnf"`
	RateLimit       int                `bson:"rate_limit"`
	MaxConn         int                `bson:"max_conn"`
	MaxTunnelNum    int                `bson:"max_tunnel_num"`
	WebUserName     string             `bson:"web_username"`
	WebPassword     string             `bson:"web_password"`
	WebTotpSecret   string             `bson:"web_totp_secret"`
	ConfigConnAllow bool               `bson:"config_conn_allow"`
	Version         string             `bson:"version"`
	BlackIpList     []string           `bson:"black_ip_list"`
	CreateTime      int64              `bson:"create_time"`
	LastOnlineTime  int64              `bson:"last_online_time"`
	InletFlow       int64              `bson:"inlet_flow"` // 聚合流量（来自下属 host/task）
	ExportFlow      int64              `bson:"export_flow"`
	Flow            flowDoc            `bson:"flow"`
}

type targetDoc struct {
	TargetStr     string `bson:"target_str"`
	LocalProxy    bool   `bson:"local_proxy"`
	ProxyProtocol int    `bson:"proxy_protocol"`
}

type accountDoc struct {
	Content string `bson:"content"`
}

type healthDoc struct {
	Timeout   int      `bson:"timeout"`
	MaxFail   int      `bson:"max_fail"`
	Interval  int      `bson:"interval"`
	HttpUrl   string   `bson:"http_url"`
	RemoveArr []string `bson:"remove_arr"`
	Type      string   `bson:"type"`
	Target    string   `bson:"target"`
}

type tunnelDoc struct {
	ID           primitive.ObjectID `bson:"_id"`
	ClientId     string             `bson:"client_id"`
	Port         int                `bson:"port"`
	ServerIp     string             `bson:"server_ip"`
	Mode         string             `bson:"mode"`
	Status       bool               `bson:"status"`
	RunStatus    bool               `bson:"run_status"`
	Password     string             `bson:"password"`
	Remark       string             `bson:"remark"`
	TargetAddr   string             `bson:"target_addr"`
	TargetType   string             `bson:"target_type"`
	DestAclMode  int                `bson:"dest_acl_mode"`
	DestAclRules string             `bson:"dest_acl_rules"`
	IsHttp       bool               `bson:"is_http"`
	HttpProxy    bool               `bson:"http_proxy"`
	Socks5Proxy  bool               `bson:"socks5_proxy"`
	LocalPath    string             `bson:"local_path"`
	StripPre     string             `bson:"strip_pre"`
	ReadOnly     bool               `bson:"read_only"`
	Ports        string             `bson:"ports"`
	Target       targetDoc          `bson:"target"`
	UserAuth     *accountDoc        `bson:"user_auth"`
	MultiAccount *accountDoc        `bson:"multi_account"`
	Health       healthDoc          `bson:"health"`
	Flow         flowDoc            `bson:"flow"`
}

type hostDoc struct {
	ID               primitive.ObjectID `bson:"_id"`
	ClientId         string             `bson:"client_id"`
	Host             string             `bson:"host"`
	HeaderChange     string             `bson:"header_change"`
	RespHeaderChange string             `bson:"resp_header_change"`
	HostChange       string             `bson:"host_change"`
	Location         string             `bson:"location"`
	PathRewrite      string             `bson:"path_rewrite"`
	Remark           string             `bson:"remark"`
	Scheme           string             `bson:"scheme"`
	RedirectURL      string             `bson:"redirect_url"`
	HttpsJustProxy   bool               `bson:"https_just_proxy"`
	TlsOffload       bool               `bson:"tls_offload"`
	AutoSSL          bool               `bson:"auto_ssl"`
	CertType         string             `bson:"cert_type"`
	CertHash         string             `bson:"cert_hash"`
	CertFile         string             `bson:"cert_file"`
	KeyFile          string             `bson:"key_file"`
	IsClose          bool               `bson:"is_close"`
	AutoHttps        bool               `bson:"auto_https"`
	AutoCORS         bool               `bson:"auto_cors"`
	CompatMode       bool               `bson:"compat_mode"`
	TargetIsHttps    bool               `bson:"target_is_https"`
	Target           targetDoc          `bson:"target"`
	UserAuth         *accountDoc        `bson:"user_auth"`
	MultiAccount     *accountDoc        `bson:"multi_account"`
	Health           healthDoc          `bson:"health"`
	Flow             flowDoc            `bson:"flow"`
}

type globDoc struct {
	ID          string   `bson:"_id"`
	BlackIpList []string `bson:"black_ip_list"`
}

type MongoBackend struct {
	client      *mongo.Client
	db          *mongo.Database
	collClients *mongo.Collection
	collHosts   *mongo.Collection
	collTasks   *mongo.Collection
	collGlobal  *mongo.Collection
	counters    *mongo.Collection
}

type mongoConfig struct {
	URI         string
	Database    string
	Watch       bool
	PollSeconds int
}

var (
	mongoBackend *MongoBackend
	mongoOn      bool
	mongoConf    mongoConfig
)

// SetMongoConfig 由 server 启动时从 nps.conf 注入，避免 lib/file 直接依赖 beego。
func SetMongoConfig(uri, database string, watch bool, pollSeconds int) {
	mongoConf = mongoConfig{URI: uri, Database: database, Watch: watch, PollSeconds: pollSeconds}
	if mongoConf.Database == "" {
		mongoConf.Database = "nps"
	}
	if mongoConf.PollSeconds <= 0 {
		mongoConf.PollSeconds = 5
	}
}

// MongoEnabled 指示当前是否使用 MongoDB 作为共享存储（连接已建立）。
func MongoEnabled() bool { return mongoOn }

// MongoConfigured 指示是否配置了 mongodb_uri（即“意图启用 MongoDB”），
// 在 SetMongoConfig 被调用后立即为真，不依赖于 GetDb() 之后的 mongoOn 标志。
// 用于 relay 动态路由等需要在 GetDb() 置位 mongoOn 之前就判断的场景，
// 避免 initRelay 早于 GetDb() 执行时把动态路由静默关闭。
func MongoConfigured() bool { return mongoConf.URI != "" }

func initMongo(jsonDb *JsonDb) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoConf.URI))
	if err != nil {
		return err
	}
	if err = cli.Ping(ctx, nil); err != nil {
		return err
	}
	db := cli.Database(mongoConf.Database)
	mongoBackend = &MongoBackend{
		client:      cli,
		db:          db,
		collClients: db.Collection("nps_clients"),
		collHosts:   db.Collection("nps_hosts"),
		collTasks:   db.Collection("nps_tasks"),
		collGlobal:  db.Collection("nps_global"),
		counters:    db.Collection("nps_counters"),
	}
	logs.Info("connected to mongodb: %s db=%s", mongoConf.URI, mongoConf.Database)

	// 加载全部实体到内存缓存（一次性，无本地 JSON 种子）
	for _, c := range mongoBackend.loadClients() {
		mergeClient(clientFromDoc(&c), flowFromDoc(c.Flow))
	}
	for _, h := range mongoBackend.loadHosts() {
		mergeHost(hostFromDoc(&h), flowFromDoc(h.Flow))
	}
	for _, t := range mongoBackend.loadTasks() {
		mergeTask(taskFromDoc(&t), flowFromDoc(t.Flow))
	}
	if g := mongoBackend.loadGlobal(); g != nil {
		mergeGlobal(g)
	}

	mongoBackend.ensureIndexes()
	mongoBackend.startSync()
	return nil
}

func (m *MongoBackend) ensureIndexes() {
	// 仅记录错误，不影响主流程
	_, _ = m.collClients.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys:    bson.D{{Key: "vkey", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	_, _ = m.collHosts.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "host", Value: 1}, {Key: "location", Value: 1}},
	})
	_, _ = m.collTasks.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "client_id", Value: 1}},
	})
	_, _ = m.collHosts.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "client_id", Value: 1}},
	})
}

// NextId 使用 nps_counters 集合的 $inc 生成全局唯一、跨节点不冲突的 ID。
func (m *MongoBackend) NextId(t string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{"_id": "seq_" + t}
	update := bson.M{"$inc": bson.M{"seq": 1}}
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	var res struct {
		Seq int `bson:"seq"`
	}
	if err := m.counters.FindOneAndUpdate(ctx, filter, update, opts).Decode(&res); err != nil {
		logs.Error("mongo next id %s error: %v", t, err)
		return 0
	}
	return res.Seq
}

// ---- 加载 ----

func (m *MongoBackend) loadClients() []clientDoc {
	res := make([]clientDoc, 0)
	cur, err := m.collClients.Find(context.Background(), bson.M{})
	if err != nil {
		logs.Error("mongo load clients error: %v", err)
		return res
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var d clientDoc
		if cur.Decode(&d) == nil {
			res = append(res, d)
		}
	}
	return res
}

func (m *MongoBackend) loadHosts() []hostDoc {
	res := make([]hostDoc, 0)
	cur, err := m.collHosts.Find(context.Background(), bson.M{})
	if err != nil {
		logs.Error("mongo load hosts error: %v", err)
		return res
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var d hostDoc
		if cur.Decode(&d) == nil {
			res = append(res, d)
		}
	}
	return res
}

func (m *MongoBackend) loadTasks() []tunnelDoc {
	res := make([]tunnelDoc, 0)
	cur, err := m.collTasks.Find(context.Background(), bson.M{})
	if err != nil {
		logs.Error("mongo load tasks error: %v", err)
		return res
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var d tunnelDoc
		if cur.Decode(&d) == nil {
			res = append(res, d)
		}
	}
	return res
}

func (m *MongoBackend) loadGlobal() *globDoc {
	var g globDoc
	err := m.collGlobal.FindOne(context.Background(), bson.M{"_id": "global"}).Decode(&g)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			logs.Error("mongo load global error: %v", err)
		}
		return nil
	}
	return &g
}

// toObjectID 将结构里的 string Id（ObjectID hex）转为原生 primitive.ObjectID。
// 空串或非法 hex 时生成新的 ObjectID（用于尚未落库的新实体）。
func toObjectID(id string) primitive.ObjectID {
	if id == "" {
		return primitive.NewObjectID()
	}
	if oid, err := primitive.ObjectIDFromHex(id); err == nil {
		return oid
	}
	return primitive.NewObjectID()
}

// ---- 文档 <-> 运行时结构 转换 ----

func flowToDoc(f *Flow) *flowDoc {
	if f == nil {
		return &flowDoc{}
	}
	expire := int64(0)
	if !f.TimeLimit.IsZero() {
		expire = f.TimeLimit.Unix()
	}
	return &flowDoc{Inlet: f.InletFlow, Export: f.ExportFlow, Limit: f.FlowLimit, Expire: expire}
}

func accountFromDoc(a *accountDoc) *MultiAccount {
	if a == nil {
		return nil
	}
	ma := &MultiAccount{Content: a.Content}
	ma.AccountMap = common.DealMultiUser(a.Content)
	return ma
}

func accountToDoc(ma *MultiAccount) *accountDoc {
	if ma == nil {
		return nil
	}
	return &accountDoc{Content: ma.Content}
}

func clientFromDoc(d *clientDoc) *Client {
	c := &Client{
		Cnf: &Config{
			U:        d.Cnf.U,
			P:        d.Cnf.P,
			Compress: d.Cnf.Compress,
			Crypt:    d.Cnf.Crypt,
		},
		Id:              d.ID.Hex(),
		VerifyKey:       d.Vkey,
		Mode:            d.Mode,
		Remark:          d.Remark,
		Status:          d.Status,
		RateLimit:       d.RateLimit,
		MaxConn:         d.MaxConn,
		MaxTunnelNum:    d.MaxTunnelNum,
		WebUserName:     d.WebUserName,
		WebPassword:     d.WebPassword,
		WebTotpSecret:   d.WebTotpSecret,
		ConfigConnAllow: d.ConfigConnAllow,
		Version:         d.Version,
		BlackIpList:     d.BlackIpList,
		CreateTime:      d.CreateTime,
		LastOnlineTime:  d.LastOnlineTime,
		InletFlow:       d.InletFlow,
		ExportFlow:      d.ExportFlow,
		Flow: &Flow{
			InletFlow:  d.Flow.Inlet,
			ExportFlow: d.Flow.Export,
			FlowLimit:  d.Flow.Limit,
		},
	}
	if d.Flow.Expire > 0 {
		c.Flow.TimeLimit = time.Unix(d.Flow.Expire, 0)
	} else {
		c.Flow.TimeLimit = time.Time{}
	}
	return c
}

func clientToDoc(c *Client) clientDoc {
	d := clientDoc{
		ID:              toObjectID(c.Id),
		Vkey:            c.VerifyKey,
		Mode:            c.Mode,
		Remark:          c.Remark,
		Status:          c.Status,
		Cnf:             cnfDoc{},
		RateLimit:       c.RateLimit,
		MaxConn:         c.MaxConn,
		MaxTunnelNum:    c.MaxTunnelNum,
		WebUserName:     c.WebUserName,
		WebPassword:     c.WebPassword,
		WebTotpSecret:   c.WebTotpSecret,
		ConfigConnAllow: c.ConfigConnAllow,
		Version:         c.Version,
		BlackIpList:     c.BlackIpList,
		CreateTime:      c.CreateTime,
		LastOnlineTime:  c.LastOnlineTime,
		InletFlow:       c.InletFlow,
		ExportFlow:      c.ExportFlow,
	}
	if c.Cnf != nil {
		d.Cnf = cnfDoc{U: c.Cnf.U, P: c.Cnf.P, Compress: c.Cnf.Compress, Crypt: c.Cnf.Crypt}
	}
	if c.Flow != nil {
		d.Flow = *flowToDoc(c.Flow)
	}
	return d
}

func taskFromDoc(d *tunnelDoc) *Tunnel {
	t := &Tunnel{
		Id:           d.ID.Hex(),
		Port:         d.Port,
		ServerIp:     d.ServerIp,
		Mode:         d.Mode,
		Status:       d.Status,
		RunStatus:    d.RunStatus,
		Password:     d.Password,
		Remark:       d.Remark,
		TargetAddr:   d.TargetAddr,
		TargetType:   d.TargetType,
		DestAclMode:  d.DestAclMode,
		DestAclRules: d.DestAclRules,
		IsHttp:       d.IsHttp,
		HttpProxy:    d.HttpProxy,
		Socks5Proxy:  d.Socks5Proxy,
		LocalPath:    d.LocalPath,
		StripPre:     d.StripPre,
		ReadOnly:     d.ReadOnly,
		Ports:        d.Ports,
		Client:       &Client{Id: d.ClientId},
		Target: &Target{
			TargetStr:     d.Target.TargetStr,
			LocalProxy:    d.Target.LocalProxy,
			ProxyProtocol: d.Target.ProxyProtocol,
		},
		UserAuth:     accountFromDoc(d.UserAuth),
		MultiAccount: accountFromDoc(d.MultiAccount),
		Flow: &Flow{
			InletFlow:  d.Flow.Inlet,
			ExportFlow: d.Flow.Export,
			FlowLimit:  d.Flow.Limit,
		},
		Health: Health{
			HealthCheckTimeout:  d.Health.Timeout,
			HealthMaxFail:       d.Health.MaxFail,
			HealthCheckInterval: d.Health.Interval,
			HttpHealthUrl:       d.Health.HttpUrl,
			HealthRemoveArr:     d.Health.RemoveArr,
			HealthCheckType:     d.Health.Type,
			HealthCheckTarget:   d.Health.Target,
		},
	}
	if d.Flow.Expire > 0 {
		t.Flow.TimeLimit = time.Unix(d.Flow.Expire, 0)
	} else {
		t.Flow.TimeLimit = time.Time{}
	}
	return t
}

func taskToDoc(t *Tunnel) tunnelDoc {
	d := tunnelDoc{
		ID:           toObjectID(t.Id),
		ClientId:     clientIdOf(t.Client),
		Port:         t.Port,
		ServerIp:     t.ServerIp,
		Mode:         t.Mode,
		Status:       t.Status,
		RunStatus:    t.RunStatus,
		Password:     t.Password,
		Remark:       t.Remark,
		TargetAddr:   t.TargetAddr,
		TargetType:   t.TargetType,
		DestAclMode:  t.DestAclMode,
		DestAclRules: t.DestAclRules,
		IsHttp:       t.IsHttp,
		HttpProxy:    t.HttpProxy,
		Socks5Proxy:  t.Socks5Proxy,
		LocalPath:    t.LocalPath,
		StripPre:     t.StripPre,
		ReadOnly:     t.ReadOnly,
		Ports:        t.Ports,
		UserAuth:     accountToDoc(t.UserAuth),
		MultiAccount: accountToDoc(t.MultiAccount),
		Health: healthDoc{
			Timeout:   t.HealthCheckTimeout,
			MaxFail:   t.HealthMaxFail,
			Interval:  t.HealthCheckInterval,
			HttpUrl:   t.HttpHealthUrl,
			RemoveArr: t.HealthRemoveArr,
			Type:      t.HealthCheckType,
			Target:    t.HealthCheckTarget,
		},
	}
	if t.Target != nil {
		d.Target = targetDoc{
			TargetStr:     t.Target.TargetStr,
			LocalProxy:    t.Target.LocalProxy,
			ProxyProtocol: t.Target.ProxyProtocol,
		}
	}
	if t.Flow != nil {
		d.Flow = *flowToDoc(t.Flow)
	}
	return d
}

func hostFromDoc(d *hostDoc) *Host {
	h := &Host{
		Id:               d.ID.Hex(),
		Host:             d.Host,
		HeaderChange:     d.HeaderChange,
		RespHeaderChange: d.RespHeaderChange,
		HostChange:       d.HostChange,
		Location:         d.Location,
		PathRewrite:      d.PathRewrite,
		Remark:           d.Remark,
		Scheme:           d.Scheme,
		RedirectURL:      d.RedirectURL,
		HttpsJustProxy:   d.HttpsJustProxy,
		TlsOffload:       d.TlsOffload,
		AutoSSL:          d.AutoSSL,
		CertType:         d.CertType,
		CertHash:         d.CertHash,
		CertFile:         d.CertFile,
		KeyFile:          d.KeyFile,
		IsClose:          d.IsClose,
		AutoHttps:        d.AutoHttps,
		AutoCORS:         d.AutoCORS,
		CompatMode:       d.CompatMode,
		TargetIsHttps:    d.TargetIsHttps,
		Client:           &Client{Id: d.ClientId},
		UserAuth:         accountFromDoc(d.UserAuth),
		MultiAccount:     accountFromDoc(d.MultiAccount),
		Flow: &Flow{
			InletFlow:  d.Flow.Inlet,
			ExportFlow: d.Flow.Export,
			FlowLimit:  d.Flow.Limit,
		},
		Health: Health{
			HealthCheckTimeout:  d.Health.Timeout,
			HealthMaxFail:       d.Health.MaxFail,
			HealthCheckInterval: d.Health.Interval,
			HttpHealthUrl:       d.Health.HttpUrl,
			HealthRemoveArr:     d.Health.RemoveArr,
			HealthCheckType:     d.Health.Type,
			HealthCheckTarget:   d.Health.Target,
		},
	}
	if d.Flow.Expire > 0 {
		h.Flow.TimeLimit = time.Unix(d.Flow.Expire, 0)
	} else {
		h.Flow.TimeLimit = time.Time{}
	}
	if h.Target == nil {
		h.Target = &Target{}
	}
	if d.Target.TargetStr != "" || d.Target.LocalProxy || d.Target.ProxyProtocol != 0 {
		h.Target.TargetStr = d.Target.TargetStr
		h.Target.LocalProxy = d.Target.LocalProxy
		h.Target.ProxyProtocol = d.Target.ProxyProtocol
	}
	return h
}

func hostToDoc(h *Host) hostDoc {
	d := hostDoc{
		ID:               toObjectID(h.Id),
		ClientId:         clientIdOf(h.Client),
		Host:             h.Host,
		HeaderChange:     h.HeaderChange,
		RespHeaderChange: h.RespHeaderChange,
		HostChange:       h.HostChange,
		Location:         h.Location,
		PathRewrite:      h.PathRewrite,
		Remark:           h.Remark,
		Scheme:           h.Scheme,
		RedirectURL:      h.RedirectURL,
		HttpsJustProxy:   h.HttpsJustProxy,
		TlsOffload:       h.TlsOffload,
		AutoSSL:          h.AutoSSL,
		CertType:         h.CertType,
		CertHash:         h.CertHash,
		CertFile:         h.CertFile,
		KeyFile:          h.KeyFile,
		IsClose:          h.IsClose,
		AutoHttps:        h.AutoHttps,
		AutoCORS:         h.AutoCORS,
		CompatMode:       h.CompatMode,
		TargetIsHttps:    h.TargetIsHttps,
		UserAuth:         accountToDoc(h.UserAuth),
		MultiAccount:     accountToDoc(h.MultiAccount),
		Health: healthDoc{
			Timeout:   h.HealthCheckTimeout,
			MaxFail:   h.HealthMaxFail,
			Interval:  h.HealthCheckInterval,
			HttpUrl:   h.HttpHealthUrl,
			RemoveArr: h.HealthRemoveArr,
			Type:      h.HealthCheckType,
			Target:    h.HealthCheckTarget,
		},
	}
	if h.Target != nil {
		d.Target = targetDoc{
			TargetStr:     h.Target.TargetStr,
			LocalProxy:    h.Target.LocalProxy,
			ProxyProtocol: h.Target.ProxyProtocol,
		}
	}
	if h.Flow != nil {
		d.Flow = *flowToDoc(h.Flow)
	}
	return d
}

func clientIdOf(c *Client) string {
	if c == nil {
		return ""
	}
	return c.Id
}

// ---- 落盘（替代原 StoreXxxToJsonFile）----

// upsertEntity 把配置写入集合（$set 全部配置字段），flow 仅在首次插入时写入（$setOnInsert），
// 这样后续配置保存不会覆盖其他节点通过 FlushFlowToMongo 写回的流量统计。
func (m *MongoBackend) upsertEntity(coll *mongo.Collection, id string, v interface{}, flow *flowDoc) {
	b, err := bson.Marshal(v)
	if err != nil {
		logs.Error("mongo marshal error: %v", err)
		return
	}
	var set bson.M
	if err := bson.Unmarshal(b, &set); err != nil {
		logs.Error("mongo unmarshal set error: %v", err)
		return
	}
	delete(set, "flow")
	delete(set, "_id") // _id 不可被 $set 修改，且已由 filter 指定
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	update := bson.M{"$set": set}
	if flow != nil {
		update["$setOnInsert"] = bson.M{"flow": flow}
	}
	if _, err := coll.UpdateOne(ctx, bson.M{"_id": toObjectID(id)}, update, options.Update().SetUpsert(true)); err != nil {
		logs.Error("mongo upsert %s error: %v", id, err)
	}
}

func (m *MongoBackend) updateFlow(coll *mongo.Collection, id string, flow *Flow) {
	if flow == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := coll.UpdateOne(ctx, bson.M{"_id": toObjectID(id)}, bson.M{"$set": bson.M{"flow": flowToDoc(flow)}}); err != nil {
		logs.Error("mongo update flow %s error: %v", id, err)
	}
}

func (m *MongoBackend) Delete(t string, id string) {
	var coll *mongo.Collection
	switch t {
	case mongoTypeClient:
		coll = m.collClients
	case mongoTypeHost:
		coll = m.collHosts
	case mongoTypeTask:
		coll = m.collTasks
	}
	if coll == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := coll.DeleteOne(ctx, bson.M{"_id": toObjectID(id)}); err != nil {
		logs.Error("mongo delete %s %s error: %v", t, id, err)
	}
}

func (m *MongoBackend) SaveAllClients() {
	Db.JsonDb.Clients.Range(func(k, v interface{}) bool {
		c := v.(*Client)
		if c.NoStore {
			return true
		}
		m.upsertEntity(m.collClients, c.Id, clientToDoc(c), flowToDoc(c.Flow))
		return true
	})
}

func (m *MongoBackend) SaveAllHosts() {
	Db.JsonDb.Hosts.Range(func(k, v interface{}) bool {
		h := v.(*Host)
		if h.NoStore {
			return true
		}
		m.upsertEntity(m.collHosts, h.Id, hostToDoc(h), flowToDoc(h.Flow))
		return true
	})
}

func (m *MongoBackend) SaveAllTasks() {
	Db.JsonDb.Tasks.Range(func(k, v interface{}) bool {
		t := v.(*Tunnel)
		if t.NoStore {
			return true
		}
		m.upsertEntity(m.collTasks, t.Id, taskToDoc(t), flowToDoc(t.Flow))
		return true
	})
}

func (m *MongoBackend) SaveGlobalDoc() {
	if Db.JsonDb.Global == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := m.collGlobal.UpdateOne(ctx, bson.M{"_id": "global"},
		bson.M{"$set": bson.M{"black_ip_list": Db.JsonDb.Global.BlackIpList}},
		options.Update().SetUpsert(true)); err != nil {
		logs.Error("mongo save global error: %v", err)
	}
}

// ---- 合并远端变更到本地缓存 ----

func mergeClient(c *Client, flow *Flow) {
	if c == nil || c.Id == "" {
		return
	}
	if flow != nil {
		c.Flow = flow
	} else if c.Flow == nil {
		c.Flow = new(Flow)
	}
	if c.RateLimit > 0 {
		c.Rate = rate.NewRate(int64(c.RateLimit) * 1024)
	} else {
		c.Rate = rate.NewRate(0)
	}
	c.Rate.Start()
	// 保留本节点上该 client 的运行态（连接中），避免被其他节点的配置副本覆盖
	if existing, ok := Db.JsonDb.Clients.Load(c.Id); ok {
		ec := existing.(*Client)
		if ec.IsConnect {
			c.IsConnect = ec.IsConnect
			c.Addr = ec.Addr
			c.LocalAddr = ec.LocalAddr
			c.NowConn = ec.NowConn
			c.Rate = ec.Rate
			c.Version = ec.Version
			c.LastOnlineTime = ec.LastOnlineTime
		}
	}
	Db.JsonDb.Clients.Store(c.Id, c)
	Blake2bVkeyIndex.Add(crypt.Blake2b(c.VerifyKey), c.Id)
}

func mergeHost(h *Host, flow *Flow) {
	if h == nil || h.Id == "" {
		return
	}
	if flow != nil {
		h.Flow = flow
	} else if h.Flow == nil {
		h.Flow = new(Flow)
	}
	if h.Client != nil {
		if c, err := Db.GetClient(h.Client.Id); err == nil {
			h.Client = c
		}
	}
	if h.Location == "" {
		h.Location = "/"
	}
	if h.CertType == "" {
		h.CertType = common.GetCertType(h.CertFile)
	}
	if h.CertHash == "" {
		h.CertHash = crypt.FNV1a64(h.CertType, h.CertFile, h.KeyFile)
	}
	if existing, ok := Db.JsonDb.Hosts.Load(h.Id); ok {
		eh := existing.(*Host)
		if eh.NowConn > 0 {
			h.NowConn = eh.NowConn
		}
	}
	HostIndex.Add(h.Host, h.Id)
	Db.JsonDb.Hosts.Store(h.Id, h)
}

func mergeTask(t *Tunnel, flow *Flow) {
	if t == nil || t.Id == "" {
		return
	}
	if flow != nil {
		t.Flow = flow
	} else if t.Flow == nil {
		t.Flow = new(Flow)
	}
	if t.Client != nil {
		if c, err := Db.GetClient(t.Client.Id); err == nil {
			t.Client = c
		}
	}
	switch t.Mode {
	case "socks5":
		t.Mode = "mixProxy"
		t.HttpProxy = false
		t.Socks5Proxy = true
	case "httpProxy":
		t.Mode = "mixProxy"
		t.HttpProxy = true
		t.Socks5Proxy = false
	}
	if t.TargetType != common.CONN_TCP && t.TargetType != common.CONN_UDP {
		t.TargetType = common.CONN_ALL
	}
	t.CompileDestACL()
	if t.Password != "" {
		TaskPasswordIndex.Add(crypt.Md5(t.Password), t.Id)
	}
	if existing, ok := Db.JsonDb.Tasks.Load(t.Id); ok {
		et := existing.(*Tunnel)
		if et.NowConn > 0 {
			t.NowConn = et.NowConn
		}
	}
	Db.JsonDb.Tasks.Store(t.Id, t)
}

func mergeGlobal(g *globDoc) {
	if g == nil {
		return
	}
	Db.JsonDb.Global = &Glob{BlackIpList: g.BlackIpList}
}

func applyDelete(t string, id string) {
	switch t {
	case mongoTypeClient:
		if v, ok := Db.JsonDb.Clients.Load(id); ok {
			c := v.(*Client)
			if c.IsConnect {
				return // 本节点正在连接，保留，避免中断在线客户端
			}
			Blake2bVkeyIndex.Remove(crypt.Blake2b(c.VerifyKey))
			Db.JsonDb.Clients.Delete(id)
		}
	case mongoTypeHost:
		if v, ok := Db.JsonDb.Hosts.Load(id); ok {
			h := v.(*Host)
			if h.Client != nil && h.Client.IsConnect {
				return
			}
			HostIndex.Remove(h.Host, id)
			Db.JsonDb.Hosts.Delete(id)
		}
	case mongoTypeTask:
		if v, ok := Db.JsonDb.Tasks.Load(id); ok {
			t := v.(*Tunnel)
			if t.Client != nil && t.Client.IsConnect {
				return
			}
			TaskPasswordIndex.Remove(crypt.Md5(t.Password))
			Db.JsonDb.Tasks.Delete(id)
		}
	}
}

// ---- 跨节点同步 ----

func (m *MongoBackend) startSync() {
	if mongoConf.Watch {
		go m.watchCollection(m.collClients, mongoTypeClient)
		go m.watchCollection(m.collHosts, mongoTypeHost)
		go m.watchCollection(m.collTasks, mongoTypeTask)
		go m.watchCollection(m.collGlobal, mongoTypeGlobal)
	}
	if mongoConf.PollSeconds > 0 {
		go m.pollLoop()
	}
}

type csEvent struct {
	OperationType string   `bson:"operationType"`
	FullDocument  bson.Raw `bson:"fullDocument"`
	DocKey        struct {
		ID primitive.ObjectID `bson:"_id"`
	} `bson:"documentKey"`
}

func (m *MongoBackend) watchCollection(coll *mongo.Collection, kind string) {
	ctx := context.Background()
	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	cs, err := coll.Watch(ctx, mongo.Pipeline{}, opts)
	if err != nil {
		logs.Warn("mongodb change stream unsupported on %s (needs a replica set); falling back to polling: %v", kind, err)
		return
	}
	defer cs.Close(ctx)
	logs.Info("mongodb sync: watching change stream on %s", kind)
	for cs.Next(ctx) {
		var ev csEvent
		if err := cs.Decode(&ev); err != nil {
			continue
		}
		switch ev.OperationType {
		case "insert", "update", "replace":
			m.applyFullDocument(kind, ev.FullDocument)
		case "delete":
			applyDelete(kind, ev.DocKey.ID.Hex())
		}
	}
	if err := cs.Err(); err != nil {
		logs.Warn("mongodb watch error on %s: %v", kind, err)
	}
}

func (m *MongoBackend) applyFullDocument(kind string, raw bson.Raw) {
	switch kind {
	case mongoTypeClient:
		var d clientDoc
		if bson.Unmarshal(raw, &d) == nil {
			mergeClient(clientFromDoc(&d), flowFromDoc(d.Flow))
		}
	case mongoTypeHost:
		var d hostDoc
		if bson.Unmarshal(raw, &d) == nil {
			mergeHost(hostFromDoc(&d), flowFromDoc(d.Flow))
		}
	case mongoTypeTask:
		var d tunnelDoc
		if bson.Unmarshal(raw, &d) == nil {
			mergeTask(taskFromDoc(&d), flowFromDoc(d.Flow))
		}
	case mongoTypeGlobal:
		var d globDoc
		if bson.Unmarshal(raw, &d) == nil {
			mergeGlobal(&d)
		}
	}
}

func (m *MongoBackend) pollLoop() {
	ticker := time.NewTicker(time.Duration(mongoConf.PollSeconds) * time.Second)
	defer ticker.Stop()
	logs.Info("mongodb sync: polling every %ds", mongoConf.PollSeconds)
	for range ticker.C {
		m.syncOnce()
	}
}

func (m *MongoBackend) syncOnce() {
	clients := m.loadClients()
	hosts := m.loadHosts()
	tasks := m.loadTasks()
	g := m.loadGlobal()

	for i := range clients {
		mergeClient(clientFromDoc(&clients[i]), flowFromDoc(clients[i].Flow))
	}
	for i := range hosts {
		mergeHost(hostFromDoc(&hosts[i]), flowFromDoc(hosts[i].Flow))
	}
	for i := range tasks {
		mergeTask(taskFromDoc(&tasks[i]), flowFromDoc(tasks[i].Flow))
	}
	if g != nil {
		mergeGlobal(g)
	}
	m.detectDeletes(clients, hosts, tasks)
}

// detectDeletes 处理在 MongoDB 中被其他节点删除、但本地缓存尚存的实体。
func (m *MongoBackend) detectDeletes(clients []clientDoc, hosts []hostDoc, tasks []tunnelDoc) {
	live := map[string]bool{}
	for _, d := range clients {
		live[d.ID.Hex()] = true
	}
	Db.JsonDb.Clients.Range(func(k, v interface{}) bool {
		id := k.(string)
		if !live[id] {
			c := v.(*Client)
			if c.IsConnect {
				return true
			}
			Blake2bVkeyIndex.Remove(crypt.Blake2b(c.VerifyKey))
			Db.JsonDb.Clients.Delete(id)
		}
		return true
	})

	live = map[string]bool{}
	for _, d := range hosts {
		live[d.ID.Hex()] = true
	}
	Db.JsonDb.Hosts.Range(func(k, v interface{}) bool {
		id := k.(string)
		if !live[id] {
			h := v.(*Host)
			if h.Client != nil && h.Client.IsConnect {
				return true
			}
			HostIndex.Remove(h.Host, id)
			Db.JsonDb.Hosts.Delete(id)
		}
		return true
	})

	live = map[string]bool{}
	for _, d := range tasks {
		live[d.ID.Hex()] = true
	}
	Db.JsonDb.Tasks.Range(func(k, v interface{}) bool {
		id := k.(string)
		if !live[id] {
			t := v.(*Tunnel)
			if t.Client != nil && t.Client.IsConnect {
				return true
			}
			TaskPasswordIndex.Remove(crypt.Md5(t.Password))
			Db.JsonDb.Tasks.Delete(id)
		}
		return true
	})
}

// FlushFlowToMongo 仅把"本节点持有连接"的实体的流量写回 MongoDB，避免跨节点覆盖。
func (s *JsonDb) FlushFlowToMongo() {
	if !mongoOn || mongoBackend == nil {
		return
	}
	s.Clients.Range(func(k, v interface{}) bool {
		c := v.(*Client)
		if c.IsConnect {
			mongoBackend.updateFlow(mongoBackend.collClients, c.Id, c.Flow)
		}
		return true
	})
	s.Hosts.Range(func(k, v interface{}) bool {
		h := v.(*Host)
		if h.Client != nil && h.Client.IsConnect {
			mongoBackend.updateFlow(mongoBackend.collHosts, h.Id, h.Flow)
		}
		return true
	})
	s.Tasks.Range(func(k, v interface{}) bool {
		t := v.(*Tunnel)
		if t.Client != nil && t.Client.IsConnect {
			mongoBackend.updateFlow(mongoBackend.collTasks, t.Id, t.Flow)
		}
		return true
	})
}

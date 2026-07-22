package file

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/index"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/rate"
)

type DbUtils struct {
	JsonDb *JsonDb
}

var (
	Db                *DbUtils
	once              sync.Once
	HostIndex         = index.NewDomainIndex()
	Blake2bVkeyIndex  = index.NewStringIDIndex()
	TaskPasswordIndex = index.NewStringIDIndex()

	errClientNotFound = errors.New("can not find client")
)

// GetDb init data from mongodb（唯一持久层；未配置 mongodb_uri 直接报错退出）
func GetDb() *DbUtils {
	once.Do(func() {
		jsonDb := NewJsonDb(common.GetRunPath())
		Db = &DbUtils{JsonDb: jsonDb}
		if mongoConf.URI == "" {
			logs.Error("mongodb_uri is not configured; nps requires MongoDB as the sole storage backend")
			panic("mongodb_uri is required: nps aborts because local JSON storage has been removed")
		}
		if err := initMongo(jsonDb); err != nil {
			logs.Error("init mongodb failed: %v", err)
			panic(err)
		}
		mongoOn = true
	})
	return Db
}

func GetMapKeys(m *sync.Map, isSort bool, sortKey, order string) (keys []string) {
	if (sortKey == "InletFlow" || sortKey == "ExportFlow") && isSort {
		return sortClientByKey(m, sortKey, order)
	}
	m.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})
	sort.Strings(keys)
	return
}

func (s *DbUtils) GetClientList(start, length int, search, sort, order string, clientId string) ([]*Client, int) {
	list := make([]*Client, 0)
	var cnt int
	originLength := length
	id := search
	keys := GetMapKeys(&s.JsonDb.Clients, true, sort, order)
	for _, key := range keys {
		if value, ok := s.JsonDb.Clients.Load(key); ok {
			v := value.(*Client)
			if v.NoDisplay {
				continue
			}
			if clientId != "" && clientId != v.Id {
				continue
			}
			if search != "" && v.Id != id && !common.ContainsFold(v.VerifyKey, search) && !common.ContainsFold(v.Remark, search) {
				continue
			}
			cnt++
			if start--; start < 0 {
				if originLength == 0 {
					list = append(list, v)
				} else if length--; length >= 0 {
					list = append(list, v)
				}
			}
		}
	}
	return list, cnt
}

func (s *DbUtils) GetIdByVerifyKey(vKey, addr, localAddr string, hashFunc func(string) string) (id string, err error) {
	var exist bool
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if hashFunc(v.VerifyKey) == vKey && v.Status && v.Id != "" {
			v.Addr = common.GetIpByAddr(addr)
			v.LocalAddr = common.GetIpByAddr(localAddr)
			id = v.Id
			exist = true
			return false
		}
		return true
	})
	if exist {
		return
	}
	return "", errors.New("not found")
}

func (s *DbUtils) GetClientIdByBlake2bVkey(vkey string) (id string, err error) {
	id, ok := Blake2bVkeyIndex.Get(vkey)
	if ok {
		return
	}
	err = errors.New("can not find client")
	return
}

func (s *DbUtils) GetClientIdByMd5Vkey(vkey string) (id string, err error) {
	var exist bool
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if crypt.Md5(v.VerifyKey) == vkey {
			exist = true
			id = v.Id
			return false
		}
		return true
	})
	if exist {
		return
	}
	err = errors.New("can not find client")
	return
}

func (s *DbUtils) NewTask(t *Tunnel) (err error) {
	//s.JsonDb.Tasks.Range(func(key, value interface{}) bool {
	//	v := value.(*Tunnel)
	//	if (v.Mode == "secret" || v.Mode == "p2p") && (t.Mode == "secret" || t.Mode == "p2p") && v.Password == t.Password {
	//		err = errors.New(fmt.Sprintf("secret mode keys %s must be unique", t.Password))
	//		return false
	//	}
	//	return true
	//})
	//if err != nil {
	//	return
	//}
	if (t.Mode == "secret" || t.Mode == "p2p") && t.Password == "" {
		t.Password = crypt.GetRandomString(16, t.Id)
	}

	t.Flow = new(Flow)

	if t.Password != "" {
		for {
			hash := crypt.Md5(t.Password)
			if idxId, ok := TaskPasswordIndex.Get(hash); !ok || idxId == t.Id {
				TaskPasswordIndex.Add(hash, t.Id)
				break
			}
			t.Password = crypt.GetRandomString(16, t.Id)
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
	s.JsonDb.Tasks.Store(t.Id, t)
	s.JsonDb.StoreTasksToJsonFile()
	return
}

func (s *DbUtils) UpdateTask(t *Tunnel) error {
	if (t.Mode == "secret" || t.Mode == "p2p") && t.Password == "" {
		t.Password = crypt.GetRandomString(16, t.Id)
	}

	if v, ok := s.JsonDb.Tasks.Load(t.Id); ok {
		if oldPwd := v.(*Tunnel).Password; oldPwd != "" {
			if idxId, ok := TaskPasswordIndex.Get(crypt.Md5(oldPwd)); ok && idxId == t.Id {
				TaskPasswordIndex.Remove(crypt.Md5(oldPwd))
			}
		}
	}

	if t.Password != "" {
		for {
			hash := crypt.Md5(t.Password)
			if idxId, ok := TaskPasswordIndex.Get(hash); !ok || idxId == t.Id {
				TaskPasswordIndex.Add(hash, t.Id)
				break
			}
			t.Password = crypt.GetRandomString(16, t.Id)
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
	s.JsonDb.Tasks.Store(t.Id, t)
	s.JsonDb.StoreTasksToJsonFile()
	return nil
}

func (s *DbUtils) SaveGlobal(t *Glob) error {
	s.JsonDb.Global = t
	s.JsonDb.StoreGlobalToJsonFile()
	return nil
}

func (s *DbUtils) DelTask(id string) error {
	if v, ok := s.JsonDb.Tasks.Load(id); ok {
		t := v.(*Tunnel)
		TaskPasswordIndex.Remove(crypt.Md5(t.Password))
	}
	s.JsonDb.Tasks.Delete(id)
	if mongoOn && mongoBackend != nil {
		mongoBackend.Delete(mongoTypeTask, id)
	}
	s.JsonDb.StoreTasksToJsonFile()
	return nil
}

// GetTaskByMd5Password md5 password
func (s *DbUtils) GetTaskByMd5Password(p string) (t *Tunnel) {
	id, ok := TaskPasswordIndex.Get(p)
	if ok {
		if v, ok := s.JsonDb.Tasks.Load(id); ok {
			t = v.(*Tunnel)
			return
		}
	}
	return
}

func (s *DbUtils) GetTaskByMd5PasswordOld(p string) (t *Tunnel) {
	s.JsonDb.Tasks.Range(func(key, value interface{}) bool {
		if crypt.Md5(value.(*Tunnel).Password) == p {
			t = value.(*Tunnel)
			return false
		}
		return true
	})
	return
}

func (s *DbUtils) GetTask(id string) (t *Tunnel, err error) {
	if v, ok := s.JsonDb.Tasks.Load(id); ok {
		t = v.(*Tunnel)
		return
	}
	err = errors.New("not found")
	return
}

func (s *DbUtils) DelHost(id string) error {
	if v, ok := s.JsonDb.Hosts.Load(id); ok {
		h := v.(*Host)
		HostIndex.Remove(h.Host, id)
	}
	s.JsonDb.Hosts.Delete(id)
	if mongoOn && mongoBackend != nil {
		mongoBackend.Delete(mongoTypeHost, id)
	}
	s.JsonDb.StoreHostToJsonFile()
	return nil
}

func (s *DbUtils) IsHostExist(h *Host) bool {
	var exist bool
	if h.Location == "" {
		h.Location = "/"
	}
	s.JsonDb.Hosts.Range(func(key, value interface{}) bool {
		v := value.(*Host)
		if v.Location == "" {
			v.Location = "/"
		}
		if v.Id != h.Id && v.Host == h.Host && h.Location == v.Location && (v.Scheme == "all" || v.Scheme == h.Scheme) {
			exist = true
			return false
		}
		return true
	})
	return exist
}

func (s *DbUtils) IsHostModify(h *Host) bool {
	if h == nil {
		return true
	}

	existingHost, err := s.GetHostById(h.Id)
	if err != nil {
		return true
	}

	if existingHost.IsClose != h.IsClose ||
		existingHost.Host != h.Host ||
		existingHost.Location != h.Location ||
		existingHost.Scheme != h.Scheme ||
		existingHost.HttpsJustProxy != h.HttpsJustProxy ||
		existingHost.CertFile != h.CertFile ||
		existingHost.KeyFile != h.KeyFile {
		return true
	}

	return false
}

func (s *DbUtils) NewHost(t *Host) error {
	if t.Location == "" {
		t.Location = "/"
	}
	if t.Scheme != "all" && t.Scheme != "http" && t.Scheme != "https" {
		t.Scheme = "all"
	}
	if s.IsHostExist(t) {
		return errors.New("host has exist")
	}
	HostIndex.Add(t.Host, t.Id)
	t.CertType = common.GetCertType(t.CertFile)
	t.CertHash = crypt.FNV1a64(t.CertType, t.CertFile, t.KeyFile)
	t.Flow = new(Flow)
	s.JsonDb.Hosts.Store(t.Id, t)
	s.JsonDb.StoreHostToJsonFile()
	return nil
}

func (s *DbUtils) GetHost(start, length int, id string, search string) ([]*Host, int) {
	list := make([]*Host, 0)
	var cnt int
	originLength := length
	keys := GetMapKeys(&s.JsonDb.Hosts, false, "", "")
	for _, key := range keys {
		if value, ok := s.JsonDb.Hosts.Load(key); ok {
			v := value.(*Host)
			if search != "" && v.Id != search && !common.ContainsFold(v.Host, search) && !common.ContainsFold(v.Remark, search) && !common.ContainsFold(v.Client.VerifyKey, search) {
				continue
			}
			if id == "" || v.Client.Id == id {
				cnt++
				if start--; start < 0 {
					if originLength == 0 {
						list = append(list, v)
					} else if length--; length >= 0 {
						list = append(list, v)
					}
				}
			}
		}
	}
	return list, cnt
}

func (s *DbUtils) DelClient(id string) error {
	if v, ok := s.JsonDb.Clients.Load(id); ok {
		c := v.(*Client)
		Blake2bVkeyIndex.Remove(crypt.Blake2b(c.VerifyKey))
		if c.Rate != nil {
			c.Rate.Stop()
		}
	}
	s.JsonDb.Clients.Delete(id)
	if mongoOn && mongoBackend != nil {
		mongoBackend.Delete(mongoTypeClient, id)
	}
	s.JsonDb.StoreClientsToJsonFile()
	return nil
}

func (s *DbUtils) NewClient(c *Client) error {
	var isNotSet bool
	if c.WebUserName != "" && !s.VerifyUserName(c.WebUserName, c.Id) {
		return errors.New("web login username duplicate, please reset")
	}
	c.EnsureWebPassword()
reset:
	if c.VerifyKey == "" || isNotSet {
		isNotSet = true
		c.VerifyKey = crypt.GetRandomString(16, c.Id)
	}
	if !s.VerifyVkey(c.VerifyKey, c.Id) {
		if isNotSet {
			goto reset
		}
		return errors.New("vkey duplicate, please reset")
	}
	if c.RateLimit == 0 {
		c.Rate = rate.NewRate(0)
	} else if c.Rate == nil {
		c.Rate = rate.NewRate(int64(c.RateLimit) * 1024)
	}
	c.Rate.Start()
	if c.Id == "" {
		c.Id = NewObjectID()
	}
	if c.Flow == nil {
		c.Flow = new(Flow)
	}
	s.JsonDb.Clients.Store(c.Id, c)
	Blake2bVkeyIndex.Add(crypt.Blake2b(c.VerifyKey), c.Id)
	s.JsonDb.StoreClientsToJsonFile()
	return nil
}

func (s *DbUtils) VerifyVkey(vkey string, id string) (res bool) {
	res = true
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if v.VerifyKey == vkey && v.Id != id {
			res = false
			return false
		}
		return true
	})
	return res
}

func (s *DbUtils) VerifyUserName(username string, id string) (res bool) {
	res = true
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if v.WebUserName == username && v.Id != id {
			res = false
			return false
		}
		return true
	})
	return res
}

func (s *DbUtils) UpdateClient(t *Client) error {
	if v, ok := s.JsonDb.Clients.Load(t.Id); ok {
		c := v.(*Client)
		Blake2bVkeyIndex.Remove(crypt.Blake2b(c.VerifyKey))
		if t.Rate == nil {
			t.Rate = c.Rate
		}
	}

	s.JsonDb.Clients.Store(t.Id, t)
	Blake2bVkeyIndex.Add(crypt.Blake2b(t.VerifyKey), t.Id)
	var limit int64
	if t.RateLimit > 0 {
		limit = int64(t.RateLimit) * 1024
	} else {
		limit = 0
	}
	if t.Rate != nil {
		if t.Rate.Limit() != limit {
			t.Rate.ResetLimit(limit)
		} else {
			t.Rate.Start()
		}
	} else {
		t.Rate = rate.NewRate(limit)
		t.Rate.Start()
	}
	if mongoOn && mongoBackend != nil {
		mongoBackend.SaveAllClients()
	}
	return nil
}

func (s *DbUtils) IsPubClient(id string) bool {
	client, err := s.GetClient(id)
	if err == nil {
		return client.NoDisplay
	}
	return false
}

func (s *DbUtils) GetClient(id string) (c *Client, err error) {
	if v, ok := s.JsonDb.Clients.Load(id); ok {
		c = v.(*Client)
		return
	}
	err = errors.New("can not find client")
	return
}

func (s *DbUtils) GetGlobal() (c *Glob) {
	return s.JsonDb.Global
}

func (s *DbUtils) GetHostById(id string) (h *Host, err error) {
	if v, ok := s.JsonDb.Hosts.Load(id); ok {
		h = v.(*Host)
		return
	}
	err = errors.New("the host could not be parsed")
	return
}

// GetInfoByHost get key by host from x
func (s *DbUtils) GetInfoByHost(host string, r *http.Request) (h *Host, err error) {
	host = common.GetIpByAddr(host)
	hostLength := len(host)

	requestPath := r.RequestURI
	if requestPath == "" {
		requestPath = "/"
	}

	scheme := r.URL.Scheme

	ids := HostIndex.Lookup(host)
	if len(ids) == 0 {
		return nil, errors.New("the host could not be parsed")
	}

	var bestMatch *Host
	var bestDomainLength int
	var bestLocationLength int
	for _, id := range ids {
		value, ok := s.JsonDb.Hosts.Load(id)
		if !ok {
			continue
		}
		v := value.(*Host)

		if v.IsClose || (v.Scheme != "all" && v.Scheme != scheme) {
			continue
		}

		curDomainLength := len(strings.TrimPrefix(v.Host, "*"))
		if hostLength < curDomainLength {
			continue
		}

		equaled := v.Host == host
		matched := equaled || (strings.HasPrefix(v.Host, "*") && strings.HasSuffix(host, v.Host[1:]))
		if !matched {
			continue
		}

		location := v.Location
		if location == "" {
			location = "/"
		}

		if !strings.HasPrefix(requestPath, location) {
			continue
		}

		curLocationLength := len(location)
		if bestMatch == nil {
			bestMatch = v
			bestDomainLength = curDomainLength
			bestLocationLength = curLocationLength
			continue
		}
		if curLocationLength > bestLocationLength {
			bestMatch = v
			bestDomainLength = curDomainLength
			bestLocationLength = curLocationLength
			continue
		}
		if curLocationLength == bestLocationLength {
			if curDomainLength > bestDomainLength {
				bestMatch = v
				bestDomainLength = curDomainLength
				bestLocationLength = curLocationLength
				continue
			}
			if equaled {
				bestMatch = v
				bestDomainLength = curDomainLength
				bestLocationLength = curLocationLength
				continue
			}
		}
	}

	if bestMatch != nil {
		return bestMatch, nil
	}
	return nil, errors.New("the host could not be parsed")
}

func (s *DbUtils) FindCertByHost(host string) (*Host, error) {
	if host == "" {
		return nil, errors.New("invalid Host")
	}

	host = common.GetIpByAddr(host)
	hostLength := len(host)

	ids := HostIndex.Lookup(host)
	if len(ids) == 0 {
		return nil, errors.New("the host could not be parsed")
	}

	var bestMatch *Host
	var bestDomainLength int
	for _, id := range ids {
		value, ok := s.JsonDb.Hosts.Load(id)
		if !ok {
			continue
		}
		v := value.(*Host)

		if v.IsClose || (v.Scheme == "http") {
			continue
		}

		curDomainLength := len(strings.TrimPrefix(v.Host, "*"))
		if hostLength < curDomainLength {
			continue
		}

		equaled := v.Host == host
		matched := false
		location := v.Location == "/" || v.Location == ""
		if equaled {
			if location {
				bestMatch = v
				break
			}
			matched = true
		} else if strings.HasPrefix(v.Host, "*") && strings.HasSuffix(host, v.Host[1:]) {
			matched = true
		}
		if !matched {
			continue
		}

		if bestMatch == nil {
			bestMatch = v
			bestDomainLength = curDomainLength
			continue
		}
		if curDomainLength > bestDomainLength {
			bestMatch = v
			bestDomainLength = curDomainLength
			continue
		}
		if curDomainLength == bestDomainLength {
			if equaled && (len(v.Location) <= len(bestMatch.Location) || strings.HasPrefix(bestMatch.Host, "*")) {
				bestMatch = v
				bestDomainLength = curDomainLength
				continue
			}
			if (len(v.Location) <= len(bestMatch.Location)) && strings.HasPrefix(bestMatch.Host, "*") {
				bestMatch = v
				bestDomainLength = curDomainLength
				continue
			}
		}
	}
	if bestMatch != nil {
		return bestMatch, nil
	}
	return nil, errors.New("the host could not be parsed")
}

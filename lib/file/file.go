package file

import (
	"sync"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NewObjectID 返回 MongoDB 原生 ObjectID 的 hex 字符串，作为全局唯一 ID。
func NewObjectID() string {
	return primitive.NewObjectID().Hex()
}

func NewJsonDb(runPath string) *JsonDb {
	return &JsonDb{RunPath: runPath}
}

type JsonDb struct {
	Tasks    sync.Map
	Hosts    sync.Map
	HostsTmp sync.Map
	Clients  sync.Map
	Global   *Glob
	RunPath  string
}

func (s *JsonDb) GetClient(id string) (c *Client, err error) {
	if v, ok := s.Clients.Load(id); ok {
		c = v.(*Client)
		return
	}
	err = errClientNotFound
	return
}

// ---- 落盘：本地 JSON 文件已彻底移除，所有写操作只走 MongoDB 后端 ----

func (s *JsonDb) StoreHostToJsonFile() {
	if mongoBackend != nil {
		mongoBackend.SaveAllHosts()
	}
}

func (s *JsonDb) StoreTasksToJsonFile() {
	if mongoBackend != nil {
		mongoBackend.SaveAllTasks()
	}
}

func (s *JsonDb) StoreClientsToJsonFile() {
	if mongoBackend != nil {
		mongoBackend.SaveAllClients()
	}
}

func (s *JsonDb) StoreGlobalToJsonFile() {
	if mongoBackend != nil {
		mongoBackend.SaveGlobalDoc()
	}
}

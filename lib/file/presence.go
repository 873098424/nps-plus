package file

import (
	"context"
	"sync"
	"time"

	"github.com/djylb/nps/lib/logs"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// 在线位置注册表（Presence Registry）
//
// 目的：让 relay 路由自动化，取代手写的 relay_routes。
//   - 每个"持有 client 连接"的节点（owner）在【客户端连接/断开的瞬间】把该 client
//     所在的 relay 拨号地址写入 MongoDB 集合 nps_presence（事件驱动，毫秒级生效）。
//   - 入口节点（entry）在 relay 时，若目标 client 不在本机，就查这张表得到应转发到哪个节点，
//     并按需建立/复用到该节点的 relay 会话。
//   - 另起一个低频心跳兜底：节点被 kill / 网络分区等"优雅断开钩子没触发"时，靠 ts 过期自动失效。
//
// 文档结构（每个 client 一条）：
//
//	{ _id:int(=clientId), node:string(advertise addr), online:bool, ts:int64(unix ms) }
//
// 用 clientId 作 _id，因此：
//   - 同一 client 全局只有一条记录，重连到别的节点会自然覆盖 node；
//   - 不再有"按节点数组"那种增删单个 client 要重写整张数组的浪费。

const (
	presenceColl     = "nps_presence"
	presenceTTLSec   = 45 // 超过该时长未刷新（心跳/连接事件）的 client 视为离线，查询时忽略
	presenceCacheDur = 2 * time.Second
	presenceBeatSec  = 15 // 心跳周期（必须 < presenceTTLSec 才能容忍丢失）
)

// PresenceBeatInterval 返回心跳周期，供 server 端定时器使用。
func PresenceBeatInterval() time.Duration {
	return presenceBeatSec * time.Second
}

type presenceDoc struct {
	ID     primitive.ObjectID `bson:"_id"`
	Node   string             `bson:"node"`
	Online bool               `bson:"online"`
	Ts     int64              `bson:"ts"`
}

var (
	presenceCache     map[string]string
	presenceCacheTime time.Time
	presenceMu        sync.RWMutex
)

// OnClientOnline 在客户端【连接成功】时调用：记录它当前所在的节点并标记为在线。
// 无论是首次连接还是从别的节点迁回，都直接覆盖写入，保证表里的 node 是最新的。
func OnClientOnline(clientId string, node string) {
	if !mongoOn || mongoBackend == nil || node == "" || clientId == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	coll := mongoBackend.db.Collection(presenceColl)
	now := time.Now().UnixMilli()
	update := bson.M{
		"$set": bson.M{
			"node":   node,
			"online": true,
			"ts":     now,
		},
	}
	if _, err := coll.UpdateOne(ctx, bson.M{"_id": toObjectID(clientId)}, update, options.Update().SetUpsert(true)); err != nil {
		logs.Error("presence online error (client %s -> %s): %v", clientId, node, err)
	}
}

// OnClientOffline 在客户端【断开】时调用：标记为离线。entry 节点查表时会跳过 offline 记录，
// 因此断线的瞬间就不可再被路由到，无残留窗口。
func OnClientOffline(clientId string) {
	if !mongoOn || mongoBackend == nil || clientId == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	coll := mongoBackend.db.Collection(presenceColl)
	update := bson.M{"$set": bson.M{"online": false, "ts": time.Now().UnixMilli()}}
	if _, err := coll.UpdateOne(ctx, bson.M{"_id": toObjectID(clientId)}, update); err != nil {
		logs.Error("presence offline error (client %s): %v", clientId, err)
	}
}

// PresenceHeartbeat 低频兜底：把本节点当前仍在线 client 的 online/node/ts 全部刷新一遍。
// 用于应对节点被强杀、网络分区等"优雅断开钩子没触发"的情况——这些 client 的 ts 不再被刷新，
// 超过 presenceTTLSec 后会被 LookupPresence 视为离线。
// 采用批量 upsert，单次往返完成。
func PresenceHeartbeat(node string, clientIds []string) {
	if !mongoOn || mongoBackend == nil || node == "" {
		return
	}
	if len(clientIds) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	coll := mongoBackend.db.Collection(presenceColl)
	now := time.Now().UnixMilli()
	models := make([]mongo.WriteModel, 0, len(clientIds))
	for _, id := range clientIds {
		if id == "" {
			continue
		}
		m := mongo.NewUpdateOneModel()
		m.SetFilter(bson.M{"_id": toObjectID(id)})
		m.SetUpdate(bson.M{"$set": bson.M{"node": node, "online": true, "ts": now}})
		m.SetUpsert(true)
		models = append(models, m)
	}
	if len(models) == 0 {
		return
	}
	opts := options.BulkWrite().SetOrdered(false)
	if _, err := coll.BulkWrite(ctx, models, opts); err != nil {
		logs.Error("presence heartbeat error: %v", err)
	}
}

// ClearPresence 进程退出时调用：把本节点持有的所有 client 标记为离线，加速下线感知。
func ClearPresence(node string) {
	if !mongoOn || mongoBackend == nil || node == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	coll := mongoBackend.db.Collection(presenceColl)
	_, _ = coll.UpdateMany(ctx, bson.M{"node": node}, bson.M{"$set": bson.M{"online": false}})
}

// LookupPresence 查询某个 client 当前所在节点的 relay 拨号地址（带 2s 本地缓存）。
// 仅返回 online 且 ts 在有效期内（未被心跳/连接事件刷新超过 presenceTTLSec）的记录。
func LookupPresence(clientId string) (string, bool) {
	if !mongoOn || mongoBackend == nil || clientId == "" {
		return "", false
	}
	m := loadPresenceMap()
	addr, ok := m[clientId]
	return addr, ok
}

func loadPresenceMap() map[string]string {
	presenceMu.RLock()
	if presenceCache != nil && time.Since(presenceCacheTime) < presenceCacheDur {
		m := presenceCache
		presenceMu.RUnlock()
		return m
	}
	presenceMu.RUnlock()

	presenceMu.Lock()
	defer presenceMu.Unlock()
	// double-check：可能在等锁期间已被其他 goroutine 刷新
	if presenceCache != nil && time.Since(presenceCacheTime) < presenceCacheDur {
		return presenceCache
	}

	m := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	coll := mongoBackend.db.Collection(presenceColl)
	cur, err := coll.Find(ctx, bson.M{})
	if err != nil {
		logs.Error("presence load error: %v", err)
		if presenceCache != nil {
			return presenceCache // 出错时沿用旧缓存，避免抖动
		}
		return m
	}
	defer cur.Close(ctx)
	minTs := time.Now().Add(-presenceTTLSec * time.Second).UnixMilli()
	for cur.Next(ctx) {
		var d presenceDoc
		if cur.Decode(&d) != nil {
			continue
		}
		if !d.Online || d.Node == "" || d.Ts < minTs {
			continue // 离线、无效地址或已过期（节点疑似宕机）
		}
		m[d.ID.Hex()] = d.Node
	}
	presenceCache = m
	presenceCacheTime = time.Now()
	return m
}

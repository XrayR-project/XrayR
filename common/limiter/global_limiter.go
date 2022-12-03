package limiter

import (
	"context"
	"fmt"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/go-redis/redis/v8"
)

const (
	updateKeyChannel = "updatekey"
	cleanInterval    = time.Second * 10 // default memory cache clean interval
)

type GlobalLimiter struct {
	rds      *redis.Client
	memCache *MemCache
	timeout  int
	expiry   int
}

func NewGlobalLimiter(globalDeviceLimit *GlobalDeviceLimitConfig) *GlobalLimiter {
	client := redis.NewClient(&redis.Options{
		Addr:     globalDeviceLimit.RedisAddr,
		Password: globalDeviceLimit.RedisPassword,
		DB:       globalDeviceLimit.RedisDB,
	})
	g := &GlobalLimiter{
		rds:      client,
		memCache: NewMemCache(cleanInterval),
		timeout:  globalDeviceLimit.Timeout,
		expiry:   globalDeviceLimit.Expiry,
	}
	go g.subscribe()
	return g
}

func (g *GlobalLimiter) Check(ip string, email string, deviceLimit int) bool {
	online, ok := g.get(email)
	if !ok { // No device online
		go g.newIP(email, ip, deviceLimit)
		return false
	}

	if online.Contains(ip) { // The device is online
		return false
	} else if online.Cardinality() < deviceLimit { // The device is not online, but the device limit is not reached
		go g.pushIP(email, ip, deviceLimit)
		return false
	} else {
		return true
	}
}

// sync memcache from redis and return the value
func (g *GlobalLimiter) syncMem(key string) (*Item, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(g.timeout))
	defer cancel()

	if exists, err := g.rds.Exists(ctx, key).Result(); err != nil {
		newError(fmt.Sprintf("Redis: %v", err)).AtError().WriteToLog()
	} else if exists == 0 { // key not exists
		return nil, false
	}

	ips, err := g.rds.SMembers(ctx, key).Result()
	if err != nil {
		newError(fmt.Errorf("redis: %v", err)).AtError().WriteToLog()
	}
	ttl := g.rds.TTL(ctx, key).Val()
	it := newItem(ips, ttl)

	g.memCache.set(key, it)
	return it, true
}

func (g *GlobalLimiter) get(key string) (mapset.Set[string], bool) {
	if v, ok := g.memCache.get(key); ok {
		return v.IPSet, true
	}

	if v, ok := g.syncMem(key); ok {
		return v.IPSet, true
	} else {
		return nil, false
	}
}

// Creat new key in redis
func (g *GlobalLimiter) newIP(email string, ip string, deviceLimit int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(g.timeout))
	defer cancel()

	if err := g.rds.SAdd(ctx, email, ip).Err(); err != nil {
		newError(fmt.Errorf("redis: %v", err)).AtError().WriteToLog()
	}

	if err := g.rds.Expire(ctx, email, time.Second*time.Duration(g.expiry)).Err(); err != nil {
		newError(fmt.Errorf("redis: %v", err)).AtError().WriteToLog()
	}
}

// Push new IP to redis
func (g *GlobalLimiter) pushIP(email string, ip string, deviceLimit int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(g.timeout))
	defer cancel()

	// First check whether the device in redis reach the limit
	if g.rds.SCard(ctx, email).Val() >= int64(deviceLimit) {
		return
	}

	if err := g.rds.SAdd(ctx, email, ip).Err(); err != nil {
		newError(fmt.Errorf("redis: %v", err)).AtError().WriteToLog()
	} else {
		g.publish(email) // Ask other instances to update the memory cache
	}
}

// redis subscriber for key deletion, delete keys in memory
func (g *GlobalLimiter) subscribe() {
	var ctx = context.Background()
	sub := g.rds.Subscribe(ctx, updateKeyChannel)
	defer sub.Close()

	for {
		msg, err := sub.ReceiveMessage(ctx)
		if err != nil {
			newError(fmt.Errorf("redis: %v", err)).AtError().WriteToLog()
		} else {
			g.memCache.delete(msg.Payload)
		}
	}
}

// publish key updating
func (g *GlobalLimiter) publish(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(g.timeout))
	defer cancel()
	if err := g.rds.Publish(ctx, updateKeyChannel, key).Err(); err != nil {
		newError(fmt.Errorf("redis: %v", err)).AtError().WriteToLog()
	}
}

// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/time/rate"

	"github.com/XrayR-project/XrayR/api"
)

type UserInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

// connIP tracks a single online IP with its UID and last-seen timestamp.
type connIP struct {
	UID      int
	LastSeen int64 // unix timestamp
}

// userOnlineEntry stores per-user IP tracking with an atomic device counter
// to avoid O(N) Range() for device counting.
type userOnlineEntry struct {
	ips   sync.Map // Key: IP string -> connIP
	count int32    // atomic device count — avoids Range() for counting
}

func newUserOnlineEntry() *userOnlineEntry {
	return &userOnlineEntry{}
}

// addIP records an IP for this user. Returns false (reject) if device limit exceeded.
func (e *userOnlineEntry) addIP(ip string, uid int, deviceLimit int) (reject bool) {
	now := time.Now().Unix()
	// Fast path: IP already tracked
	if v, loaded := e.ips.Load(ip); loaded {
		entry := v.(connIP)
		entry.LastSeen = now
		e.ips.Store(ip, entry)
		return false
	}
	// New IP — check device limit before adding
	if deviceLimit > 0 {
		current := atomic.LoadInt32(&e.count)
		if int(current) >= deviceLimit {
			return true // reject
		}
	}
	// Try to store; if another goroutine stored the same IP concurrently, don't double-count
	if _, loaded := e.ips.LoadOrStore(ip, connIP{UID: uid, LastSeen: now}); !loaded {
		atomic.AddInt32(&e.count, 1)
	}
	return false
}

// cleanStale removes IPs not seen within ttl and returns remaining count.
func (e *userOnlineEntry) cleanStale(ttl int64) int32 {
	now := time.Now().Unix()
	e.ips.Range(func(key, value interface{}) bool {
		entry := value.(connIP)
		if now-entry.LastSeen > ttl {
			e.ips.Delete(key)
			atomic.AddInt32(&e.count, -1)
		}
		return true
	})
	return atomic.LoadInt32(&e.count)
}

// collectOnline gathers all online user records efficiently.
func (e *userOnlineEntry) collectOnline(out *[]api.OnlineUser) {
	e.ips.Range(func(key, value interface{}) bool {
		entry := value.(connIP)
		*out = append(*out, api.OnlineUser{UID: entry.UID, IP: key.(string)})
		return true
	})
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	UserInfo       *sync.Map // Key: user tag (buildUserTag) -> UserInfo
	BucketHub      *sync.Map // Key: user tag -> *rate.Limiter
	UserOnlineIP   *sync.Map // Key: user tag -> *userOnlineEntry
	GlobalLimit    struct {
		config         *GlobalDeviceLimitConfig
		globalOnlineIP *marshaler.Marshaler
	}
}

type Limiter struct {
	InboundInfo *sync.Map // Key: Tag, Value: *InboundInfo
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig) error {
	inboundInfo := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		UserOnlineIP:   new(sync.Map),
	}

	if globalLimit != nil && globalLimit.Enable {
		inboundInfo.GlobalLimit.config = globalLimit

		// init local store
		gs := goCacheStore.NewGoCache(goCache.New(time.Duration(globalLimit.Expiry)*time.Second, 1*time.Minute))

		// init redis store
		rs := redisStore.NewRedis(redis.NewClient(
			&redis.Options{
				Network:  globalLimit.RedisNetwork,
				Addr:     globalLimit.RedisAddr,
				Username: globalLimit.RedisUsername,
				Password: globalLimit.RedisPassword,
				DB:       globalLimit.RedisDB,
			}),
			store.WithExpiration(time.Duration(globalLimit.Expiry)*time.Second))

		// init chained cache. First use local go-cache, if go-cache is nil, then use redis cache
		cacheManager := cache.NewChain[any](
			cache.New[any](gs), // go-cache is priority
			cache.New[any](rs),
		)
		inboundInfo.GlobalLimit.globalOnlineIP = marshaler.New(cacheManager)
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		userKey := fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)
		userMap.Store(userKey, UserInfo{
			UID:         u.UID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.UserInfo = userMap
	l.InboundInfo.Store(tag, inboundInfo) // Replace the old inbound info
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedUserList {
			userKey := fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)
			inboundInfo.UserInfo.Store(userKey, UserInfo{
				UID:         u.UID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(userKey); ok {
					limiter := bucket.(*rate.Limiter)
					limiter.SetLimit(rate.Limit(limit))
					limiter.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(userKey)
			}
		}
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	l.InboundInfo.Delete(tag)
	return nil
}

// ipTTL is the time-to-live for online IP entries. IPs not seen within this
// duration are considered stale and cleaned up during GetOnlineDevice.
const ipTTL int64 = 120 // seconds

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Pre-allocate with a reasonable capacity to reduce slice growth
		onlineUser := make([]api.OnlineUser, 0, 256)

		// Single pass: collect online IPs and clean stale entries
		inboundInfo.UserOnlineIP.Range(func(userKey, value interface{}) bool {
			entry := value.(*userOnlineEntry)
			// Clean stale IPs (not seen within TTL)
			remaining := entry.cleanStale(ipTTL)
			if remaining == 0 {
				// No IPs left — remove the entry and its rate bucket
				inboundInfo.UserOnlineIP.Delete(userKey)
				inboundInfo.BucketHub.Delete(userKey)
				return true
			}
			entry.collectOnline(&onlineUser)
			return true
		})

		return &onlineUser, nil
	}
	return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
}

func (l *Limiter) GetUserBucket(tag string, userKey string, ip string) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			userLimit        uint64
			deviceLimit, uid int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
			u := v.(UserInfo)
			uid = u.UID
			userLimit = u.SpeedLimit
			deviceLimit = u.DeviceLimit
		}

		// Local device limit — O(1) via atomic counter instead of O(N) Range()
		entry := newUserOnlineEntry()
		if v, loaded := inboundInfo.UserOnlineIP.LoadOrStore(userKey, entry); loaded {
			entry = v.(*userOnlineEntry)
		}
		if entry.addIP(ip, uid, deviceLimit) {
			return nil, false, true // device limit exceeded
		}

		if inboundInfo.GlobalLimit.config != nil && inboundInfo.GlobalLimit.config.Enable {
			if reject := globalLimit(inboundInfo, userKey, uid, ip, deviceLimit); reject {
				return nil, false, true
			}
		}

		limit := determineRate(nodeLimit, userLimit)
		if limit > 0 {
			// Reuse existing bucket if available; only create new one on first access
			if v, ok := inboundInfo.BucketHub.Load(userKey); ok {
				return v.(*rate.Limiter), true, false
			}
			newLimiter := rate.NewLimiter(rate.Limit(limit), int(limit))
			if v, loaded := inboundInfo.BucketHub.LoadOrStore(userKey, newLimiter); loaded {
				return v.(*rate.Limiter), true, false
			}
			return newLimiter, true, false
		}
		return nil, false, false
	}

	errors.LogDebug(context.Background(), "Get Inbound Limiter information failed")
	return nil, false, false
}

// Global device limit
func globalLimit(inboundInfo *InboundInfo, userKey string, uid int, ip string, deviceLimit int) bool {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	uniqueKey := userKey

	v, err := inboundInfo.GlobalLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			go pushIP(inboundInfo, uniqueKey, &map[string]int{ip: uid})
		} else {
			errors.LogErrorInner(context.Background(), err, "cache service")
		}
		return false
	}

	ipMap := v.(*map[string]int)
	if deviceLimit > 0 && len(*ipMap) > deviceLimit {
		return true
	}

	if _, ok := (*ipMap)[ip]; !ok {
		(*ipMap)[ip] = uid
		go pushIP(inboundInfo, uniqueKey, ipMap)
	}

	return false
}

// push the ip to cache
func pushIP(inboundInfo *InboundInfo, uniqueKey string, ipMap *map[string]int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	if err := inboundInfo.GlobalLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap); err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
	}
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 && userLimit == 0 {
		return 0
	}
	if nodeLimit == 0 {
		return userLimit
	}
	if userLimit == 0 {
		return nodeLimit
	}
	if nodeLimit < userLimit {
		return nodeLimit
	}
	return userLimit
}

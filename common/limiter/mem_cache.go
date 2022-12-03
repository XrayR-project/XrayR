package limiter

import (
	"sync"
	"time"
)

type MemCache struct {
	items *sync.Map
	ci    time.Duration
}

// NewMemCache memcache will scan all objects for every clean interval and delete expired key.
func NewMemCache(ci time.Duration) *MemCache {
	c := &MemCache{
		items: new(sync.Map),
		ci:    ci,
	}

	go c.runJanitor()
	return c
}

// get an item from the memcache. Returns the item or nil, and a bool indicating whether the key was found.
func (c *MemCache) get(k string) (*Item, bool) {
	tmp, ok := c.items.Load(k)
	if !ok {
		return nil, false
	}
	item := tmp.(*Item)
	if item.Outdated() {
		return nil, false
	}
	return item, true
}

func (c *MemCache) set(k string, it *Item) {
	c.items.Store(k, it)
}

// Delete an item from the memcache. Does nothing if the key is not in the memcache.
func (c *MemCache) delete(k string) {
	c.items.Delete(k)
}

// update IP in cache
func (c *MemCache) update(k string, ip string) {
	if tmp, ok := c.items.Load(k); ok {
		item := tmp.(*Item)
		item.IPSet.Add(ip)
	}
}

// start key scanning to delete expired keys
func (c *MemCache) runJanitor() {
	ticker := time.NewTicker(c.ci)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.DeleteExpired()
		}
	}
}

// DeleteExpired delete all expired items from the memcache.
func (c *MemCache) DeleteExpired() {
	c.items.Range(func(key, value interface{}) bool {
		v := value.(*Item)
		k := key.(string)
		// delete outdated for memory cache
		if v.Outdated() {
			c.items.Delete(k)
		}
		return true
	})
}

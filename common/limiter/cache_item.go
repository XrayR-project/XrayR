package limiter

import (
	"time"

	mapset "github.com/deckarep/golang-set/v2"
)

type Item struct {
	IPSet   mapset.Set[string]
	Expire time.Time
}

// Outdated returns true if data is outdated.
func (i *Item) Outdated() bool {
	if time.Now().After(i.Expire) {
		return true
	}
	return false
}

func newItem(v []string, ttl time.Duration) *Item {
	return &Item{
		IPSet:   mapset.NewThreadUnsafeSet[string](v...),
		Expire: time.Now().Add(ttl),
	}
}

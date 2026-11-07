package protocol

import (
	"sync"
	"time"
)

// DigestCache stores only public authentication challenges, never credentials
// or generated Authorization values.
type DigestCache struct {
	ttl     time.Duration
	max     int
	mu      sync.Mutex
	entries map[string]digestCacheEntry
}

type digestCacheEntry struct {
	challenge *digestChallenge
	expires   time.Time
}

func NewDigestCache(ttl time.Duration, maxEntries int) *DigestCache {
	return &DigestCache{ttl: ttl, max: max(1, maxEntries), entries: make(map[string]digestCacheEntry)}
}

func (c *DigestCache) Get(key string) (*digestChallenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.challenge, true
}

func (c *DigestCache) Put(key string, challenge *digestChallenge) {
	if challenge == nil {
		return
	}
	c.mu.Lock()
	if len(c.entries) >= c.max {
		for old := range c.entries {
			delete(c.entries, old)
			break
		}
	}
	c.entries[key] = digestCacheEntry{challenge: challenge, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

func (c *DigestCache) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

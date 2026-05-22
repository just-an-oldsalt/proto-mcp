package approval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
)

// cache stores per-(tool, pid, args) approval entries with an
// absolute expiry. Lookup is two operations — hit() checks + GCs;
// set() writes. Lock is a mutex, not RWMutex, because every read
// path also writes (we sweep expired entries on hit() to keep the
// map bounded).
type cache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key → expires-at (UTC)
	now     func() time.Time     // injectable for tests
}

func newCache() *cache {
	return &cache{
		entries: map[string]time.Time{},
		now:     time.Now,
	}
}

// hit returns true if key has a non-expired entry. Expired entries
// are removed on the way out (lazy GC — saves a separate sweeper
// goroutine).
func (c *cache) hit(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires, ok := c.entries[key]
	if !ok {
		return false
	}
	if c.now().After(expires) {
		delete(c.entries, key)
		return false
	}
	return true
}

// set stores key with the given TTL from now.
func (c *cache) set(key string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = c.now().Add(ttl)
}

// cacheKey computes sha256(tool || pid || args). PID is included so
// concurrent Claude Desktop sessions (Phase 6 multi-process scenario)
// can't piggyback on each other's approvals. args is included so
// changing the recipient list invalidates a cached approval — the
// safe answer for write tools.
func cacheKey(tool string, pid int, args []byte) string {
	h := sha256.New()
	h.Write([]byte(tool))
	var pidBuf [8]byte
	binary.LittleEndian.PutUint64(pidBuf[:], uint64(pid))
	h.Write(pidBuf[:])
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

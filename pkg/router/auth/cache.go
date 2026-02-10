/*
Copyright The Volcano Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package auth provides authentication and authorization middleware for the
// AgentCube Router. It includes a high-performance sharded token cache,
// HMAC-based session binding, and namespace authorization.
package auth

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

const (
	// defaultShardCount is the number of shards to split the cache into.
	// Must be a power of two for the fast bitmask-based shard selection.
	defaultShardCount = 64

	// defaultMaxEntries is the default maximum total entries across all shards.
	defaultMaxEntries = 10000

	// defaultTTL is the default cache entry time-to-live.
	defaultTTL = 5 * time.Minute
)

// cacheEntry holds a single cached token validation result.
type cacheEntry struct {
	tokenHash     [sha256.Size]byte // we store hash, never plaintext
	authenticated bool
	identity      *UserIdentity
	expiresAt     time.Time     // absolute expiry = insertedAt + ttl
	element       *list.Element // position in the shard's LRU list
}

// cacheShard is a single shard of the sharded LRU cache.
// Each shard has its own mutex to minimise contention.
type cacheShard struct {
	mu       sync.Mutex
	items    map[[sha256.Size]byte]*cacheEntry
	lru      *list.List
	maxItems int
}

// ShardedTokenCache is a bounded, sharded LRU cache for token validation
// results keyed by SHA-256 hash of the token string.
//
// Design choices for production workloads:
//   - Sharding by token hash reduces lock contention under high concurrency.
//   - Tokens are never stored in plaintext; only their SHA-256 hash is kept.
//   - Each shard independently enforces its entry limit via LRU eviction.
//   - TTL-based expiry ensures stale results are discarded.
//   - All public methods are safe for concurrent use.
type ShardedTokenCache struct {
	shards     []*cacheShard
	shardCount uint64
	shardMask  uint64 // shardCount - 1, used for fast modulo
	ttl        time.Duration
}

// TokenCacheOption configures a ShardedTokenCache.
type TokenCacheOption func(*ShardedTokenCache)

// WithShardCount sets the number of shards (rounded up to next power of two).
func WithShardCount(n int) TokenCacheOption {
	return func(c *ShardedTokenCache) {
		if n > 0 {
			c.shardCount = nextPowerOfTwo(uint64(n))
		}
	}
}

// WithMaxEntries sets the total maximum entries across all shards.
func WithMaxEntries(n int) TokenCacheOption {
	return func(c *ShardedTokenCache) {
		if n > 0 {
			perShard := n / int(c.shardCount)
			if perShard < 1 {
				perShard = 1
			}
			for _, s := range c.shards {
				s.maxItems = perShard
			}
		}
	}
}

// WithTTL sets the cache entry time-to-live.
func WithTTL(d time.Duration) TokenCacheOption {
	return func(c *ShardedTokenCache) {
		if d > 0 {
			c.ttl = d
		}
	}
}

// NewShardedTokenCache creates a new sharded LRU token cache.
// Options can be used to override defaults for shard count, max entries, and TTL.
func NewShardedTokenCache(opts ...TokenCacheOption) *ShardedTokenCache {
	sc := uint64(defaultShardCount)

	c := &ShardedTokenCache{
		shardCount: sc,
		shardMask:  sc - 1,
		ttl:        defaultTTL,
	}

	// Apply options that might change shardCount first.
	for _, o := range opts {
		o(c)
	}
	// Recompute mask after potential shardCount change.
	c.shardMask = c.shardCount - 1

	perShard := defaultMaxEntries / int(c.shardCount)
	if perShard < 1 {
		perShard = 1
	}

	c.shards = make([]*cacheShard, c.shardCount)
	for i := range c.shards {
		c.shards[i] = &cacheShard{
			items:    make(map[[sha256.Size]byte]*cacheEntry),
			lru:      list.New(),
			maxItems: perShard,
		}
	}

	// Apply remaining options (e.g. WithMaxEntries, WithTTL).
	for _, o := range opts {
		o(c)
	}

	return c
}

// Get looks up a token in the cache. It returns:
//   - found: whether the token was present and not expired
//   - identity: the cached UserIdentity (nil if not authenticated or not found)
//
// Token is hashed with SHA-256; the original is never stored.
func (c *ShardedTokenCache) Get(token string) (found bool, identity *UserIdentity) {
	h := hashToken(token)
	shard := c.shards[c.shardIndex(h)]

	shard.mu.Lock()
	entry, ok := shard.items[h]
	if !ok {
		shard.mu.Unlock()
		return false, nil
	}

	// Check expiry.
	if time.Now().After(entry.expiresAt) {
		// Expired — remove inline to keep the hot path tight.
		shard.lru.Remove(entry.element)
		delete(shard.items, h)
		shard.mu.Unlock()
		return false, nil
	}

	// Promote in LRU.
	shard.lru.MoveToFront(entry.element)
	id := entry.identity
	shard.mu.Unlock()

	return true, id
}

// Set inserts or updates a token validation result.
// If identity is nil the token was not authenticated (negative cache).
func (c *ShardedTokenCache) Set(token string, identity *UserIdentity) {
	h := hashToken(token)
	shard := c.shards[c.shardIndex(h)]
	now := time.Now()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if existing, ok := shard.items[h]; ok {
		existing.identity = identity
		existing.authenticated = identity != nil
		existing.expiresAt = now.Add(c.ttl)
		shard.lru.MoveToFront(existing.element)
		return
	}

	// Evict if full.
	for len(shard.items) >= shard.maxItems {
		shard.evictOldest()
	}

	entry := &cacheEntry{
		tokenHash:     h,
		authenticated: identity != nil,
		identity:      identity,
		expiresAt:     now.Add(c.ttl),
	}
	entry.element = shard.lru.PushFront(entry)
	shard.items[h] = entry
}

// Remove explicitly removes a token from the cache.
func (c *ShardedTokenCache) Remove(token string) {
	h := hashToken(token)
	shard := c.shards[c.shardIndex(h)]

	shard.mu.Lock()
	if entry, ok := shard.items[h]; ok {
		shard.lru.Remove(entry.element)
		delete(shard.items, h)
	}
	shard.mu.Unlock()
}

// Size returns the total number of entries across all shards.
// Only used for monitoring/testing; not on hot path.
func (c *ShardedTokenCache) Size() int {
	total := 0
	for _, shard := range c.shards {
		shard.mu.Lock()
		total += len(shard.items)
		shard.mu.Unlock()
	}
	return total
}

// --- internal helpers ---

// shardIndex returns the shard index for a given token hash.
// Uses the first 8 bytes of the hash as a uint64 and masks with shardMask
// (bitwise AND instead of modulo because shardCount is a power of two).
func (c *ShardedTokenCache) shardIndex(h [sha256.Size]byte) uint64 {
	return binary.LittleEndian.Uint64(h[:8]) & c.shardMask
}

// hashToken computes the SHA-256 digest of the token string.
// SHA-256 is used so that plaintext tokens are never stored in memory.
func hashToken(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// evictOldest removes the least-recently-used entry.
// Caller MUST hold shard.mu.
func (s *cacheShard) evictOldest() {
	back := s.lru.Back()
	if back == nil {
		return
	}
	entry := back.Value.(*cacheEntry)
	s.lru.Remove(back)
	delete(s.items, entry.tokenHash)
}

// nextPowerOfTwo returns the smallest power of two >= n.
func nextPowerOfTwo(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	return n + 1
}

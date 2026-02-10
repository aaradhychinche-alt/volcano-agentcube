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

package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestShardedTokenCache_BasicOperations(t *testing.T) {
	cache := NewShardedTokenCache(WithMaxEntries(100), WithTTL(5*time.Minute))

	token := "test-token-123"
	identity := &UserIdentity{
		Username:  "system:serviceaccount:default:test-sa",
		Namespace: "default",
	}

	// Test Set and Get
	cache.Set(token, identity)
	found, retrieved := cache.Get(token)
	if !found {
		t.Fatal("Expected token to be found in cache")
	}
	if retrieved == nil || retrieved.Username != identity.Username {
		t.Errorf("Expected identity %v, got %v", identity, retrieved)
	}

	// Test Remove
	cache.Remove(token)
	found, _ = cache.Get(token)
	if found {
		t.Fatal("Expected token to be removed from cache")
	}
}

func TestShardedTokenCache_NegativeCaching(t *testing.T) {
	cache := NewShardedTokenCache()

	token := "invalid-token"

	// Cache negative result (nil identity)
	cache.Set(token, nil)

	found, identity := cache.Get(token)
	if !found {
		t.Fatal("Expected negative cache entry to be found")
	}
	if identity != nil {
		t.Error("Expected nil identity for negative cache entry")
	}
}

func TestShardedTokenCache_TTLExpiry(t *testing.T) {
	cache := NewShardedTokenCache(WithTTL(100 * time.Millisecond))

	token := "short-lived-token"
	identity := &UserIdentity{Username: "test-user"}

	cache.Set(token, identity)

	// Should be present immediately
	found, _ := cache.Get(token)
	if !found {
		t.Fatal("Expected token to be found immediately after Set")
	}

	// Wait for TTL expiry
	time.Sleep(150 * time.Millisecond)

	// Should be expired and automatically evicted
	found, _ = cache.Get(token)
	if found {
		t.Error("Expected token to be expired and removed")
	}
}

func TestShardedTokenCache_LRUEviction(t *testing.T) {
	shardCount := 4
	maxEntries := 16 // 16/4 = 4 per shard exactly
	cache := NewShardedTokenCache(WithMaxEntries(maxEntries), WithShardCount(shardCount))

	// Fill cache beyond capacity
	for i := 0; i < maxEntries+10; i++ {
		token := generateToken(i)
		identity := &UserIdentity{Username: generateUsername(i)}
		cache.Set(token, identity)
	}

	// Cache size should be bounded (may be less than maxEntries due to hash distribution)
	size := cache.Size()
	if size > maxEntries {
		t.Errorf("Expected cache size <= %d after eviction, got %d", maxEntries, size)
	}

	// The most recently added entry should still be present
	lastToken := generateToken(maxEntries + 9)
	found, _ := cache.Get(lastToken)
	if !found {
		t.Error("Expected most recent entry to be present after evictions")
	}

	// Some older entry should have been evicted
	firstToken := generateToken(0)
	found, _ = cache.Get(firstToken)
	if found {
		t.Error("Expected oldest entry to be evicted, but it's still present")
	}
}

func TestShardedTokenCache_ConcurrentAccess(t *testing.T) {
	cache := NewShardedTokenCache(WithMaxEntries(1000))
	const goroutines = 100
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Concurrent writers
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				token := generateToken(id*opsPerGoroutine + j)
				identity := &UserIdentity{Username: generateUsername(id)}
				cache.Set(token, identity)
			}
		}(i)
	}

	wg.Wait()

	// Concurrent readers
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				token := generateToken(id*opsPerGoroutine + j)
				cache.Get(token)
			}
		}(i)
	}

	wg.Wait()

	// Should not panic or deadlock
}

func TestShardedTokenCache_ConcurrentReadWrite(t *testing.T) {
	cache := NewShardedTokenCache()
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			token := generateToken(i)
			identity := &UserIdentity{Username: generateUsername(i)}
			cache.Set(token, identity)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			token := generateToken(i)
			cache.Get(token)
		}
		done <- true
	}()

	// Wait for both to complete
	<-done
	<-done
}

func TestShardedTokenCache_ShardDistribution(t *testing.T) {
	cache := NewShardedTokenCache(WithShardCount(64))

	// Add many tokens and verify they're distributed across shards
	const numTokens = 1000
	for i := 0; i < numTokens; i++ {
		token := generateToken(i)
		identity := &UserIdentity{Username: generateUsername(i)}
		cache.Set(token, identity)
	}

	// Check that tokens are reasonably distributed
	// (not all in one shard)
	emptyShards := 0
	for _, shard := range cache.shards {
		shard.mu.Lock()
		if len(shard.items) == 0 {
			emptyShards++
		}
		shard.mu.Unlock()
	}

	// With 1000 tokens and 64 shards, we expect most shards to have entries
	if emptyShards > len(cache.shards)/2 {
		t.Errorf("Too many empty shards (%d/%d), sharding may be broken",
			emptyShards, len(cache.shards))
	}
}

func TestShardedTokenCache_UpdateExisting(t *testing.T) {
	cache := NewShardedTokenCache()

	token := "test-token"
	identity1 := &UserIdentity{Username: "user1", Namespace: "ns1"}
	identity2 := &UserIdentity{Username: "user2", Namespace: "ns2"}

	// Set initial value
	cache.Set(token, identity1)
	found, retrieved := cache.Get(token)
	if !found || retrieved.Username != "user1" {
		t.Fatal("Initial set failed")
	}

	// Update with new identity
	cache.Set(token, identity2)
	found, retrieved = cache.Get(token)
	if !found || retrieved.Username != "user2" {
		t.Error("Update failed, expected user2")
	}

	// Size should still be 1
	if size := cache.Size(); size != 1 {
		t.Errorf("Expected size 1 after update, got %d", size)
	}
}

func TestNextPowerOfTwo(t *testing.T) {
	tests := []struct {
		input    uint64
		expected uint64
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{15, 16},
		{16, 16},
		{17, 32},
		{63, 64},
		{64, 64},
		{65, 128},
	}

	for _, tt := range tests {
		result := nextPowerOfTwo(tt.input)
		if result != tt.expected {
			t.Errorf("nextPowerOfTwo(%d) = %d, expected %d",
				tt.input, result, tt.expected)
		}
	}
}

// Helper functions

func generateToken(i int) string {
	// Use fmt.Sprintf to create unique tokens with better distribution
	return fmt.Sprintf("token-%d-%x", i, i*i)
}

func generateUsername(i int) string {
	return fmt.Sprintf("user-%d", i)
}

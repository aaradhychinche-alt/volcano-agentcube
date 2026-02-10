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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"sync"
)

// SessionValidator validates that a session belongs to the requesting user.
type SessionValidator interface {
	// BindSession generates a cryptographic binding token for (user, sessionID).
	BindSession(username, sessionID string) string

	// ValidateSession verifies that the given session belongs to the user.
	// Uses constant-time comparison to prevent timing attacks.
	ValidateSession(username, sessionID, mac string) bool
}

// HMACSessionValidator binds sessions to users using HMAC-SHA256.
//
// Performance:
//   - sync.Pool reuses hash.Hash objects to avoid allocations on each call.
//   - hmac.Equal provides constant-time comparison to prevent timing attacks.
type HMACSessionValidator struct {
	key  []byte
	pool sync.Pool
}

// NewHMACSessionValidator creates a session validator with the given HMAC key.
// The key must be at least 32 bytes long.
func NewHMACSessionValidator(key []byte) (*HMACSessionValidator, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("HMAC key must be at least 32 bytes, got %d", len(key))
	}

	// Make a defensive copy of the key so the caller can't mutate it.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	v := &HMACSessionValidator{
		key: keyCopy,
	}
	v.pool = sync.Pool{
		New: func() interface{} {
			return hmac.New(sha256.New, keyCopy)
		},
	}
	return v, nil
}

// BindSession computes HMAC-SHA256(username || ":" || sessionID) and returns
// the hex-encoded MAC. This is stored alongside the session and later used
// for ownership verification.
func (v *HMACSessionValidator) BindSession(username, sessionID string) string {
	h := v.pool.Get().(hash.Hash)
	h.Reset()
	// Write username, separator, and sessionID. The separator prevents
	// ambiguity between e.g. ("ab","c:d") and ("ab:c","d").
	h.Write([]byte(username))
	h.Write([]byte{':'})
	h.Write([]byte(sessionID))
	mac := h.Sum(nil)
	v.pool.Put(h)

	return hex.EncodeToString(mac)
}

// ValidateSession checks whether the given MAC matches the expected
// HMAC-SHA256(username || ":" || sessionID). Uses constant-time comparison.
func (v *HMACSessionValidator) ValidateSession(username, sessionID, mac string) bool {
	expected := v.BindSession(username, sessionID)

	// Decode both to bytes for constant-time comparison.
	expectedBytes, err1 := hex.DecodeString(expected)
	actualBytes, err2 := hex.DecodeString(mac)
	if err1 != nil || err2 != nil {
		return false
	}

	return hmac.Equal(expectedBytes, actualBytes)
}

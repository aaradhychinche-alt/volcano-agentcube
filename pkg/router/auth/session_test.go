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
	"crypto/rand"
	"testing"
)

func TestHMACSessionValidator_BindAndValidate(t *testing.T) {
	key := generateRandomKey(32)
	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	username := "system:serviceaccount:default:test-sa"
	sessionID := "session-123-abc"

	// Bind session
	mac := validator.BindSession(username, sessionID)
	if mac == "" {
		t.Fatal("Expected non-empty MAC")
	}

	// Validate with correct credentials
	if !validator.ValidateSession(username, sessionID, mac) {
		t.Error("Expected validation to succeed with correct MAC")
	}
}

func TestHMACSessionValidator_RejectForgedSession(t *testing.T) {
	key := generateRandomKey(32)
	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	username := "system:serviceaccount:default:test-sa"
	sessionID := "session-123"

	mac := validator.BindSession(username, sessionID)

	// Attempt to use session with different user
	otherUser := "system:serviceaccount:default:attacker-sa"
	if validator.ValidateSession(otherUser, sessionID, mac) {
		t.Error("Expected validation to fail with different username")
	}

	// Attempt to use MAC with different session
	otherSession := "session-456"
	if validator.ValidateSession(username, otherSession, mac) {
		t.Error("Expected validation to fail with different sessionID")
	}

	// Attempt to use completely forged MAC
	forgedMAC := "0123456789abcdef"
	if validator.ValidateSession(username, sessionID, forgedMAC) {
		t.Error("Expected validation to fail with forged MAC")
	}
}

func TestHMACSessionValidator_Deterministic(t *testing.T) {
	key := generateRandomKey(32)
	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	username := "test-user"
	sessionID := "test-session"

	// Generate MAC multiple times
	mac1 := validator.BindSession(username, sessionID)
	mac2 := validator.BindSession(username, sessionID)
	mac3 := validator.BindSession(username, sessionID)

	// All MACs should be identical (deterministic)
	if mac1 != mac2 || mac2 != mac3 {
		t.Error("Expected BindSession to be deterministic")
	}
}

func TestHMACSessionValidator_DifferentKeysProduceDifferentMACs(t *testing.T) {
	key1 := generateRandomKey(32)
	key2 := generateRandomKey(32)

	validator1, _ := NewHMACSessionValidator(key1)
	validator2, _ := NewHMACSessionValidator(key2)

	username := "test-user"
	sessionID := "test-session"

	mac1 := validator1.BindSession(username, sessionID)
	mac2 := validator2.BindSession(username, sessionID)

	// Different keys should produce different MACs
	if mac1 == mac2 {
		t.Error("Expected different keys to produce different MACs")
	}

	// validator1's MAC should not validate with validator2
	if validator2.ValidateSession(username, sessionID, mac1) {
		t.Error("Expected MAC from validator1 to fail validation with validator2")
	}
}

func TestHMACSessionValidator_KeyTooShort(t *testing.T) {
	shortKey := []byte("too-short")

	_, err := NewHMACSessionValidator(shortKey)
	if err == nil {
		t.Fatal("Expected error for key shorter than 32 bytes")
	}
}

func TestHMACSessionValidator_KeyImmutability(t *testing.T) {
	key := generateRandomKey(32)
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Mutate the original key
	for i := range key {
		key[i] = 0
	}

	// Validator should still work (it made a defensive copy)
	username := "test-user"
	sessionID := "test-session"
	mac := validator.BindSession(username, sessionID)

	if !validator.ValidateSession(username, sessionID, mac) {
		t.Error("Expected validator to work with defensive key copy")
	}
}

func TestHMACSessionValidator_EmptyInputs(t *testing.T) {
	key := generateRandomKey(32)
	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Empty username
	mac1 := validator.BindSession("", "session-123")
	if mac1 == "" {
		t.Error("Expected BindSession to return MAC even with empty username")
	}

	// Empty sessionID
	mac2 := validator.BindSession("user", "")
	if mac2 == "" {
		t.Error("Expected BindSession to return MAC even with empty sessionID")
	}

	// Both empty
	mac3 := validator.BindSession("", "")
	if mac3 == "" {
		t.Error("Expected BindSession to return MAC even with both empty")
	}

	// MACs should be different
	if mac1 == mac2 || mac2 == mac3 {
		t.Error("Expected different MACs for different empty combinations")
	}
}

func TestHMACSessionValidator_SpecialCharacters(t *testing.T) {
	key := generateRandomKey(32)
	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test with special characters that could cause issues
	username := "user:with:colons"
	sessionID := "session:with:colons"

	mac := validator.BindSession(username, sessionID)
	if !validator.ValidateSession(username, sessionID, mac) {
		t.Error("Expected validation to succeed with colons in inputs")
	}

	// Test that different username/sessionID pairs produce different MACs
	mac1 := validator.BindSession("user1", "session1")
	mac2 := validator.BindSession("user2", "session2")

	if mac1 == mac2 {
		t.Error("Expected different inputs to produce different MACs")
	}
}

func TestHMACSessionValidator_InvalidHexMAC(t *testing.T) {
	key := generateRandomKey(32)
	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	username := "test-user"
	sessionID := "test-session"

	// Try to validate with invalid hex string
	invalidMAC := "not-valid-hex-zzz"
	if validator.ValidateSession(username, sessionID, invalidMAC) {
		t.Error("Expected validation to fail with invalid hex MAC")
	}
}

func TestHMACSessionValidator_ConcurrentAccess(t *testing.T) {
	key := generateRandomKey(32)
	validator, err := NewHMACSessionValidator(key)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	const goroutines = 100
	done := make(chan bool, goroutines)

	// Concurrent BindSession calls
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			username := "user-" + string(rune('0'+id%10))
			sessionID := "session-" + string(rune('0'+id%10))
			mac := validator.BindSession(username, sessionID)
			if !validator.ValidateSession(username, sessionID, mac) {
				t.Error("Concurrent validation failed")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// Helper function to generate random key
func generateRandomKey(length int) []byte {
	key := make([]byte, length)
	rand.Read(key)
	return key
}

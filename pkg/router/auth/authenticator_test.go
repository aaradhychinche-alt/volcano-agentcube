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
	"context"
	"errors"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	authv1fake "k8s.io/client-go/kubernetes/typed/authentication/v1/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestKubernetesAuthenticator_AuthenticateSuccess(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	cache := NewShardedTokenCache()
	authn := NewKubernetesAuthenticator(clientset, cache)

	token := "valid-token-123"
	expectedUsername := "system:serviceaccount:default:test-sa"
	expectedUID := "test-uid-456"

	// Mock TokenReview response
	clientset.AuthenticationV1().(*authv1fake.FakeAuthenticationV1).
		PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: expectedUsername,
						UID:      expectedUID,
					},
				},
			}
			return true, review, nil
		})

	// First call: should hit Kubernetes API
	identity, err := authn.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Expected successful authentication, got error: %v", err)
	}
	if identity == nil {
		t.Fatal("Expected non-nil identity")
	}
	if identity.Username != expectedUsername {
		t.Errorf("Expected username %s, got %s", expectedUsername, identity.Username)
	}
	if identity.Namespace != "default" {
		t.Errorf("Expected namespace 'default', got %s", identity.Namespace)
	}
	if identity.ServiceAccountName != "test-sa" {
		t.Errorf("Expected SA name 'test-sa', got %s", identity.ServiceAccountName)
	}
	if identity.UID != expectedUID {
		t.Errorf("Expected UID %s, got %s", expectedUID, identity.UID)
	}

	// Second call: should hit cache (no API call)
	identity2, err := authn.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Expected cached authentication to succeed, got error: %v", err)
	}
	if identity2.Username != expectedUsername {
		t.Errorf("Cached identity mismatch")
	}
}

func TestKubernetesAuthenticator_AuthenticateFailure(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	cache := NewShardedTokenCache()
	authn := NewKubernetesAuthenticator(clientset, cache)

	token := "invalid-token"

	// Mock TokenReview response (not authenticated)
	clientset.AuthenticationV1().(*authv1fake.FakeAuthenticationV1).
		PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: false,
				},
			}
			return true, review, nil
		})

	identity, err := authn.Authenticate(context.Background(), token)
	if err == nil {
		t.Fatal("Expected authentication to fail")
	}
	if identity != nil {
		t.Error("Expected nil identity for failed authentication")
	}

	// Second call: should hit cache (negative cache)
	identity2, err := authn.Authenticate(context.Background(), token)
	if err == nil {
		t.Fatal("Expected cached negative result to fail")
	}
	if identity2 != nil {
		t.Error("Expected nil identity for cached negative result")
	}
}

func TestKubernetesAuthenticator_TokenReviewAPIError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	cache := NewShardedTokenCache()
	authn := NewKubernetesAuthenticator(clientset, cache)

	token := "error-token"

	// Mock TokenReview API error
	clientset.AuthenticationV1().(*authv1fake.FakeAuthenticationV1).
		PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("API server unreachable")
		})

	identity, err := authn.Authenticate(context.Background(), token)
	if err == nil {
		t.Fatal("Expected error when TokenReview API fails")
	}
	if identity != nil {
		t.Error("Expected nil identity on API error")
	}
}

func TestParseServiceAccountUsername_Valid(t *testing.T) {
	tests := []struct {
		username          string
		uid               string
		expectedNamespace string
		expectedSAName    string
		expectedUID       string
		shouldSucceed     bool
	}{
		{
			username:          "system:serviceaccount:default:my-sa",
			uid:               "uid-123",
			expectedNamespace: "default",
			expectedSAName:    "my-sa",
			expectedUID:       "uid-123",
			shouldSucceed:     true,
		},
		{
			username:          "system:serviceaccount:kube-system:coredns",
			uid:               "uid-456",
			expectedNamespace: "kube-system",
			expectedSAName:    "coredns",
			expectedUID:       "uid-456",
			shouldSucceed:     true,
		},
		{
			username:          "system:serviceaccount:team-a:robot-sa",
			uid:               "uid-789",
			expectedNamespace: "team-a",
			expectedSAName:    "robot-sa",
			expectedUID:       "uid-789",
			shouldSucceed:     true,
		},
		{
			// Invalid: missing parts
			username:      "system:serviceaccount:default",
			shouldSucceed: false,
		},
		{
			// Invalid: not a service account
			username:      "system:node:worker-1",
			shouldSucceed: false,
		},
		{
			// Invalid: regular user
			username:      "admin",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		identity, err := parseServiceAccountUsername(tt.username, tt.uid)
		if tt.shouldSucceed {
			if err != nil {
				t.Errorf("Expected parsing %s to succeed, got error: %v", tt.username, err)
				continue
			}
			if identity.Namespace != tt.expectedNamespace {
				t.Errorf("Expected namespace %s, got %s", tt.expectedNamespace, identity.Namespace)
			}
			if identity.ServiceAccountName != tt.expectedSAName {
				t.Errorf("Expected SA name %s, got %s", tt.expectedSAName, identity.ServiceAccountName)
			}
			if identity.UID != tt.expectedUID {
				t.Errorf("Expected UID %s, got %s", tt.expectedUID, identity.UID)
			}
			if identity.Username != tt.username {
				t.Errorf("Expected username %s, got %s", tt.username, identity.Username)
			}
		} else {
			if err == nil {
				t.Errorf("Expected parsing %s to fail, but it succeeded", tt.username)
			}
		}
	}
}

func TestKubernetesAuthenticator_CacheHitAvoidAPICall(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	cache := NewShardedTokenCache()
	authn := NewKubernetesAuthenticator(clientset, cache)

	token := "cached-token"
	apiCallCount := 0

	// Mock TokenReview response and count API calls
	clientset.AuthenticationV1().(*authv1fake.FakeAuthenticationV1).
		PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			apiCallCount++
			review := &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "system:serviceaccount:default:test",
						UID:      "test-uid",
					},
				},
			}
			return true, review, nil
		})

	// First call: should make API call
	_, err := authn.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("First authentication failed: %v", err)
	}
	if apiCallCount != 1 {
		t.Errorf("Expected 1 API call, got %d", apiCallCount)
	}

	// Second call: should use cache (no additional API call)
	_, err = authn.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Second authentication failed: %v", err)
	}
	if apiCallCount != 1 {
		t.Errorf("Expected 1 API call total (cache hit), got %d", apiCallCount)
	}

	// Third call: should still use cache
	_, err = authn.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Third authentication failed: %v", err)
	}
	if apiCallCount != 1 {
		t.Errorf("Expected 1 API call total (cache hit), got %d", apiCallCount)
	}
}

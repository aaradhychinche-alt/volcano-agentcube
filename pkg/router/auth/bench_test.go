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
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	authv1fake "k8s.io/client-go/kubernetes/typed/authentication/v1/fake"
	k8stesting "k8s.io/client-go/testing"
)

// BenchmarkShardedTokenCache_Get benchmarks cache lookups (the hot path).
// Target: < 1µs per operation.
func BenchmarkShardedTokenCache_Get(b *testing.B) {
	cache := NewShardedTokenCache()

	token := "benchmark-token-12345678"
	identity := &UserIdentity{
		Username:  "system:serviceaccount:default:bench-sa",
		Namespace: "default",
	}

	cache.Set(token, identity)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cache.Get(token)
	}
}

// BenchmarkShardedTokenCache_Set benchmarks cache insertions.
func BenchmarkShardedTokenCache_Set(b *testing.B) {
	cache := NewShardedTokenCache()

	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		tokens[i] = fmt.Sprintf("token-%d", i)
	}

	identity := &UserIdentity{
		Username:  "system:serviceaccount:default:bench-sa",
		Namespace: "default",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cache.Set(tokens[i], identity)
	}
}

// BenchmarkShardedTokenCache_ConcurrentGet benchmarks concurrent cache reads.
func BenchmarkShardedTokenCache_ConcurrentGet(b *testing.B) {
	cache := NewShardedTokenCache()

	// Pre-populate cache
	tokens := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		tokens[i] = fmt.Sprintf("token-%d", i)
		identity := &UserIdentity{Username: fmt.Sprintf("user-%d", i)}
		cache.Set(tokens[i], identity)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			token := tokens[i%1000]
			cache.Get(token)
			i++
		}
	})
}

// BenchmarkHMACSessionValidator_BindSession benchmarks HMAC generation.
// Target: < 1µs per operation.
func BenchmarkHMACSessionValidator_BindSession(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	validator, _ := NewHMACSessionValidator(key)

	username := "system:serviceaccount:default:test-sa"
	sessionID := "session-12345678-abcd-efgh"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.BindSession(username, sessionID)
	}
}

// BenchmarkHMACSessionValidator_ValidateSession benchmarks HMAC verification.
// Target: < 1µs per operation.
func BenchmarkHMACSessionValidator_ValidateSession(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	validator, _ := NewHMACSessionValidator(key)

	username := "system:serviceaccount:default:test-sa"
	sessionID := "session-12345678-abcd-efgh"
	mac := validator.BindSession(username, sessionID)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator.ValidateSession(username, sessionID, mac)
	}
}

// BenchmarkKubernetesAuthenticator_CacheHit benchmarks authentication with cache hit.
// Target: < 1µs per operation (cache hot path).
func BenchmarkKubernetesAuthenticator_CacheHit(b *testing.B) {
	clientset := fake.NewSimpleClientset()
	cache := NewShardedTokenCache()
	authn := NewKubernetesAuthenticator(clientset, cache)

	token := "benchmark-token"

	// Mock TokenReview (should not be called after first request)
	clientset.AuthenticationV1().(*authv1fake.FakeAuthenticationV1).
		PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "system:serviceaccount:default:bench-sa",
						UID:      "bench-uid",
					},
				},
			}
			return true, review, nil
		})

	// Warm up cache
	authn.Authenticate(context.Background(), token)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		authn.Authenticate(context.Background(), token)
	}
}

// BenchmarkAuthenticationMiddleware_Cached benchmarks full middleware with cached token.
// Target: < 150µs per request (cached).
func BenchmarkAuthenticationMiddleware_Cached(b *testing.B) {
	gin.SetMode(gin.TestMode)

	// Setup authenticator with cache
	clientset := fake.NewSimpleClientset()
	cache := NewShardedTokenCache()
	authn := NewKubernetesAuthenticator(clientset, cache)

	token := "benchmark-token"

	// Mock TokenReview
	clientset.AuthenticationV1().(*authv1fake.FakeAuthenticationV1).
		PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "system:serviceaccount:default:bench-sa",
						UID:      "bench-uid",
					},
				},
			}
			return true, review, nil
		})

	// Setup router
	router := gin.New()
	router.Use(AuthenticationMiddleware(authn))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Warm up cache
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkNamespaceAuthorizationMiddleware benchmarks namespace authorization.
func BenchmarkNamespaceAuthorizationMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	identity := &UserIdentity{
		Username:  "system:serviceaccount:team-a:robot-sa",
		Namespace: "team-a",
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), UserIdentityKey, identity)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	router.Use(NamespaceAuthorizationMiddleware())
	router.GET("/namespaces/:namespace/resources", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/namespaces/team-a/resources", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkFullAuthPipeline benchmarks authentication + namespace authorization.
// Target: < 200µs per request (cached).
func BenchmarkFullAuthPipeline(b *testing.B) {
	gin.SetMode(gin.TestMode)

	// Setup authenticator with cache
	clientset := fake.NewSimpleClientset()
	cache := NewShardedTokenCache()
	authn := NewKubernetesAuthenticator(clientset, cache)

	token := "benchmark-token"

	// Mock TokenReview
	clientset.AuthenticationV1().(*authv1fake.FakeAuthenticationV1).
		PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "system:serviceaccount:team-a:robot-sa",
						UID:      "bench-uid",
					},
				},
			}
			return true, review, nil
		})

	// Setup router with both middlewares
	router := gin.New()
	router.Use(AuthenticationMiddleware(authn))
	router.Use(NamespaceAuthorizationMiddleware())
	router.GET("/namespaces/:namespace/resources", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Warm up cache
	req := httptest.NewRequest(http.MethodGet, "/namespaces/team-a/resources", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/namespaces/team-a/resources", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

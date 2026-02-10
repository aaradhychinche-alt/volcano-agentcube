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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// mockAuthenticator for testing
type mockAuthenticator struct {
	authenticateFunc func(ctx context.Context, token string) (*UserIdentity, error)
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, token string) (*UserIdentity, error) {
	return m.authenticateFunc(ctx, token)
}

func TestAuthenticationMiddleware_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	expectedIdentity := &UserIdentity{
		Username:  "system:serviceaccount:default:test-sa",
		Namespace: "default",
		UID:       "test-uid",
	}

	authn := &mockAuthenticator{
		authenticateFunc: func(ctx context.Context, token string) (*UserIdentity, error) {
			if token == "valid-token" {
				return expectedIdentity, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	router := gin.New()
	router.Use(AuthenticationMiddleware(authn))
	router.GET("/test", func(c *gin.Context) {
		identity := IdentityFromContext(c.Request.Context())
		if identity == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no identity"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user": identity.Username})
	})

	// Test with valid token
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthenticationMiddleware_MissingAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authn := &mockAuthenticator{
		authenticateFunc: func(ctx context.Context, token string) (*UserIdentity, error) {
			return nil, errors.New("should not be called")
		},
	}

	router := gin.New()
	router.Use(AuthenticationMiddleware(authn))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthenticationMiddleware_InvalidAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authn := &mockAuthenticator{
		authenticateFunc: func(ctx context.Context, token string) (*UserIdentity, error) {
			return nil, errors.New("should not be called")
		},
	}

	router := gin.New()
	router.Use(AuthenticationMiddleware(authn))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	tests := []struct {
		name   string
		header string
	}{
		{"missing Bearer prefix", "some-token"},
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
		{"empty token", "Bearer "},
		{"only Bearer", "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", tt.header)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected status 401 for %s, got %d", tt.name, w.Code)
			}
		})
	}
}

func TestAuthenticationMiddleware_AuthenticationFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authn := &mockAuthenticator{
		authenticateFunc: func(ctx context.Context, token string) (*UserIdentity, error) {
			return nil, errors.New("authentication failed")
		},
	}

	router := gin.New()
	router.Use(AuthenticationMiddleware(authn))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestNamespaceAuthorizationMiddleware_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	identity := &UserIdentity{
		Username:  "system:serviceaccount:team-a:robot-sa",
		Namespace: "team-a",
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Inject identity into context
		ctx := context.WithValue(c.Request.Context(), UserIdentityKey, identity)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	router.Use(NamespaceAuthorizationMiddleware())
	router.GET("/namespaces/:namespace/resources", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/namespaces/team-a/resources", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for matching namespace, got %d", w.Code)
	}
}

func TestNamespaceAuthorizationMiddleware_Mismatch(t *testing.T) {
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
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Attempt to access different namespace
	req := httptest.NewRequest(http.MethodGet, "/namespaces/team-b/resources", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for namespace mismatch, got %d", w.Code)
	}
}

func TestNamespaceAuthorizationMiddleware_NoNamespaceParam(t *testing.T) {
	gin.SetMode(gin.TestMode)

	identity := &UserIdentity{
		Username:  "system:serviceaccount:default:test-sa",
		Namespace: "default",
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), UserIdentityKey, identity)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	router.Use(NamespaceAuthorizationMiddleware())
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Route without :namespace param should be allowed
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for route without namespace, got %d", w.Code)
	}
}

func TestNamespaceAuthorizationMiddleware_NoIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(NamespaceAuthorizationMiddleware())
	router.GET("/namespaces/:namespace/resources", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/namespaces/default/resources", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 when identity not in context, got %d", w.Code)
	}
}

func TestIdentityFromContext(t *testing.T) {
	identity := &UserIdentity{
		Username:  "test-user",
		Namespace: "test-ns",
	}

	ctx := context.WithValue(context.Background(), UserIdentityKey, identity)

	retrieved := IdentityFromContext(ctx)
	if retrieved == nil {
		t.Fatal("Expected non-nil identity")
	}
	if retrieved.Username != identity.Username {
		t.Error("Retrieved identity mismatch")
	}

	// Test with empty context
	emptyCtx := context.Background()
	retrieved2 := IdentityFromContext(emptyCtx)
	if retrieved2 != nil {
		t.Error("Expected nil identity from empty context")
	}
}

func TestExtractBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		authHeader    string
		expectedToken string
		shouldSucceed bool
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer my-token-123",
			expectedToken: "my-token-123",
			shouldSucceed: true,
		},
		{
			name:          "valid bearer token with long value",
			authHeader:    "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			shouldSucceed: true,
		},
		{
			name:          "missing bearer prefix",
			authHeader:    "my-token",
			shouldSucceed: false,
		},
		{
			name:          "wrong scheme",
			authHeader:    "Basic dXNlcjpwYXNz",
			shouldSucceed: false,
		},
		{
			name:          "empty header",
			authHeader:    "",
			shouldSucceed: false,
		},
		{
			name:          "bearer with empty token",
			authHeader:    "Bearer ",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				c.Request.Header.Set("Authorization", tt.authHeader)
			}

			token, ok := extractBearerToken(c)

			if tt.shouldSucceed {
				if !ok {
					t.Errorf("Expected extraction to succeed")
				}
				if token != tt.expectedToken {
					t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
				}
			} else {
				if ok {
					t.Errorf("Expected extraction to fail, but got token: %s", token)
				}
			}
		})
	}
}

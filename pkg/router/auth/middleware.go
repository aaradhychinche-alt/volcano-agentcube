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
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"k8s.io/klog/v2"
)

// AuthenticationMiddleware returns Gin middleware that validates Kubernetes
// ServiceAccount bearer tokens on every request. The authenticated
// UserIdentity is propagated via the request context.
//
// Middleware order in the Router:
//  1. AuthenticationMiddleware   – validates token, sets UserIdentity
//  2. NamespaceAuthorizationMiddleware – checks namespace match
//  3. concurrencyLimitMiddleware (existing)
func AuthenticationMiddleware(authn Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract bearer token from Authorization header.
		token, ok := extractBearerToken(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "missing or invalid Authorization header",
				"code":  "UNAUTHENTICATED",
			})
			c.Abort()
			return
		}

		identity, err := authn.Authenticate(c.Request.Context(), token)
		if err != nil {
			klog.V(4).Infof("Authentication failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication failed",
				"code":  "UNAUTHENTICATED",
			})
			c.Abort()
			return
		}

		// Propagate identity through request context.
		ctx := context.WithValue(c.Request.Context(), UserIdentityKey, identity)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// NamespaceAuthorizationMiddleware returns Gin middleware that enforces
// namespace-scoped authorization. The URL namespace parameter must match
// the authenticated user's ServiceAccount namespace.
//
// This prevents cross-namespace access: a SA in namespace "team-a" cannot
// invoke resources in namespace "team-b".
func NamespaceAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := IdentityFromContext(c.Request.Context())
		if identity == nil {
			// Should not happen if AuthenticationMiddleware ran first.
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthenticated request",
				"code":  "UNAUTHENTICATED",
			})
			c.Abort()
			return
		}

		// Extract namespace from URL parameter.
		urlNamespace := c.Param("namespace")
		if urlNamespace == "" {
			// Route without namespace parameter — allow.
			c.Next()
			return
		}

		// Enforce: user's SA namespace must match URL namespace.
		if identity.Namespace != urlNamespace {
			klog.V(2).Infof("Namespace authorization denied: user=%s (ns=%s) tried to access namespace=%s",
				identity.Username, identity.Namespace, urlNamespace)
			c.JSON(http.StatusForbidden, gin.H{
				"error": "access denied: namespace mismatch",
				"code":  "FORBIDDEN",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// IdentityFromContext extracts the UserIdentity from the request context.
// Returns nil if no identity is present (unauthenticated request).
func IdentityFromContext(ctx context.Context) *UserIdentity {
	id, _ := ctx.Value(UserIdentityKey).(*UserIdentity)
	return id
}

// extractBearerToken parses "Authorization: Bearer <token>" from the request.
func extractBearerToken(c *gin.Context) (string, bool) {
	header := c.GetHeader("Authorization")
	if header == "" {
		return "", false
	}

	// Use SplitN for a single allocation.
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", false
	}

	token := parts[1]
	if token == "" {
		return "", false
	}

	return token, true
}

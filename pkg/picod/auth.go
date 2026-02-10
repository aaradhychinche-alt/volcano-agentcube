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

package picod

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"k8s.io/klog/v2"
)

const (
	// MaxBodySize limits request body size to prevent memory exhaustion
	MaxBodySize = 32 << 20 // 32 MB

	// PublicKeyEnvVar is the environment variable name for the public key
	PublicKeyEnvVar = "PICOD_AUTH_PUBLIC_KEY"
)

// AuthManager manages RSA public key authentication
// The public key is loaded from environment variable at startup
type AuthManager struct {
	publicKey           *rsa.PublicKey
	mutex               sync.RWMutex
	expectedSandboxID   string // Expected sandbox_id claim (from env)
	expectedNamespace   string // Expected namespace claim (from env)
	expectedSandboxName string // Expected sandbox_name claim (from env)
}

// NewAuthManager creates a new auth manager
func NewAuthManager() *AuthManager {
	return &AuthManager{}
}

// LoadPublicKeyFromEnv loads the public key from environment variable.
// The key should be in PEM format.
func (am *AuthManager) LoadPublicKeyFromEnv() error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	keyData := os.Getenv(PublicKeyEnvVar)
	if keyData == "" {
		return fmt.Errorf("environment variable %s is not set", PublicKeyEnvVar)
	}

	block, _ := pem.Decode([]byte(keyData))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from %s", PublicKeyEnvVar)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not an RSA public key")
	}

	am.publicKey = rsaPub
	klog.Info("Public key loaded successfully from environment variable")
	return nil
}

// LoadExpectedClaims loads sandbox identity from environment variables.
// These are used to validate that JWTs are scoped to THIS specific sandbox.
func (am *AuthManager) LoadExpectedClaims() {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.expectedSandboxID = os.Getenv("SANDBOX_ID")
	am.expectedNamespace = os.Getenv("SANDBOX_NAMESPACE")
	am.expectedSandboxName = os.Getenv("SANDBOX_NAME")

	if am.expectedSandboxID != "" {
		klog.Infof("PicoD sandbox identity: sandbox_id=%s namespace=%s name=%s",
			am.expectedSandboxID, am.expectedNamespace, am.expectedSandboxName)
	} else {
		klog.Warning("SANDBOX_ID not set - sandbox-scoped JWT validation disabled (backward compatibility mode)")
	}
}

// AuthMiddleware creates authentication middleware with JWT verification.
// Validates both signature and sandbox-scoped claims if configured.
func (am *AuthManager) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":  "Missing Authorization header",
				"code":   http.StatusUnauthorized,
				"detail": "Request requires JWT authentication",
			})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":  "Invalid Authorization header format",
				"code":   http.StatusUnauthorized,
				"detail": "Use Bearer <token>",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Parse and validate JWT using the public key
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			am.mutex.RLock()
			defer am.mutex.RUnlock()
			return am.publicKey, nil
		}, jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(time.Minute))

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":  "Invalid token",
				"code":   http.StatusUnauthorized,
				"detail": fmt.Sprintf("JWT verification failed: %v", err),
			})
			c.Abort()
			return
		}

		// Validate sandbox-scoped claims if expected values are configured.
		am.mutex.RLock()
		expectedSandboxID := am.expectedSandboxID
		expectedNamespace := am.expectedNamespace
		am.mutex.RUnlock()

		if expectedSandboxID != "" {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":  "Invalid token claims",
					"code":   http.StatusUnauthorized,
					"detail": "Unable to parse JWT claims",
				})
				c.Abort()
				return
			}

			// Validate sandbox_id claim
			sandboxID, _ := claims["sandbox_id"].(string)
			if sandboxID != expectedSandboxID {
				klog.Warningf("JWT sandbox_id mismatch: expected=%s got=%s", expectedSandboxID, sandboxID)
				c.JSON(http.StatusForbidden, gin.H{
					"error":  "Token not valid for this sandbox",
					"code":   http.StatusForbidden,
					"detail": "JWT sandbox_id claim does not match",
				})
				c.Abort()
				return
			}

			// Validate namespace claim
			namespace, _ := claims["namespace"].(string)
			if namespace != expectedNamespace {
				klog.Warningf("JWT namespace mismatch: expected=%s got=%s", expectedNamespace, namespace)
				c.JSON(http.StatusForbidden, gin.H{
					"error":  "Token not valid for this sandbox",
					"code":   http.StatusForbidden,
					"detail": "JWT namespace claim does not match",
				})
				c.Abort()
				return
			}
		}

		// Enforce maximum body size to prevent memory exhaustion
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxBodySize)

		c.Next()
	}
}

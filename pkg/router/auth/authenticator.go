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
	"fmt"
	"strings"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// Authenticator validates bearer tokens and returns the caller's identity.
type Authenticator interface {
	// Authenticate validates the given token and returns the identity.
	// Returns a non-nil error if the token is invalid or validation fails.
	Authenticate(ctx context.Context, token string) (*UserIdentity, error)
}

// KubernetesAuthenticator validates Kubernetes ServiceAccount tokens
// via the TokenReview API, with an integrated sharded cache.
type KubernetesAuthenticator struct {
	clientset kubernetes.Interface
	cache     *ShardedTokenCache
}

// NewKubernetesAuthenticator creates an authenticator backed by the
// Kubernetes TokenReview API with an integrated token cache.
func NewKubernetesAuthenticator(clientset kubernetes.Interface, cache *ShardedTokenCache) *KubernetesAuthenticator {
	return &KubernetesAuthenticator{
		clientset: clientset,
		cache:     cache,
	}
}

// Authenticate validates a bearer token. On the hot path (cache hit) this
// requires no Kubernetes API calls and completes in < 1µs.
func (a *KubernetesAuthenticator) Authenticate(ctx context.Context, token string) (*UserIdentity, error) {
	// Fast path: check cache first.
	if found, identity := a.cache.Get(token); found {
		if identity != nil {
			return identity, nil
		}
		// Negative cache hit — token was previously rejected.
		return nil, fmt.Errorf("token previously rejected")
	}

	// Slow path: call Kubernetes TokenReview API.
	review := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := a.clientset.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review API call failed: %w", err)
	}

	if !result.Status.Authenticated {
		// Cache the negative result to prevent repeated API calls.
		a.cache.Set(token, nil)
		return nil, fmt.Errorf("token not authenticated")
	}

	// Parse the SA username: system:serviceaccount:<namespace>:<name>
	identity, err := parseServiceAccountUsername(result.Status.User.Username, result.Status.User.UID)
	if err != nil {
		return nil, err
	}

	// Cache the positive result.
	a.cache.Set(token, identity)

	klog.V(4).Infof("Authenticated service account: %s", identity.Username)
	return identity, nil
}

// parseServiceAccountUsername extracts namespace and SA name from the
// Kubernetes SA username format: system:serviceaccount:<namespace>:<name>
func parseServiceAccountUsername(username, uid string) (*UserIdentity, error) {
	parts := strings.SplitN(username, ":", 4)
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return nil, fmt.Errorf("invalid service account username format: %s", username)
	}

	return &UserIdentity{
		Username:           username,
		Namespace:          parts[2],
		ServiceAccountName: parts[3],
		UID:                uid,
		AuthenticatedAt:    time.Now(),
	}, nil
}

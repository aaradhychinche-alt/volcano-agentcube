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

import "time"

// UserIdentity holds the authenticated user's identity information,
// extracted from a validated Kubernetes ServiceAccount token.
type UserIdentity struct {
	// Username is the full Kubernetes username
	// (e.g. "system:serviceaccount:default:my-sa")
	Username string

	// Namespace is the SA's namespace (e.g. "default")
	Namespace string

	// ServiceAccountName is the short SA name (e.g. "my-sa")
	ServiceAccountName string

	// UID is the unique identifier of the user (from TokenReview)
	UID string

	// AuthenticatedAt records when this identity was validated.
	AuthenticatedAt time.Time
}

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	// UserIdentityKey is the context key for UserIdentity.
	UserIdentityKey contextKey = iota
)

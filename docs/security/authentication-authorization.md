# AgentCube Authentication & Authorization

This document describes the security architecture for AgentCube, including authentication (AuthN) and authorization (AuthZ) mechanisms for the Router, Workload Manager, and PicoD runtime.

## 1. Architecture Overview

AgentCube implements a multi-layered security model:

1.  **Kubernetes-Native Identity**: ServiceAccount tokens are used as the primary identity mechanism.
2.  **Mandatory Authentication**: All external and internal requests must be authenticated.
3.  **Namespace Isolation**: Strict namespace boundaries are enforced.
4.  **Session Binding via HMAC**: Cryptographic binding of sessions to user identities.
5.  **Sandbox-Scoped JWTs**: Short-lived, scoped tokens for PicoD access.

### 1.1 Request Flow

1.  **Client Request**: User sends `POST /v1/namespaces/ns1/agent-runtimes/my-agent/invocations` with `Authorization: Bearer <service-account-token>`.
2.  **Router Authentication**:
    *   Router checks internal **Sharded Token Cache** (<1µs).
    *   On cache miss, calls **Kubernetes TokenReview API**.
    *   Validates identity: `system:serviceaccount:ns1:my-sa`.
3.  **Router Authorization**:
    *   Checks if user's namespace (`ns1`) matches URL namespace (`ns1`).
    *   Denies cross-namespace access (e.g., accessing `ns2` resources).
4.  **Session Binding (HMAC)**:
    *   On session creation, generates a session ID.
    *   Computes `MAC = HMAC-SHA256(user_id + ":" + session_id, key)`.
    *   Stores MAC alongside session metadata.
    *   On subsequent requests, verifies MAC matches user identity (prevents hijacking).
5.  **PicoD Access (JWT)**:
    *   Router generates a short-lived JWT scoped to: `sandbox_id`, `namespace`, `user_identity`.
    *   Router forwards request to PicoD sidecar.
    *   PicoD validates JWT signature and scoped claims.

---

## 2. Router Security

### 2.1 Configuration

Flags and Environment Variables:

| Flag / Env Var | Default | Description |
| :--- | :--- | :--- |
| `--enable-auth` | `true` | **MANDATORY** for production. Enables token validation & authz. (Secure by default). |
| `--token-cache-size` | `10000` | Max entries in the sharded token cache. |
| `--token-cache-ttl` | `5m` | Time-to-live for cached token validation results. |
| `AGENTCUBE_SESSION_SECRET` | (none) | **REQUIRED**. Hex-encoded 32-byte (min) key for HMAC session binding. |

### 2.2 Performance

The Router uses a **sharded, lock-free LRU cache** to minimize latency overhead:

*   **Cache Hit (Hot Path)**: < 1.5 µs latency added (zero allocations).
*   **Cache Miss**: ~10-50ms (dominating factor: K8s API RTT).
*   **Throughput**: 770k req/s+ on standard hardware (cached).

### 2.3 Threat Model

| Threat | Mitigation |
| :--- | :--- |
| **Unauthorized Access** | Mandatory K8s TokenReview authentication. |
| **Cross-Namespace Access** | Namespace authorization middleware enforces `user.namespace == url.namespace`. |
| **Session Hijacking** | HMAC-SHA256 binding locks session ID to creating user identity. |
| **Token Replay** | Short TTL cache (5m) + K8s token expiry. |
| **Timing Attacks** | Constant-time HMAC comparison. |
| **Memory Exhaustion** | Bounded local cache (LRU eviction). |

---

## 3. Workload Manager Security

### 3.1 Mandatory Authentication

The Workload Manager no longer supports `--enable-auth=false`. Authentication is **mandatory**.
It validates requests from the Router using the same Kubernetes ServiceAccount identity mechanism.

### 3.2 Secure Injection

When creating sandboxes, the Workload Manager injects:
1.  `PICOD_AUTH_PUBLIC_KEY`: RSA public key for JWT verification.
2.  `SANDBOX_ID`: Unique ID of the sandbox.
3.  `SANDBOX_NAMESPACE`: Namespace of the sandbox.
4.  `SANDBOX_NAME`: Name of the resource.

These environment variables enable PicoD to perform **scoped validation**.

---

## 4. PicoD Security (Runtime)

PicoD acts as the gatekeeper for the sandbox environment.

### 4.1 JWT Validation

All requests to PicoD must bear a JWT signed by the Router. PicoD validates:
1.  **Signature**: Using the injected RSA public key.
2.  **Expiration**: Tokens are short-lived (default 5m).
3.  **Scoped Claims**:
    *   `sandbox_id` must match `SANDBOX_ID` env var.
    *   `namespace` must match `SANDBOX_NAMESPACE` env var.

This prevents a compromised Router token for *Sandbox A* from being used to access *Sandbox B*.

---

## 5. Deployment Guide

### 5.1 Generate HMAC Secret

Generate a random 32-byte hex key:

```bash
openssl rand -hex 32
# Example output: 8f3b... (64 chars)
```

Create a Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: router-auth-secret
  namespace: agentcube-system
type: Opaque
stringData:
  session-secret: "8f3b..." # Paste generated hex key here
```

### 5.2 Configure Router

Update your Router Deployment:

```yaml
env:
  - name: AGENTCUBE_SESSION_SECRET
    valueFrom:
      secretKeyRef:
        name: router-auth-secret
        key: session-secret
args:
  - --enable-auth=true
  - --token-cache-size=20000
```

### 5.3 Network Policies

For strict isolation, ensure Pod-to-Pod communication is restricted. Only the **Router** should be allowed to talk to **PicoD** ports.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-router-access
spec:
  podSelector:
    matchLabels:
      app: agent-runtime
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: agentcube-router
    ports:
    - protocol: TCP
      port: 8080
```

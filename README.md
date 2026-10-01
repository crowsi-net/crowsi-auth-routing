# Crowsi Auth Routing

This crate keeps application and MCP entry points on one service-owned account
and authorization path. It does not authenticate users, issue tokens, store
sessions, or custody credentials. A service policy pins an Ed25519 verification
key. A transport adapter signs a closed, five-minute assertion and
`ProductionVerifier` validates its structure, issuer, signature, lifetime,
pinned signed current device identity, and durably consumed nonce before it
creates `VerifiedContext`. The default production API does not accept caller-
supplied freshness or replay implementations. Generic verifier seams are
available only through the non-default `test-support` feature for this crate's
contract tests. Unavailable identity state, a stale scoped revocation epoch, a
changed proof key, or a non-compliant posture fails closed.

Policy version 4 and evidence version 5 are the only active contracts. Evidence signs the
pairwise service subject, device ID, non-exportable device proof-key reference,
posture revision, subject/service/device/session revocation epochs, assurance,
and canonical `sha256:` operation
digest. A sensitive route is authorized only via
`authorize_operation` with the same digest. That call consumes the non-cloneable
verified context, so one evidence cannot authorize another action or a second
execution on the same route.

The trusted service adapter maps iHAT `baseline` to AAL1,
`phishing-resistant` to AAL2, and verified `hardware-bound` to AAL3. Caller
input, a method name, or an unsigned claim cannot perform that mapping.

## Route model

| Entry | Credential location | Authentication adapter |
|---|---|---|
| App HTTP | Secure, HttpOnly, SameSite cookie | Service session lookup |
| MCP HTTP | `Authorization` header | OAuth resource-server validation |
| MCP stdio | Crowsi reference supplied to an approved launcher | Local broker/session lookup |

Credentials never belong in MCP tool arguments, JSON-RPC payloads, route
configuration, logs, or UI projections. MCP HTTP must publish RFC 9728
Protected Resource Metadata and validate the token audience. The stdio
environment may contain an opaque Crowsi reference, never a bearer token or
password. Each service remains the authority for its account, session, and
scope records; Crowsi and Zixcel do not create a second customer database.

## Verify

```bash
# WONDERLAND_ROOT is the workspace checkout root.
"$WONDERLAND_ROOT/bin/verify-repositories" --rust --tier standard
```

The crate deliberately contains no HTTP server and no identity-provider
implementation. HTTP adapters, local launchers, and session stores remain
service-owned deployment components.

Policies with an `active` route require `context_verifier`. Legacy v1/v2/v3 policy
and v1/v2/v3/v4 evidence documents are rejected and require explicit re-enrollment.
Planned, simulation, and contract-ready policies may omit the key but cannot verify
a context.

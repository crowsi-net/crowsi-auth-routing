# crowsi-auth-routing interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

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

The crate deliberately contains no HTTP server and no identity-provider
implementation. HTTP adapters, local launchers, and session stores remain
service-owned deployment components.

Policies with an `active` route require `context_verifier`. Legacy v1/v2/v3 policy
and v1/v2/v3/v4 evidence documents are rejected and require explicit re-enrollment.
Planned, simulation, and contract-ready policies may omit the key but cannot verify
a context.

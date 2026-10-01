# Security

- `VerifiedContext` has no public constructor. Accept only
  `ProductionVerifier` output from a closed signed assertion whose Ed25519 public
  key is pinned in the service-owned policy and whose current identity status is
  independently pinned.
- Do not construct a context from MCP tool arguments, model output, query
  parameters, display names, or unsigned client claims.
- Bind every protected MCP HTTP token to the canonical resource audience.
- Keep bearer values out of process arguments, environment values, logs,
  SQLite application records, and repository files.
- For stdio, resolve an opaque Crowsi reference inside the approved launcher or
  local broker and pass only a verified context to the child boundary.
- Reject expired, wrong-channel, wrong-audience, or under-scoped contexts.
- Require current version 5 evidence and exact pairwise subject, Device proof
  key, opaque `session_ref`, posture revision, and
  subject/service/device/session revocation epochs for every active route.
- Require recent AAL2/AAL3 evidence for network
  isolation, credential changes, certificate issuance, and emergency controls.
- Bind version 5 evidence to the canonical operation digest and call
  `authorize_operation`; a route/scope match alone never authorizes step-up.
- Production composition uses `ProductionVerifier`, a pinned independently
  signed current-status document, and owner-only `FileReplayLedger`; caller
  supplied freshness snapshots and in-memory replay ledgers are test-only.
  The authorization must exactly match the status binding and cannot expire
  after that status.
- Rotate verifier keys through an authenticated service configuration path.
  Keep signing keys in the adapter's dedicated credential boundary; never in
  route JSON, UI state, repository files, or model-accessible processes.
- Keep assertions inside authenticated local IPC and bind the upstream session
  to its transport proof. Replay consumption complements, but does not replace,
  session revocation and transport sender constraints.

`FileReplayLedger` and the current-status rollback watermark use owner-only
same-directory anchors. They detect partial rollback, but cannot detect an
attacker who can coherently restore both state and anchor. Such deployments
must use an independent TPM/remote monotonic witness. Status remains short-lived
and production callers must reopen against newly signed authority status so a
compromised Device A cannot make Device B inherit A's state.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.

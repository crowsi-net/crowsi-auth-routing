# Standard Cargo release boundary

This revision reuses the independently reviewed task-7 gateway release gate,
archive checker and standard Cargo workflow, changing package identity/license
files and keeping separate routing default/all-features tests. No custom
publisher is required or added. The earlier prepare-only/always-fail proposal
and categorical cargo-repack prohibition are superseded.

Prepare has contents:read, no registry token, environment secrets or OIDC.
It tests/clippy-checks/packages the approved immutable tagged commit and exports
the actual archive and its digest/artifact ID. Publication is disabled unless
the reviewed SHA and explicit bootstrap/publish variables are configured.
The crates-public environment reviewer must review this release run's own
prepare artifact/run attempt and digest. A previous run/local digest does not
automatically approve newly generated runner bytes.

Publish pins the same source, rechecks gates/registry state, downloads that
exact artifact ID, inspects source/archive/normalized metadata/public lock,
and runs credential-free cargo publish --dry-run --locked --no-verify.
Native cmp must match the downloaded prepare archive before a registry token
is passed. The only token-bearing repository command is pinned standard Cargo
publish --locked --no-verify. No test, clippy, dependency compilation or repository
helper runs after the token is supplied. Cargo still repacks; this fixed-source,
fixed-config observation is not a guarantee for arbitrary future code/config.

OIDC id-token:write is a job-wide permission, including checkout, rustup, Cargo
and repository gate/archive checker before the auth action. All are trusted
review inputs; the auth step is not an OIDC isolation boundary. Future repository
Cargo config, credential provider, build.rs, workspace/include/generated inputs
or dependency changes require renewed review. VCS information is required for
runner release archives; the older local package without it is not release-ready.

Target-scoped dependencies are checked recursively by the reused archive checker.
Initial ownership/token and exact repository/workflow/environment Trusted Publisher
configuration remain unverified and unchanged. Bootstrap token is step-env only;
no cargo login or persistent credential file is proposed. No blind retry after an
ambiguous upload; inspect registry version/checksum before any resumption.

Routing remains HOLD until identity 0.10.0 is actually public, real public lock
is regenerated and registry/package/consumer checks plus independent review pass.
Source-overlay tests never substitute for public artifact resolution.

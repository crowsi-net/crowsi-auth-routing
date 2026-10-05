# Distribution candidate and release gates

Runtime sources, schemas, fixtures, license and attribution are unchanged.
The package allowlist includes implementation, contract schemas, tests, reviewed
fixtures, documentation, README, LICENSE and NOTICE; CI and operational stores
are excluded. Apache-2.0 remains the existing license. Source-overlay lockfiles
and fabricated registry checksums must not be substituted for public artifacts.

Release order: identity 0.10.0, then routing 0.1.0; gateway is independent.
Before adoption, resolve real public dependencies, regenerate the lock only when
required, review its actual diff, and pass locked tests/doc tests/clippy/package
including compilation of the extracted crate. Inspect package --list and archive.
Routing cannot complete registry verification until identity is published.

crate-quality.yml verifies public dependencies without registry credentials.
The initial OIDC draft was replaced by prepare-only/always-fail CI, which is now
superseded by the fixed-source standard Cargo workflow described in
[the current release boundary](../.github/PUBLISHING-HOLD.md). That document is
available in the repository; it is intentionally outside the crate allowlist.
Prepare builds/tests/packages without credentials. Before a token is supplied,
the publish runner verifies the same approved source and artifact ID/digest,
performs standard native no-verify dry-run packaging, and compares exact bytes.
The token step uses cargo publish --locked --no-verify; Cargo still repacks.
OIDC permission applies to the whole publish job and all its steps are trusted.
Do not extrapolate the fixed-source/config validation to arbitrary future crates.
No settings, ownership, authentication or hosted release have been verified here.
Default and test-support configurations are separate routing checks; test-support
is an opt-in verifier/replay/freshness testing seam, not the normal trust boundary.

Initial publication requires an approved short-lived minimally scoped API token;
later OIDC requires the exact Trusted Publisher tuple. Configure repository
release variables/environment protection only after independent review/approval.
The environment reviewer must approve this run's actual prepare artifact/digest;
generated digests do not constitute automatic or earlier-run approval.

Official references:
- https://doc.rust-lang.org/cargo/commands/cargo-publish.html
- https://crates.io/docs/trusted-publishing

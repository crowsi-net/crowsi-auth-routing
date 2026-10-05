# crowsi-auth-routing

Use the same validated authorization route declarations across an application and its MCP interface.

## What you can do

- Verify pinned route evidence.
- Resolve declared audience and scope requirements.

## Current scope

This library validates routing contracts. It does not authenticate users or own an identity database.

This library verifies declared transport authentication/authorization contracts. It is not an authentication service. Its production verifier uses caller-supplied trust and replay/status files; filesystem behavior is Linux-oriented.

## Package availability and verification

This is a reviewed distribution candidate; enabling crates.io in the manifest does not mean the version has been published. Verify registry availability before using the exact version. Rust 1.97 or newer is required. All dependencies must resolve from crates.io.

```sh
cargo test --locked --all-targets
cargo test --locked --doc
cargo package --locked
```

Publish and verify ihat-identity-assertion-contracts 0.10.0 first. Until it exists on crates.io, public-registry package/build verification is blocked. The existing private-registry lockfile is preserved as a historical source lock and must be regenerated from actual public registry artifacts before adoption. Source-overlay tests are separate evidence.

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

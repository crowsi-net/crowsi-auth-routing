# Using crowsi-auth-routing

Use the same validated authorization route declarations across an application and its MCP interface.

## Before you start

This library validates routing contracts. It does not authenticate users or own an identity database.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Verify pinned route evidence.
- Resolve declared audience and scope requirements.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)

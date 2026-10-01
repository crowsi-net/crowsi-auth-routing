use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_auth_routing::{AuthChannel, AuthError, PinnedStatusTrust, ProductionVerifier};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1,
    canonical_current_status_payload,
};

mod support;

#[test]
// ID-44
fn production_surface_exports_no_caller_constructible_freshness_or_memory_ledger() {
    let source = fs::read_to_string(format!("{}/src/lib.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("library source");
    assert!(!source.contains("ExactIdentitySnapshot"));
    assert!(!source.contains("InMemoryReplayLedger"));
    assert!(!source.contains("pub use identity_freshness::"));
    assert!(!source.contains("pub use replay::"));
    assert!(!source.contains("pub use verifier::verify_context"));
    assert!(source.contains("#[cfg(feature = \"test-support\")]"));
    assert!(source.contains("pub mod test_support"));
    assert!(source.contains("ProductionVerifier"));
}

#[test]
// ID-45
fn durable_replay_survives_restart_and_detects_state_rollback() {
    let root = private_root();
    let context_key = support::key(7);
    let policy = support::policy(&context_key, "active");
    let now = support::now();
    let evidence = support::signed_with_times(
        &context_key,
        AuthChannel::McpStdio,
        "sample-mcp",
        &["account.read"],
        now.saturating_sub(1),
        now + 20,
    );
    let status_key = SigningKey::from_bytes(&[11; 32]);
    let status_path = root.path().join("current-status.json");
    let replay_path = root.path().join("replay.json");
    let status_state_path = root.path().join("status-state.json");
    write_status(&status_path, &evidence, &status_key);
    let verifier = ProductionVerifier::open(
        &replay_path,
        &status_path,
        &status_state_path,
        trust(&status_key),
    )
    .expect("production verifier");
    let initial = fs::read(&replay_path).expect("initial state");
    verifier.verify(&policy, &evidence).expect("first use");
    let reopened = ProductionVerifier::open(
        &replay_path,
        &status_path,
        &status_state_path,
        trust(&status_key),
    )
    .expect("reopen");
    assert_eq!(
        reopened.verify(&policy, &evidence).err(),
        Some(AuthError::ReplayDetected)
    );
    fs::write(&replay_path, initial).expect("simulate rollback");
    assert!(matches!(
        ProductionVerifier::open(
            &replay_path,
            &status_path,
            &status_state_path,
            trust(&status_key),
        ),
        Err(AuthError::ReplayProtectionUnavailable)
    ));
}

#[test]
fn production_composition_checks_signature_then_pinned_status_then_durable_replay() {
    let root = private_root();
    let context_key = support::key(7);
    let policy = support::policy(&context_key, "active");
    let now = support::now();
    let evidence = support::signed_with_times(
        &context_key,
        AuthChannel::McpStdio,
        "sample-mcp",
        &["account.read"],
        now.saturating_sub(1),
        now + 20,
    );
    let status_key = SigningKey::from_bytes(&[11; 32]);
    let status_path = root.path().join("current-status.json");
    write_status(&status_path, &evidence, &status_key);
    let verifier = ProductionVerifier::open(
        root.path().join("replay.json"),
        &status_path,
        root.path().join("status-state.json"),
        trust(&status_key),
    )
    .expect("production composition");
    let mut tampered = evidence.clone();
    tampered.device_id = "device-attacker".into();
    assert_eq!(
        verifier.verify(&policy, &tampered).err(),
        Some(AuthError::InvalidSignature)
    );
    verifier
        .verify(&policy, &evidence)
        .expect("valid after rejected tamper");
    assert_eq!(
        verifier.verify(&policy, &evidence).err(),
        Some(AuthError::ReplayDetected)
    );
}

#[test]
// ID-46
fn authorization_expiry_cannot_outlive_its_exact_pinned_status() {
    let root = private_root();
    let context_key = support::key(7);
    let policy = support::policy(&context_key, "active");
    let evidence = support::signed(
        &context_key,
        AuthChannel::McpStdio,
        "sample-mcp",
        &["account.read"],
    );
    let status_key = SigningKey::from_bytes(&[11; 32]);
    let status_path = root.path().join("current-status.json");
    write_status(&status_path, &evidence, &status_key);
    let verifier = ProductionVerifier::open(
        root.path().join("replay.json"),
        &status_path,
        root.path().join("status-state.json"),
        trust(&status_key),
    )
    .expect("production composition");
    assert_eq!(
        verifier.verify(&policy, &evidence).err(),
        Some(AuthError::IdentityBindingMismatch)
    );
}

include!("support/production_boundary_helpers.rs");

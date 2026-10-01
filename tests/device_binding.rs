#![cfg(feature = "test-support")]

use crowsi_auth_routing::test_support::{DeviceIdentityBinding, verify_context};
use crowsi_auth_routing::{AuthChannel, AuthError};
use ed25519_dalek::Signer;
use support::{
    TestIdentitySnapshot as ExactIdentitySnapshot, TestReplayLedger as InMemoryReplayLedger,
};

mod support;

#[test]
fn signed_context_and_receipt_bind_the_exact_physical_device() {
    let key = support::key(7);
    let policy = support::policy(&key, "active");
    let evidence = support::signed(&key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    let receipt = verify_context(
        &policy,
        &evidence,
        &InMemoryReplayLedger::default(),
        &support::identity(&evidence),
    )
    .expect("signed device context")
    .authorize(&policy, "mcp-stdio")
    .expect("device-bound route");
    assert!(receipt.device_bound);
    assert_eq!(receipt.pairwise_subject, evidence.pairwise_subject);
    assert_eq!(receipt.device_id, evidence.device_id);
    assert_eq!(receipt.device_proof_key_ref, evidence.device_proof_key_ref);
    assert_eq!(receipt.session_ref, evidence.session_ref);
    assert_eq!(
        receipt.device_revocation_epoch,
        evidence.device_revocation_epoch
    );
}

#[test]
fn unavailable_stale_or_substituted_identity_state_fails_closed() {
    let key = support::key(7);
    let policy = support::policy(&key, "active");
    let evidence = support::signed(&key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    let binding = binding(&evidence);
    let unavailable = ExactIdentitySnapshot::unavailable(binding.clone());
    assert_eq!(
        verify_context(
            &policy,
            &evidence,
            &InMemoryReplayLedger::default(),
            &unavailable,
        )
        .err(),
        Some(AuthError::IdentityAuthorityUnavailable),
    );
    let mut current = binding.clone();
    current.device_revocation_epoch += 1;
    assert_eq!(
        verify_context(
            &policy,
            &evidence,
            &InMemoryReplayLedger::default(),
            &ExactIdentitySnapshot::available(current),
        )
        .err(),
        Some(AuthError::StaleRevocationEpoch),
    );
    let mut substituted = binding;
    substituted.session_ref = "sref_service_sample_attacker".into();
    assert_eq!(
        verify_context(
            &policy,
            &evidence,
            &InMemoryReplayLedger::default(),
            &ExactIdentitySnapshot::available(substituted),
        )
        .err(),
        Some(AuthError::IdentityBindingMismatch),
    );
}

#[test]
fn posture_and_device_fields_are_covered_by_the_adapter_signature() {
    let key = support::key(7);
    let policy = support::policy(&key, "active");
    let mut evidence =
        support::signed(&key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    evidence.device_id = "device-substituted".into();
    assert_eq!(
        verify_context(
            &policy,
            &evidence,
            &InMemoryReplayLedger::default(),
            &support::identity(&evidence),
        )
        .err(),
        Some(AuthError::InvalidSignature),
    );

    let mut posture = support::signed(&key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    posture.nonce = "assertion-nonce-posture".into();
    posture.device_posture = "quarantined".into();
    posture.signature = hex::encode(
        key.sign(&posture.signing_payload().expect("posture payload"))
            .to_bytes(),
    );
    assert_eq!(
        verify_context(
            &policy,
            &posture,
            &InMemoryReplayLedger::default(),
            &support::identity(&posture),
        )
        .err(),
        Some(AuthError::DevicePostureRejected),
    );
}

fn binding(evidence: &crowsi_auth_routing::UntrustedContext) -> DeviceIdentityBinding {
    DeviceIdentityBinding {
        pairwise_subject: evidence.pairwise_subject.clone(),
        device_id: evidence.device_id.clone(),
        device_proof_key_ref: evidence.device_proof_key_ref.clone(),
        session_ref: evidence.session_ref.clone(),
        device_posture: evidence.device_posture.clone(),
        device_posture_revision: evidence.device_posture_revision,
        subject_revocation_epoch: evidence.subject_revocation_epoch,
        service_revocation_epoch: evidence.service_revocation_epoch,
        device_revocation_epoch: evidence.device_revocation_epoch,
        session_revocation_epoch: evidence.session_revocation_epoch,
    }
}

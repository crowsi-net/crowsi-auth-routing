#![cfg(feature = "test-support")]

use crowsi_auth_routing::test_support::{DeviceIdentityBinding, verify_context};
use crowsi_auth_routing::{AuthChannel, AuthError};
use ed25519_dalek::Signer;
use support::{
    TestIdentitySnapshot as ExactIdentitySnapshot, TestReplayLedger as InMemoryReplayLedger,
};

mod support;

#[test]
fn revoking_device_a_does_not_invalidate_device_b() {
    let key = support::key(7);
    let policy = support::policy(&key, "active");
    let device_a = support::signed(&key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    let mut device_b = device_a.clone();
    device_b.device_id = "device-sample-2".into();
    device_b.device_proof_key_ref = "device-key-sample-2".into();
    device_b.nonce = "assertion-nonce-device-b".into();
    device_b.signature = hex::encode(
        key.sign(&device_b.signing_payload().expect("B payload"))
            .to_bytes(),
    );
    let mut current_a = binding(&device_a);
    current_a.device_revocation_epoch += 1;
    assert_eq!(
        verify_context(
            &policy,
            &device_a,
            &InMemoryReplayLedger::default(),
            &ExactIdentitySnapshot::available(current_a),
        )
        .err(),
        Some(AuthError::StaleRevocationEpoch),
    );
    assert!(
        verify_context(
            &policy,
            &device_b,
            &InMemoryReplayLedger::default(),
            &ExactIdentitySnapshot::available(binding(&device_b)),
        )
        .is_ok()
    );
}

fn binding(value: &crowsi_auth_routing::UntrustedContext) -> DeviceIdentityBinding {
    DeviceIdentityBinding {
        pairwise_subject: value.pairwise_subject.clone(),
        device_id: value.device_id.clone(),
        device_proof_key_ref: value.device_proof_key_ref.clone(),
        session_ref: value.session_ref.clone(),
        device_posture: value.device_posture.clone(),
        device_posture_revision: value.device_posture_revision,
        subject_revocation_epoch: value.subject_revocation_epoch,
        service_revocation_epoch: value.service_revocation_epoch,
        device_revocation_epoch: value.device_revocation_epoch,
        session_revocation_epoch: value.session_revocation_epoch,
    }
}

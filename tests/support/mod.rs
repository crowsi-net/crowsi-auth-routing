#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "test-support")]
use std::{collections::BTreeSet, sync::Mutex};

#[cfg(feature = "test-support")]
use crowsi_auth_routing::test_support::ReplayLedger;
use crowsi_auth_routing::{AuthChannel, AuthenticationAssurance, Policy, UntrustedContext};
use ed25519_dalek::{Signer, SigningKey};

#[cfg(feature = "test-support")]
mod identity;

#[cfg(feature = "test-support")]
pub use identity::TestIdentitySnapshot;

#[cfg(feature = "test-support")]
#[derive(Default)]
pub struct TestReplayLedger(Mutex<BTreeSet<(String, String)>>);

#[cfg(feature = "test-support")]
impl ReplayLedger for TestReplayLedger {
    fn consume(
        &self,
        issuer: &str,
        nonce: &str,
        _expires_at: u64,
        _now: u64,
    ) -> crowsi_auth_routing::Result<()> {
        let mut entries = self
            .0
            .lock()
            .map_err(|_| crowsi_auth_routing::AuthError::ReplayProtectionUnavailable)?;
        if !entries.insert((issuer.into(), nonce.into())) {
            return Err(crowsi_auth_routing::AuthError::ReplayDetected);
        }
        Ok(())
    }
}

#[cfg(feature = "test-support")]
pub fn identity(evidence: &UntrustedContext) -> TestIdentitySnapshot {
    identity::identity(evidence)
}

#[cfg(feature = "test-support")]
pub fn verify(
    policy: &Policy,
    evidence: &UntrustedContext,
    replay: &dyn ReplayLedger,
) -> crowsi_auth_routing::Result<crowsi_auth_routing::VerifiedContext> {
    identity::verify(policy, evidence, replay)
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_secs()
}

pub fn operation_digest() -> &'static str {
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

pub fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

pub fn verifier_fragment(key: &SigningKey) -> String {
    format!(
        "\"context_verifier\":{{\"issuer\":\"sample-session-adapter\",\
         \"ed25519_public_key\":\"{}\"}},",
        hex::encode(key.verifying_key().to_bytes())
    )
}

pub fn policy_json(key: &SigningKey, activation: &str) -> String {
    format!(
        r#"{{
          "schema_version":4,
          "service_id":"sample-service",
          "session_authority":"service-sqlite",
          {}
          "routes":[
            {{"id":"app-api","channel":"app-http","audience":"sample-local-api",
              "credential_source":"secure-cookie","required_scopes":["account.read"],
              "activation":"{}","protected_resource_metadata":null}},
            {{"id":"mcp-stdio","channel":"mcp-stdio","audience":"sample-mcp",
              "credential_source":"crowsi-broker-reference",
              "required_scopes":["account.read"],"activation":"active",
              "protected_resource_metadata":null}}
          ]
        }}"#,
        verifier_fragment(key),
        activation
    )
}

pub fn policy(key: &SigningKey, activation: &str) -> Policy {
    Policy::from_json(&policy_json(key, activation)).expect("valid policy")
}

pub fn unsigned_json(channel: AuthChannel, audience: &str) -> String {
    serde_json::json!({
        "schema_version": 5,
        "issuer": "sample-session-adapter",
        "service_id": "sample-service",
        "pairwise_subject": "pairwise-sample-account-1",
        "device_id": "device-sample-1",
        "device_proof_key_ref": "device-key-sample-1",
        "session_ref": "sref_service_sample_session_1",
        "device_posture": "compliant",
        "device_posture_revision": 4,
        "subject_revocation_epoch": 3,
        "service_revocation_epoch": 5,
        "device_revocation_epoch": 7,
        "session_revocation_epoch": 11,
        "channel": channel,
        "audience": audience,
        "scopes": ["account.read"],
        "issued_at": now(),
        "expires_at": now() + 120,
        "nonce": "assertion-nonce-1",
        "authentication_assurance": "aal1",
        "authenticated_at": now(),
        "operation_digest": operation_digest(),
        "signature": "0".repeat(128)
    })
    .to_string()
}

pub fn signed(
    key: &SigningKey,
    channel: AuthChannel,
    audience: &str,
    scopes: &[&str],
) -> UntrustedContext {
    let current = now();
    signed_with_times(
        key,
        channel,
        audience,
        scopes,
        current.saturating_sub(1),
        current + 120,
    )
}

include!("step_up.rs");

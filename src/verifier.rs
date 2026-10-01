use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::policy::ContextVerifierConfig;
use crate::{
    AuthError, Policy, Result, UntrustedContext, VerifiedContext,
    identity_freshness::{DeviceIdentityBinding, IdentityFreshness},
    replay::ReplayLedger,
};

#[cfg(feature = "test-support")]
pub fn verify_context(
    policy: &Policy,
    evidence: &UntrustedContext,
    replay_ledger: &dyn ReplayLedger,
    identity_freshness: &dyn IdentityFreshness,
) -> Result<VerifiedContext> {
    verify_at(
        policy,
        evidence,
        replay_ledger,
        identity_freshness,
        unix_now()?,
    )
}

pub(crate) fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthError::ClockUnavailable)
}

pub(crate) fn verify_at(
    policy: &Policy,
    evidence: &UntrustedContext,
    replay_ledger: &dyn ReplayLedger,
    identity_freshness: &dyn IdentityFreshness,
    now: u64,
) -> Result<VerifiedContext> {
    let verifier = policy
        .context_verifier()
        .ok_or(AuthError::VerificationUnavailable)?;
    if evidence.issuer != verifier.issuer {
        return Err(AuthError::InvalidSignature);
    }
    let claims = evidence.validate(now)?;
    let key_bytes = decode::<32>(&verifier.ed25519_public_key)?;
    let signature_bytes = decode::<64>(&evidence.signature)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| AuthError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(&evidence.signing_payload()?, &signature)
        .map_err(|_| AuthError::InvalidSignature)?;
    identity_freshness.verify_current(
        &DeviceIdentityBinding {
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
        },
        evidence.expires_at,
    )?;
    replay_ledger.consume(&evidence.issuer, &evidence.nonce, evidence.expires_at, now)?;
    Ok(VerifiedContext::from_verified(claims, binding(verifier)))
}

pub(crate) fn binding(verifier: &ContextVerifierConfig) -> String {
    format!("{}:{}", verifier.issuer, verifier.ed25519_public_key)
}

fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| AuthError::InvalidSignature)?;
    Ok(bytes)
}

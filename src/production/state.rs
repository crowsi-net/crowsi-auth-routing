use std::{collections::BTreeMap, path::Path};

use ihat_identity_assertion_contracts::{CurrentDeviceStatusV1, canonical_current_status_payload};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuthError, Result, identity_freshness::DeviceIdentityBinding, secure_file};

use super::freshness::binding;

const SCHEMA: &str = "crowsi://auth/current-status-anchor/v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    revision: u64,
    service_id: String,
    binding: DeviceIdentityBinding,
    expires_at: u64,
    last_payload_digest: String,
    seen_nonces: BTreeMap<String, u64>,
}

pub(super) fn apply(path: &Path, status: &CurrentDeviceStatusV1, now: u64) -> Result<()> {
    let anchor_path = secure_file::sibling(path, "anchor").map_err(identity)?;
    let lock_path = secure_file::sibling(path, "lock").map_err(identity)?;
    let _guard = secure_file::lock(&lock_path).map_err(identity)?;
    let bytes = secure_file::read(path).map_err(identity)?;
    let anchored = secure_file::read(&anchor_path).map_err(identity)?;
    let mut state = load(bytes.as_deref(), anchored.as_deref())?;
    let payload_digest = hex::encode(Sha256::digest(canonical_current_status_payload(status)));
    let nonce_digest = hex::encode(Sha256::digest(status.nonce.as_bytes()));
    if state.seen_nonces.contains_key(&nonce_digest) {
        return (state.last_payload_digest == payload_digest)
            .then_some(())
            .ok_or(AuthError::IdentityAuthorityUnavailable);
    }
    enforce_monotonic(&state, status)?;
    state.seen_nonces.retain(|_, expiry| *expiry > now);
    if state.seen_nonces.len() >= 100_000 {
        return Err(AuthError::IdentityAuthorityUnavailable);
    }
    state
        .seen_nonces
        .insert(nonce_digest, status.expires_at_epoch_s);
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(AuthError::IdentityAuthorityUnavailable)?;
    state.service_id = status.service_id.clone();
    state.binding = binding(status);
    state.expires_at = status.expires_at_epoch_s;
    state.last_payload_digest = payload_digest;
    write(path, &anchor_path, &state)
}

fn load(bytes: Option<&[u8]>, anchor_bytes: Option<&[u8]>) -> Result<State> {
    match (bytes, anchor_bytes) {
        (None, None) => Ok(empty()),
        (Some(bytes), Some(anchor_bytes)) => {
            let state: State = serde_json::from_slice(bytes)
                .map_err(|_| AuthError::IdentityAuthorityUnavailable)?;
            if state.schema != SCHEMA || anchor_bytes != anchor(state.revision, bytes) {
                return Err(AuthError::IdentityAuthorityUnavailable);
            }
            Ok(state)
        }
        _ => Err(AuthError::IdentityAuthorityUnavailable),
    }
}

fn write(path: &Path, anchor_path: &Path, state: &State) -> Result<()> {
    let bytes = serde_json::to_vec(state).map_err(|_| AuthError::IdentityAuthorityUnavailable)?;
    secure_file::write(path, &bytes).map_err(identity)?;
    secure_file::write(anchor_path, &anchor(state.revision, &bytes)).map_err(identity)
}

fn anchor(revision: u64, bytes: &[u8]) -> Vec<u8> {
    format!(
        "CROWSI-AUTH-STATUS-ANCHOR-V1\n{revision}\n{}\n",
        hex::encode(Sha256::digest(bytes))
    )
    .into_bytes()
}

fn enforce_monotonic(state: &State, status: &CurrentDeviceStatusV1) -> Result<()> {
    if state.revision == 0 {
        return Ok(());
    }
    let new = binding(status);
    let old = &state.binding;
    if new.subject_revocation_epoch < old.subject_revocation_epoch
        || new.service_revocation_epoch < old.service_revocation_epoch
        || (new.device_id == old.device_id
            && new.device_revocation_epoch < old.device_revocation_epoch)
        || (new.session_ref == old.session_ref
            && new.session_revocation_epoch < old.session_revocation_epoch)
    {
        return Err(AuthError::StaleRevocationEpoch);
    }
    Ok(())
}

fn empty() -> State {
    State {
        schema: SCHEMA.into(),
        revision: 0,
        service_id: String::new(),
        binding: DeviceIdentityBinding {
            pairwise_subject: String::new(),
            device_id: String::new(),
            device_proof_key_ref: String::new(),
            session_ref: String::new(),
            device_posture: String::new(),
            device_posture_revision: 0,
            subject_revocation_epoch: 0,
            service_revocation_epoch: 0,
            device_revocation_epoch: 0,
            session_revocation_epoch: 0,
        },
        expires_at: 0,
        last_payload_digest: String::new(),
        seen_nonces: BTreeMap::new(),
    }
}

fn identity(_: AuthError) -> AuthError {
    AuthError::IdentityAuthorityUnavailable
}

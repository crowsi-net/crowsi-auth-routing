use std::path::Path;

use ihat_identity_assertion_contracts::{
    CurrentDeviceStatusV1, decode_current_status_strict, verify_current_status_at,
};

use crate::{
    AuthError, Result,
    identity_freshness::{DeviceIdentityBinding, IdentityFreshness},
    secure_file,
};

use super::{state, trust::PinnedStatusTrust};

pub(super) struct PinnedCurrentStatus {
    trust: PinnedStatusTrust,
    binding: DeviceIdentityBinding,
    expires_at: u64,
}

impl PinnedCurrentStatus {
    pub(super) fn open(
        status_path: &Path,
        state_path: &Path,
        trust: PinnedStatusTrust,
    ) -> Result<Self> {
        let status_path = secure_file::absolute_private_path(status_path).map_err(identity)?;
        let state_path = secure_file::absolute_private_path(state_path).map_err(identity)?;
        let wire = secure_file::read(&status_path)
            .map_err(identity)?
            .ok_or(AuthError::IdentityAuthorityUnavailable)?;
        let status = decode_current_status_strict(&wire)
            .map_err(|_| AuthError::IdentityAuthorityUnavailable)?;
        let now = crate::verifier::unix_now()?;
        verify_current_status_at(&status, &trust, &trust.issuer, &trust.audience, now)
            .map_err(|_| AuthError::IdentityAuthorityUnavailable)?;
        if status.service_id != trust.service_id {
            return Err(AuthError::IdentityAuthorityUnavailable);
        }
        state::apply(&state_path, &status, now)?;
        Ok(Self {
            trust,
            binding: binding(&status),
            expires_at: status.expires_at_epoch_s,
        })
    }

    pub(super) fn status_public_key_hex(&self) -> String {
        self.trust.public_key_hex()
    }
}

impl IdentityFreshness for PinnedCurrentStatus {
    fn verify_current(
        &self,
        value: &DeviceIdentityBinding,
        authorization_expires_at_epoch_s: u64,
    ) -> Result<()> {
        if crate::verifier::unix_now()? >= self.expires_at {
            return Err(AuthError::IdentityAuthorityUnavailable);
        }
        if value != &self.binding || authorization_expires_at_epoch_s > self.expires_at {
            return Err(AuthError::IdentityBindingMismatch);
        }
        if value.device_posture != "compliant" {
            return Err(AuthError::DevicePostureRejected);
        }
        Ok(())
    }
}

pub(super) fn binding(value: &CurrentDeviceStatusV1) -> DeviceIdentityBinding {
    DeviceIdentityBinding {
        pairwise_subject: value.pairwise_subject.clone(),
        device_id: value.device_id.clone(),
        device_proof_key_ref: value.device_proof_key_ref.clone(),
        session_ref: value.session_ref.clone(),
        device_posture: value.device_posture.state.clone(),
        device_posture_revision: value.device_posture.revision,
        subject_revocation_epoch: value.revocation_epochs.subject,
        service_revocation_epoch: value.revocation_epochs.service,
        device_revocation_epoch: value.revocation_epochs.device,
        session_revocation_epoch: value.revocation_epochs.session,
    }
}

fn identity(_: AuthError) -> AuthError {
    AuthError::IdentityAuthorityUnavailable
}

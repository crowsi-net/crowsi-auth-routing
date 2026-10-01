use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceIdentityBinding {
    pub pairwise_subject: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub session_ref: String,
    pub device_posture: String,
    pub device_posture_revision: u64,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
}

pub trait IdentityFreshness: Send + Sync {
    /// Compares a signed short-lived binding with the current identity authority state.
    ///
    /// # Errors
    ///
    /// Must fail closed when the authority is unavailable, the device is not active,
    /// or any proof-key, posture, or revocation field is not current.
    fn verify_current(
        &self,
        binding: &DeviceIdentityBinding,
        authorization_expires_at_epoch_s: u64,
    ) -> Result<()>;
}

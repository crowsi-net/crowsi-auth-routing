use std::collections::BTreeSet;

use crate::{AuthChannel, AuthenticationAssurance};

pub(crate) struct ValidatedClaims {
    pub service_id: String,
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
    pub channel: AuthChannel,
    pub audience: String,
    pub scopes: BTreeSet<String>,
    pub expires_at: u64,
    pub assurance: Option<AuthenticationAssurance>,
    pub authenticated_at: Option<u64>,
    pub operation_digest: Option<String>,
}

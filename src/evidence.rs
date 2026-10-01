use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::assurance::validate_evidence;
use crate::claims::ValidatedClaims;
use crate::validation::{context_audience, context_identifier, session_reference};
use crate::{AuthChannel, AuthError, AuthenticationAssurance, Result};

const MAX_ASSERTION_SECONDS: u64 = 300;

/// Caller-controlled data that becomes trusted only after `verify_context`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedContext {
    pub schema_version: u8,
    pub issuer: String,
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
    pub scopes: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_assurance: Option<AuthenticationAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_digest: Option<String>,
    pub signature: String,
}

impl UntrustedContext {
    pub fn from_json(input: &str) -> Result<Self> {
        let evidence: Self =
            serde_json::from_str(input).map_err(|_| AuthError::InvalidContext("json"))?;
        evidence.validate_structure()?;
        Ok(evidence)
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        crate::evidence_canonical::signing_payload(self)
    }

    pub(crate) fn validate(&self, now: u64) -> Result<ValidatedClaims> {
        let scopes = self.validate_structure()?;
        if self.issued_at > now
            || now >= self.expires_at
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > MAX_ASSERTION_SECONDS
        {
            return Err(AuthError::Expired);
        }
        Ok(ValidatedClaims {
            service_id: context_identifier("service_id", &self.service_id, 64)?,
            pairwise_subject: context_identifier("pairwise_subject", &self.pairwise_subject, 128)?,
            device_id: context_identifier("device_id", &self.device_id, 128)?,
            device_proof_key_ref: context_identifier(
                "device_proof_key_ref",
                &self.device_proof_key_ref,
                128,
            )?,
            session_ref: session_reference(&self.session_ref)?,
            device_posture: context_identifier("device_posture", &self.device_posture, 64)?,
            device_posture_revision: self.device_posture_revision,
            subject_revocation_epoch: self.subject_revocation_epoch,
            service_revocation_epoch: self.service_revocation_epoch,
            device_revocation_epoch: self.device_revocation_epoch,
            session_revocation_epoch: self.session_revocation_epoch,
            channel: self.channel,
            audience: context_audience(&self.audience)?,
            scopes,
            expires_at: self.expires_at,
            assurance: self.authentication_assurance,
            authenticated_at: self.authenticated_at,
            operation_digest: self.operation_digest.clone(),
        })
    }

    pub(crate) fn validate_structure(&self) -> Result<BTreeSet<String>> {
        if self.issued_at == 0
            || self.expires_at == 0
            || self.signature.len() != 128
            || !self.signature.bytes().all(lower_hex)
        {
            return Err(AuthError::InvalidContext("assertion"));
        }
        validate_evidence(
            self.schema_version,
            self.authentication_assurance,
            self.authenticated_at,
            self.operation_digest.as_deref(),
            self.issued_at,
        )?;
        context_identifier("issuer", &self.issuer, 128)?;
        context_identifier("service_id", &self.service_id, 64)?;
        context_identifier("pairwise_subject", &self.pairwise_subject, 128)?;
        context_identifier("device_id", &self.device_id, 128)?;
        context_identifier("device_proof_key_ref", &self.device_proof_key_ref, 128)?;
        session_reference(&self.session_ref)?;
        context_identifier("device_posture", &self.device_posture, 64)?;
        if self.device_posture_revision == 0
            || [
                self.subject_revocation_epoch,
                self.service_revocation_epoch,
                self.device_revocation_epoch,
                self.session_revocation_epoch,
            ]
            .contains(&0)
        {
            return Err(AuthError::InvalidContext("identity_epoch"));
        }
        context_audience(&self.audience)?;
        context_identifier("nonce", &self.nonce, 128)?;
        let scopes = self
            .scopes
            .iter()
            .map(|scope| context_identifier("scope", scope, 96))
            .collect::<Result<BTreeSet<_>>>()?;
        if scopes.is_empty() || scopes.len() != self.scopes.len() || scopes.len() > 32 {
            return Err(AuthError::InvalidContext("scopes"));
        }
        Ok(scopes)
    }
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

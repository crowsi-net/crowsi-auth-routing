use std::collections::BTreeSet;

use crate::assurance::valid_operation_digest;
use crate::claims::ValidatedClaims;
use crate::identity_freshness::DeviceIdentityBinding;
use crate::verifier::{binding, unix_now};
use crate::{Activation, AuthChannel, AuthError, AuthenticationAssurance, Policy, Result};

/// A context produced only by verification of a service-trusted signed assertion.
pub struct VerifiedContext {
    service_id: String,
    identity: DeviceIdentityBinding,
    channel: AuthChannel,
    audience: String,
    scopes: BTreeSet<String>,
    expires_at: u64,
    assurance: Option<AuthenticationAssurance>,
    authenticated_at: Option<u64>,
    operation_digest: Option<String>,
    verifier_binding: String,
}

impl VerifiedContext {
    pub(crate) fn from_verified(claims: ValidatedClaims, verifier_binding: String) -> Self {
        Self {
            service_id: claims.service_id,
            identity: DeviceIdentityBinding {
                pairwise_subject: claims.pairwise_subject,
                device_id: claims.device_id,
                device_proof_key_ref: claims.device_proof_key_ref,
                session_ref: claims.session_ref,
                device_posture: claims.device_posture,
                device_posture_revision: claims.device_posture_revision,
                subject_revocation_epoch: claims.subject_revocation_epoch,
                service_revocation_epoch: claims.service_revocation_epoch,
                device_revocation_epoch: claims.device_revocation_epoch,
                session_revocation_epoch: claims.session_revocation_epoch,
            },
            channel: claims.channel,
            audience: claims.audience,
            scopes: claims.scopes,
            expires_at: claims.expires_at,
            assurance: claims.assurance,
            authenticated_at: claims.authenticated_at,
            operation_digest: claims.operation_digest,
            verifier_binding,
        }
    }

    pub fn authorize(&self, policy: &Policy, route_id: &str) -> Result<AuthorizationReceipt> {
        self.authorize_bound(policy, route_id, None)
    }

    pub fn authorize_operation(
        self,
        policy: &Policy,
        route_id: &str,
        operation_digest: &str,
    ) -> Result<AuthorizationReceipt> {
        if !valid_operation_digest(operation_digest) {
            return Err(AuthError::OperationBindingMismatch);
        }
        self.authorize_bound(policy, route_id, Some(operation_digest))
    }

    fn authorize_bound(
        &self,
        policy: &Policy,
        route_id: &str,
        operation_digest: Option<&str>,
    ) -> Result<AuthorizationReceipt> {
        let route = policy.route(route_id)?;
        if route.activation != Activation::Active {
            return Err(AuthError::InactiveRoute);
        }
        if policy.context_verifier().map(binding).as_deref() != Some(&self.verifier_binding) {
            return Err(AuthError::InvalidSignature);
        }
        let now = unix_now()?;
        if now >= self.expires_at {
            return Err(AuthError::Expired);
        }
        if self.service_id != policy.service_id || self.audience != route.audience {
            return Err(AuthError::WrongAudience);
        }
        if self.channel != route.channel {
            return Err(AuthError::WrongChannel);
        }
        if route
            .required_scopes
            .iter()
            .any(|scope| !self.scopes.contains(scope))
        {
            return Err(AuthError::MissingScope);
        }
        if let Some(minimum) = route.minimum_assurance {
            let recent = self.authenticated_at.is_some_and(|authenticated_at| {
                authenticated_at <= now
                    && route
                        .max_authentication_age_seconds
                        .is_some_and(|maximum| now.saturating_sub(authenticated_at) <= maximum)
            });
            if self.assurance.is_none_or(|actual| actual < minimum) || !recent {
                return Err(AuthError::StepUpRequired);
            }
            if self.operation_digest.as_deref() != operation_digest {
                return Err(AuthError::OperationBindingMismatch);
            }
        }
        Ok(AuthorizationReceipt {
            service_id: policy.service_id.clone(),
            route_id: route.id.clone(),
            channel: route.channel,
            expires_at: self.expires_at,
            account_bound: !self.identity.pairwise_subject.is_empty(),
            pairwise_subject: self.identity.pairwise_subject.clone(),
            device_id: self.identity.device_id.clone(),
            device_proof_key_ref: self.identity.device_proof_key_ref.clone(),
            session_ref: self.identity.session_ref.clone(),
            device_posture_revision: self.identity.device_posture_revision,
            subject_revocation_epoch: self.identity.subject_revocation_epoch,
            service_revocation_epoch: self.identity.service_revocation_epoch,
            device_revocation_epoch: self.identity.device_revocation_epoch,
            session_revocation_epoch: self.identity.session_revocation_epoch,
            device_bound: true,
            assurance: self.assurance,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationReceipt {
    pub service_id: String,
    pub route_id: String,
    pub channel: AuthChannel,
    pub expires_at: u64,
    pub account_bound: bool,
    pub pairwise_subject: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub session_ref: String,
    pub device_posture_revision: u64,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub device_bound: bool,
    pub assurance: Option<AuthenticationAssurance>,
}

use crowsi_auth_routing::test_support::{
    DeviceIdentityBinding, IdentityFreshness, ReplayLedger, verify_context,
};
use crowsi_auth_routing::{AuthError, Policy, Result, UntrustedContext, VerifiedContext};

#[derive(Clone)]
pub struct TestIdentitySnapshot {
    binding: DeviceIdentityBinding,
    available: bool,
}

impl TestIdentitySnapshot {
    pub fn available(binding: DeviceIdentityBinding) -> Self {
        Self {
            binding,
            available: true,
        }
    }

    pub fn unavailable(binding: DeviceIdentityBinding) -> Self {
        Self {
            binding,
            available: false,
        }
    }
}

impl IdentityFreshness for TestIdentitySnapshot {
    fn verify_current(&self, binding: &DeviceIdentityBinding, _: u64) -> Result<()> {
        if !self.available {
            return Err(AuthError::IdentityAuthorityUnavailable);
        }
        if binding.subject_revocation_epoch < self.binding.subject_revocation_epoch
            || binding.service_revocation_epoch < self.binding.service_revocation_epoch
            || binding.device_revocation_epoch < self.binding.device_revocation_epoch
            || binding.session_revocation_epoch < self.binding.session_revocation_epoch
        {
            return Err(AuthError::StaleRevocationEpoch);
        }
        if binding != &self.binding {
            return Err(AuthError::IdentityBindingMismatch);
        }
        if binding.device_posture != "compliant" {
            return Err(AuthError::DevicePostureRejected);
        }
        Ok(())
    }
}

pub fn identity(evidence: &UntrustedContext) -> TestIdentitySnapshot {
    TestIdentitySnapshot::available(DeviceIdentityBinding {
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
    })
}

pub fn verify(
    policy: &Policy,
    evidence: &UntrustedContext,
    replay: &dyn ReplayLedger,
) -> Result<VerifiedContext> {
    verify_context(policy, evidence, replay, &identity(evidence))
}

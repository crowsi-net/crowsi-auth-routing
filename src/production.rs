use std::path::Path;

use crate::{
    AuthError, Policy, Result, UntrustedContext, VerifiedContext, replay::FileReplayLedger,
};

mod freshness;
mod state;
mod trust;

use freshness::PinnedCurrentStatus;
pub use trust::PinnedStatusTrust;

pub struct ProductionVerifier {
    replay: FileReplayLedger,
    freshness: PinnedCurrentStatus,
}

impl ProductionVerifier {
    /// Opens a production verifier backed only by pinned status and durable replay state.
    ///
    /// # Errors
    /// Rejects unsafe state, untrusted status, rollback, or ambiguous key reuse.
    pub fn open(
        replay_path: impl AsRef<Path>,
        status_path: impl AsRef<Path>,
        status_state_path: impl AsRef<Path>,
        trust: PinnedStatusTrust,
    ) -> Result<Self> {
        Ok(Self {
            replay: FileReplayLedger::open(replay_path)?,
            freshness: PinnedCurrentStatus::open(
                status_path.as_ref(),
                status_state_path.as_ref(),
                trust,
            )?,
        })
    }

    /// Verifies signature, pinned current identity, then durably consumes replay state.
    ///
    /// # Errors
    /// Fails closed at any verification or durable-state boundary.
    pub fn verify(&self, policy: &Policy, evidence: &UntrustedContext) -> Result<VerifiedContext> {
        let verifier = policy
            .context_verifier()
            .ok_or(AuthError::VerificationUnavailable)?;
        if verifier.ed25519_public_key == self.freshness.status_public_key_hex() {
            return Err(AuthError::IdentityAuthorityUnavailable);
        }
        crate::verifier::verify_at(
            policy,
            evidence,
            &self.replay,
            &self.freshness,
            crate::verifier::unix_now()?,
        )
    }
}

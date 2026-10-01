use ed25519_dalek::{Signature, VerifyingKey};
use ihat_identity_assertion_contracts::AssertionVerifier;

use crate::{AuthError, Result};

#[derive(Clone)]
pub struct PinnedStatusTrust {
    pub(super) key: VerifyingKey,
    pub(super) key_id: String,
    pub(super) issuer: String,
    pub(super) audience: String,
    pub(super) service_id: String,
}

impl PinnedStatusTrust {
    /// Pins the independent identity-status signer and exact consumer context.
    ///
    /// # Errors
    /// Rejects weak keys and empty or oversized identifiers.
    pub fn new(
        key: [u8; 32],
        key_id: &str,
        issuer: &str,
        audience: &str,
        service: &str,
    ) -> Result<Self> {
        let key =
            VerifyingKey::from_bytes(&key).map_err(|_| AuthError::IdentityAuthorityUnavailable)?;
        if key.is_weak()
            || !valid(key_id, 128)
            || !valid(issuer, 512)
            || !valid(audience, 128)
            || !valid(service, 128)
        {
            return Err(AuthError::IdentityAuthorityUnavailable);
        }
        Ok(Self {
            key,
            key_id: key_id.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            service_id: service.into(),
        })
    }

    pub(super) fn public_key_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }
}

impl AssertionVerifier for PinnedStatusTrust {
    fn verify(&self, key_id: &str, payload: &[u8], encoded: &str) -> bool {
        let Ok(bytes) = hex::decode(encoded) else {
            return false;
        };
        let Ok(signature) = Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        key_id == self.key_id && self.key.verify_strict(payload, &signature).is_ok()
    }
}

fn valid(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

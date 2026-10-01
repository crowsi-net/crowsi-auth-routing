use serde::{Deserialize, Serialize};

use crate::{AuthError, Result};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticationAssurance {
    Aal1,
    Aal2,
    Aal3,
}

impl AuthenticationAssurance {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Aal1 => "aal1",
            Self::Aal2 => "aal2",
            Self::Aal3 => "aal3",
        }
    }
}

pub(crate) fn validate_evidence(
    schema_version: u8,
    assurance: Option<AuthenticationAssurance>,
    authenticated_at: Option<u64>,
    operation_digest: Option<&str>,
    issued_at: u64,
) -> Result<()> {
    match (
        schema_version,
        assurance,
        authenticated_at,
        operation_digest,
    ) {
        (5, Some(_), Some(time), Some(digest))
            if time > 0 && time <= issued_at && valid_operation_digest(digest) =>
        {
            Ok(())
        }
        (5, _, _, _) => Err(AuthError::InvalidContext("assurance")),
        _ => Err(AuthError::InvalidContext("assertion")),
    }
}

pub(crate) fn valid_operation_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| digest.len() == 64 && digest.bytes().all(lower_hex))
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

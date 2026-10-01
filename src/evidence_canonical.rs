use crate::{AuthError, Result, UntrustedContext};

pub(crate) fn signing_payload(value: &UntrustedContext) -> Result<Vec<u8>> {
    let scopes = value.validate_structure()?;
    let mut output = Vec::new();
    for field in [
        "crowsi-context-v5",
        &value.issuer,
        &value.service_id,
        &value.pairwise_subject,
        &value.device_id,
        &value.device_proof_key_ref,
        &value.session_ref,
        &value.device_posture,
        &value.device_posture_revision.to_string(),
        &value.subject_revocation_epoch.to_string(),
        &value.service_revocation_epoch.to_string(),
        &value.device_revocation_epoch.to_string(),
        &value.session_revocation_epoch.to_string(),
        value.channel.label(),
        &value.audience,
        &value.issued_at.to_string(),
        &value.expires_at.to_string(),
        &value.nonce,
    ] {
        append(&mut output, field)?;
    }
    if let (Some(assurance), Some(authenticated_at), Some(operation_digest)) = (
        value.authentication_assurance,
        value.authenticated_at,
        value.operation_digest.as_deref(),
    ) {
        append(&mut output, assurance.label())?;
        append(&mut output, &authenticated_at.to_string())?;
        append(&mut output, operation_digest)?;
    }
    for scope in scopes {
        append(&mut output, &scope)?;
    }
    Ok(output)
}

fn append(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length =
        u32::try_from(value.len()).map_err(|_| AuthError::InvalidContext("canonical_length"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

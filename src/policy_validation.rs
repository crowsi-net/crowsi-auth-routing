use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;

use crate::policy::ContextVerifierConfig;
use crate::validation::{https_uri, identifier};
use crate::{AuthChannel, AuthError, CredentialSource, Result, Route};

pub(crate) fn verifier(config: &ContextVerifierConfig) -> Result<()> {
    identifier("context_issuer", &config.issuer, 128)?;
    let key = config.ed25519_public_key.as_bytes();
    if key.len() != 64
        || !key
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(AuthError::InvalidPolicy("context_verification_key"));
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(&config.ed25519_public_key, &mut bytes)
        .map_err(|_| AuthError::InvalidPolicy("context_verification_key"))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| AuthError::InvalidPolicy("context_verification_key"))?;
    if key.is_weak() {
        return Err(AuthError::InvalidPolicy("context_verification_key"));
    }
    Ok(())
}

pub(crate) fn route(schema_version: u8, route: &Route) -> Result<()> {
    identifier("route_id", &route.id, 64)?;
    if route.channel == AuthChannel::McpHttp {
        https_uri("audience", &route.audience)?;
    } else {
        identifier("audience", &route.audience, 128)?;
    }
    let expected = match route.channel {
        AuthChannel::AppHttp => CredentialSource::SecureCookie,
        AuthChannel::McpHttp => CredentialSource::AuthorizationHeader,
        AuthChannel::McpStdio => CredentialSource::CrowsiBrokerReference,
    };
    if route.credential_source != expected {
        return Err(AuthError::InvalidPolicy("credential_source"));
    }
    scopes(&route.required_scopes)?;
    match (
        schema_version,
        route.minimum_assurance,
        route.max_authentication_age_seconds,
    ) {
        (4, Some(_), Some(60..=3600)) | (4, None, None) => {}
        _ => return Err(AuthError::InvalidPolicy("step_up")),
    }
    match (route.channel, route.protected_resource_metadata.as_deref()) {
        (AuthChannel::McpHttp, Some("rfc9728"))
        | (AuthChannel::AppHttp, None)
        | (AuthChannel::McpStdio, None) => Ok(()),
        _ => Err(AuthError::InvalidPolicy("protected_resource_metadata")),
    }
}

fn scopes(scopes: &[String]) -> Result<()> {
    let unique = scopes.iter().collect::<BTreeSet<_>>();
    if scopes.is_empty() || scopes.len() > 32 || unique.len() != scopes.len() {
        return Err(AuthError::InvalidPolicy("required_scopes"));
    }
    for scope in scopes {
        identifier("scope", scope, 96)?;
    }
    Ok(())
}

use crate::{AuthError, Result};

pub(crate) fn identifier(field: &'static str, value: &str, max: usize) -> Result<String> {
    let valid = !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b':')
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase());
    valid
        .then(|| value.to_owned())
        .ok_or(AuthError::InvalidPolicy(field))
}

pub(crate) fn context_identifier(field: &'static str, value: &str, max: usize) -> Result<String> {
    identifier(field, value, max).map_err(|_| AuthError::InvalidContext(field))
}

pub(crate) fn session_reference(value: &str) -> Result<String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase());
    valid
        .then(|| value.to_owned())
        .ok_or(AuthError::InvalidContext("session_ref"))
}

pub(crate) fn context_audience(value: &str) -> Result<String> {
    let valid = !value.is_empty()
        && value.len() <= 300
        && value
            .chars()
            .all(|character| character.is_ascii_graphic() && !character.is_ascii_whitespace());
    valid
        .then(|| value.to_owned())
        .ok_or(AuthError::InvalidContext("audience"))
}

pub(crate) fn https_uri(field: &'static str, value: &str) -> Result<String> {
    let suffix = value
        .strip_prefix("https://")
        .filter(|suffix| !suffix.is_empty() && !suffix.contains('@'));
    let valid = suffix.is_some_and(|suffix| {
        suffix.len() <= 300
            && !suffix.contains("//")
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_/:%".contains(&byte))
    });
    valid
        .then(|| value.to_owned())
        .ok_or(AuthError::InvalidPolicy(field))
}

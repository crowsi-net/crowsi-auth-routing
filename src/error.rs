use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AuthError {
    #[error("authorization policy is invalid: {0}")]
    InvalidPolicy(&'static str),
    #[error("verified authentication context is invalid: {0}")]
    InvalidContext(&'static str),
    #[error("authentication context verifier is not configured")]
    VerificationUnavailable,
    #[error("authentication context signature is invalid")]
    InvalidSignature,
    #[error("authentication assertion replay was detected")]
    ReplayDetected,
    #[error("authentication replay protection is unavailable")]
    ReplayProtectionUnavailable,
    #[error("the identity authority is unavailable")]
    IdentityAuthorityUnavailable,
    #[error("the signed device identity does not match authoritative state")]
    IdentityBindingMismatch,
    #[error("the signed revocation epoch is stale")]
    StaleRevocationEpoch,
    #[error("the current device posture does not permit authorization")]
    DevicePostureRejected,
    #[error("system authentication clock is unavailable")]
    ClockUnavailable,
    #[error("authorization route was not found")]
    UnknownRoute,
    #[error("authorization route is not active")]
    InactiveRoute,
    #[error("authentication context expired")]
    Expired,
    #[error("authentication context is not valid for this service or audience")]
    WrongAudience,
    #[error("authentication channel is not permitted")]
    WrongChannel,
    #[error("required authorization scope is missing")]
    MissingScope,
    #[error("a recent stronger authentication ceremony is required")]
    StepUpRequired,
    #[error("step-up evidence is not bound to the requested operation")]
    OperationBindingMismatch,
}

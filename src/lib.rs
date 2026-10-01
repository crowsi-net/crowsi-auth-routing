//! Shared authorization rules for signed transport authentication assertions.
//!
//! A verified context has no public or adapter-controlled constructor:
//! ```compile_fail
//! use crowsi_auth_routing::{AuthChannel, VerifiedContext};
//! let _ = VerifiedContext::from_adapter(
//!     "service", "account", AuthChannel::McpStdio, "audience",
//!     ["scope".to_owned()], 1,
//! );
//! ```

mod assurance;
mod claims;
mod context;
mod error;
mod evidence;
mod evidence_canonical;
mod identity_freshness;
mod policy;
mod policy_access;
mod policy_validation;
mod production;
mod replay;
mod report;
mod secure_file;
mod validation;
mod verifier;

pub use assurance::AuthenticationAssurance;
pub use context::{AuthorizationReceipt, VerifiedContext};
pub use error::{AuthError, Result};
pub use evidence::UntrustedContext;
pub use policy::{Activation, AuthChannel, CredentialSource, Policy, Route, SessionAuthority};
pub use production::{PinnedStatusTrust, ProductionVerifier};
pub use report::{AUTH_ROUTE_CHECK_SCHEMA, RouteCheck, RouteCheckReport};

/// Generic verifier seams used only by this crate's contract tests.
#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::identity_freshness::{DeviceIdentityBinding, IdentityFreshness};
    pub use crate::replay::ReplayLedger;
    pub use crate::verifier::verify_context;
}

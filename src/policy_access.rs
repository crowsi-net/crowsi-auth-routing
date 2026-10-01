use crate::policy::ContextVerifierConfig;
use crate::{AuthError, Policy, Result, Route};

impl Policy {
    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn route(&self, id: &str) -> Result<&Route> {
        self.routes
            .iter()
            .find(|route| route.id == id)
            .ok_or(AuthError::UnknownRoute)
    }

    pub(crate) fn context_verifier(&self) -> Option<&ContextVerifierConfig> {
        self.context_verifier.as_ref()
    }
}

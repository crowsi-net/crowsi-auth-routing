use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy_validation;
use crate::validation::identifier;
use crate::{AuthError, AuthenticationAssurance, Result};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthChannel {
    AppHttp,
    McpHttp,
    McpStdio,
}

impl AuthChannel {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::AppHttp => "app-http",
            Self::McpHttp => "mcp-http",
            Self::McpStdio => "mcp-stdio",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialSource {
    SecureCookie,
    AuthorizationHeader,
    CrowsiBrokerReference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Activation {
    Active,
    Simulation,
    ContractReady,
    Planned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionAuthority {
    ServiceSqlite,
    ServiceIdentityProvider,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: String,
    pub channel: AuthChannel,
    pub audience: String,
    pub credential_source: CredentialSource,
    pub required_scopes: Vec<String>,
    pub activation: Activation,
    pub protected_resource_metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_assurance: Option<AuthenticationAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_authentication_age_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContextVerifierConfig {
    pub(crate) issuer: String,
    pub(crate) ed25519_public_key: String,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub(crate) schema_version: u8,
    pub(crate) service_id: String,
    pub(crate) session_authority: SessionAuthority,
    pub(crate) context_verifier: Option<ContextVerifierConfig>,
    pub(crate) routes: Vec<Route>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    schema_version: u8,
    service_id: String,
    session_authority: SessionAuthority,
    context_verifier: Option<ContextVerifierConfig>,
    routes: Vec<Route>,
}

impl Policy {
    /// Parses and validates one closed, non-secret service authorization policy.
    pub fn from_json(input: &str) -> Result<Self> {
        let document: PolicyDocument =
            serde_json::from_str(input).map_err(|_| AuthError::InvalidPolicy("json"))?;
        let policy = Self {
            schema_version: document.schema_version,
            service_id: document.service_id,
            session_authority: document.session_authority,
            context_verifier: document.context_verifier,
            routes: document.routes,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 4 {
            return Err(AuthError::InvalidPolicy("schema_version"));
        }
        identifier("service_id", &self.service_id, 64)?;
        if self.routes.is_empty() || self.routes.len() > 12 {
            return Err(AuthError::InvalidPolicy("routes"));
        }
        if let Some(config) = &self.context_verifier {
            policy_validation::verifier(config)?;
        }
        if self
            .routes
            .iter()
            .any(|route| route.activation == Activation::Active)
            && self.context_verifier.is_none()
        {
            return Err(AuthError::InvalidPolicy("context_verifier"));
        }
        let mut ids = BTreeSet::new();
        for route in &self.routes {
            policy_validation::route(self.schema_version, route)?;
            if !ids.insert(route.id.as_str()) {
                return Err(AuthError::InvalidPolicy("route_ids"));
            }
        }
        Ok(())
    }
}

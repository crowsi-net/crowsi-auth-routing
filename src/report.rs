use serde::Serialize;

use crate::{
    Activation, AuthChannel, AuthenticationAssurance, CredentialSource, Policy, SessionAuthority,
};

pub const AUTH_ROUTE_CHECK_SCHEMA: &str = "crowsi://auth/route-check/v3";

#[derive(Debug, Serialize)]
pub struct RouteCheck {
    pub id: String,
    pub channel: AuthChannel,
    pub credential_source: CredentialSource,
    pub activation: Activation,
    pub audience_bound: bool,
    pub scope_bound: bool,
    pub transport_authentication_required: bool,
    pub minimum_assurance: Option<AuthenticationAssurance>,
    pub max_authentication_age_seconds: Option<u64>,
    pub step_up_required: bool,
    pub operation_binding_required: bool,
    pub device_identity_required: bool,
    pub current_scoped_revocation_epochs_required: bool,
}

#[derive(Debug, Serialize)]
pub struct RouteCheckReport {
    pub schema: &'static str,
    pub service_id: String,
    pub session_authority: SessionAuthority,
    pub routes: Vec<RouteCheck>,
    pub credentials_in_tool_arguments: bool,
    pub separate_mcp_account_store: bool,
    pub valid: bool,
}

impl RouteCheckReport {
    #[must_use]
    pub fn from_policy(policy: &Policy) -> Self {
        let routes = policy
            .routes
            .iter()
            .map(|route| RouteCheck {
                id: route.id.clone(),
                channel: route.channel,
                credential_source: route.credential_source,
                activation: route.activation,
                audience_bound: true,
                scope_bound: !route.required_scopes.is_empty(),
                transport_authentication_required: true,
                minimum_assurance: route.minimum_assurance,
                max_authentication_age_seconds: route.max_authentication_age_seconds,
                step_up_required: route.minimum_assurance.is_some(),
                operation_binding_required: route.minimum_assurance.is_some(),
                device_identity_required: true,
                current_scoped_revocation_epochs_required: true,
            })
            .collect();
        Self {
            schema: AUTH_ROUTE_CHECK_SCHEMA,
            service_id: policy.service_id.clone(),
            session_authority: policy.session_authority,
            routes,
            credentials_in_tool_arguments: false,
            separate_mcp_account_store: false,
            valid: true,
        }
    }

    /// Serializes the metadata-only route check for local diagnostics.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string(self).map_err(|_| crate::AuthError::InvalidPolicy("report"))
    }
}

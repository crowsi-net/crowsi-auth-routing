pub fn signed_with_times(
    key: &SigningKey,
    channel: AuthChannel,
    audience: &str,
    scopes: &[&str],
    issued_at: u64,
    expires_at: u64,
) -> UntrustedContext {
    let mut evidence = UntrustedContext::from_json(&unsigned_json(channel, audience))
        .expect("valid unsigned structure");
    evidence.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    evidence.issued_at = issued_at;
    evidence.expires_at = expires_at;
    evidence.authenticated_at = Some(issued_at);
    let signature = key.sign(&evidence.signing_payload().expect("canonical assertion"));
    evidence.signature = hex::encode(signature.to_bytes());
    evidence
}

pub fn step_up_policy(key: &SigningKey) -> Policy {
    let mut value: serde_json::Value =
        serde_json::from_str(&policy_json(key, "active")).expect("policy json");
    value["schema_version"] = serde_json::json!(4);
    let routes = value["routes"].as_array_mut().expect("routes");
    let route = routes
        .iter_mut()
        .find(|route| route["id"] == "mcp-stdio")
        .expect("sensitive route");
    route["minimum_assurance"] = serde_json::json!("aal2");
    route["max_authentication_age_seconds"] = serde_json::json!(300);
    Policy::from_json(&value.to_string()).expect("valid step-up policy")
}

pub fn signed_v5(key: &SigningKey, assurance: AuthenticationAssurance) -> UntrustedContext {
    let mut evidence = signed(key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    evidence.schema_version = 5;
    evidence.authentication_assurance = Some(assurance);
    evidence.authenticated_at = Some(evidence.issued_at);
    evidence.operation_digest = Some(operation_digest().to_owned());
    let signature = key.sign(&evidence.signing_payload().expect("canonical v5 assertion"));
    evidence.signature = hex::encode(signature.to_bytes());
    evidence
}

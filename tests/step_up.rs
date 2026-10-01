#![cfg(feature = "test-support")]

use crowsi_auth_routing::{AuthError, AuthenticationAssurance, RouteCheckReport, UntrustedContext};
use ed25519_dalek::Signer;
use support::TestReplayLedger as InMemoryReplayLedger;

mod support;

#[test]
fn sensitive_route_accepts_recent_aal2_evidence() {
    let key = support::key(7);
    let policy = support::step_up_policy(&key);
    let evidence = support::signed_v5(&key, AuthenticationAssurance::Aal2);
    let receipt = support::verify(&policy, &evidence, &InMemoryReplayLedger::default())
        .expect("trusted evidence")
        .authorize_operation(&policy, "mcp-stdio", support::operation_digest())
        .expect("recent step-up");
    assert_eq!(receipt.assurance, Some(AuthenticationAssurance::Aal2));
    let report = RouteCheckReport::from_policy(&policy);
    let route = report
        .routes
        .iter()
        .find(|route| route.id == "mcp-stdio")
        .expect("route report");
    assert!(route.step_up_required);
    assert_eq!(route.minimum_assurance, Some(AuthenticationAssurance::Aal2));
}

#[test]
fn sensitive_route_rejects_weak_evidence() {
    let key = support::key(7);
    let policy = support::step_up_policy(&key);
    let weak = support::signed_v5(&key, AuthenticationAssurance::Aal1);
    let weak_result = support::verify(&policy, &weak, &InMemoryReplayLedger::default())
        .expect("trusted weak evidence")
        .authorize_operation(&policy, "mcp-stdio", support::operation_digest());
    assert_eq!(weak_result, Err(AuthError::StepUpRequired));
}

#[test]
fn stale_authentication_requires_a_new_challenge() {
    let key = support::key(7);
    let policy = support::step_up_policy(&key);
    let mut stale = support::signed_v5(&key, AuthenticationAssurance::Aal3);
    stale.authenticated_at = Some(support::now() - 301);
    stale.signature = hex::encode(
        key.sign(&stale.signing_payload().expect("stale payload"))
            .to_bytes(),
    );
    let result = support::verify(&policy, &stale, &InMemoryReplayLedger::default())
        .expect("trusted stale evidence")
        .authorize_operation(&policy, "mcp-stdio", support::operation_digest());
    assert_eq!(result, Err(AuthError::StepUpRequired));
}

#[test]
fn incomplete_v5_binding_is_rejected_before_signature_verification() {
    let key = support::key(7);
    for field in ["authenticated_at", "operation_digest"] {
        let mut value =
            serde_json::to_value(support::signed_v5(&key, AuthenticationAssurance::Aal2))
                .expect("json");
        value.as_object_mut().expect("object").remove(field);
        let error = UntrustedContext::from_json(&value.to_string()).expect_err("incomplete v4");
        assert_eq!(error, AuthError::InvalidContext("assurance"), "{field}");
    }
}

#[test]
fn sensitive_route_rejects_a_different_operation_digest() {
    let key = support::key(7);
    let policy = support::step_up_policy(&key);
    let evidence = support::signed_v5(&key, AuthenticationAssurance::Aal3);
    let context = support::verify(&policy, &evidence, &InMemoryReplayLedger::default())
        .expect("trusted operation-bound evidence");
    let different = format!("sha256:{}", "f".repeat(64));
    assert_eq!(
        context.authorize_operation(&policy, "mcp-stdio", &different),
        Err(AuthError::OperationBindingMismatch),
    );
}

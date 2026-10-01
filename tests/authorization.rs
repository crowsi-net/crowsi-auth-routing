#![cfg(feature = "test-support")]

use crowsi_auth_routing::{AuthChannel, AuthError, Policy, RouteCheckReport};
use ed25519_dalek::SigningKey;
use support::TestReplayLedger as InMemoryReplayLedger;

mod support;

#[test]
fn app_and_mcp_use_one_verified_authorization_core() {
    let key = support::key(7);
    let policy = support::policy(&key, "active");
    for (channel, audience, route) in [
        (AuthChannel::AppHttp, "sample-local-api", "app-api"),
        (AuthChannel::McpStdio, "sample-mcp", "mcp-stdio"),
    ] {
        let evidence = support::signed(&key, channel, audience, &["account.read"]);
        let context = support::verify(&policy, &evidence, &InMemoryReplayLedger::default())
            .expect("trusted assertion");
        assert!(context.authorize(&policy, route).is_ok());
    }
    let report = RouteCheckReport::from_policy(&policy);
    assert!(!report.credentials_in_tool_arguments);
    assert!(!report.separate_mcp_account_store);
}

#[test]
fn audience_scope_channel_and_expiry_fail_closed() {
    let key = support::key(7);
    let policy = support::policy(&key, "active");
    let cases = [
        support::signed(&key, AuthChannel::McpStdio, "wrong-mcp", &["account.read"]),
        support::signed(&key, AuthChannel::AppHttp, "sample-mcp", &["account.read"]),
        support::signed(
            &key,
            AuthChannel::McpStdio,
            "sample-mcp",
            &["account.write"],
        ),
    ];
    let errors = cases.map(|evidence| {
        support::verify(&policy, &evidence, &InMemoryReplayLedger::default())
            .expect("validly signed")
            .authorize(&policy, "mcp-stdio")
    });
    assert_eq!(errors[0], Err(AuthError::WrongAudience));
    assert_eq!(errors[1], Err(AuthError::WrongChannel));
    assert_eq!(errors[2], Err(AuthError::MissingScope));

    let expired = support::signed_with_times(
        &key,
        AuthChannel::McpStdio,
        "sample-mcp",
        &["account.read"],
        support::now() - 2,
        support::now() - 1,
    );
    assert!(matches!(
        support::verify(&policy, &expired, &InMemoryReplayLedger::default()),
        Err(AuthError::Expired)
    ));
}

#[test]
fn self_signed_or_tampered_context_is_not_trusted() {
    let trusted = support::key(7);
    let policy = support::policy(&trusted, "active");
    let attacker = support::key(8);
    let forged = support::signed(
        &attacker,
        AuthChannel::McpStdio,
        "sample-mcp",
        &["account.read"],
    );
    assert!(matches!(
        support::verify(&policy, &forged, &InMemoryReplayLedger::default()),
        Err(AuthError::InvalidSignature)
    ));
    let attacker_policy = support::policy(&attacker, "active");
    let attacker_context =
        support::verify(&attacker_policy, &forged, &InMemoryReplayLedger::default())
            .expect("attacker trusts own assertion");
    assert_eq!(
        attacker_context.authorize(&policy, "mcp-stdio"),
        Err(AuthError::InvalidSignature)
    );

    let mut tampered = support::signed(
        &trusted,
        AuthChannel::McpStdio,
        "sample-mcp",
        &["account.read"],
    );
    tampered.pairwise_subject = "attacker-pairwise-subject".to_owned();
    assert!(matches!(
        support::verify(&policy, &tampered, &InMemoryReplayLedger::default()),
        Err(AuthError::InvalidSignature)
    ));
}

#[test]
fn invalid_evidence_and_unconfigured_active_policy_are_rejected() {
    let invalid = support::unsigned_json(AuthChannel::McpStdio, "mcp\nspoof");
    assert!(matches!(
        crowsi_auth_routing::UntrustedContext::from_json(&invalid),
        Err(AuthError::InvalidContext("audience"))
    ));
    let key = support::key(7);
    let without_verifier =
        support::policy_json(&key, "active").replace(&support::verifier_fragment(&key), "");
    assert!(matches!(
        Policy::from_json(&without_verifier),
        Err(AuthError::InvalidPolicy("context_verifier"))
    ));
    let weak = support::policy_json(&key, "active").replace(
        &hex::encode(key.verifying_key().to_bytes()),
        &"00".repeat(32),
    );
    assert!(matches!(
        Policy::from_json(&weak),
        Err(AuthError::InvalidPolicy("context_verification_key"))
    ));
}

#[test]
fn legacy_policy_and_evidence_versions_require_explicit_reenrollment() {
    let key = support::key(7);
    let legacy_policy = support::policy_json(&key, "active")
        .replace("\"schema_version\":4", "\"schema_version\":3");
    assert_eq!(
        Policy::from_json(&legacy_policy).err(),
        Some(AuthError::InvalidPolicy("schema_version")),
    );
    let current = support::signed(&key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    let mut legacy = serde_json::to_value(current).expect("evidence JSON");
    legacy["schema_version"] = serde_json::json!(4);
    assert_eq!(
        crowsi_auth_routing::UntrustedContext::from_json(&legacy.to_string()).err(),
        Some(AuthError::InvalidContext("assertion")),
    );
}

#[test]
fn non_active_routes_never_authorize() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let policy = support::policy(&key, "simulation");
    let evidence = support::signed(
        &key,
        AuthChannel::AppHttp,
        "sample-local-api",
        &["account.read"],
    );
    let result = support::verify(&policy, &evidence, &InMemoryReplayLedger::default())
        .expect("trusted assertion")
        .authorize(&policy, "app-api");
    assert_eq!(result, Err(AuthError::InactiveRoute));
}

#![cfg(feature = "test-support")]

use crowsi_auth_routing::{AuthChannel, AuthError};
use support::TestReplayLedger as InMemoryReplayLedger;

mod support;

#[test]
fn a_signed_assertion_is_consumed_exactly_once() {
    let key = support::key(7);
    let policy = support::policy(&key, "active");
    let evidence = support::signed(&key, AuthChannel::McpStdio, "sample-mcp", &["account.read"]);
    let ledger = InMemoryReplayLedger::default();
    assert!(support::verify(&policy, &evidence, &ledger).is_ok());
    assert!(matches!(
        support::verify(&policy, &evidence, &ledger),
        Err(AuthError::ReplayDetected)
    ));
}

fn write_status(
    path: &std::path::Path,
    evidence: &crowsi_auth_routing::UntrustedContext,
    key: &SigningKey,
) {
    let mut status = CurrentDeviceStatusV1 {
        schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
        issuer: "ihat://identity-authority".into(),
        audience: "crowsi://auth-routing/current-status".into(),
        service_id: evidence.service_id.clone(),
        pairwise_subject: evidence.pairwise_subject.clone(),
        device_id: evidence.device_id.clone(),
        device_proof_key_ref: evidence.device_proof_key_ref.clone(),
        session_ref: evidence.session_ref.clone(),
        device_posture: DevicePostureV1 {
            state: evidence.device_posture.clone(),
            revision: evidence.device_posture_revision,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: evidence.subject_revocation_epoch,
            service: evidence.service_revocation_epoch,
            device: evidence.device_revocation_epoch,
            session: evidence.session_revocation_epoch,
        },
        issued_at_epoch_s: evidence.issued_at,
        expires_at_epoch_s: evidence.issued_at + 30,
        nonce: "status-production-test".into(),
        key_id: "status-key:1".into(),
        signature: String::new(),
    };
    status.signature = hex::encode(
        key.sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    fs::write(path, serde_json::to_vec(&status).expect("status JSON")).expect("status");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("status mode");
}

fn trust(key: &SigningKey) -> PinnedStatusTrust {
    PinnedStatusTrust::new(
        key.verifying_key().to_bytes(),
        "status-key:1",
        "ihat://identity-authority",
        "crowsi://auth-routing/current-status",
        "sample-service",
    )
    .expect("trust")
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
    root
}

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuthError, Result, secure_file};

const MAX_LIVE_ASSERTIONS: usize = 100_000;
const SCHEMA: &str = "crowsi://auth/replay-state/v1";

pub trait ReplayLedger: Send + Sync {
    fn consume(&self, issuer: &str, nonce: &str, expires_at: u64, now: u64) -> Result<()>;
}

pub struct FileReplayLedger {
    state: PathBuf,
    anchor: PathBuf,
    lock: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    revision: u64,
    entries: BTreeMap<String, u64>,
}

impl FileReplayLedger {
    /// Opens or creates owner-only durable replay state.
    ///
    /// # Errors
    /// Rejects unsafe paths, rollback, malformed state, and unavailable storage.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let state = secure_file::absolute_private_path(path.as_ref())?;
        let value = Self {
            anchor: secure_file::sibling(&state, "anchor")?,
            lock: secure_file::sibling(&state, "lock")?,
            state,
        };
        let _guard = secure_file::lock(&value.lock)?;
        match (
            secure_file::read(&value.state)?,
            secure_file::read(&value.anchor)?,
        ) {
            (None, None) => value.write(&State {
                schema: SCHEMA.into(),
                revision: 0,
                entries: BTreeMap::new(),
            })?,
            (Some(bytes), Some(anchor)) => {
                decode(&bytes, &anchor)?;
            }
            _ => return Err(AuthError::ReplayProtectionUnavailable),
        }
        Ok(value)
    }

    fn write(&self, state: &State) -> Result<()> {
        let bytes =
            serde_json::to_vec(state).map_err(|_| AuthError::ReplayProtectionUnavailable)?;
        secure_file::write(&self.state, &bytes)?;
        secure_file::write(&self.anchor, &anchor(state.revision, &bytes))
    }
}

impl ReplayLedger for FileReplayLedger {
    fn consume(&self, issuer: &str, nonce: &str, expires_at: u64, now: u64) -> Result<()> {
        let _guard = secure_file::lock(&self.lock)?;
        let bytes =
            secure_file::read(&self.state)?.ok_or(AuthError::ReplayProtectionUnavailable)?;
        let anchored =
            secure_file::read(&self.anchor)?.ok_or(AuthError::ReplayProtectionUnavailable)?;
        let mut state = decode(&bytes, &anchored)?;
        state.entries.retain(|_, expiry| *expiry > now);
        let key = digest(issuer, nonce);
        if state.entries.contains_key(&key) {
            return Err(AuthError::ReplayDetected);
        }
        if state.entries.len() >= MAX_LIVE_ASSERTIONS {
            return Err(AuthError::ReplayProtectionUnavailable);
        }
        state.entries.insert(key, expires_at);
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(AuthError::ReplayProtectionUnavailable)?;
        self.write(&state)
    }
}

fn decode(bytes: &[u8], anchored: &[u8]) -> Result<State> {
    let state: State =
        serde_json::from_slice(bytes).map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    if state.schema != SCHEMA || anchored != anchor(state.revision, bytes) {
        return Err(AuthError::ReplayProtectionUnavailable);
    }
    Ok(state)
}

fn anchor(revision: u64, bytes: &[u8]) -> Vec<u8> {
    format!(
        "CROWSI-AUTH-REPLAY-ANCHOR-V1\n{revision}\n{}\n",
        hex::encode(Sha256::digest(bytes))
    )
    .into_bytes()
}

fn digest(issuer: &str, nonce: &str) -> String {
    let mut hash = Sha256::new();
    for field in [issuer, nonce] {
        hash.update(field.len().to_be_bytes());
        hash.update(field);
    }
    hex::encode(hash.finalize())
}

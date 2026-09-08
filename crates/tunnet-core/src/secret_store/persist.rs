//! Helpers to persist public state + sealed secrets together.

use std::collections::BTreeMap;

use crate::identity::AgentIdentity;
use crate::secret_store::{self, AgentSecrets, NetworkSecrets, SealPolicy, SealTier};
use crate::state::{PersistedState, StatePaths};

/// Write `state.json` + `state.enc`.
pub fn persist_agent(
    paths: &StatePaths,
    identity: &AgentIdentity,
    state: PersistedState,
    policy: SealPolicy,
) -> anyhow::Result<SealTier> {
    let mut networks = BTreeMap::new();
    for d in state.direct_networks() {
        networks.insert(
            d.network_id,
            NetworkSecrets {
                join_secret: d.join_secret.clone(),
                doc_ticket: d.doc_ticket.clone(),
                coordinator_signing_key: d.coordinator_signing_key.clone(),
                network_grant: d.network_grant.clone(),
                content_key: d.content_key.clone(),
            },
        );
    }
    let auth = secret_store::load_auth(paths).ok().flatten();
    let relay_auth = secret_store::load_relay_auth(paths).unwrap_or_default();

    let secrets = AgentSecrets {
        identity_seed: identity.secret_bytes,
        networks,
        auth,
        relay_auth,
    };

    state.save_public(paths)?;
    secret_store::save_secrets(paths, &secrets, policy)
}

/// Load identity + persisted state with secrets merged from `state.enc`.
pub fn load_agent(
    paths: &StatePaths,
    _policy: SealPolicy,
) -> anyhow::Result<(AgentIdentity, PersistedState, SealTier)> {
    let (secrets, tier) = secret_store::load_secrets(paths)?;
    let identity = secrets.identity();
    let mut state = PersistedState::load(paths)?;
    state.apply_secrets(&secrets);
    Ok((identity, state, tier))
}

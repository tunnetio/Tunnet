pub mod acl;
pub mod acl_hook;
pub mod agent_config;
#[cfg(feature = "managed")]
pub mod control;
pub mod coordinator;
pub mod direct;
#[cfg(feature = "dns")]
pub mod dns_stub;
pub mod effective_config;
pub mod identity;
#[cfg(feature = "tunnel")]
pub mod inspect;
pub mod ipc;
pub mod iroh_pool;
pub mod known_hosts;
#[cfg(feature = "direct")]
pub mod mdns_relay;
pub mod node;
pub mod ping;
#[cfg(feature = "recording")]
pub mod recording;
pub mod routing;
pub mod secret_store;
#[cfg(feature = "send")]
pub mod send;
#[cfg(feature = "serve")]
pub mod serve;
pub mod state;
pub mod stream;
pub mod stream_proxy;
#[cfg(feature = "managed")]
pub mod sync;
#[cfg(feature = "tunnel")]
pub mod tunnel;
#[cfg(feature = "managed")]
pub mod ws_client;

pub use agent_config::{TunnetConfig, load_dns, load_firewall};
pub use effective_config::{EffectiveAgentConfigState, EffectiveConfigStore};
pub use secret_store::{
    AgentSecrets, NetworkSecrets, SealPolicy, SealTier, load_agent, persist_agent,
};

pub use acl::{AclEngine, SelfIdentity};
pub use acl_hook::AclHook;
#[cfg(feature = "managed")]
pub use control::{ManagementClient, SignedClient, UnauthedClient};
pub use identity::AgentIdentity;
pub use iroh_pool::ConnPool;
#[cfg(feature = "direct")]
pub use node::DirectNetworkRuntime;
pub use node::{AgentConfigHooks, CoreNode, CoreNodeConfig, KillSshHook, PostureHooks};
pub use routing::{PeerInfo, RoutingTable};
#[cfg(feature = "send")]
pub use send::{SendConfig, SendManager, TransferDirection, TransferRecord, TransferStatus};
#[cfg(feature = "serve")]
pub use serve::{ServeAcl, ServeManager};
pub use state::{CliAuthTokens, DirectState, ManagedState, NodeMode, PersistedState, StatePaths};
pub use stream::{
    StreamHandler, StreamProtocolHandler, TUNNEL_STREAM_ALPN, dial_stream, serve_stream_connection,
};
pub use stream_proxy::stream_handler;
#[cfg(feature = "tunnel")]
pub use tunnel::TunnelManager;

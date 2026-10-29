//! This module implements the same features as the main crate, but using async io.

mod gateway;

#[cfg(feature = "aio_tokio")]
pub mod tokio;

use crate::RequestError;
use std::future::Future;

pub use self::gateway::Gateway;
#[cfg(feature = "ipv6")]
pub use self::gateway::Ipv6FirewallGateway;

pub(crate) const MAX_RESPONSE_SIZE: usize = 1500;
pub(crate) const HEADER_NAME: &str = "SOAPAction";

/// Trait to allow abstracting over `tokio`.
pub trait Provider: Clone {
    /// Send an async request over the executor.
    fn send_async(
        &self,
        url: &str,
        action: &str,
        body: &str,
    ) -> impl Future<Output = Result<String, RequestError>> + Send;
}

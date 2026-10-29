//! An address lookup service that uses an mdns-like service to discover and lookup the addresses of local endpoints.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about endpoints that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.
//!
//! When [`MdnsAddressLookup`] is enabled, it's possible to get a list of the locally discovered endpoints by filtering a list of `RemoteInfo`s.
//!
//! In order to get a list of locally discovered addresses, you must call `MdnsAddressLookup::subscribe` to subscribe
//! to a stream of discovered addresses.
//!
//! ```no_run
//! use iroh::{Endpoint, endpoint::presets};
//! use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
//! use n0_future::StreamExt;
//!
//! #[tokio::main]
//! async fn main() {
//!     let endpoint = Endpoint::bind(presets::Minimal).await.unwrap();
//!
//!     // Register the Address Lookupwith the endpoint
//!     let mdns = MdnsAddressLookup::builder().build(endpoint.id()).unwrap();
//!     endpoint.address_lookup().unwrap().add(mdns.clone());
//!
//!     // Subscribe to the mdns discovery events
//!     let mut events = mdns.subscribe().await;
//!     while let Some(event) = events.next().await {
//!         match event {
//!             DiscoveryEvent::Discovered { endpoint_info, .. } => {
//!                 println!("MDNS discovered: {:?}", endpoint_info);
//!             }
//!             DiscoveryEvent::Expired { endpoint_id } => {
//!                 println!("MDNS expired: {endpoint_id}");
//!             }
//!             _ => {}
//!         }
//!     }
//! }
//! ```
//!
//! ## Filtering
//!
//! By default, [`MdnsAddressLookup`] publishes all addresses it receives:
//! direct IP addresses and up to one [`RelayUrl`]. The following constraints apply regardless
//! of any user-supplied filter:
//!
//! - Only the first [`RelayUrl`] in the address set is published.
//! - A [`RelayUrl`] longer than 249 bytes is silently dropped.
//!
//! You can supply an [`AddrFilter`] via [`MdnsAddressLookupBuilder::addr_filter`] to
//! control which addresses are published and in what order. The filter is applied before the
//! constraints above, so for example you can use it to exclude relay URLs entirely or to
//! prioritize certain addresses.
//!
//! [`AddrFilter`]: iroh::address_lookup::AddrFilter
//! [`RelayUrl`]: iroh_base::RelayUrl
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use futures_util::stream::FuturesUnordered;
use iroh::{
    Endpoint,
    address_lookup::{
        AddrFilter, AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData,
        EndpointInfo, Error as AddressLookupError, Item as AddressLookupItem,
    },
};
use iroh_base::{EndpointId, PublicKey};
use n0_future::{
    Stream, StreamExt,
    boxed::BoxStream,
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};
use n0_watcher::{Watchable, Watcher as _};
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    watch,
};
use tracing::{Instrument, debug, error, info_span, trace, warn};

/// The n0 local service name.
const N0_SERVICE_NAME: &str = "irohv1";

/// Name of this address lookup service.
///
/// Used as the `provenance` field in [`AddressLookupItem`]s.
pub const NAME: &str = "mdns";

/// The key of the attribute under which the `UserData` is stored in
/// the TXT record supported by swarm-discovery.
const USER_DATA_ATTRIBUTE: &str = "user-data";

/// Minimum time to wait while resolving an endpoint ID to an address.
const MIN_LOOKUP_DURATION: Duration = Duration::from_secs(10);

/// The key of the attribute under which the `RelayUrl` is stored in
/// the TXT record supported by swarm-discovery.
const RELAY_URL_ATTRIBUTE: &str = "relay";

/// Address Lookup using `swarm-discovery`, a variation on mdns.
///
/// Resolution streams yield the latest known endpoint information. Unread updates
/// may be coalesced.
#[derive(Debug, Clone)]
pub struct MdnsAddressLookup {
    #[allow(dead_code)]
    handle: Arc<AbortOnDropHandle<()>>,
    sender: mpsc::Sender<Message>,
    advertise: bool,
    /// When `local_addrs` changes, we re-publish our info.
    local_addrs: Watchable<Option<EndpointData>>,
}

#[derive(Debug)]
enum Message {
    Discovered(EndpointId, Option<AddressLookupItem>),
    Resolve(EndpointId, watch::Sender<Option<AddressLookupItem>>),
    Subscribe(mpsc::Sender<DiscoveryEvent>),
    #[cfg(test)]
    ResolutionCount(tokio::sync::oneshot::Sender<(usize, usize)>),
}

/// Manages the list of subscribers that are subscribed to this Address Lookup.
#[derive(Debug)]
struct Subscribers(Vec<mpsc::Sender<DiscoveryEvent>>);

impl Subscribers {
    fn new() -> Self {
        Self(vec![])
    }

    /// Add the subscriber to the list of subscribers.
    fn push(&mut self, subscriber: mpsc::Sender<DiscoveryEvent>) {
        self.0.push(subscriber);
    }

    /// Sends the `endpoint_id` and `item` to each subscriber.
    ///
    /// Cleans up any subscribers that have been dropped.
    fn send(&mut self, item: DiscoveryEvent) {
        let mut clean_up = vec![];
        for (i, subscriber) in self.0.iter().enumerate() {
            // assume subscriber was dropped
            if let Err(err) = subscriber.try_send(item.clone()) {
                match err {
                    TrySendError::Full(_) => {
                        warn!(?item, idx = i, "mdns subscriber is blocked, dropping item")
                    }
                    TrySendError::Closed(_) => clean_up.push(i),
                }
            }
        }
        for i in clean_up.into_iter().rev() {
            self.0.swap_remove(i);
        }
    }
}

/// Builder for [`MdnsAddressLookup`].
#[derive(Debug)]
pub struct MdnsAddressLookupBuilder {
    advertise: bool,
    service_name: String,
    filter: AddrFilter,
    cadence: Duration,
    socket_config: Option<[Option<netwatch::SocketConfig>; 2]>,
}

impl MdnsAddressLookupBuilder {
    /// Creates a new [`MdnsAddressLookupBuilder`] with default settings.
    fn new() -> Self {
        Self {
            advertise: true,
            service_name: N0_SERVICE_NAME.to_string(),
            filter: AddrFilter::default(),
            cadence: Duration::from_millis(700),
            socket_config: None,
        }
    }

    /// Sets whether this endpoint should advertise its presence.
    ///
    /// Default is true.
    pub fn advertise(mut self, advertise: bool) -> Self {
        self.advertise = advertise;
        self
    }

    /// Sets a custom service name.
    ///
    /// The default is `irohv1`, which will show up on a record in the
    /// following form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._irohv1._udp.local`
    ///
    /// Any custom service name will take the form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._{service_name}._udp.local`
    pub fn service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_name = service_name.into();
        self
    }

    /// Sets the base interval between mDNS discovery query cycles.
    ///
    /// Queries ask peers on the local network to announce their addresses.
    /// Before sending a query, `swarm-discovery` waits for this interval plus
    /// a random delay that grows with the number of currently known peers.
    /// If another peer sends a query during that wait, it uses that query
    /// instead of sending its own, reducing duplicate traffic.
    ///
    /// The default is 700 ms. Longer intervals reduce background traffic and
    /// also lengthen peer-expiry detection. Must be nonzero.
    /// The address lookup deadline grows with the cadence, so longer intervals
    /// also make unsuccessful lookups take longer.
    ///
    /// # Panics
    /// Panics if the cadence is zero.
    pub fn discovery_cadence(mut self, cadence: Duration) -> Self {
        assert!(!cadence.is_zero());
        self.cadence = cadence;
        self
    }

    /// Sets a filter to control which addresses are published by this service.
    pub fn addr_filter(mut self, filter: AddrFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Builds an [`MdnsAddressLookup`] instance with the configured settings.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn build(
        self,
        endpoint_id: EndpointId,
    ) -> Result<MdnsAddressLookup, AddressLookupBuilderError> {
        MdnsAddressLookup::new(
            endpoint_id,
            self.advertise,
            self.service_name,
            self.filter,
            self.cadence,
            self.socket_config,
        )
    }
}

impl Default for MdnsAddressLookupBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressLookupBuilder for MdnsAddressLookupBuilder {
    fn into_address_lookup(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        self.socket_config = endpoint.udp_socket_config();
        self.build(endpoint.id())
    }
}

/// An event emitted from the [`MdnsAddressLookup`] service.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiscoveryEvent {
    /// A peer was discovered or it's information was updated.
    Discovered {
        /// The endpoint info for the endpoint, as discovered.
        endpoint_info: EndpointInfo,
        /// Optional timestamp when this endpoint address info was last updated.
        last_updated: Option<u64>,
    },
    /// A peer was expired due to being inactive, unreachable, or otherwise
    /// unavailable.
    Expired {
        /// The id of the endpoint that expired.
        endpoint_id: EndpointId,
    },
}

impl MdnsAddressLookup {
    /// Returns a [`MdnsAddressLookupBuilder`] used to construct [`MdnsAddressLookup`].
    pub fn builder() -> MdnsAddressLookupBuilder {
        MdnsAddressLookupBuilder::default()
    }

    /// Create a new [`MdnsAddressLookup`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses (if advertise is set to true)
    /// and receives addresses from other endpoints in your local network.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    fn new(
        endpoint_id: EndpointId,
        advertise: bool,
        service_name: String,
        filter: AddrFilter,
        cadence: Duration,
        socket_config: Option<[Option<netwatch::SocketConfig>; 2]>,
    ) -> Result<Self, AddressLookupBuilderError> {
        debug!("Creating new Mdns service");
        let lookup_duration = lookup_duration(cadence);
        let (send, mut recv) = mpsc::channel(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let address_lookup = MdnsAddressLookup::spawn_discoverer(
            endpoint_id,
            task_sender.clone(),
            service_name,
            cadence,
            &rt,
            socket_config,
        )?;

        let local_addrs: Watchable<Option<EndpointData>> = Watchable::default();
        let mut addrs_change = local_addrs.watch();
        let address_lookup_fut = async move {
            let mut endpoint_addrs: HashMap<PublicKey, AddressLookupItem> = HashMap::default();
            let mut subscribers = Subscribers::new();
            let mut senders: HashMap<PublicKey, Vec<watch::Sender<Option<AddressLookupItem>>>> =
                HashMap::default();
            let mut timeouts = FuturesUnordered::new();
            loop {
                trace!(?endpoint_addrs, "Mdns Service loop tick");
                let msg = tokio::select! {
                    Some((endpoint_id, sender)) = timeouts.next(), if !timeouts.is_empty() => {
                        if let Some(resolutions) = senders.get_mut(&endpoint_id) {
                            resolutions.retain(|other| !other.same_channel(&sender));
                            if resolutions.is_empty() {
                                senders.remove(&endpoint_id);
                            }
                        }
                        continue;
                    }
                    msg = recv.recv() => {
                        msg
                    }
                    Ok(Some(data)) = addrs_change.updated() => {
                        tracing::trace!(?data, "Mdns address changed");
                        address_lookup.remove_all();

                        // apply user-supplied filter
                        let data = data.apply_filter(&filter).into_owned();


                        let addrs =
                            MdnsAddressLookup::socketaddrs_to_addrs(data.ip_addrs());
                        for addr in addrs {
                            address_lookup.add(addr.0, addr.1)
                        }
                        if let Some(relay) = data.relay_urls().next()
                            && let Err(err) = address_lookup.set_txt_attribute(RELAY_URL_ATTRIBUTE.to_string(), Some(relay.to_string()))  {
                                warn!("Failed to set the relay url in mDNS: {err:?}");
                        }
                        if let Some(user_data) = data.user_data()
                            && let Err(err) = address_lookup.set_txt_attribute(USER_DATA_ATTRIBUTE.to_string(), Some(user_data.to_string())) {
                                warn!("Failed to set the user-defined data in mDNS: {err:?}");
                        }
                        continue;
                    }
                };
                let msg = match msg {
                    None => {
                        error!("Mdns channel closed");
                        error!("closing Mdns");
                        address_lookup.remove_all();
                        return;
                    }
                    Some(msg) => msg,
                };
                match msg {
                    Message::Discovered(discovered_endpoint_id, item) => {
                        if discovered_endpoint_id == endpoint_id {
                            continue;
                        }
                        let Some(item) = item else {
                            endpoint_addrs.remove(&discovered_endpoint_id);
                            if let Some(resolutions) = senders.get(&discovered_endpoint_id) {
                                for sender in resolutions {
                                    sender.send(None).ok();
                                }
                            }
                            subscribers.send(DiscoveryEvent::Expired {
                                endpoint_id: discovered_endpoint_id,
                            });
                            continue;
                        };
                        if endpoint_addrs.len() >= 4096
                            && !endpoint_addrs.contains_key(&discovered_endpoint_id)
                        {
                            continue;
                        }
                        if !cache_discovery(&mut endpoint_addrs, item.clone()) {
                            continue;
                        }
                        let mut resolved = false;
                        if let Some(resolutions) = senders.get_mut(&discovered_endpoint_id) {
                            resolutions.retain(|sender| sender.send(Some(item.clone())).is_ok());
                            resolved = !resolutions.is_empty();
                            if !resolved {
                                senders.remove(&discovered_endpoint_id);
                            }
                        }
                        if !resolved {
                            subscribers.send(DiscoveryEvent::Discovered {
                                endpoint_info: item.endpoint_info().clone(),
                                last_updated: item.last_updated(),
                            });
                        }
                    }
                    Message::Resolve(endpoint_id, sender) => {
                        if timeouts.len() >= 64 {
                            continue;
                        }
                        if sender
                            .send(endpoint_addrs.get(&endpoint_id).cloned())
                            .is_err()
                        {
                            continue;
                        }
                        senders.entry(endpoint_id).or_default().push(sender.clone());
                        let timeout = time::sleep(lookup_duration);
                        timeouts.push(async move {
                            tokio::select! {
                                _ = timeout => {},
                                _ = sender.closed() => {},
                            }
                            (endpoint_id, sender)
                        });
                    }
                    #[cfg(test)]
                    Message::ResolutionCount(reply) => {
                        reply
                            .send((senders.values().map(Vec::len).sum(), timeouts.len()))
                            .ok();
                    }
                    Message::Subscribe(subscriber) => {
                        trace!("Mdns Message::Subscribe");
                        subscribers.push(subscriber);
                    }
                }
            }
        };
        let handle =
            task::spawn(address_lookup_fut.instrument(info_span!("swarm-discovery.actor")));
        Ok(Self {
            handle: Arc::new(AbortOnDropHandle::new(handle)),
            sender: send,
            advertise,
            local_addrs,
        })
    }

    /// Subscribe to discovered endpoints.
    pub async fn subscribe(&self) -> impl Stream<Item = DiscoveryEvent> + Unpin + use<> {
        let (sender, recv) = mpsc::channel(20);
        let address_lookup_sender = self.sender.clone();
        address_lookup_sender
            .send(Message::Subscribe(sender))
            .await
            .ok();
        tokio_stream::wrappers::ReceiverStream::new(recv)
    }

    fn spawn_discoverer(
        endpoint_id: PublicKey,
        sender: mpsc::Sender<Message>,
        service_name: String,
        cadence: Duration,
        rt: &tokio::runtime::Handle,
        socket_config: Option<[Option<netwatch::SocketConfig>; 2]>,
    ) -> Result<DropGuard, AddressLookupBuilderError> {
        let callback = move |endpoint_id: &str, peer: &Peer| {
            trace!(endpoint_id, ?peer, "Received peer information from Mdns");

            let endpoint_id = match endpoint_id.parse::<EndpointId>() {
                Ok(endpoint_id) => endpoint_id,
                Err(error) => {
                    warn!(endpoint_id, %error, "could not parse discovered endpoint ID");
                    return;
                }
            };
            let item = (!peer.is_expiry()).then(|| peer_to_discovery_item(peer, &endpoint_id));
            sender.try_send(Message::Discovered(endpoint_id, item)).ok();
        };
        let endpoint_id_str = data_encoding::BASE32_NOPAD
            .encode(endpoint_id.as_bytes())
            .to_ascii_lowercase();
        let mut discoverer = Discoverer::new_interactive(service_name, endpoint_id_str)
            .with_cadence(cadence)
            .with_callback(callback)
            .with_ip_class(IpClass::Auto);
        if let Some(config) = socket_config {
            discoverer = discoverer.with_socket_config(config);
        }
        discoverer
            .spawn(rt)
            .map_err(|e| AddressLookupBuilderError::from_err("mdns", e))
    }

    fn socketaddrs_to_addrs<'a>(
        socketaddrs: impl Iterator<Item = &'a SocketAddr>,
    ) -> HashMap<u16, Vec<IpAddr>> {
        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        for socketaddr in socketaddrs {
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| a.push(socketaddr.ip()))
                .or_insert(vec![socketaddr.ip()]);
        }
        addrs
    }
}

/// Computes the lookup timeout from the query cadence.
///
/// Allows for swarm-discovery's worst-case query delay of 1.2 times the cadence,
/// plus five seconds for the response, with a minimum of [`MIN_LOOKUP_DURATION`].
fn lookup_duration(cadence: Duration) -> Duration {
    MIN_LOOKUP_DURATION.max(
        cadence
            .saturating_add(cadence / 5)
            .saturating_add(Duration::from_secs(5)),
    )
}

/// Caches the latest discovery item for an endpoint.
///
/// Returns `true` if the endpoint is new or its advertised content changed.
/// Observation timestamps do not affect the comparison. The cached item is
/// always replaced so later lookups use the latest addresses.
fn cache_discovery(
    cache: &mut HashMap<PublicKey, AddressLookupItem>,
    item: AddressLookupItem,
) -> bool {
    let id = item.endpoint_id();
    let changed = cache
        .get(&id)
        .is_none_or(|old| old.endpoint_info() != item.endpoint_info());
    cache.insert(id, item);
    changed
}

fn peer_to_discovery_item(peer: &Peer, endpoint_id: &EndpointId) -> AddressLookupItem {
    let ip_addrs: BTreeSet<SocketAddr> = peer
        .addrs()
        .iter()
        .map(|(ip, port)| SocketAddr::new(*ip, *port))
        .collect();

    // Get the relay url from the resolved peer info. We expect an attribute that parses as
    // a `RelayUrl`. Otherwise, omit.
    let relay_url = if let Some(Some(relay_url)) = peer.txt_attribute(RELAY_URL_ATTRIBUTE) {
        match relay_url.parse() {
            Err(err) => {
                debug!("failed to parse relay url from TXT attribute: {err}");
                None
            }
            Ok(url) => Some(url),
        }
    } else {
        None
    };

    // Get the user-defined data from the resolved peer info. We expect an attribute with a value
    // that parses as `UserData`. Otherwise, omit.
    let user_data = if let Some(Some(user_data)) = peer.txt_attribute(USER_DATA_ATTRIBUTE) {
        match user_data.parse() {
            Err(err) => {
                debug!("failed to parse user data from TXT attribute: {err}");
                None
            }
            Ok(data) => Some(data),
        }
    } else {
        None
    };

    let mut data = EndpointData::from(ip_addrs);
    if let Some(relay_url) = relay_url {
        data.add_relay_url(relay_url);
    }
    data.set_user_data(user_data);

    let endpoint_info = EndpointInfo::from_parts(*endpoint_id, data);
    AddressLookupItem::new(endpoint_info, NAME, None)
}

impl AddressLookup for MdnsAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        use futures_util::FutureExt;

        let (send, recv) = watch::channel(None);
        let address_lookup_sender = self.sender.clone();
        let stream = async move {
            address_lookup_sender
                .send(Message::Resolve(endpoint_id, send))
                .await
                .ok();
            tokio_stream::wrappers::WatchStream::new(recv).filter_map(|item| item.map(Ok))
        };
        Some(Box::pin(stream.flatten_stream()))
    }

    fn publish(&self, data: &EndpointData) {
        if self.advertise {
            self.local_addrs.set(Some(data.clone())).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures_util::FutureExt;

    fn discovered(endpoint_id: EndpointId, port: u16) -> Message {
        Message::Discovered(
            endpoint_id,
            Some(AddressLookupItem::new(
                EndpointInfo::from_parts(
                    endpoint_id,
                    EndpointData::from_iter([iroh_base::TransportAddr::Ip(
                        ([192, 168, 1, 8], port).into(),
                    )]),
                ),
                NAME,
                None,
            )),
        )
    }

    fn start_resolution(
        lookup: &MdnsAddressLookup,
        id: EndpointId,
    ) -> BoxStream<Result<AddressLookupItem, AddressLookupError>> {
        let mut stream = lookup.resolve(id).unwrap();
        assert!(stream.next().now_or_never().is_none());
        stream
    }

    async fn wait_for_resolutions(lookup: &MdnsAddressLookup, expected: usize) {
        time::timeout(Duration::from_secs(1), async {
            loop {
                let (sender, receiver) = tokio::sync::oneshot::channel();
                lookup
                    .sender
                    .send(Message::ResolutionCount(sender))
                    .await
                    .unwrap();
                if receiver.await.unwrap() == (expected, expected) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    fn port(item: Result<AddressLookupItem, AddressLookupError>) -> u16 {
        item.unwrap()
            .endpoint_info()
            .data
            .ip_addrs()
            .next()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn stalled_resolution_coalesces_updates_without_blocking_other_consumers() {
        let local = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let remote = iroh_base::SecretKey::from_bytes(&[8; 32]).public();
        let lookup = MdnsAddressLookup::builder()
            .advertise(false)
            .build(local)
            .unwrap();
        let mut slow = start_resolution(&lookup, remote);
        let mut healthy = start_resolution(&lookup, remote);
        let mut events = lookup.subscribe().await;
        wait_for_resolutions(&lookup, 2).await;
        for value in 1..=64 {
            lookup.sender.send(discovered(remote, value)).await.unwrap();
            assert_eq!(port(healthy.next().await.unwrap()), value);
        }
        assert_eq!(port(slow.next().await.unwrap()), 64);
        assert!(slow.next().now_or_never().is_none());
        lookup.sender.send(discovered(remote, 65)).await.unwrap();
        assert_eq!(port(healthy.next().await.unwrap()), 65);
        assert_eq!(port(slow.next().await.unwrap()), 65);
        lookup.sender.send(discovered(remote, 65)).await.unwrap();
        wait_for_resolutions(&lookup, 2).await;
        assert!(healthy.next().now_or_never().is_none());
        assert!(slow.next().now_or_never().is_none());
        assert!(events.next().now_or_never().is_none());
        let other = iroh_base::SecretKey::from_bytes(&[9; 32]).public();
        lookup.sender.send(discovered(other, 70)).await.unwrap();
        assert!(
            matches!(events.next().await, Some(DiscoveryEvent::Discovered { endpoint_info, .. })
            if endpoint_info.endpoint_id == other)
        );
        drop((slow, healthy));
        wait_for_resolutions(&lookup, 0).await;
        lookup.sender.send(discovered(remote, 66)).await.unwrap();
        assert!(
            matches!(events.next().await, Some(DiscoveryEvent::Discovered { endpoint_info, .. })
            if endpoint_info.endpoint_id == remote)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cached_resolution_clears_expiry_and_drains_latest_state_at_timeout() {
        let local = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let remote = iroh_base::SecretKey::from_bytes(&[8; 32]).public();
        let lookup = MdnsAddressLookup::builder()
            .advertise(false)
            .build(local)
            .unwrap();
        let mut events = lookup.subscribe().await;
        lookup.sender.send(discovered(remote, 1)).await.unwrap();
        wait_for_resolutions(&lookup, 0).await;
        let mut stream = start_resolution(&lookup, remote);
        wait_for_resolutions(&lookup, 1).await;
        lookup
            .sender
            .send(Message::Discovered(remote, None))
            .await
            .unwrap();
        wait_for_resolutions(&lookup, 1).await;
        assert!(stream.next().now_or_never().is_none());
        assert!(matches!(
            events.next().await,
            Some(DiscoveryEvent::Discovered { .. })
        ));
        assert!(
            matches!(events.next().await, Some(DiscoveryEvent::Expired { endpoint_id })
            if endpoint_id == remote)
        );
        let mut fresh = start_resolution(&lookup, remote);
        wait_for_resolutions(&lookup, 2).await;
        assert!(fresh.next().now_or_never().is_none());
        lookup.sender.send(discovered(remote, 2)).await.unwrap();
        assert_eq!(port(stream.next().await.unwrap()), 2);
        assert_eq!(port(fresh.next().await.unwrap()), 2);
        let mut repeated = start_resolution(&lookup, remote);
        wait_for_resolutions(&lookup, 3).await;
        assert_eq!(port(repeated.next().await.unwrap()), 2);
        assert!(repeated.next().now_or_never().is_none());
        drop(repeated);
        wait_for_resolutions(&lookup, 2).await;
        lookup.sender.send(discovered(remote, 3)).await.unwrap();
        wait_for_resolutions(&lookup, 2).await;
        tokio::time::advance(MIN_LOOKUP_DURATION).await;
        wait_for_resolutions(&lookup, 0).await;
        for mut receiver in [stream, fresh] {
            assert_eq!(port(receiver.next().await.unwrap()), 3);
            assert!(receiver.next().await.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn canceled_resolutions_release_state_without_ending_other_resolutions() {
        let local = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let remote = iroh_base::SecretKey::from_bytes(&[8; 32]).public();
        let lookup = MdnsAddressLookup::builder()
            .advertise(false)
            .build(local)
            .unwrap();
        drop(lookup.resolve(remote));
        wait_for_resolutions(&lookup, 0).await;
        let first = start_resolution(&lookup, remote);
        wait_for_resolutions(&lookup, 1).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        let mut second = start_resolution(&lookup, remote);
        wait_for_resolutions(&lookup, 2).await;
        drop(first);
        wait_for_resolutions(&lookup, 1).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        wait_for_resolutions(&lookup, 1).await;
        assert!(second.next().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(5)).await;
        wait_for_resolutions(&lookup, 0).await;
        assert!(second.next().await.is_none());
        let mut last = start_resolution(&lookup, remote);
        wait_for_resolutions(&lookup, 1).await;
        drop(lookup);
        assert!(last.next().await.is_none());
    }

    #[test]
    fn refreshes_are_quiet_and_changed_addresses_replace_the_cache() {
        let id = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let make = |port| {
            let data = EndpointData::from_iter([iroh_base::TransportAddr::Ip(
                ([192, 168, 1, 8], port).into(),
            )]);
            AddressLookupItem::new(EndpointInfo::from_parts(id, data), NAME, None)
        };
        let mut cache = HashMap::new();
        assert!(cache_discovery(&mut cache, make(1234)));
        assert!(!cache_discovery(&mut cache, make(1234)));
        assert!(cache_discovery(&mut cache, make(5678)));
        assert_eq!(cache[&id].endpoint_info(), make(5678).endpoint_info());
        assert!(!cache_discovery(&mut cache, make(5678)));
        // Expiry forgets the record, so the same peer is announced on return.
        cache.remove(&id);
        assert!(cache_discovery(&mut cache, make(5678)));
    }

    #[test]
    fn relay_and_user_data_changes_are_not_suppressed() {
        let id = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let mut cache = HashMap::new();
        let mut data = EndpointData::default();
        for relay in ["https://one.example", "https://two.example"] {
            data.add_relay_url(relay.parse().unwrap());
            assert!(cache_discovery(
                &mut cache,
                AddressLookupItem::new(EndpointInfo::from_parts(id, data.clone()), NAME, None,)
            ));
        }
        data.set_user_data(Some("new metadata".parse().unwrap()));
        assert!(cache_discovery(
            &mut cache,
            AddressLookupItem::new(EndpointInfo::from_parts(id, data), NAME, None,)
        ));
    }

    #[test]
    fn background_cadence_preserves_interactive_default() {
        assert_eq!(
            MdnsAddressLookup::builder().cadence,
            Duration::from_millis(700)
        );
        assert_eq!(
            MdnsAddressLookup::builder()
                .discovery_cadence(Duration::from_secs(30))
                .cadence,
            Duration::from_secs(30)
        );
    }

    #[test]
    #[should_panic]
    fn zero_cadence_is_rejected() {
        MdnsAddressLookup::builder().discovery_cadence(Duration::ZERO);
    }

    #[test]
    fn long_background_cadence_is_accepted() {
        assert_eq!(
            MdnsAddressLookup::builder()
                .discovery_cadence(Duration::from_secs(60))
                .cadence,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn lookup_deadline_tracks_cadence() {
        assert_eq!(
            lookup_duration(Duration::from_millis(700)),
            Duration::from_secs(10)
        );
        assert_eq!(
            lookup_duration(Duration::from_secs(30)),
            Duration::from_secs(41)
        );
        assert_eq!(
            lookup_duration(Duration::from_secs(60)),
            Duration::from_secs(77)
        );
    }

    /// This module's name signals nextest to run test in a single thread (no other concurrent
    /// tests).
    mod run_in_isolation {
        use iroh::endpoint_info::UserData;
        use iroh_base::{SecretKey, TransportAddr};
        use n0_error::{AnyError as Error, Result, StdResultExt, bail_any};
        use n0_future::StreamExt;
        use n0_tracing_test::traced_test;
        use rand::{CryptoRng, RngExt, SeedableRng};

        use super::super::*;

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_resolve() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create Address LookupA with advertise=false (only listens)
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            // Create Address LookupB with advertise=true (will broadcast)
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, true)?;

            // make addr info for discoverer b
            let user_data: UserData = "foobar".parse()?;
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())])
                    .with_user_data(user_data.clone());

            // resolve twice to ensure we can create separate streams for the same endpoint_id
            let mut s1 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });
            let mut s2 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });

            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");
            // publish address_lookup_b's address
            address_lookup_b.publish(&endpoint_data);
            let DiscoveryEvent::Discovered {
                endpoint_info: s1_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            let DiscoveryEvent::Discovered {
                endpoint_info: s2_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            assert_eq!(s1_endpoint_info.data, endpoint_data);
            assert_eq!(s2_endpoint_info.data, endpoint_data);

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_expire() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, true)?;

            // publish address_lookup_b's address
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())])
                    .with_user_data("".parse()?);
            address_lookup_b.publish(&endpoint_data);

            let mut s1 = address_lookup_a.subscribe().await;
            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");

            // Wait for the specific endpoint to be discovered
            loop {
                let event = tokio::time::timeout(Duration::from_secs(5), s1.next())
                    .await
                    .std_context("timeout")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. }
                        if endpoint_info.endpoint_id == endpoint_id_b =>
                    {
                        break;
                    }
                    _ => continue, // Ignore other discovery events
                }
            }

            // Shutdown endpoint B
            drop(address_lookup_b);
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Wait for the expiration event for the specific endpoint
            loop {
                let event = tokio::time::timeout(Duration::from_secs(10), s1.next())
                    .await
                    .std_context("timeout waiting for expiration event")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Expired {
                        endpoint_id: expired_endpoint_id,
                    } if expired_endpoint_id == endpoint_id_b => {
                        break;
                    }
                    _ => continue, // Ignore other events
                }
            }

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_subscribe() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let num_endpoints = 5;
            let mut endpoint_ids = BTreeSet::new();
            let mut address_lookup_list = vec![];

            let (_, address_lookup) = make_address_lookup(&mut rng, false)?;
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);

            for i in 0..num_endpoints {
                let (endpoint_id, address_lookup) = make_address_lookup(&mut rng, true)?;
                let user_data: UserData = format!("endpoint{i}").parse()?;
                let endpoint_data = endpoint_data.clone().with_user_data(user_data.clone());
                endpoint_ids.insert((endpoint_id, Some(user_data)));
                address_lookup.publish(&endpoint_data);
                address_lookup_list.push(address_lookup);
            }

            let mut events = address_lookup.subscribe().await;

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_endpoints {
                    if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) =
                        events.next().await
                    {
                        let data = endpoint_info.data.user_data().cloned();
                        if endpoint_ids.contains(&(endpoint_info.endpoint_id, data.clone())) {
                            got_ids.insert((endpoint_info.endpoint_id, data));
                        }
                    } else {
                        bail_any!(
                            "no more events, only got {} ids, expected {num_endpoints}\n",
                            got_ids.len()
                        );
                    }
                }
                assert_eq!(got_ids, endpoint_ids);
                Ok::<_, Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), test)
                .await
                .std_context("timeout")?
        }

        #[tokio::test]
        #[traced_test]
        async fn non_advertising_endpoint_not_discovered() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, false)?;

            let (endpoint_id_c, address_lookup_c) = make_address_lookup(&mut rng, true)?;
            let endpoint_data_c =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:22222".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let endpoint_data_b =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let mut stream_c = address_lookup_a.resolve(endpoint_id_c).unwrap();
            let result_c = tokio::time::timeout(Duration::from_secs(2), stream_c.next()).await;
            assert!(
                result_c.is_ok(),
                "Advertising endpoint should be discoverable"
            );

            let mut stream_b = address_lookup_a.resolve(endpoint_id_b).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Expected timeout since endpoint b isn't advertising"
            );

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn test_service_names() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create an Address Lookupusing the default
            // service name
            let id_a = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_a = MdnsAddressLookup::builder().build(id_a)?;

            // Create a Address Lookupusing a custom
            // service name
            let id_b = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_b = MdnsAddressLookup::builder()
                .service_name("different.name")
                .build(id_b)?;

            // Create an Address Lookupusing the same
            // custom service name
            let id_c = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_c = MdnsAddressLookup::builder()
                .service_name("different.name")
                .build(id_c)?;

            let endpoint_data_a =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);
            address_lookup_a.publish(&endpoint_data_a);

            let endpoint_data_b =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:22222".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let endpoint_data_c =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:33333".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let mut stream_a = address_lookup_a.resolve(id_b).unwrap();
            let result_a = tokio::time::timeout(Duration::from_secs(2), stream_a.next()).await;
            assert!(
                result_a.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_c).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_ok(),
                "Endpoint on the same service should be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_a).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_relay_url() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create an mdns address lookup A that only listens
            let (_, mdns_a) = make_address_lookup(&mut rng, false)?;

            // Create an mdns address lookup B that includes a relay url for publishing
            let (endpoint_id_b, mdns_b) = make_address_lookup(&mut rng, true)?;
            let relay_url: iroh_base::RelayUrl = "https://relay.example.com".parse().unwrap();
            let endpoint_data = EndpointData::from_iter([
                TransportAddr::Ip("0.0.0.0:11111".parse().unwrap()),
                TransportAddr::Relay(relay_url.clone()),
            ]);

            // Subscribe to discovery events filtered for endpoint B
            let mut events = mdns_a.subscribe().await.filter(|event| match event {
                DiscoveryEvent::Discovered { endpoint_info, .. } => {
                    endpoint_info.endpoint_id == endpoint_id_b
                }
                _ => false,
            });

            // Publish mdns_b's address with relay URL
            mdns_b.publish(&endpoint_data);

            // Wait for discovery
            let DiscoveryEvent::Discovered { endpoint_info, .. } =
                tokio::time::timeout(Duration::from_secs(2), events.next())
                    .await
                    .std_context("timeout")?
                    .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };

            // Verify the relay URL was received
            let discovered_relay_urls: Vec<_> = endpoint_info.data.relay_urls().collect();
            assert_eq!(discovered_relay_urls.len(), 1);
            assert_eq!(discovered_relay_urls[0], &relay_url);

            Ok(())
        }

        fn make_address_lookup<R: CryptoRng + ?Sized>(
            rng: &mut R,
            advertise: bool,
        ) -> Result<(PublicKey, MdnsAddressLookup)> {
            let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
            Ok((
                endpoint_id,
                MdnsAddressLookup::builder()
                    .advertise(advertise)
                    .build(endpoint_id)?,
            ))
        }
    }
}

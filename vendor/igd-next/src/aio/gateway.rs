use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

use super::Provider;
use crate::errors::{self, AddAnyPortError, AddPortError, GetExternalIpError, RemovePortError, RequestError};

use crate::common::{self, messages, parsing, parsing::RequestReponse};
use crate::PortMappingProtocol;

/// This structure represents a gateway found by the search functions.
#[derive(Clone, Debug)]
pub struct Gateway<P> {
    /// Socket address of the gateway
    pub addr: SocketAddr,
    /// Root url of the device
    pub root_url: String,
    /// Control path or absolute HTTP URL of the device
    pub control_url: String,
    /// Path or absolute HTTP URL for schema data
    pub control_schema_url: String,
    /// Control schema for all actions
    pub control_schema: HashMap<String, Vec<String>>,
    /// Service type of the gateway's WAN connection service (e.g.
    /// `urn:schemas-upnp-org:service:WANIPConnection:1`)
    pub service_type: String,
    /// Control path or absolute HTTP URL for the `WANIPv6FirewallControl` service.
    #[cfg(feature = "ipv6")]
    pub ipv6_firewall_control_url: Option<String>,
    /// Executor provider
    pub provider: P,
}

#[cfg(feature = "ipv6")]
/// A handle to a gateway's IPv6 firewall service.
#[derive(Clone, Debug)]
pub struct Ipv6FirewallGateway<P> {
    /// Address used to reach the gateway.
    pub addr: SocketAddr,
    /// Path to the device description.
    pub root_url: String,
    /// Control URL for the IPv6 firewall service.
    pub control_url: String,
    provider: P,
}

#[cfg(feature = "ipv6")]
impl<P> Ipv6FirewallGateway<P> {
    pub(crate) fn new(addr: SocketAddr, root_url: String, control_url: String, provider: P) -> Self {
        Self {
            addr,
            root_url,
            control_url,
            provider,
        }
    }
}

impl<P: Provider> Gateway<P> {
    async fn perform_request(&self, action: &str, body: &str, ok: &str) -> Result<RequestReponse, RequestError> {
        let url = common::endpoint::target(self.addr, &self.control_url)
            .map_err(|_| RequestError::InvalidResponse("invalid control URL".into()))?
            .transport_url();
        let header = messages::soap_action(&self.service_type, action);
        let text = self.provider.send_async(&url, &header, body).await?;
        parsing::parse_response(text, ok)
    }

    /// Get the external IP address of the gateway in a tokio compatible way
    pub async fn get_external_ip(&self) -> Result<IpAddr, GetExternalIpError> {
        let result = self
            .perform_request(
                messages::GET_EXTERNAL_IP_ACTION,
                &messages::format_get_external_ip_message(&self.service_type),
                "GetExternalIPAddressResponse",
            )
            .await;
        parsing::parse_get_external_ip_response(result)
    }

    /// Get an external socket address with our external ip and any port. This is a convenience
    /// function that calls `get_external_ip` followed by `add_any_port`
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    ///
    /// # Returns
    ///
    /// The external address that was mapped on success. Otherwise an error.
    pub async fn get_any_address(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<SocketAddr, AddAnyPortError> {
        let description = description.to_owned();
        let ip = self.get_external_ip().await?;
        let port = self
            .add_any_port(protocol, local_addr, lease_duration, &description)
            .await?;
        Ok(SocketAddr::new(ip, port))
    }

    /// Add a port mapping.with any external port.
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    ///
    /// # Returns
    ///
    /// The external port that was mapped on success. Otherwise an error.
    pub async fn add_any_port(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        // This function first attempts to call AddAnyPortMapping on the IGD with a random port
        // number. If that fails due to the method being unknown it attempts to call AddPortMapping
        // instead with a random port number. If that fails due to ConflictInMappingEntry it retrys
        // with another port up to a maximum of 20 times. If it fails due to SamePortValuesRequired
        // it retrys once with the same port values.

        if local_addr.port() == 0 {
            return Err(AddAnyPortError::InternalPortZeroInvalid);
        }

        let schema = self.control_schema.get("AddAnyPortMapping");
        if let Some(schema) = schema {
            let external_port = common::random_port();

            let description = description.to_owned();

            let resp = self
                .perform_request(
                    messages::ADD_ANY_PORT_MAPPING_ACTION,
                    &messages::format_add_any_port_mapping_message(
                        &self.service_type,
                        schema,
                        protocol,
                        external_port,
                        local_addr,
                        lease_duration,
                        &description,
                    ),
                    "AddAnyPortMappingResponse",
                )
                .await;
            parsing::parse_add_any_port_mapping_response(resp)
        } else {
            // The router does not have the AddAnyPortMapping method.
            // Fall back to using AddPortMapping with a random port.
            self.retry_add_random_port_mapping(protocol, local_addr, lease_duration, description)
                .await
        }
    }

    async fn retry_add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        for _ in 0u8..20u8 {
            match self
                .add_random_port_mapping(protocol, local_addr, lease_duration, description)
                .await
            {
                Ok(port) => return Ok(port),
                Err(AddAnyPortError::NoPortsAvailable) => continue,
                e => return e,
            }
        }
        Err(AddAnyPortError::NoPortsAvailable)
    }

    async fn add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        let description = description.to_owned();
        let external_port = common::random_port();
        let res = self
            .add_port_mapping(protocol, external_port, local_addr, lease_duration, &description)
            .await;

        match res {
            Ok(_) => Ok(external_port),
            Err(err) => match parsing::convert_add_random_port_mapping_error(err) {
                Some(err) => Err(err),
                None => {
                    self.add_same_port_mapping(protocol, local_addr, lease_duration, &description)
                        .await
                }
            },
        }
    }

    async fn add_same_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        let res = self
            .add_port_mapping(protocol, local_addr.port(), local_addr, lease_duration, description)
            .await;
        match res {
            Ok(_) => Ok(local_addr.port()),
            Err(err) => Err(parsing::convert_add_same_port_mapping_error(err)),
        }
    }

    async fn add_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), RequestError> {
        self.perform_request(
            messages::ADD_PORT_MAPPING_ACTION,
            &messages::format_add_port_mapping_message(
                &self.service_type,
                self.control_schema
                    .get("AddPortMapping")
                    .ok_or_else(|| RequestError::UnsupportedAction("AddPortMapping".to_string()))?,
                protocol,
                external_port,
                local_addr,
                lease_duration,
                description,
            ),
            "AddPortMappingResponse",
        )
        .await?;
        Ok(())
    }

    /// Add a port mapping.
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    pub async fn add_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), AddPortError> {
        if external_port == 0 {
            return Err(AddPortError::ExternalPortZeroInvalid);
        }
        if local_addr.port() == 0 {
            return Err(AddPortError::InternalPortZeroInvalid);
        }

        let res = self
            .add_port_mapping(protocol, external_port, local_addr, lease_duration, description)
            .await;
        if let Err(err) = res {
            return Err(parsing::convert_add_port_error(err));
        };
        Ok(())
    }

    /// Remove a port mapping.
    pub async fn remove_port(&self, protocol: PortMappingProtocol, external_port: u16) -> Result<(), RemovePortError> {
        let res = self
            .perform_request(
                messages::DELETE_PORT_MAPPING_ACTION,
                &messages::format_delete_port_message(
                    &self.service_type,
                    self.control_schema.get("DeletePortMapping").ok_or_else(|| {
                        RemovePortError::RequestError(RequestError::UnsupportedAction("DeletePortMapping".to_string()))
                    })?,
                    protocol,
                    external_port,
                ),
                "DeletePortMappingResponse",
            )
            .await;
        parsing::parse_delete_port_mapping_response(res)
    }

    /// Get one port mapping entry
    ///
    /// Gets one port mapping entry by its index.
    /// Not all existing port mappings might be visible to this client.
    /// If the index is out of bound, GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid will be returned
    pub async fn get_generic_port_mapping_entry(
        &self,
        index: u32,
    ) -> Result<parsing::PortMappingEntry, errors::GetGenericPortMappingEntryError> {
        let result = self
            .perform_request(
                messages::GET_GENERIC_PORT_MAPPING_ENTRY_ACTION,
                &messages::formate_get_generic_port_mapping_entry_message(&self.service_type, index),
                "GetGenericPortMappingEntryResponse",
            )
            .await;
        parsing::parse_get_generic_port_mapping_entry(result)
    }

    #[cfg(feature = "ipv6")]
    /// Get a handle to this gateway's IPv6 firewall service, if it exposes one.
    pub fn ipv6_firewall(&self) -> Option<Ipv6FirewallGateway<P>> {
        self.ipv6_firewall_control_url.as_ref().map(|control_url| {
            Ipv6FirewallGateway::new(
                self.addr,
                self.root_url.clone(),
                control_url.clone(),
                self.provider.clone(),
            )
        })
    }

    /// Open an IPv6 firewall pinhole allowing inbound traffic to `internal_client`.
    ///
    /// This is the IPv6 equivalent of port forwarding: IPv6 is not NATed, so rather than a port
    /// mapping the gateway opens a pinhole in its firewall to the (globally routable) internal
    /// IPv6 client. The remote host and port are wildcarded, so any source is allowed.
    ///
    /// `lease_duration` is in seconds and must be between `1` and `86400`
    /// (`0` is not valid for a pinhole). Requires the gateway to expose a
    /// `WANIPv6FirewallControl` service.
    #[cfg(feature = "ipv6")]
    pub async fn add_pinhole(
        &self,
        protocol: PortMappingProtocol,
        internal_client: std::net::SocketAddrV6,
        lease_duration: u32,
    ) -> Result<u16, errors::PinholeError> {
        if !(1..=86400).contains(&lease_duration) {
            return Err(errors::PinholeError::InvalidLeaseDuration);
        }
        self.ipv6_firewall()
            .ok_or(errors::PinholeError::FirewallControlUnavailable)?
            .add_pinhole(protocol, internal_client, lease_duration)
            .await
    }

    /// Extend the lease of an existing pinhole identified by its `UniqueID`.
    ///
    /// Note that `lease_duration` is in seconds and must be between `1` and `86400`.
    #[cfg(feature = "ipv6")]
    pub async fn update_pinhole(&self, unique_id: u16, lease_duration: u32) -> Result<(), errors::PinholeError> {
        if !(1..=86400).contains(&lease_duration) {
            return Err(errors::PinholeError::InvalidLeaseDuration);
        }
        self.ipv6_firewall()
            .ok_or(errors::PinholeError::FirewallControlUnavailable)?
            .update_pinhole(unique_id, lease_duration)
            .await
    }

    /// Remove an existing pinhole identified by its `UniqueID`.
    #[cfg(feature = "ipv6")]
    pub async fn remove_pinhole(&self, unique_id: u16) -> Result<(), errors::PinholeError> {
        self.ipv6_firewall()
            .ok_or(errors::PinholeError::FirewallControlUnavailable)?
            .remove_pinhole(unique_id)
            .await
    }

    /// Query whether the gateway's IPv6 firewall is enabled and whether inbound pinholes are allowed.
    #[cfg(feature = "ipv6")]
    pub async fn get_firewall_status(&self) -> Result<parsing::FirewallStatus, errors::PinholeError> {
        self.ipv6_firewall()
            .ok_or(errors::PinholeError::FirewallControlUnavailable)?
            .get_firewall_status()
            .await
    }
}

#[cfg(feature = "ipv6")]
impl<P: Provider> Ipv6FirewallGateway<P> {
    async fn firewall_request(&self, action: &str, body: &str, ok: &str) -> Result<RequestReponse, RequestError> {
        let url = common::endpoint::target(self.addr, &self.control_url)
            .map_err(|_| RequestError::InvalidResponse("invalid control URL".into()))?
            .transport_url();
        let header = messages::soap_action(messages::WAN_IPV6_FIREWALL_CONTROL, action);
        let text = self.provider.send_async(&url, &header, body).await?;
        parsing::parse_response(text, ok)
    }

    /// Open a pinhole to an IPv6 client from any remote host and port.
    ///
    /// The lease duration must be between 1 and 86400 seconds.
    pub async fn add_pinhole(
        &self,
        protocol: PortMappingProtocol,
        internal_client: std::net::SocketAddrV6,
        lease_duration: u32,
    ) -> Result<u16, errors::PinholeError> {
        if !(1..=86400).contains(&lease_duration) {
            return Err(errors::PinholeError::InvalidLeaseDuration);
        }
        let result = self
            .firewall_request(
                messages::ADD_PINHOLE_ACTION,
                &messages::format_add_pinhole_message(
                    "",
                    0,
                    *internal_client.ip(),
                    internal_client.port(),
                    protocol,
                    lease_duration,
                ),
                "AddPinholeResponse",
            )
            .await;
        parsing::parse_add_pinhole_response(result)
    }

    /// Extend the lease of a pinhole by its unique ID.
    pub async fn update_pinhole(&self, unique_id: u16, lease_duration: u32) -> Result<(), errors::PinholeError> {
        if !(1..=86400).contains(&lease_duration) {
            return Err(errors::PinholeError::InvalidLeaseDuration);
        }
        let result = self
            .firewall_request(
                messages::UPDATE_PINHOLE_ACTION,
                &messages::format_update_pinhole_message(unique_id, lease_duration),
                "UpdatePinholeResponse",
            )
            .await;
        parsing::parse_pinhole_unit_response(result)
    }

    /// Remove a pinhole by its unique ID.
    pub async fn remove_pinhole(&self, unique_id: u16) -> Result<(), errors::PinholeError> {
        let result = self
            .firewall_request(
                messages::DELETE_PINHOLE_ACTION,
                &messages::format_delete_pinhole_message(unique_id),
                "DeletePinholeResponse",
            )
            .await;
        parsing::parse_pinhole_unit_response(result)
    }

    /// Query whether the firewall is enabled and allows inbound pinholes.
    pub async fn get_firewall_status(&self) -> Result<parsing::FirewallStatus, errors::PinholeError> {
        let result = self
            .firewall_request(
                messages::GET_FIREWALL_STATUS_ACTION,
                &messages::format_get_firewall_status_message(),
                "GetFirewallStatusResponse",
            )
            .await;
        parsing::parse_firewall_status_response(result)
    }
}

impl<P> fmt::Display for Gateway<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match common::endpoint::target(self.addr, &self.control_url) {
            Ok(target) => f.write_str(&target.transport_url()),
            Err(_) => write!(f, "http://{}{}", self.addr, self.control_url),
        }
    }
}

impl<P> PartialEq for Gateway<P> {
    fn eq(&self, other: &Gateway<P>) -> bool {
        self.addr == other.addr && self.control_url == other.control_url
    }
}

impl<P> Eq for Gateway<P> {}

impl<P> Hash for Gateway<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.control_url.hash(state);
    }
}

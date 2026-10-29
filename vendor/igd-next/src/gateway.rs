use attohttpc::{Method, RequestBuilder};
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

use crate::common::options::{DEFAULT_REQUEST_TIMEOUT, MAX_RESPONSE_BYTES};
use crate::common::{self, messages, parsing, parsing::RequestResult};
use crate::errors::{self, AddAnyPortError, AddPortError, GetExternalIpError, RemovePortError, RequestError};
use crate::PortMappingProtocol;
use crate::RequestError::AttoHttpError;

/// This structure represents a gateway found by the search functions.
#[derive(Clone, Debug)]
pub struct Gateway {
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
}

#[cfg(feature = "ipv6")]
/// A handle to a gateway's IPv6 firewall service.
#[derive(Clone, Debug)]
pub struct Ipv6FirewallGateway {
    /// Address used to reach the gateway.
    pub addr: SocketAddr,
    /// Path to the device description.
    pub root_url: String,
    /// Control URL for the IPv6 firewall service.
    pub control_url: String,
}

fn send_soap(addr: SocketAddr, control_url: &str, header: &str, body: &str, ok: &str) -> RequestResult {
    let target = common::endpoint::target(addr, control_url)
        .map_err(|_| RequestError::InvalidResponse("invalid control URL".into()))?;
    // A link-local gateway can only be reached on a specific interface (the address's zone id),
    // which a URL cannot carry, so connect to the scoped address directly instead of attohttpc.
    let bytes = if common::linklocal::is_scoped_link_local(&target.addr) {
        common::linklocal::raw_http_request(
            target.addr,
            "POST",
            &target.path_and_query,
            &[("SOAPAction", header), ("Content-Type", "text/xml")],
            Some(body),
            DEFAULT_REQUEST_TIMEOUT,
            MAX_RESPONSE_BYTES,
        )?
    } else {
        let response = match RequestBuilder::try_new(Method::POST, target.transport_url()) {
            Ok(request_builder) => request_builder
                .follow_redirects(false)
                .connect_timeout(DEFAULT_REQUEST_TIMEOUT)
                .timeout(DEFAULT_REQUEST_TIMEOUT)
                .header("SOAPAction", header)
                .header("Content-Type", "text/xml")
                .text(body)
                .send()?,
            Err(e) => return Err(AttoHttpError(e)),
        };
        common::read_response_body(response, MAX_RESPONSE_BYTES)?
    };
    let text = String::from_utf8_lossy(&bytes).into_owned();
    parsing::parse_response(text, ok)
}

impl Gateway {
    fn perform_request(&self, action: &str, body: &str, ok: &str) -> RequestResult {
        let header = messages::soap_action(&self.service_type, action);
        send_soap(self.addr, &self.control_url, &header, body, ok)
    }

    /// Get the external IP address of the gateway.
    pub fn get_external_ip(&self) -> Result<IpAddr, GetExternalIpError> {
        parsing::parse_get_external_ip_response(self.perform_request(
            messages::GET_EXTERNAL_IP_ACTION,
            &messages::format_get_external_ip_message(&self.service_type),
            "GetExternalIPAddressResponse",
        ))
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
    pub fn get_any_address(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<SocketAddr, AddAnyPortError> {
        let ip = self.get_external_ip()?;
        let port = self.add_any_port(protocol, local_addr, lease_duration, description)?;
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
    pub fn add_any_port(
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

            parsing::parse_add_any_port_mapping_response(self.perform_request(
                messages::ADD_ANY_PORT_MAPPING_ACTION,
                &messages::format_add_any_port_mapping_message(
                    &self.service_type,
                    schema,
                    protocol,
                    external_port,
                    local_addr,
                    lease_duration,
                    description,
                ),
                "AddAnyPortMappingResponse",
            ))
        } else {
            self.retry_add_random_port_mapping(protocol, local_addr, lease_duration, description)
        }
    }

    fn retry_add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        const ATTEMPTS: usize = 20;

        for _ in 0..ATTEMPTS {
            match self.add_random_port_mapping(protocol, local_addr, lease_duration, description) {
                Ok(port) => return Ok(port),
                Err(AddAnyPortError::NoPortsAvailable) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(AddAnyPortError::NoPortsAvailable)
    }

    fn add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        let external_port = common::random_port();

        if let Err(err) = self.add_port_mapping(protocol, external_port, local_addr, lease_duration, description) {
            match parsing::convert_add_random_port_mapping_error(err) {
                Some(err) => return Err(err),
                None => return self.add_same_port_mapping(protocol, local_addr, lease_duration, description),
            }
        }

        Ok(external_port)
    }

    fn add_same_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> Result<u16, AddAnyPortError> {
        match self.add_port_mapping(protocol, local_addr.port(), local_addr, lease_duration, description) {
            Ok(_) => Ok(local_addr.port()),
            Err(e) => Err(parsing::convert_add_same_port_mapping_error(e)),
        }
    }

    fn add_port_mapping(
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
        )?;

        Ok(())
    }

    /// Add a port mapping.
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    pub fn add_port(
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

        self.add_port_mapping(protocol, external_port, local_addr, lease_duration, description)
            .map_err(parsing::convert_add_port_error)
    }

    /// Remove a port mapping.
    pub fn remove_port(&self, protocol: PortMappingProtocol, external_port: u16) -> Result<(), RemovePortError> {
        parsing::parse_delete_port_mapping_response(self.perform_request(
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
        ))
    }

    /// Get one port mapping entry
    ///
    /// Gets one port mapping entry by its index.
    /// Not all existing port mappings might be visible to this client.
    /// If the index is out of bound, GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid will be returned
    pub fn get_generic_port_mapping_entry(
        &self,
        index: u32,
    ) -> Result<parsing::PortMappingEntry, errors::GetGenericPortMappingEntryError> {
        parsing::parse_get_generic_port_mapping_entry(self.perform_request(
            messages::GET_GENERIC_PORT_MAPPING_ENTRY_ACTION,
            &messages::formate_get_generic_port_mapping_entry_message(&self.service_type, index),
            "GetGenericPortMappingEntryResponse",
        ))
    }

    #[cfg(feature = "ipv6")]
    /// Get a handle to this gateway's IPv6 firewall service, if it exposes one.
    pub fn ipv6_firewall(&self) -> Option<Ipv6FirewallGateway> {
        self.ipv6_firewall_control_url
            .as_ref()
            .map(|control_url| Ipv6FirewallGateway {
                addr: self.addr,
                root_url: self.root_url.clone(),
                control_url: control_url.clone(),
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
    pub fn add_pinhole(
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
    }

    /// Extend the lease of an existing pinhole identified by its `UniqueID`.
    #[cfg(feature = "ipv6")]
    pub fn update_pinhole(&self, unique_id: u16, lease_duration: u32) -> Result<(), errors::PinholeError> {
        if !(1..=86400).contains(&lease_duration) {
            return Err(errors::PinholeError::InvalidLeaseDuration);
        }
        self.ipv6_firewall()
            .ok_or(errors::PinholeError::FirewallControlUnavailable)?
            .update_pinhole(unique_id, lease_duration)
    }

    /// Remove an existing pinhole identified by its `UniqueID`.
    #[cfg(feature = "ipv6")]
    pub fn remove_pinhole(&self, unique_id: u16) -> Result<(), errors::PinholeError> {
        self.ipv6_firewall()
            .ok_or(errors::PinholeError::FirewallControlUnavailable)?
            .remove_pinhole(unique_id)
    }

    /// Query whether the gateway's IPv6 firewall is enabled and whether inbound pinholes are allowed.
    #[cfg(feature = "ipv6")]
    pub fn get_firewall_status(&self) -> Result<parsing::FirewallStatus, errors::PinholeError> {
        self.ipv6_firewall()
            .ok_or(errors::PinholeError::FirewallControlUnavailable)?
            .get_firewall_status()
    }
}

#[cfg(feature = "ipv6")]
impl Ipv6FirewallGateway {
    fn firewall_request(&self, action: &str, body: &str, ok: &str) -> RequestResult {
        let header = messages::soap_action(messages::WAN_IPV6_FIREWALL_CONTROL, action);
        send_soap(self.addr, &self.control_url, &header, body, ok)
    }

    /// Open a pinhole to an IPv6 client from any remote host and port.
    ///
    /// The lease duration must be between 1 and 86400 seconds.
    pub fn add_pinhole(
        &self,
        protocol: PortMappingProtocol,
        internal_client: std::net::SocketAddrV6,
        lease_duration: u32,
    ) -> Result<u16, errors::PinholeError> {
        if !(1..=86400).contains(&lease_duration) {
            return Err(errors::PinholeError::InvalidLeaseDuration);
        }
        let result = self.firewall_request(
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
        );
        parsing::parse_add_pinhole_response(result)
    }

    /// Extend the lease of a pinhole by its unique ID.
    pub fn update_pinhole(&self, unique_id: u16, lease_duration: u32) -> Result<(), errors::PinholeError> {
        if !(1..=86400).contains(&lease_duration) {
            return Err(errors::PinholeError::InvalidLeaseDuration);
        }
        let result = self.firewall_request(
            messages::UPDATE_PINHOLE_ACTION,
            &messages::format_update_pinhole_message(unique_id, lease_duration),
            "UpdatePinholeResponse",
        );
        parsing::parse_pinhole_unit_response(result)
    }

    /// Remove a pinhole by its unique ID.
    pub fn remove_pinhole(&self, unique_id: u16) -> Result<(), errors::PinholeError> {
        let result = self.firewall_request(
            messages::DELETE_PINHOLE_ACTION,
            &messages::format_delete_pinhole_message(unique_id),
            "DeletePinholeResponse",
        );
        parsing::parse_pinhole_unit_response(result)
    }

    /// Query whether the firewall is enabled and allows inbound pinholes.
    pub fn get_firewall_status(&self) -> Result<parsing::FirewallStatus, errors::PinholeError> {
        let result = self.firewall_request(
            messages::GET_FIREWALL_STATUS_ACTION,
            &messages::format_get_firewall_status_message(),
            "GetFirewallStatusResponse",
        );
        parsing::parse_firewall_status_response(result)
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match common::endpoint::target(self.addr, &self.control_url) {
            Ok(target) => f.write_str(&target.transport_url()),
            Err(_) => write!(f, "http://{}{}", self.addr, self.control_url),
        }
    }
}

impl PartialEq for Gateway {
    fn eq(&self, other: &Gateway) -> bool {
        self.addr == other.addr && self.control_url == other.control_url
    }
}

impl Eq for Gateway {}

impl Hash for Gateway {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.control_url.hash(state);
    }
}

#[cfg(all(test, feature = "ipv6"))]
mod ipv6_tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    fn test_gateway(firewall: Option<String>) -> Gateway {
        Gateway {
            addr: "127.0.0.1:0".parse().unwrap(),
            root_url: String::new(),
            control_url: String::new(),
            control_schema_url: String::new(),
            control_schema: HashMap::new(),
            service_type: String::new(),
            ipv6_firewall_control_url: firewall,
        }
    }

    #[test]
    fn add_pinhole_rejects_out_of_range_lease_locally() {
        let gw = test_gateway(Some("/ctl/fw".to_string()));
        let client = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0);
        // 0 and >86400 are invalid for a pinhole and must be rejected before any network call.
        assert!(matches!(
            gw.add_pinhole(PortMappingProtocol::TCP, client, 0),
            Err(errors::PinholeError::InvalidLeaseDuration)
        ));
        assert!(matches!(
            gw.add_pinhole(PortMappingProtocol::TCP, client, 86_401),
            Err(errors::PinholeError::InvalidLeaseDuration)
        ));
    }

    #[test]
    fn pinhole_without_firewall_service_is_unavailable() {
        let gw = test_gateway(None);
        let client = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0);
        // A valid lease but no discovered firewall service yields FirewallControlUnavailable.
        assert!(matches!(
            gw.add_pinhole(PortMappingProtocol::TCP, client, 3600),
            Err(errors::PinholeError::FirewallControlUnavailable)
        ));
    }
}

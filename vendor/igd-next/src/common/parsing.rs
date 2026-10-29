use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};

use url::{Host, Url};
use xml::reader::{EventReader, XmlEvent};
use xmltree::{self, Element};

use crate::common::endpoint;
use crate::common::options::MAX_RESPONSE_BYTES;
use crate::errors::{
    AddAnyPortError, AddPortError, GetExternalIpError, GetGenericPortMappingEntryError, RemovePortError, RequestError,
    SearchError,
};
use crate::PortMappingProtocol;

const MAX_XML_DEPTH: usize = 64;

fn parse_limited_xml<R: io::Read>(resp: R) -> Result<Element, SearchError> {
    let mut body = Vec::new();
    resp.take(MAX_RESPONSE_BYTES as u64 + 1).read_to_end(&mut body)?;
    if body.len() > MAX_RESPONSE_BYTES || !xml_depth_ok(&body) {
        return Err(SearchError::InvalidResponse);
    }
    Ok(Element::parse(body.as_slice())?)
}

fn xml_depth_ok(body: &[u8]) -> bool {
    let mut depth = 0;
    for event in EventReader::new(body) {
        match event {
            Ok(XmlEvent::StartElement { .. }) => {
                depth += 1;
                if depth > MAX_XML_DEPTH {
                    return false;
                }
            }
            Ok(XmlEvent::EndElement { .. }) => depth = depth.saturating_sub(1),
            Err(_) => return false,
            _ => {}
        }
    }
    true
}

// Parse the result.
pub fn parse_search_result(text: &str) -> Result<(SocketAddr, String), SearchError> {
    use SearchError::InvalidResponse;

    for line in text.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("location:") {
            if let Some(colon) = line.find(':') {
                let url_text = &line[colon + 1..].trim();
                let url = Url::parse(url_text).map_err(|_| InvalidResponse)?;
                if url.scheme() != "http"
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    return Err(InvalidResponse);
                }
                // Note that we use the typed host rather than `host_str()`, which returns the bracketed
                // form (eg `[2001:db8::1]`) for IPv6 that `IpAddr` cannot parse, so an IPv6 gateway
                // LOCATION is handled correctly.
                let addr: IpAddr = match url.host() {
                    Some(Host::Ipv4(addr)) => addr.into(),
                    Some(Host::Ipv6(addr)) => addr.into(),
                    _ => return Err(InvalidResponse),
                };
                let port: u16 = url.port_or_known_default().ok_or(InvalidResponse)?;

                return Ok((SocketAddr::new(addr, port), endpoint::path_and_query(&url)));
            }
        }
    }
    Err(InvalidResponse)
}

/// Parse the device description, returning `(service_type, control_schema_url, control_url)`
/// for the first supported WAN connection service found.
#[cfg(test)]
pub fn parse_control_urls<R>(resp: R) -> Result<(String, String, String), SearchError>
where
    R: io::Read,
{
    let urls = parse_device_urls(resp)?;
    let wan = urls.wan.ok_or(SearchError::InvalidResponse)?;
    Ok((wan.service_type, wan.control_schema_url, wan.control_url))
}

/// Service URLs extracted from a device description document during discovery.
pub struct DeviceUrls {
    /// Base URL from the device description, when present.
    pub url_base: Option<String>,
    /// The WAN connection service, if the device exposes one.
    pub wan: Option<WanConnectionUrls>,
    /// Control URL of the IPv6 firewall service, if the device exposes one.
    #[cfg(feature = "ipv6")]
    pub ipv6_firewall_control_url: Option<String>,
}

/// URLs for a WAN connection service.
pub struct WanConnectionUrls {
    /// Service type of the WAN connection service.
    pub service_type: String,
    /// SCPD URL of the WAN connection service.
    pub control_schema_url: String,
    /// Control URL of the WAN connection service.
    pub control_url: String,
}

/// Parse the available WAN connection and IPv6 firewall services.
pub fn parse_device_urls<R>(resp: R) -> Result<DeviceUrls, SearchError>
where
    R: io::Read,
{
    let root = parse_limited_xml(resp)?;
    let url_base = root
        .get_child("URLBase")
        .and_then(|child| child.get_text())
        .map(|text| text.into_owned());

    let wan = root.children.iter().find_map(|child| {
        let child = child.as_element()?;
        if child.name == "device" {
            parse_device(child)
        } else {
            None
        }
    });

    #[cfg(feature = "ipv6")]
    let ipv6_firewall_control_url = root.children.iter().find_map(|child| {
        let device = child.as_element()?;
        if device.name == "device" {
            find_firewall_control_url(device)
        } else {
            None
        }
    });

    #[cfg(feature = "ipv6")]
    if wan.is_none() && ipv6_firewall_control_url.is_none() {
        return Err(SearchError::InvalidResponse);
    }
    #[cfg(not(feature = "ipv6"))]
    if wan.is_none() {
        return Err(SearchError::InvalidResponse);
    }

    Ok(DeviceUrls {
        url_base,
        wan: wan.map(|(service_type, control_schema_url, control_url)| WanConnectionUrls {
            service_type,
            control_schema_url,
            control_url,
        }),
        #[cfg(feature = "ipv6")]
        ipv6_firewall_control_url,
    })
}

/// Find the control URL of the `WANIPv6FirewallControl:1` service in a device description.
#[cfg(all(test, feature = "ipv6"))]
pub fn parse_firewall_control_url<R>(resp: R) -> Option<String>
where
    R: io::Read,
{
    let root = parse_limited_xml(resp).ok()?;
    root.children.iter().find_map(|child| {
        let device = child.as_element()?;
        if device.name == "device" {
            find_firewall_control_url(device)
        } else {
            None
        }
    })
}

#[cfg(feature = "ipv6")]
fn find_firewall_control_url(device: &Element) -> Option<String> {
    let mut pending = vec![device];
    while let Some(device) = pending.pop() {
        if let Some(service_list) = device.get_child("serviceList") {
            for service in service_list.children.iter().filter_map(|child| child.as_element()) {
                if service.name == "service"
                    && service
                        .get_child("serviceType")
                        .and_then(|child| child.get_text())
                        .as_deref()
                        == Some("urn:schemas-upnp-org:service:WANIPv6FirewallControl:1")
                {
                    if let Some(url) = service
                        .get_child("controlURL")
                        .and_then(|child| child.get_text())
                        .filter(|url| !url.is_empty())
                    {
                        return Some(url.into_owned());
                    }
                }
            }
        }
        push_child_devices(device, &mut pending);
    }
    None
}

fn parse_device(device: &Element) -> Option<(String, String, String)> {
    let mut pending = vec![device];
    while let Some(device) = pending.pop() {
        if let Some(service_list) = device.get_child("serviceList") {
            if let Some(service) = service_list
                .children
                .iter()
                .filter_map(|child| child.as_element())
                .filter(|child| child.name == "service")
                .find_map(parse_service)
            {
                return Some(service);
            }
        }
        push_child_devices(device, &mut pending);
    }
    None
}

fn push_child_devices<'a>(device: &'a Element, pending: &mut Vec<&'a Element>) {
    if let Some(device_list) = device.get_child("deviceList") {
        pending.extend(device_list.children.iter().rev().filter_map(|child| {
            let child = child.as_element()?;
            (child.name == "device").then_some(child)
        }));
    }
}

fn parse_service(service: &Element) -> Option<(String, String, String)> {
    let service_type = service.get_child("serviceType")?;
    let service_type = service_type
        .get_text()
        .map(|s| s.into_owned())
        .unwrap_or_else(|| "".into());
    if [
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
    ]
    .contains(&service_type.as_str())
    {
        let scpd_url = service.get_child("SCPDURL");
        let control_url = service.get_child("controlURL");
        if let (Some(scpd_url), Some(control_url)) = (scpd_url, control_url) {
            Some((
                service_type,
                scpd_url.get_text().map(|s| s.into_owned()).unwrap_or_else(|| "".into()),
                control_url
                    .get_text()
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|| "".into()),
            ))
        } else {
            None
        }
    } else {
        None
    }
}

pub fn parse_schemas<R>(resp: R) -> Result<HashMap<String, Vec<String>>, SearchError>
where
    R: io::Read,
{
    let root = parse_limited_xml(resp)?;

    let mut schema = root.children.iter().filter_map(|child| {
        let child = child.as_element()?;
        if child.name == "actionList" {
            parse_action_list(child)
        } else {
            None
        }
    });

    schema.next().ok_or(SearchError::InvalidResponse)
}

fn parse_action_list(action_list: &Element) -> Option<HashMap<String, Vec<String>>> {
    Some(
        action_list
            .children
            .iter()
            .filter_map(|child| {
                let child = child.as_element()?;
                if child.name == "action" {
                    parse_action(child)
                } else {
                    None
                }
            })
            .collect(),
    )
}

fn parse_action(action: &Element) -> Option<(String, Vec<String>)> {
    Some((
        action.get_child("name")?.get_text()?.into_owned(),
        parse_argument_list(action.get_child("argumentList")?)?,
    ))
}

fn parse_argument_list(argument_list: &Element) -> Option<Vec<String>> {
    Some(
        argument_list
            .children
            .iter()
            .filter_map(|child| {
                let child = child.as_element()?;
                if child.name == "argument" {
                    parse_argument(child)
                } else {
                    None
                }
            })
            .collect(),
    )
}

fn parse_argument(action: &Element) -> Option<String> {
    if action.get_child("direction")?.get_text()?.into_owned().as_str() == "in" {
        Some(action.get_child("name")?.get_text()?.into_owned())
    } else {
        None
    }
}

pub struct RequestReponse {
    text: String,
    xml: xmltree::Element,
}

pub type RequestResult = Result<RequestReponse, RequestError>;

pub fn parse_response(text: String, ok: &str) -> RequestResult {
    if text.len() > MAX_RESPONSE_BYTES || !xml_depth_ok(text.as_bytes()) {
        return Err(RequestError::InvalidResponse(text));
    }
    let mut xml = match xmltree::Element::parse(text.as_bytes()) {
        Ok(xml) => xml,
        Err(..) => return Err(RequestError::InvalidResponse(text)),
    };
    let body = match xml.get_mut_child("Body") {
        Some(body) => body,
        None => return Err(RequestError::InvalidResponse(text)),
    };
    if let Some(ok) = body.take_child(ok) {
        return Ok(RequestReponse { text, xml: ok });
    }
    let upnp_error = match body
        .get_child("Fault")
        .and_then(|e| e.get_child("detail"))
        .and_then(|e| e.get_child("UPnPError"))
    {
        Some(upnp_error) => upnp_error,
        None => return Err(RequestError::InvalidResponse(text)),
    };

    match (
        upnp_error.get_child("errorCode"),
        upnp_error.get_child("errorDescription"),
    ) {
        (Some(e), Some(d)) => match (e.get_text().as_ref(), d.get_text().as_ref()) {
            (Some(et), Some(dt)) => match et.parse::<u16>() {
                Ok(en) => Err(RequestError::ErrorCode(en, From::from(&dt[..]))),
                Err(..) => Err(RequestError::InvalidResponse(text)),
            },
            _ => Err(RequestError::InvalidResponse(text)),
        },
        _ => Err(RequestError::InvalidResponse(text)),
    }
}

pub fn parse_get_external_ip_response(result: RequestResult) -> Result<IpAddr, GetExternalIpError> {
    match result {
        Ok(resp) => match resp
            .xml
            .get_child("NewExternalIPAddress")
            .and_then(|e| e.get_text())
            .and_then(|t| t.parse::<IpAddr>().ok())
        {
            Some(ipv4_addr) => Ok(ipv4_addr),
            None => Err(GetExternalIpError::RequestError(RequestError::InvalidResponse(
                resp.text,
            ))),
        },
        Err(RequestError::ErrorCode(606, _)) => Err(GetExternalIpError::ActionNotAuthorized),
        Err(e) => Err(GetExternalIpError::RequestError(e)),
    }
}

pub fn parse_add_any_port_mapping_response(result: RequestResult) -> Result<u16, AddAnyPortError> {
    match result {
        Ok(resp) => {
            match resp
                .xml
                .get_child("NewReservedPort")
                .and_then(|e| e.get_text())
                .and_then(|t| t.parse::<u16>().ok())
            {
                Some(port) => Ok(port),
                None => Err(AddAnyPortError::RequestError(RequestError::InvalidResponse(resp.text))),
            }
        }
        Err(err) => Err(match err {
            RequestError::ErrorCode(605, _) => AddAnyPortError::DescriptionTooLong,
            RequestError::ErrorCode(606, _) => AddAnyPortError::ActionNotAuthorized,
            RequestError::ErrorCode(728, _) => AddAnyPortError::NoPortsAvailable,
            e => AddAnyPortError::RequestError(e),
        }),
    }
}

pub fn convert_add_random_port_mapping_error(error: RequestError) -> Option<AddAnyPortError> {
    match error {
        RequestError::ErrorCode(724, _) => None,
        RequestError::ErrorCode(605, _) => Some(AddAnyPortError::DescriptionTooLong),
        RequestError::ErrorCode(606, _) => Some(AddAnyPortError::ActionNotAuthorized),
        RequestError::ErrorCode(718, _) => Some(AddAnyPortError::NoPortsAvailable),
        RequestError::ErrorCode(725, _) => Some(AddAnyPortError::OnlyPermanentLeasesSupported),
        e => Some(AddAnyPortError::RequestError(e)),
    }
}

pub fn convert_add_same_port_mapping_error(error: RequestError) -> AddAnyPortError {
    match error {
        RequestError::ErrorCode(606, _) => AddAnyPortError::ActionNotAuthorized,
        RequestError::ErrorCode(718, _) => AddAnyPortError::ExternalPortInUse,
        RequestError::ErrorCode(725, _) => AddAnyPortError::OnlyPermanentLeasesSupported,
        e => AddAnyPortError::RequestError(e),
    }
}

pub fn convert_add_port_error(err: RequestError) -> AddPortError {
    match err {
        RequestError::ErrorCode(605, _) => AddPortError::DescriptionTooLong,
        RequestError::ErrorCode(606, _) => AddPortError::ActionNotAuthorized,
        RequestError::ErrorCode(718, _) => AddPortError::PortInUse,
        RequestError::ErrorCode(724, _) => AddPortError::SamePortValuesRequired,
        RequestError::ErrorCode(725, _) => AddPortError::OnlyPermanentLeasesSupported,
        e => AddPortError::RequestError(e),
    }
}

pub fn parse_delete_port_mapping_response(result: RequestResult) -> Result<(), RemovePortError> {
    match result {
        Ok(_) => Ok(()),
        Err(err) => Err(match err {
            RequestError::ErrorCode(606, _) => RemovePortError::ActionNotAuthorized,
            RequestError::ErrorCode(714, _) => RemovePortError::NoSuchPortMapping,
            e => RemovePortError::RequestError(e),
        }),
    }
}

/// One port mapping entry as returned by GetGenericPortMappingEntry
pub struct PortMappingEntry {
    /// The remote host for which the mapping is valid
    /// Can be an IP address or a host name
    pub remote_host: String,
    /// The external port of the mapping
    pub external_port: u16,
    /// The protocol of the mapping
    pub protocol: PortMappingProtocol,
    /// The internal (local) port
    pub internal_port: u16,
    /// The internal client of the port mapping
    /// Can be an IP address or a host name
    pub internal_client: String,
    /// A flag whether this port mapping is enabled
    pub enabled: bool,
    /// A description for this port mapping
    pub port_mapping_description: String,
    /// The lease duration of this port mapping in seconds
    pub lease_duration: u32,
}

pub fn parse_get_generic_port_mapping_entry(
    result: RequestResult,
) -> Result<PortMappingEntry, GetGenericPortMappingEntryError> {
    let response = result?;
    let xml = response.xml;
    let make_err = |msg: String| || GetGenericPortMappingEntryError::RequestError(RequestError::InvalidResponse(msg));
    let extract_field = |field: &str| xml.get_child(field).ok_or_else(make_err(format!("{field} is missing")));
    let remote_host = extract_field("NewRemoteHost")?
        .get_text()
        .map(|c| c.into_owned())
        .unwrap_or_else(|| "".into());
    let external_port = extract_field("NewExternalPort")?
        .get_text()
        .and_then(|t| t.parse::<u16>().ok())
        .ok_or_else(make_err("Field NewExternalPort is invalid".into()))?;
    let protocol = match extract_field("NewProtocol")?.get_text() {
        Some(std::borrow::Cow::Borrowed("UDP")) => PortMappingProtocol::UDP,
        Some(std::borrow::Cow::Borrowed("TCP")) => PortMappingProtocol::TCP,
        _ => {
            return Err(GetGenericPortMappingEntryError::RequestError(
                RequestError::InvalidResponse("Field NewProtocol is invalid".into()),
            ))
        }
    };
    let internal_port = extract_field("NewInternalPort")?
        .get_text()
        .and_then(|t| t.parse::<u16>().ok())
        .ok_or_else(make_err("Field NewInternalPort is invalid".into()))?;
    let internal_client = extract_field("NewInternalClient")?
        .get_text()
        .map(|c| c.into_owned())
        .ok_or_else(make_err("Field NewInternalClient is empty".into()))?;
    let enabled = match extract_field("NewEnabled")?
        .get_text()
        .and_then(|t| t.parse::<u16>().ok())
        .ok_or_else(make_err("Field Enabled is invalid".into()))?
    {
        0 => false,
        1 => true,
        _ => {
            return Err(GetGenericPortMappingEntryError::RequestError(
                RequestError::InvalidResponse("Field NewEnabled is invalid".into()),
            ))
        }
    };
    let port_mapping_description = extract_field("NewPortMappingDescription")?
        .get_text()
        .map(|c| c.into_owned())
        .unwrap_or_else(|| "".into());
    let lease_duration = extract_field("NewLeaseDuration")?
        .get_text()
        .and_then(|t| t.parse::<u32>().ok())
        .ok_or_else(make_err("Field NewLeaseDuration is invalid".into()))?;
    Ok(PortMappingEntry {
        remote_host,
        external_port,
        protocol,
        internal_port,
        internal_client,
        enabled,
        port_mapping_description,
        lease_duration,
    })
}

/// Status of the gateway's IPv6 firewall.
#[cfg(feature = "ipv6")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FirewallStatus {
    /// Whether the firewall is currently enabled on the gateway.
    pub firewall_enabled: bool,
    /// Whether inbound pinholes are currently allowed to be created.
    pub inbound_pinhole_allowed: bool,
}

#[cfg(feature = "ipv6")]
fn parse_upnp_bool(xml: &Element, field: &str) -> Option<bool> {
    match xml.get_child(field)?.get_text()?.as_ref() {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

#[cfg(feature = "ipv6")]
pub fn convert_pinhole_error(error: RequestError) -> crate::errors::PinholeError {
    use crate::errors::PinholeError;
    match error {
        RequestError::ErrorCode(606, _) => PinholeError::ActionNotAuthorized,
        RequestError::ErrorCode(701, _) => PinholeError::PinholeSpaceExhausted,
        RequestError::ErrorCode(702, _) => PinholeError::FirewallDisabled,
        RequestError::ErrorCode(703, _) => PinholeError::InboundPinholeNotAllowed,
        RequestError::ErrorCode(704, _) => PinholeError::NoSuchEntry,
        e => PinholeError::RequestError(e),
    }
}

#[cfg(feature = "ipv6")]
pub fn parse_add_pinhole_response(result: RequestResult) -> Result<u16, crate::errors::PinholeError> {
    match result {
        Ok(resp) => {
            let id = resp
                .xml
                .get_child("UniqueID")
                .and_then(|e| e.get_text())
                .and_then(|t| t.parse::<u16>().ok());
            match id {
                Some(id) => Ok(id),
                None => Err(crate::errors::PinholeError::RequestError(
                    RequestError::InvalidResponse(resp.text),
                )),
            }
        }
        Err(e) => Err(convert_pinhole_error(e)),
    }
}

#[cfg(feature = "ipv6")]
pub fn parse_pinhole_unit_response(result: RequestResult) -> Result<(), crate::errors::PinholeError> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(convert_pinhole_error(e)),
    }
}

#[cfg(feature = "ipv6")]
pub fn parse_firewall_status_response(result: RequestResult) -> Result<FirewallStatus, crate::errors::PinholeError> {
    let resp = result.map_err(convert_pinhole_error)?;
    let firewall_enabled = parse_upnp_bool(&resp.xml, "FirewallEnabled");
    let inbound_pinhole_allowed = parse_upnp_bool(&resp.xml, "InboundPinholeAllowed");
    match (firewall_enabled, inbound_pinhole_allowed) {
        (Some(firewall_enabled), Some(inbound_pinhole_allowed)) => Ok(FirewallStatus {
            firewall_enabled,
            inbound_pinhole_allowed,
        }),
        _ => Err(crate::errors::PinholeError::RequestError(
            RequestError::InvalidResponse(resp.text),
        )),
    }
}

#[test]
fn test_parse_search_result_case_insensitivity() {
    assert!(parse_search_result("location:http://0.0.0.0:0/control_url").is_ok());
    assert!(parse_search_result("LOCATION:http://0.0.0.0:0/control_url").is_ok());
}

#[test]
fn test_parse_search_result_ok() {
    let result = parse_search_result("location:http://0.0.0.0:0/control_url").unwrap();
    assert_eq!(result.0.ip(), IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(result.0.port(), 0);
    assert_eq!(&result.1[..], "/control_url");
}

#[test]
fn test_parse_search_result_ipv6() {
    let (addr, path) = parse_search_result("location:http://[2001:db8::1]:5000/desc.xml").unwrap();
    assert_eq!(addr.ip(), IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(addr.port(), 5000);
    assert_eq!(&path[..], "/desc.xml");
}

#[test]
fn test_parse_search_result_fail() {
    assert!(parse_search_result("content-type:http://0.0.0.0:0/control_url").is_err());
}

#[test]
fn test_parse_device1() {
    let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
   <specVersion>
      <major>1</major>
      <minor>0</minor>
   </specVersion>
   <device>
      <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
      <friendlyName></friendlyName>
      <manufacturer></manufacturer>
      <manufacturerURL></manufacturerURL>
      <modelDescription></modelDescription>
      <modelName></modelName>
      <modelNumber>1</modelNumber>
      <serialNumber>00000000</serialNumber>
      <UDN></UDN>
      <serviceList>
         <service>
            <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:Layer3Forwarding1</serviceId>
            <controlURL>/ctl/L3F</controlURL>
            <eventSubURL>/evt/L3F</eventSubURL>
            <SCPDURL>/L3F.xml</SCPDURL>
         </service>
      </serviceList>
      <deviceList>
         <device>
            <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
            <friendlyName>WANDevice</friendlyName>
            <manufacturer>MiniUPnP</manufacturer>
            <manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
            <modelDescription>WAN Device</modelDescription>
            <modelName>WAN Device</modelName>
            <modelNumber>20180615</modelNumber>
            <modelURL>http://miniupnp.free.fr/</modelURL>
            <serialNumber>00000000</serialNumber>
            <UDN>uuid:804e2e56-7bfe-4733-bae0-04bf6d569692</UDN>
            <UPC>MINIUPNPD</UPC>
            <serviceList>
               <service>
                  <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
                  <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
                  <controlURL>/ctl/CmnIfCfg</controlURL>
                  <eventSubURL>/evt/CmnIfCfg</eventSubURL>
                  <SCPDURL>/WANCfg.xml</SCPDURL>
               </service>
            </serviceList>
            <deviceList>
               <device>
                  <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                  <friendlyName>WANConnectionDevice</friendlyName>
                  <manufacturer>MiniUPnP</manufacturer>
                  <manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
                  <modelDescription>MiniUPnP daemon</modelDescription>
                  <modelName>MiniUPnPd</modelName>
                  <modelNumber>20180615</modelNumber>
                  <modelURL>http://miniupnp.free.fr/</modelURL>
                  <serialNumber>00000000</serialNumber>
                  <UDN>uuid:804e2e56-7bfe-4733-bae0-04bf6d569692</UDN>
                  <UPC>MINIUPNPD</UPC>
                  <serviceList>
                     <service>
                        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                        <controlURL>/ctl/IPConn</controlURL>
                        <eventSubURL>/evt/IPConn</eventSubURL>
                        <SCPDURL>/WANIPCn.xml</SCPDURL>
                     </service>
                  </serviceList>
               </device>
            </deviceList>
         </device>
      </deviceList>
      <presentationURL>http://192.168.0.1/</presentationURL>
   </device>
</root>"#;

    let (service_type, control_schema_url, control_url) = parse_control_urls(text.as_bytes()).unwrap();
    assert_eq!(service_type, "urn:schemas-upnp-org:service:WANIPConnection:1");
    assert_eq!(control_url, "/ctl/IPConn");
    assert_eq!(control_schema_url, "/WANIPCn.xml");
}

#[test]
fn test_parse_device2() {
    let text = r#"<?xml version="1.0" encoding="UTF-8"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0">
        <specVersion>
            <major>1</major>
            <minor>0</minor>
        </specVersion>
        <device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <friendlyName>FRITZ!Box 7430</friendlyName>
            <manufacturer>AVM Berlin</manufacturer>
            <manufacturerURL>http://www.avm.de</manufacturerURL>
            <modelDescription>FRITZ!Box 7430</modelDescription>
            <modelName>FRITZ!Box 7430</modelName>
            <modelNumber>avm</modelNumber>
            <modelURL>http://www.avm.de</modelURL>
            <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
            <iconList>
                <icon>
                    <mimetype>image/gif</mimetype>
                    <width>118</width>
                    <height>119</height>
                    <depth>8</depth>
                    <url>/ligd.gif</url>
                </icon>
            </iconList>
            <serviceList>
                <service>
                    <serviceType>urn:schemas-any-com:service:Any:1</serviceType>
                    <serviceId>urn:any-com:serviceId:any1</serviceId>
                    <controlURL>/igdupnp/control/any</controlURL>
                    <eventSubURL>/igdupnp/control/any</eventSubURL>
                    <SCPDURL>/any.xml</SCPDURL>
                </service>
            </serviceList>
            <deviceList>
                <device>
                    <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
                    <friendlyName>WANDevice - FRITZ!Box 7430</friendlyName>
                    <manufacturer>AVM Berlin</manufacturer>
                    <manufacturerURL>www.avm.de</manufacturerURL>
                    <modelDescription>WANDevice - FRITZ!Box 7430</modelDescription>
                    <modelName>WANDevice - FRITZ!Box 7430</modelName>
                    <modelNumber>avm</modelNumber>
                    <modelURL>www.avm.de</modelURL>
                    <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
                    <UPC>AVM IGD</UPC>
                    <serviceList>
                        <service>
                            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
                            <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
                            <controlURL>/igdupnp/control/WANCommonIFC1</controlURL>
                            <eventSubURL>/igdupnp/control/WANCommonIFC1</eventSubURL>
                            <SCPDURL>/igdicfgSCPD.xml</SCPDURL>
                        </service>
                    </serviceList>
                    <deviceList>
                        <device>
                            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                            <friendlyName>WANConnectionDevice - FRITZ!Box 7430</friendlyName>
                            <manufacturer>AVM Berlin</manufacturer>
                            <manufacturerURL>www.avm.de</manufacturerURL>
                            <modelDescription>WANConnectionDevice - FRITZ!Box 7430</modelDescription>
                            <modelName>WANConnectionDevice - FRITZ!Box 7430</modelName>
                            <modelNumber>avm</modelNumber>
                            <modelURL>www.avm.de</modelURL>
                            <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
                            <UPC>AVM IGD</UPC>
                            <serviceList>
                                <service>
                                    <serviceType>urn:schemas-upnp-org:service:WANDSLLinkConfig:1</serviceType>
                                    <serviceId>urn:upnp-org:serviceId:WANDSLLinkC1</serviceId>
                                    <controlURL>/igdupnp/control/WANDSLLinkC1</controlURL>
                                    <eventSubURL>/igdupnp/control/WANDSLLinkC1</eventSubURL>
                                    <SCPDURL>/igddslSCPD.xml</SCPDURL>
                                </service>
                                <service>
                                    <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                                    <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                                    <controlURL>/igdupnp/control/WANIPConn1</controlURL>
                                    <eventSubURL>/igdupnp/control/WANIPConn1</eventSubURL>
                                    <SCPDURL>/igdconnSCPD.xml</SCPDURL>
                                </service>
                                <service>
                                    <serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType>
                                    <serviceId>urn:upnp-org:serviceId:WANIPv6Firewall1</serviceId>
                                    <controlURL>/igd2upnp/control/WANIPv6Firewall1</controlURL>
                                    <eventSubURL>/igd2upnp/control/WANIPv6Firewall1</eventSubURL>
                                    <SCPDURL>/igd2ipv6fwcSCPD.xml</SCPDURL>
                                </service>
                            </serviceList>
                        </device>
                    </deviceList>
                </device>
            </deviceList>
            <presentationURL>http://fritz.box</presentationURL>
        </device>
    </root>
    "#;
    let result = parse_control_urls(text.as_bytes());
    assert!(result.is_ok());
    let (service_type, control_schema_url, control_url) = result.unwrap();
    assert_eq!(service_type, "urn:schemas-upnp-org:service:WANIPConnection:1");
    assert_eq!(control_url, "/igdupnp/control/WANIPConn1");
    assert_eq!(control_schema_url, "/igdconnSCPD.xml");
}

#[test]
fn test_parse_device3() {
    let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion>
    <major>1</major>
    <minor>0</minor>
</specVersion>
<device xmlns="urn:schemas-upnp-org:device-1-0">
   <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
   <friendlyName></friendlyName>
   <manufacturer></manufacturer>
   <manufacturerURL></manufacturerURL>
   <modelDescription></modelDescription>
   <modelName></modelName>
   <modelNumber></modelNumber>
   <serialNumber></serialNumber>
   <presentationURL>http://192.168.1.1</presentationURL>
   <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
   <UPC>999999999001</UPC>
   <iconList>
      <icon>
         <mimetype>image/png</mimetype>
         <width>16</width>
         <height>16</height>
         <depth>8</depth>
         <url>/ligd.png</url>
      </icon>
   </iconList>
   <deviceList>
      <device>
         <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
         <friendlyName></friendlyName>
         <manufacturer></manufacturer>
         <manufacturerURL></manufacturerURL>
         <modelDescription></modelDescription>
         <modelName></modelName>
         <modelNumber></modelNumber>
         <modelURL></modelURL>
         <serialNumber></serialNumber>
         <presentationURL>http://192.168.1.254</presentationURL>
         <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
         <UPC>999999999001</UPC>
         <serviceList>
            <service>
               <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
               <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
               <controlURL>/upnp/control/WANCommonIFC1</controlURL>
               <eventSubURL>/upnp/control/WANCommonIFC1</eventSubURL>
               <SCPDURL>/332b484d/wancomicfgSCPD.xml</SCPDURL>
            </service>
         </serviceList>
         <deviceList>
            <device>
               <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
               <friendlyName></friendlyName>
               <manufacturer></manufacturer>
               <manufacturerURL></manufacturerURL>
               <modelDescription></modelDescription>
               <modelName></modelName>
               <modelNumber></modelNumber>
               <modelURL></modelURL>
               <serialNumber></serialNumber>
               <presentationURL>http://192.168.1.254</presentationURL>
               <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
               <UPC>999999999001</UPC>
               <serviceList>
                  <service>
                     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                     <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                     <controlURL>/upnp/control/WANIPConn1</controlURL>
                     <eventSubURL>/upnp/control/WANIPConn1</eventSubURL>
                     <SCPDURL>/332b484d/wanipconnSCPD.xml</SCPDURL>
                  </service>
               </serviceList>
            </device>
         </deviceList>
      </device>
   </deviceList>
</device>
</root>"#;

    let (service_type, control_schema_url, control_url) = parse_control_urls(text.as_bytes()).unwrap();
    assert_eq!(service_type, "urn:schemas-upnp-org:service:WANIPConnection:1");
    assert_eq!(control_url, "/upnp/control/WANIPConn1");
    assert_eq!(control_schema_url, "/332b484d/wanipconnSCPD.xml");
}

#[test]
fn test_parse_device_pppconnection() {
    // A DSL/PPP gateway that only exposes WANPPPConnection:1 (not WANIPConnection).
    let text = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
   <device>
      <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
      <deviceList>
         <device>
            <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
            <deviceList>
               <device>
                  <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                  <serviceList>
                     <service>
                        <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
                        <serviceId>urn:upnp-org:serviceId:WANPPPConn1</serviceId>
                        <controlURL>/ctl/PPPConn</controlURL>
                        <eventSubURL>/evt/PPPConn</eventSubURL>
                        <SCPDURL>/WANPPPCn.xml</SCPDURL>
                     </service>
                  </serviceList>
               </device>
            </deviceList>
         </device>
      </deviceList>
   </device>
</root>"#;

    let (service_type, control_schema_url, control_url) = parse_control_urls(text.as_bytes()).unwrap();
    assert_eq!(service_type, "urn:schemas-upnp-org:service:WANPPPConnection:1");
    assert_eq!(control_url, "/ctl/PPPConn");
    assert_eq!(control_schema_url, "/WANPPPCn.xml");
}

#[cfg(feature = "ipv6")]
#[test]
fn test_parse_firewall_control_url() {
    let text = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <controlURL>/ctl/IPConn</controlURL>
            <SCPDURL>/WANIPCn.xml</SCPDURL>
          </service>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType>
            <controlURL>/ctl/IPv6FwCtrl</controlURL>
            <SCPDURL>/IPv6FwCtrl.xml</SCPDURL>
          </service>
        </serviceList>
      </device>
    </deviceList>
  </device>
</root>"#;
    assert_eq!(
        parse_firewall_control_url(text.as_bytes()),
        Some("/ctl/IPv6FwCtrl".to_string())
    );
}

#[cfg(feature = "ipv6")]
#[test]
fn test_parse_firewall_control_url_absent() {
    let text = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
      </service>
    </serviceList>
  </device>
</root>"#;
    assert_eq!(parse_firewall_control_url(text.as_bytes()), None);
}

#[cfg(feature = "ipv6")]
#[test]
fn test_parse_firewall_control_url_empty_is_absent() {
    // A firewall service that is present but has an empty controlURL must be treated as absent.
    let text = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType>
        <controlURL></controlURL>
      </service>
    </serviceList>
  </device>
</root>"#;
    assert_eq!(parse_firewall_control_url(text.as_bytes()), None);
}

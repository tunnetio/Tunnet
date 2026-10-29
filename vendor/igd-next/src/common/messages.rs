use crate::PortMappingProtocol;
use std::net::{IpAddr, SocketAddr};

// SSDP targets used during discovery.
const ST_LIST: &[&str] = &[
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    #[cfg(feature = "ipv6")]
    "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
];

/// Build an SSDP request for one target using the chosen multicast address.
fn search_request(host: &SocketAddr, target: &str) -> String {
    let host = match host.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", host.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", host.port()),
    };
    format!("M-SEARCH * HTTP/1.1\r\nHost:{host}\r\nST:{target}\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n")
}

pub fn search_requests(host: &SocketAddr) -> Vec<String> {
    ST_LIST.iter().map(|target| search_request(host, target)).collect()
}

// SOAP action names.
pub const GET_EXTERNAL_IP_ACTION: &str = "GetExternalIPAddress";

pub const ADD_ANY_PORT_MAPPING_ACTION: &str = "AddAnyPortMapping";

pub const ADD_PORT_MAPPING_ACTION: &str = "AddPortMapping";

pub const DELETE_PORT_MAPPING_ACTION: &str = "DeletePortMapping";

pub const GET_GENERIC_PORT_MAPPING_ENTRY_ACTION: &str = "GetGenericPortMappingEntry";

/// Build the quoted `SOAPAction` header value (`"<service_type>#<action>"`) for a request.
pub fn soap_action(service_type: &str, action: &str) -> String {
    format!("\"{service_type}#{action}\"")
}

const MESSAGE_HEAD: &str = r#"<?xml version="1.0"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>"#;

const MESSAGE_TAIL: &str = r#"</s:Body>
</s:Envelope>"#;

fn format_message(body: String) -> String {
    format!("{MESSAGE_HEAD}{body}{MESSAGE_TAIL}")
}

/// Escape a string for inclusion in XML text/attribute content, so a user-supplied value
/// cannot produce malformed XML or inject elements into the SOAP request body.
fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn format_get_external_ip_message(service_type: &str) -> String {
    format_message(format!(
        r#"<m:GetExternalIPAddress xmlns:m="{service_type}">
        </m:GetExternalIPAddress>"#
    ))
}

pub fn format_add_any_port_mapping_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
    local_addr: SocketAddr,
    lease_duration: u32,
    description: &str,
) -> String {
    let args = schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewEnabled" => 1.to_string(),
                "NewExternalPort" => external_port.to_string(),
                "NewInternalClient" => local_addr.ip().to_string(),
                "NewInternalPort" => local_addr.port().to_string(),
                "NewLeaseDuration" => lease_duration.to_string(),
                "NewPortMappingDescription" => description.to_string(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => "".to_string(),
                unknown => {
                    log::warn!("Unknown argument: {}", unknown);
                    return None;
                }
            };
            Some(format!("<{argument}>{}</{argument}>", xml_escape(&value)))
        })
        .collect::<Vec<_>>()
        .join("\n");

    format_message(format!(
        r#"<u:AddAnyPortMapping xmlns:u="{service_type}">
        {args}
        </u:AddAnyPortMapping>"#,
    ))
}

pub fn format_add_port_mapping_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
    local_addr: SocketAddr,
    lease_duration: u32,
    description: &str,
) -> String {
    let args = schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewEnabled" => 1.to_string(),
                "NewExternalPort" => external_port.to_string(),
                "NewInternalClient" => local_addr.ip().to_string(),
                "NewInternalPort" => local_addr.port().to_string(),
                "NewLeaseDuration" => lease_duration.to_string(),
                "NewPortMappingDescription" => description.to_string(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => "".to_string(),
                unknown => {
                    log::warn!("Unknown argument: {}", unknown);
                    return None;
                }
            };
            Some(format!("<{argument}>{}</{argument}>", xml_escape(&value)))
        })
        .collect::<Vec<_>>()
        .join("\n");

    format_message(format!(
        r#"<u:AddPortMapping xmlns:u="{service_type}">
        {args}
        </u:AddPortMapping>"#
    ))
}

pub fn format_delete_port_message(
    service_type: &str,
    schema: &[String],
    protocol: PortMappingProtocol,
    external_port: u16,
) -> String {
    let args = schema
        .iter()
        .filter_map(|argument| {
            let value = match argument.as_str() {
                "NewExternalPort" => external_port.to_string(),
                "NewProtocol" => protocol.to_string(),
                "NewRemoteHost" => "".to_string(),
                unknown => {
                    log::warn!("Unknown argument: {}", unknown);
                    return None;
                }
            };
            Some(format!("<{argument}>{}</{argument}>", xml_escape(&value)))
        })
        .collect::<Vec<_>>()
        .join("\n");

    format_message(format!(
        r#"<u:DeletePortMapping xmlns:u="{service_type}">
        {args}
        </u:DeletePortMapping>"#
    ))
}

pub fn formate_get_generic_port_mapping_entry_message(service_type: &str, port_mapping_index: u32) -> String {
    format_message(format!(
        r#"<u:GetGenericPortMappingEntry xmlns:u="{service_type}">
        <NewPortMappingIndex>{port_mapping_index}</NewPortMappingIndex>
        </u:GetGenericPortMappingEntry>"#
    ))
}

// IPv6 firewall pinhole messages.

/// Service type of the IGD:2 IPv6 firewall control service.
#[cfg(feature = "ipv6")]
pub const WAN_IPV6_FIREWALL_CONTROL: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

#[cfg(feature = "ipv6")]
pub const ADD_PINHOLE_ACTION: &str = "AddPinhole";

#[cfg(feature = "ipv6")]
pub const UPDATE_PINHOLE_ACTION: &str = "UpdatePinhole";

#[cfg(feature = "ipv6")]
pub const DELETE_PINHOLE_ACTION: &str = "DeletePinhole";

#[cfg(feature = "ipv6")]
pub const GET_FIREWALL_STATUS_ACTION: &str = "GetFirewallStatus";

/// IANA protocol number for a port-mapping protocol, as required by `AddPinhole`
#[cfg(feature = "ipv6")]
fn protocol_number(protocol: PortMappingProtocol) -> u16 {
    match protocol {
        PortMappingProtocol::TCP => 6,
        PortMappingProtocol::UDP => 17,
    }
}

#[cfg(feature = "ipv6")]
pub fn format_add_pinhole_message(
    remote_host: &str,
    remote_port: u16,
    internal_client: std::net::Ipv6Addr,
    internal_port: u16,
    protocol: PortMappingProtocol,
    lease_time: u32,
) -> String {
    let service = WAN_IPV6_FIREWALL_CONTROL;
    let remote_host = xml_escape(remote_host);
    let internal_client = xml_escape(&internal_client.to_string());
    let protocol = protocol_number(protocol);
    format_message(format!(
        r#"<u:AddPinhole xmlns:u="{service}">
<RemoteHost>{remote_host}</RemoteHost>
<RemotePort>{remote_port}</RemotePort>
<InternalClient>{internal_client}</InternalClient>
<InternalPort>{internal_port}</InternalPort>
<Protocol>{protocol}</Protocol>
<LeaseTime>{lease_time}</LeaseTime>
</u:AddPinhole>"#
    ))
}

#[cfg(feature = "ipv6")]
pub fn format_update_pinhole_message(unique_id: u16, new_lease_time: u32) -> String {
    let service = WAN_IPV6_FIREWALL_CONTROL;
    format_message(format!(
        r#"<u:UpdatePinhole xmlns:u="{service}">
<UniqueID>{unique_id}</UniqueID>
<NewLeaseTime>{new_lease_time}</NewLeaseTime>
</u:UpdatePinhole>"#
    ))
}

#[cfg(feature = "ipv6")]
pub fn format_delete_pinhole_message(unique_id: u16) -> String {
    let service = WAN_IPV6_FIREWALL_CONTROL;
    format_message(format!(
        r#"<u:DeletePinhole xmlns:u="{service}">
<UniqueID>{unique_id}</UniqueID>
</u:DeletePinhole>"#
    ))
}

#[cfg(feature = "ipv6")]
pub fn format_get_firewall_status_message() -> String {
    let service = WAN_IPV6_FIREWALL_CONTROL;
    format_message(format!(
        r#"<u:GetFirewallStatus xmlns:u="{service}">
</u:GetFirewallStatus>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_request_host_ipv4() {
        let req = search_request(
            &"239.255.255.250:1900".parse().unwrap(),
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        );
        assert!(req.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(req.contains("Host:239.255.255.250:1900\r\n"));
    }

    #[test]
    fn search_request_host_ipv6_brackets_and_strips_scope() {
        let req = search_request(
            &"[ff02::c%3]:1900".parse().unwrap(),
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        );
        // bracketed for IPv6, and the zone (scope) id is not included in the HOST header
        assert!(req.contains("Host:[ff02::c]:1900\r\n"));
        assert!(!req.contains("%3"));
    }

    const PPP: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

    #[test]
    fn soap_action_uses_service_type() {
        assert_eq!(
            soap_action(PPP, "AddPortMapping"),
            "\"urn:schemas-upnp-org:service:WANPPPConnection:1#AddPortMapping\""
        );
    }

    #[test]
    fn message_body_uses_service_type() {
        let body = format_add_port_mapping_message(
            PPP,
            &["NewProtocol".to_string(), "NewExternalPort".to_string()],
            PortMappingProtocol::TCP,
            12345,
            "192.168.1.5:80".parse().unwrap(),
            0,
            "test",
        );
        assert!(body.contains(r#"xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1""#));
        assert!(body.contains("<NewProtocol>TCP</NewProtocol>"));
        assert!(body.contains("<NewExternalPort>12345</NewExternalPort>"));
    }

    #[test]
    fn xml_escape_escapes_special_characters() {
        assert_eq!(
            xml_escape("a & b < c > d \" e ' f"),
            "a &amp; b &lt; c &gt; d &quot; e &apos; f"
        );
        assert_eq!(xml_escape("plain text 123"), "plain text 123");
    }

    #[test]
    fn description_is_xml_escaped_in_message_body() {
        let body = format_add_port_mapping_message(
            PPP,
            &["NewPortMappingDescription".to_string()],
            PortMappingProtocol::TCP,
            12345,
            "192.168.1.5:80".parse().unwrap(),
            0,
            "Bob & Alice </NewPortMappingDescription><evil>",
        );
        // The raw special characters must not appear unescaped in the body.
        assert!(body.contains("Bob &amp; Alice &lt;/NewPortMappingDescription&gt;&lt;evil&gt;"));
        assert!(!body.contains("<evil>"));
        assert!(!body.contains("Bob & Alice"));
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn add_pinhole_message_uses_firewall_namespace_and_protocol_number() {
        let body = format_add_pinhole_message(
            "",
            0,
            "2001:db8::1".parse().unwrap(),
            8080,
            PortMappingProtocol::TCP,
            3600,
        );
        assert!(body.contains(r#"xmlns:u="urn:schemas-upnp-org:service:WANIPv6FirewallControl:1""#));
        assert!(body.contains("<u:AddPinhole"));
        assert!(body.contains("<InternalClient>2001:db8::1</InternalClient>"));
        assert!(body.contains("<InternalPort>8080</InternalPort>"));
        assert!(body.contains("<Protocol>6</Protocol>")); // TCP = IANA protocol 6
        assert!(body.contains("<LeaseTime>3600</LeaseTime>"));
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn udp_pinhole_uses_protocol_number_17() {
        let body = format_add_pinhole_message("", 0, "fe80::1".parse().unwrap(), 53, PortMappingProtocol::UDP, 600);
        assert!(body.contains("<Protocol>17</Protocol>")); // UDP = IANA protocol 17
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn update_and_delete_pinhole_messages() {
        let update = format_update_pinhole_message(42, 7200);
        assert!(update.contains("<u:UpdatePinhole"));
        assert!(update.contains("<UniqueID>42</UniqueID>"));
        assert!(update.contains("<NewLeaseTime>7200</NewLeaseTime>"));

        let delete = format_delete_pinhole_message(42);
        assert!(delete.contains("<u:DeletePinhole"));
        assert!(delete.contains("<UniqueID>42</UniqueID>"));
    }
}

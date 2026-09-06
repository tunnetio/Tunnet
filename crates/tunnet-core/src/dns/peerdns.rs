//! Authoritative PeerDNS answers for mesh names and hostname routes.

use std::net::Ipv4Addr;

use hickory_proto::op::{DEFAULT_MAX_PAYLOAD_LEN, Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, NS, PTR, SOA, TXT},
};

use crate::routing::RoutingTable;

pub const TTL_SECS: u32 = 30;

pub fn name_in_suffix(qname: &Name, suffix: &str) -> bool {
    let Ok(zone) = Name::from_utf8(suffix) else {
        return false;
    };
    zone.zone_of(qname) || zone == *qname
}

pub fn owned_forward_name(
    qname: &Name,
    name_str: &str,
    suffix: &str,
    routes: &RoutingTable,
) -> bool {
    name_in_suffix(qname, suffix)
        || routes
            .lookup_hostname_route(name_str.trim_end_matches('.'))
            .is_some()
}

pub fn parse_in_addr_arpa(qname: &Name) -> Option<Ipv4Addr> {
    let s = qname.to_string().trim_end_matches('.').to_ascii_lowercase();
    let rest = s.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u8 = parts[3].parse().ok()?;
    let b: u8 = parts[2].parse().ok()?;
    let c: u8 = parts[1].parse().ok()?;
    let d: u8 = parts[0].parse().ok()?;
    Some(Ipv4Addr::new(a, b, c, d))
}

pub fn echo_edns(query: &Message, response: &mut Message) {
    if let Some(req_edns) = &query.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(req_edns.max_payload().max(DEFAULT_MAX_PAYLOAD_LEN));
        edns.set_version(0);
        response.set_edns(edns);
    }
}

pub fn base_response(query: &Message, authoritative: bool) -> Message {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.authoritative = authoritative;
    response.metadata.recursion_available = true;
    response.queries = query.queries.clone();
    echo_edns(query, &mut response);
    response
}

pub fn answer_owned(
    query: &Message,
    qname: &Name,
    qtype: RecordType,
    name_str: &str,
    suffix: &str,
    routes: &RoutingTable,
) -> Message {
    let mut response = base_response(query, true);
    match qtype {
        RecordType::A => {
            if let Some(ip) = routes.resolve_dns_a(name_str) {
                response.add_answer(Record::from_rdata(qname.clone(), TTL_SECS, RData::A(A(ip))));
                response.metadata.response_code = ResponseCode::NoError;
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
        }
        RecordType::AAAA => {
            response.metadata.response_code = ResponseCode::NoError;
        }
        RecordType::TXT => {
            if let Some(key) = routes.resolve_dns_txt(name_str) {
                let txt = TXT::new(vec![format!("ssh-hostkey={key}")]);
                response.add_answer(Record::from_rdata(qname.clone(), TTL_SECS, RData::TXT(txt)));
                response.metadata.response_code = ResponseCode::NoError;
            } else if routes.resolve_dns_a(name_str).is_some() {
                response.metadata.response_code = ResponseCode::NoError;
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
        }
        RecordType::SOA => {
            if let Some(soa) = zone_soa(qname, suffix, routes) {
                response.add_answer(soa);
                response.metadata.response_code = ResponseCode::NoError;
            } else if routes.resolve_dns_a(name_str).is_some() {
                response.metadata.response_code = ResponseCode::NoError;
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
        }
        RecordType::NS => {
            if let Some(ns) = zone_ns(qname, suffix) {
                response.add_answer(ns);
                response.metadata.response_code = ResponseCode::NoError;
            } else if routes.resolve_dns_a(name_str).is_some() {
                response.metadata.response_code = ResponseCode::NoError;
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
        }
        _ => {
            if routes.resolve_dns_a(name_str).is_some() || name_in_suffix(qname, suffix) {
                if routes.resolve_dns_a(name_str).is_some() {
                    response.metadata.response_code = ResponseCode::NoError;
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            } else {
                response.metadata.response_code = ResponseCode::NoError;
            }
        }
    }
    response
}

pub fn answer_ptr(
    query: &Message,
    qname: &Name,
    ip: Ipv4Addr,
    suffix: &str,
    routes: &RoutingTable,
) -> Option<Message> {
    let mut response = base_response(query, true);
    if let Some(fqdn) = routes.resolve_dns_ptr(ip) {
        let ptr_name = Name::from_utf8(format!("{fqdn}."))
            .unwrap_or_else(|_| Name::from_utf8("invalid.").expect("literal"));
        response.add_answer(Record::from_rdata(
            qname.clone(),
            TTL_SECS,
            RData::PTR(PTR(ptr_name)),
        ));
        response.metadata.response_code = ResponseCode::NoError;
        return Some(response);
    }
    if ip == tunnet_common::LocalResolverEndpoint::default().ip {
        let ns = Name::from_utf8(format!("ns.{suffix}."))
            .unwrap_or_else(|_| Name::from_utf8("ns.tunnet.").expect("literal"));
        response.add_answer(Record::from_rdata(
            qname.clone(),
            TTL_SECS,
            RData::PTR(PTR(ns)),
        ));
        response.metadata.response_code = ResponseCode::NoError;
        return Some(response);
    }
    None
}

fn zone_soa(qname: &Name, suffix: &str, routes: &RoutingTable) -> Option<Record> {
    if !name_in_suffix(qname, suffix) {
        return None;
    }
    let mname = Name::from_utf8(format!("ns.{suffix}.")).ok()?;
    let rname = Name::from_utf8(format!("hostmaster.{suffix}.")).ok()?;
    let serial = routes.version().max(1) as u32;
    let soa = SOA::new(mname, rname, serial, 300, 60, 86400, TTL_SECS);
    Some(Record::from_rdata(qname.clone(), TTL_SECS, RData::SOA(soa)))
}

fn zone_ns(qname: &Name, suffix: &str) -> Option<Record> {
    if !name_in_suffix(qname, suffix) {
        return None;
    }
    let ns = Name::from_utf8(format!("ns.{suffix}.")).ok()?;
    Some(Record::from_rdata(
        qname.clone(),
        TTL_SECS,
        RData::NS(NS(ns)),
    ))
}

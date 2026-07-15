use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Added,
    Updated,
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub service_type: String,
    pub instance_name: String,
    pub fullname: String,
    pub origin_peer_ip: Ipv4Addr,
    pub origin_endpoint_id: String,
    pub lan_ip: Ipv4Addr,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
    pub ttl: u32,
    pub event_type: EventType,
}

#[derive(Debug, Clone)]
pub struct LocalService {
    pub service_type: String,
    pub instance_name: String,
    pub fullname: String,
    pub lan_ip: Ipv4Addr,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
    pub host: String,
}

impl LocalService {
    pub fn record(
        &self,
        origin_peer_ip: Ipv4Addr,
        origin_endpoint_id: &str,
        event_type: EventType,
        ttl: u32,
    ) -> ServiceRecord {
        ServiceRecord {
            service_type: self.service_type.clone(),
            instance_name: self.instance_name.clone(),
            fullname: self.fullname.clone(),
            origin_peer_ip,
            origin_endpoint_id: origin_endpoint_id.to_string(),
            lan_ip: self.lan_ip,
            port: self.port,
            txt_records: self.txt_records.clone(),
            ttl,
            event_type,
        }
    }
}

#[derive(Debug, Default)]
pub struct LocalServiceTable {
    by_fullname: HashMap<String, LocalService>,
}

impl LocalServiceTable {
    pub fn upsert(&mut self, svc: LocalService) -> Option<EventType> {
        let key = svc.fullname.clone();
        if let Some(prev) = self.by_fullname.get(&key) {
            if prev.port == svc.port
                && prev.lan_ip == svc.lan_ip
                && prev.txt_records == svc.txt_records
                && prev.service_type == svc.service_type
            {
                return None;
            }
            self.by_fullname.insert(key, svc);
            Some(EventType::Updated)
        } else {
            self.by_fullname.insert(key, svc);
            Some(EventType::Added)
        }
    }

    pub fn remove(&mut self, fullname: &str) -> Option<LocalService> {
        self.by_fullname.remove(fullname)
    }

    pub fn get(&self, fullname: &str) -> Option<&LocalService> {
        self.by_fullname.get(fullname)
    }

    pub fn iter(&self) -> impl Iterator<Item = &LocalService> {
        self.by_fullname.values()
    }
}

#[derive(Debug, Clone)]
struct RemoteEntry {
    record: ServiceRecord,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct RemoteServiceTable {
    by_fullname: HashMap<String, RemoteEntry>,
}

impl RemoteServiceTable {
    pub fn apply(&mut self, record: ServiceRecord) -> Option<EventType> {
        match record.event_type {
            EventType::Removed => {
                if self.by_fullname.remove(&record.fullname).is_some() {
                    Some(EventType::Removed)
                } else {
                    None
                }
            }
            EventType::Added | EventType::Updated => {
                let ttl = Duration::from_secs(u64::from(record.ttl.max(30)));
                let fullname = record.fullname.clone();
                let was = self.by_fullname.contains_key(&fullname);
                self.by_fullname.insert(
                    fullname,
                    RemoteEntry {
                        record,
                        expires_at: Instant::now() + ttl,
                    },
                );
                Some(if was {
                    EventType::Updated
                } else {
                    EventType::Added
                })
            }
        }
    }

    pub fn expire(&mut self) -> Vec<ServiceRecord> {
        let now = Instant::now();
        let expired: Vec<String> = self
            .by_fullname
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::new();
        for k in expired {
            if let Some(e) = self.by_fullname.remove(&k) {
                let mut r = e.record;
                r.event_type = EventType::Removed;
                out.push(r);
            }
        }
        out
    }

    pub fn get(&self, fullname: &str) -> Option<&ServiceRecord> {
        self.by_fullname.get(fullname).map(|e| &e.record)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ServiceRecord> {
        self.by_fullname.values().map(|e| &e.record)
    }
}

/// TunTun / CGNAT shared address space used for mesh IPs.
pub fn is_mesh_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

pub fn instance_name_from_fullname(fullname: &str, service_type: &str) -> String {
    let suffix = format!(".{service_type}");
    let trimmed = fullname
        .strip_suffix(&suffix)
        .or_else(|| fullname.strip_suffix(service_type))
        .unwrap_or(fullname);
    trimmed.trim_end_matches('.').to_string()
}

use std::collections::HashMap;
use std::net::Ipv4Addr;

use mdns_sd::{ServiceDaemon, ServiceInfo};
use parking_lot::Mutex;

use super::scanner::AdvertisedSet;
use super::types::{EventType, ServiceRecord};

struct Registered {
    fullname: String,
}

pub struct Responder {
    daemon: ServiceDaemon,
    advertised: AdvertisedSet,
    /// fullname -> registration
    active: Mutex<HashMap<String, Registered>>,
}

impl Responder {
    pub fn new(daemon: ServiceDaemon, advertised: AdvertisedSet) -> Self {
        Self {
            daemon,
            advertised,
            active: Mutex::new(HashMap::new()),
        }
    }

    pub fn apply(&self, record: &ServiceRecord) {
        match record.event_type {
            EventType::Removed => self.unregister(&record.fullname),
            EventType::Added | EventType::Updated => {
                self.unregister(&record.fullname);
                if let Err(e) = self.register(record) {
                    tracing::warn!(
                        fullname = %record.fullname,
                        ?e,
                        "failed to register remote mDNS service"
                    );
                }
            }
        }
    }

    fn register(&self, record: &ServiceRecord) -> anyhow::Result<()> {
        let host = mesh_host_name(record.origin_peer_ip);
        let props: Vec<(String, String)> = record
            .txt_records
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let prop_refs: Vec<(&str, &str)> = props
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let mut info = ServiceInfo::new(
            &record.service_type,
            &record.instance_name,
            &host,
            record.origin_peer_ip.to_string(),
            record.port,
            prop_refs.as_slice(),
        )
        .map_err(|e| anyhow::anyhow!("ServiceInfo: {e}"))?;
        info.set_requires_probe(false);

        let fullname = info.get_fullname().to_string();
        self.daemon
            .register(info)
            .map_err(|e| anyhow::anyhow!("register: {e}"))?;

        self.advertised.lock().insert(fullname.to_lowercase());
        self.active.lock().insert(
            record.fullname.to_lowercase(),
            Registered {
                fullname: fullname.clone(),
            },
        );
        tracing::info!(
            fullname = %fullname,
            mesh = %record.origin_peer_ip,
            port = record.port,
            "advertising remote mDNS service"
        );
        Ok(())
    }

    fn unregister(&self, fullname: &str) {
        let key = fullname.to_lowercase();
        let reg = self.active.lock().remove(&key);
        if let Some(reg) = reg {
            let _ = self.daemon.unregister(&reg.fullname);
            self.advertised.lock().remove(&reg.fullname.to_lowercase());
            tracing::info!(fullname = %reg.fullname, "unregistered remote mDNS service");
        }
    }
}

fn mesh_host_name(ip: Ipv4Addr) -> String {
    format!("tuntun-{}.local.", ip.to_string().replace('.', "-"))
}

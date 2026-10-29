use super::HickoryLookup;
use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::net::NetError;
use iroh::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
use n0_error::{AnyError, e};
use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
};

type LookupFuture<T> = Pin<Box<dyn Future<Output = Result<BoxIter<T>, DnsError>> + Send>>;

#[derive(Debug, Clone)]
pub struct IrohResolver(pub Arc<HickoryLookup>);

pub(super) fn error(error: NetError) -> DnsError {
    if error.is_nx_domain() {
        return e!(DnsError::NxDomain);
    }
    if matches!(error, NetError::Timeout) {
        return e!(DnsError::Timeout);
    }
    if matches!(error, NetError::NoConnections) {
        return e!(DnsError::NoResponse);
    }
    e!(DnsError::Resolve, AnyError::from_std(error))
}

impl IrohResolver {
    fn lookup<T: Send + 'static>(
        &self,
        host: String,
        kind: RecordType,
        convert: fn(&RData) -> Option<T>,
    ) -> LookupFuture<T> {
        let service = self.0.clone();
        Box::pin(async move {
            match service.records(host, kind).await {
                Ok(answer) => Ok(Box::new(
                    answer
                        .message()
                        .answers
                        .iter()
                        .filter_map(|record| convert(&record.data))
                        .collect::<Vec<_>>()
                        .into_iter(),
                ) as BoxIter<T>),
                Err(err) if super::upstream::is_nodata(&err) => {
                    Ok(Box::new(std::iter::empty()) as BoxIter<T>)
                }
                Err(err) => Err(error(err)),
            }
        })
    }
}

impl Resolver for IrohResolver {
    fn lookup_ipv4(&self, host: String) -> LookupFuture<Ipv4Addr> {
        self.lookup(host, RecordType::A, |data| match data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
    }
    fn lookup_ipv6(&self, host: String) -> LookupFuture<Ipv6Addr> {
        self.lookup(host, RecordType::AAAA, |data| match data {
            RData::AAAA(a) => Some(a.0),
            _ => None,
        })
    }
    fn lookup_txt(&self, host: String) -> LookupFuture<TxtRecordData> {
        self.lookup(host, RecordType::TXT, |data| match data {
            RData::TXT(txt) => Some(txt.txt_data.iter().cloned().collect()),
            _ => None,
        })
    }
    fn clear_cache(&self) {
        self.0.clear_cache();
    }
    fn reset(&self) -> Box<dyn Resolver> {
        self.0.reset();
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::NativeHickoryRuntimeProvider;
    use futures_util::StreamExt;
    use iroh::{
        Endpoint, RelayMode, SecretKey,
        address_lookup::{AddressLookup, AddressLookupBuilder, pkarr::PkarrResolver},
        endpoint::presets,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn published_dns_keeps_endpoint_http_authority_explicit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let external = Arc::new(
            HickoryLookup::with_runtime(
                &tunnet_common::DnsConfig::default(),
                NativeHickoryRuntimeProvider::new([None; 2], [None; 2]),
            )
            .unwrap(),
        );
        let endpoint = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .dns_resolver(iroh::dns::DnsResolver::custom(IrohResolver(external)))
            .relay_tcp_config([None; 2])
            .bind()
            .await
            .unwrap();
        let lookup = PkarrResolver::builder(
            format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
        )
        .into_address_lookup(&endpoint)
        .unwrap();
        let mut answers = lookup.resolve(SecretKey::generate().public()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), answers.next())
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        endpoint.close().await;
        assert!(
            Endpoint::builder(presets::Minimal)
                .relay_tcp_config([None; 2])
                .bind()
                .await
                .is_err()
        );
    }
}

use iroh::EndpointId;
use tunnet_common::policy::Direction;
use uuid::Uuid;

use super::ForwardingSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostureAuthorization {
    pub source: Direction,
}

impl PostureAuthorization {
    pub fn valid_until(
        self,
        snapshot: &ForwardingSnapshot,
        network: Uuid,
        peer: EndpointId,
    ) -> Option<jiff::Timestamp> {
        match self.source {
            Direction::Outbound
                if snapshot.managed == Some(network) && **snapshot.posture_ok.load() =>
            {
                snapshot.self_id.posture.valid_until()
            }
            Direction::Outbound => None,
            Direction::Inbound => snapshot.binding(network, peer)?.posture.valid_until(),
        }
    }

    pub fn allows(self, snapshot: &ForwardingSnapshot, network: Uuid, peer: EndpointId) -> bool {
        self.valid_until(snapshot, network, peer)
            .is_some_and(|deadline| jiff::Timestamp::now() < deadline)
    }
}

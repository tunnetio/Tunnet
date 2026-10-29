use bytes::{Bytes, BytesMut};

use super::{FRAME_OVERHEAD, frame, unframe};

pub(crate) enum PreparedDatagram {
    Ready(Bytes),
    Fragments(Vec<Bytes>),
    Feedback(Bytes),
    Drop,
}

pub(crate) fn prepare_datagram(packet: Bytes, maximum: usize) -> PreparedDatagram {
    let (network, ip) = unframe(&packet).expect("authorized tunnel frame");
    let mtu = maximum
        .saturating_sub(FRAME_OVERHEAD)
        .min(u16::MAX as usize) as u16;
    if packet.len() > maximum {
        if let Some(fragments) = tunnet_common::packet::fragment_ipv4(ip, mtu) {
            return PreparedDatagram::Fragments(
                fragments
                    .into_iter()
                    .map(|ip| frame(network, &ip))
                    .collect(),
            );
        }
        return tunnet_common::packet::synthesize_frag_needed(ip, mtu)
            .map_or(PreparedDatagram::Drop, PreparedDatagram::Feedback);
    }
    let syn = etherparse::Ipv4HeaderSlice::from_slice(ip)
        .ok()
        .filter(|ip| ip.protocol() == etherparse::IpNumber::TCP && !ip.is_fragmenting_payload())
        .and_then(|header| etherparse::TcpHeaderSlice::from_slice(&ip[header.slice().len()..]).ok())
        .is_some_and(|tcp| tcp.syn());
    if syn && let Some(mss) = mtu.checked_sub(40).filter(|mss| *mss != 0) {
        let mut packet = packet
            .try_into_mut()
            .unwrap_or_else(|packet| BytesMut::from(packet.as_ref()));
        tunnet_common::packet::clamp_tcp_mss(&mut packet[FRAME_OVERHEAD..], mss);
        return PreparedDatagram::Ready(packet.freeze());
    }
    PreparedDatagram::Ready(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    fn resizing_preserves_network_or_returns_exact_inner_mtu(#[case] df: bool) {
        let network = uuid::Uuid::new_v4();
        let mut ip = etherparse::Ipv4Header::new(
            1260,
            64,
            etherparse::IpNumber::UDP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        )
        .unwrap();
        ip.dont_fragment = df;
        let mut raw = Vec::new();
        etherparse::PacketBuilder::ip(etherparse::IpHeaders::Ipv4(ip, Default::default()))
            .udp(1234, 5678)
            .write(&mut raw, &[42; 1252])
            .unwrap();
        let framed = frame(network, &raw);
        assert!(
            matches!(prepare_datagram(framed.clone(), framed.len()), PreparedDatagram::Ready(packet) if packet == framed)
        );
        let maximum = 1162;
        match prepare_datagram(framed, maximum) {
            PreparedDatagram::Feedback(reply) if df => {
                let (_, rest) = etherparse::Ipv4Header::from_slice(&reply).unwrap();
                let (icmp, quoted) = etherparse::Icmpv4Header::from_slice(rest).unwrap();
                assert_eq!(
                    icmp.icmp_type,
                    etherparse::Icmpv4Type::DestinationUnreachable(
                        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded {
                            next_hop_mtu: (maximum - FRAME_OVERHEAD) as u16
                        }
                    )
                );
                assert_eq!(quoted, &raw[..28]);
                assert_eq!(icmp.checksum, icmp.icmp_type.calc_checksum(quoted));
            }
            PreparedDatagram::Fragments(fragments) if !df => {
                let mut payload = Vec::new();
                for fragment in fragments {
                    assert!(fragment.len() <= maximum);
                    let (tag, ip) = unframe(&fragment).unwrap();
                    assert_eq!(tag, network);
                    let (header, bytes) = etherparse::Ipv4Header::from_slice(ip).unwrap();
                    assert_eq!(header.header_checksum, header.calc_header_checksum());
                    payload.extend_from_slice(bytes);
                }
                assert_eq!(payload, &raw[20..]);
            }
            _ => panic!("incorrect MTU response"),
        }
    }

    #[test]
    fn syn_mss_uses_framed_budget_and_preserves_checksum() {
        let mut raw = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(1234, 443, 1, 4096)
            .syn()
            .options(&[etherparse::TcpOptionElement::MaximumSegmentSize(1460)])
            .unwrap()
            .write(&mut raw, &[])
            .unwrap();
        let PreparedDatagram::Ready(packet) =
            prepare_datagram(frame(uuid::Uuid::nil(), &raw), 1162)
        else {
            panic!("SYN must fit")
        };
        let (_, raw) = unframe(&packet).unwrap();
        let tcp = etherparse::TcpHeaderSlice::from_slice(&raw[20..]).unwrap();
        assert_eq!(
            tcp.options_iterator().next().unwrap().unwrap(),
            etherparse::TcpOptionElement::MaximumSegmentSize(1104)
        );
        assert_eq!(
            tcp.checksum(),
            tunnet_common::packet::tcp_ipv4_checksum_of(raw).unwrap()
        );
    }
}

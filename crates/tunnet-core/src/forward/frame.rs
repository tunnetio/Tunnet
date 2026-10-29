use bytes::Bytes;
use uuid::Uuid;

pub const FRAME_MARKER: [u8; 2] = [0x54, 0x4E];
pub const FRAME_OVERHEAD: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadMarker,
    BadNetwork,
}

impl FrameError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooShort => "frame_too_short",
            Self::BadMarker => "frame_bad_marker",
            Self::BadNetwork => "frame_bad_network",
        }
    }
}

pub fn frame(network: Uuid, ip: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(FRAME_OVERHEAD + ip.len());
    out.extend_from_slice(&FRAME_MARKER);
    out.extend_from_slice(network.as_bytes());
    out.extend_from_slice(ip);
    Bytes::from(out)
}

pub fn unframe(dg: &[u8]) -> Result<(Uuid, &[u8]), FrameError> {
    if dg.len() < FRAME_OVERHEAD {
        return Err(FrameError::TooShort);
    }
    if dg[0] != FRAME_MARKER[0] || dg[1] != FRAME_MARKER[1] {
        return Err(FrameError::BadMarker);
    }
    let network = Uuid::from_slice(&dg[2..FRAME_OVERHEAD]).map_err(|_| FrameError::BadNetwork)?;
    Ok((network, &dg[FRAME_OVERHEAD..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn frame_roundtrip() {
        let net = Uuid::from_u128(0x0102030405060708090a0b0c0d0e0f10);
        let ip = vec![0x45u8; 64];
        let framed = frame(net, &ip);
        assert_eq!(framed.len(), FRAME_OVERHEAD + 64);
        let (parsed_net, parsed_ip) = unframe(&framed).unwrap();
        assert_eq!(parsed_net, net);
        assert_eq!(parsed_ip, ip.as_slice());
    }

    #[rstest]
    #[case(vec![0x45u8; 10], FrameError::TooShort)]
    #[case(vec![0x45u8; 64], FrameError::BadMarker)]
    fn unframe_rejects_invalid(#[case] dg: Vec<u8>, #[case] err: FrameError) {
        assert_eq!(unframe(&dg), Err(err));
    }

    #[test]
    fn unframe_rejects_untagged_datagram() {
        let raw = vec![0x45u8; 64];
        assert_eq!(unframe(&raw), Err(FrameError::BadMarker));
    }

    #[test]
    fn unframe_rejects_short_marker_prefix() {
        assert_eq!(unframe(&[0x54, 0x4E]), Err(FrameError::TooShort));
    }
}

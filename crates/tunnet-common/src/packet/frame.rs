//! Tunnel /4: one explicitly network-bound IP packet per QUIC DATAGRAM.
use uuid::Uuid;
pub const KIND_SINGLE: u8 = 0x40;
pub const SINGLE_OVERHEAD: usize = 17;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Single { net: Uuid, payload: &'a [u8] },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    InvalidKind,
    InvalidLength,
}
impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DecodeError {}
pub fn decode_frame(data: &[u8]) -> Result<Frame<'_>, DecodeError> {
    if data.first() != Some(&KIND_SINGLE) {
        return Err(DecodeError::InvalidKind);
    }
    if data.len() <= SINGLE_OVERHEAD || data.len() > SINGLE_OVERHEAD + super::MAX_LOGICAL_LEN {
        return Err(DecodeError::InvalidLength);
    }
    Ok(Frame::Single {
        net: Uuid::from_bytes(data[1..17].try_into().expect("checked header")),
        payload: &data[17..],
    })
}
pub fn encode_single_prefix(out: &mut [u8], net: Uuid) -> usize {
    out[0] = KIND_SINGLE;
    out[1..17].copy_from_slice(net.as_bytes());
    SINGLE_OVERHEAD
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_binding_and_version() {
        let net = Uuid::new_v4();
        let mut bytes = vec![0; 37];
        encode_single_prefix(&mut bytes, net);
        assert_eq!(
            decode_frame(&bytes),
            Ok(Frame::Single {
                net,
                payload: &bytes[17..]
            })
        );
        for kind in [0x20, 0x30, 0x31, 0x41] {
            bytes[0] = kind;
            assert!(decode_frame(&bytes).is_err());
        }
        assert!(decode_frame(&[KIND_SINGLE; 17]).is_err());
    }
}

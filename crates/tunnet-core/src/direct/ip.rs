use uuid::Uuid;

pub fn network_id_from_topic(topic_hash_hex: &str) -> Uuid {
    let raw = hex::decode(topic_hash_hex).unwrap_or_else(|_| topic_hash_hex.as_bytes().to_vec());
    let hash = blake3::hash(&raw);
    let b = hash.as_bytes();
    Uuid::from_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::canonical_hex("aa".repeat(32))]
    #[case::raw_fallback("not-hex-topic".into())]
    fn network_id_is_stable(#[case] topic: String) {
        assert_eq!(network_id_from_topic(&topic), network_id_from_topic(&topic));
    }
}

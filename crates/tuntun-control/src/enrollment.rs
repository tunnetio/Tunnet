pub fn hash_token(token: &str) -> String {
    hex::encode(blake3::hash(token.as_bytes()).as_bytes())
}

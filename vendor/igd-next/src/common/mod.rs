pub mod endpoint;
pub mod linklocal;
pub mod messages;
pub mod options;
pub mod parsing;

pub use self::options::SearchOptions;

use rand::{self, RngExt};

pub fn random_port() -> u16 {
    rand::rng().random_range(32_768_u16..65_535_u16)
}

/// Read response body, rejecting a body larger than `max` bytes (and never
/// buffering more than that) so a malicious or buggy gateway cannot exhaust memory.
#[cfg(feature = "io_sync")]
pub fn read_response_body(response: attohttpc::Response, max: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let (_, _, reader) = response.split();
    let mut buf = Vec::new();
    reader.take(max as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "gateway response body exceeded the maximum allowed size",
        ));
    }
    Ok(buf)
}

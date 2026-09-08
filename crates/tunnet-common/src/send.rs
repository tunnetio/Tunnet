//! File-transfer offer protocol (ALPN `tunnet/send/1`).
//!
//! Blob bytes ride on stock `iroh_blobs::ALPN`. This module is only the
//! control plane that offers / accepts / rejects a transfer.

use serde::{Deserialize, Serialize};

/// ALPN for Tunnet transfer offer streams.
pub const SEND_ALPN: &[u8] = b"tunnet/send/1";

/// Consent mode for inbound file offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SendConsentMode {
    /// Accept from every mesh peer.
    AutoAccept,
    /// Queue offers until CLI / dashboard accepts or rejects.
    /// Peers that share a mesh tag are still auto-accepted.
    #[default]
    Prompt,
    /// Reject all inbound offers.
    Deny,
}

impl SendConsentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AutoAccept => "auto_accept",
            Self::Prompt => "prompt",
            Self::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto_accept" | "auto-accept" | "auto" => Some(Self::AutoAccept),
            "prompt" => Some(Self::Prompt),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    /// Resolve an inbound offer: shared-tag peers auto-accept under [`Self::Prompt`].
    pub fn decide(self, peer_shares_tag: bool) -> ConsentDecision {
        match self {
            Self::Deny => ConsentDecision::Deny,
            Self::AutoAccept => ConsentDecision::Accept,
            Self::Prompt if peer_shares_tag => ConsentDecision::Accept,
            Self::Prompt => ConsentDecision::Prompt,
        }
    }
}

/// Outcome of [`SendConsentMode::decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Accept,
    Deny,
    Prompt,
}

/// Whether the payload is a single blob or a HashSeq collection (directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SendBlobFormat {
    #[default]
    Blob,
    HashSeq,
}

impl SendBlobFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::HashSeq => "hash_seq",
        }
    }
}

/// Wire messages on a `SEND_ALPN` bi-stream (length-prefixed JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SendWireMsg {
    Offer(TransferOffer),
    Decision(TransferDecision),
    Done(TransferDone),
}

impl SendWireMsg {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOffer {
    pub transfer_id: String,
    /// BLAKE3 hash as hex.
    pub hash: String,
    pub format: SendBlobFormat,
    pub file_name: String,
    pub size: u64,
    pub sender_endpoint_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// When true, `hash` is a HashSeq whose first child is JSON metadata.
    #[serde(default)]
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDecision {
    pub transfer_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDone {
    pub transfer_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_path: Option<String>,
}

/// Directory entry metadata stored as the first HashSeq child blob (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryManifest {
    pub version: u32,
    pub root_name: String,
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// Path relative to the directory root (POSIX separators).
    pub path: String,
    pub size: u64,
    /// BLAKE3 hex of the file blob (index into HashSeq is `entries[i] + 1`).
    pub hash: String,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn wire_roundtrip_offer() {
        let msg = SendWireMsg::Offer(TransferOffer {
            transfer_id: "abc".into(),
            hash: "00".repeat(32),
            format: SendBlobFormat::Blob,
            file_name: "photo.jpg".into(),
            size: 1024,
            sender_endpoint_id: "deadbeef".into(),
            message: Some("hi".into()),
            is_directory: false,
        });
        let bytes = msg.encode().unwrap();
        let decoded = SendWireMsg::decode(&bytes).unwrap();
        match decoded {
            SendWireMsg::Offer(o) => {
                assert_eq!(o.transfer_id, "abc");
                assert_eq!(o.file_name, "photo.jpg");
                assert_eq!(o.size, 1024);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[rstest]
    #[case::auto_accept("auto_accept", Some(SendConsentMode::AutoAccept))]
    #[case::prompt("prompt", Some(SendConsentMode::Prompt))]
    #[case::deny("deny", Some(SendConsentMode::Deny))]
    #[case::unknown("nope", None)]
    fn consent_parse(#[case] raw: &str, #[case] expected: Option<SendConsentMode>) {
        assert_eq!(SendConsentMode::parse(raw), expected);
    }

    #[rstest]
    #[case::deny_always(SendConsentMode::Deny, true, ConsentDecision::Deny)]
    #[case::deny_no_tag(SendConsentMode::Deny, false, ConsentDecision::Deny)]
    #[case::auto_accept_no_tag(SendConsentMode::AutoAccept, false, ConsentDecision::Accept)]
    #[case::prompt_shared_tag(SendConsentMode::Prompt, true, ConsentDecision::Accept)]
    #[case::prompt_no_tag(SendConsentMode::Prompt, false, ConsentDecision::Prompt)]
    fn consent_decide_shared_tag(
        #[case] mode: SendConsentMode,
        #[case] shared_tag: bool,
        #[case] expected: ConsentDecision,
    ) {
        assert_eq!(mode.decide(shared_tag), expected);
    }
}

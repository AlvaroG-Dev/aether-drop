//! Bounded framing primitives for the WebTransport application protocol.
//!
//! This module intentionally contains no file-system operations. It provides the
//! validated wire-format building blocks that the WebTransport dispatcher must use.
//! A protocol frame is a 4-byte big-endian JSON-header length followed by that many
//! UTF-8 JSON bytes. Binary payloads are carried separately and must be bounded by
//! the operation handler before allocation or writing.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const FRAME_PREFIX_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeader {
    pub version: u16,
    pub request_id: String,
    pub op: String,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub payload_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeader {
    pub version: u16,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    Empty,
    TooLarge,
    InvalidUtf8,
    InvalidJson,
    UnsupportedVersion,
    InvalidRequestId,
    InvalidOperation,
    InvalidLength,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "empty protocol header",
            Self::TooLarge => "protocol header exceeds limit",
            Self::InvalidUtf8 => "protocol header is not UTF-8",
            Self::InvalidJson => "protocol header is invalid JSON",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::InvalidRequestId => "invalid request identifier",
            Self::InvalidOperation => "invalid operation",
            Self::InvalidLength => "invalid payload length",
        })
    }
}

impl std::error::Error for FrameError {}

/// Encode a JSON header with its bounded, network-byte-order length prefix.
pub fn encode_header<T: Serialize>(header: &T) -> Result<Vec<u8>, FrameError> {
    let json = serde_json::to_vec(header).map_err(|_| FrameError::InvalidJson)?;
    if json.is_empty() {
        return Err(FrameError::Empty);
    }
    if json.len() > MAX_HEADER_BYTES {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(json.len()).map_err(|_| FrameError::TooLarge)?;
    let mut output = Vec::with_capacity(FRAME_PREFIX_BYTES + json.len());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&json);
    Ok(output)
}

/// Decode a complete prefix + JSON header. Trailing bytes are rejected so callers
/// cannot accidentally treat payload bytes as part of the header.
pub fn decode_header<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, FrameError> {
    if frame.len() < FRAME_PREFIX_BYTES {
        return Err(FrameError::InvalidLength);
    }
    let length = u32::from_be_bytes(frame[..FRAME_PREFIX_BYTES].try_into().unwrap()) as usize;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > MAX_HEADER_BYTES {
        return Err(FrameError::TooLarge);
    }
    if frame.len() != FRAME_PREFIX_BYTES + length {
        return Err(FrameError::InvalidLength);
    }
    let json = std::str::from_utf8(&frame[FRAME_PREFIX_BYTES..])
        .map_err(|_| FrameError::InvalidUtf8)?;
    serde_json::from_str(json).map_err(|_| FrameError::InvalidJson)
}

pub fn validate_request(header: &RequestHeader) -> Result<(), FrameError> {
    if header.version != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion);
    }
    if header.request_id.is_empty()
        || header.request_id.len() > 64
        || !header.request_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(FrameError::InvalidRequestId);
    }
    const ALLOWED_OPS: &[&str] = &[
        "session.check",
        "files.list",
        "upload.start",
        "upload.status",
        "upload.chunk",
        "upload.finish",
        "upload.cancel",
        "download.start",
        "download.read",
        "clipboard.get",
        "clipboard.set",
    ];
    if !ALLOWED_OPS.contains(&header.op.as_str()) {
        return Err(FrameError::InvalidOperation);
    }
    if header.payload_bytes.is_some_and(|length| length > 2 * 1024 * 1024 * 1024) {
        return Err(FrameError::InvalidLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> RequestHeader {
        RequestHeader {
            version: PROTOCOL_VERSION,
            request_id: "req_01aBc".to_owned(),
            op: "files.list".to_owned(),
            session: Some("opaque-token".to_owned()),
            payload_bytes: None,
        }
    }

    #[test]
    fn round_trips_bounded_header() {
        let request = valid_request();
        let encoded = encode_header(&request).unwrap();
        let decoded: RequestHeader = decode_header(&encoded).unwrap();
        assert_eq!(decoded, request);
        validate_request(&decoded).unwrap();
    }

    #[test]
    fn rejects_truncated_and_trailing_data() {
        let encoded = encode_header(&valid_request()).unwrap();
        assert!(matches!(decode_header::<RequestHeader>(&encoded[..3]), Err(FrameError::InvalidLength)));
        assert!(matches!(decode_header::<RequestHeader>(&encoded[..encoded.len() - 1]), Err(FrameError::InvalidLength)));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(decode_header::<RequestHeader>(&trailing), Err(FrameError::InvalidLength)));
    }

    #[test]
    fn rejects_zero_and_oversized_lengths_before_parsing() {
        assert!(matches!(decode_header::<RequestHeader>(&[0, 0, 0, 0]), Err(FrameError::Empty)));
        let oversized = (MAX_HEADER_BYTES as u32 + 1).to_be_bytes();
        assert!(matches!(decode_header::<RequestHeader>(&oversized), Err(FrameError::TooLarge)));
    }

    #[test]
    fn rejects_invalid_utf8_and_json() {
        let invalid_utf8 = [0, 0, 0, 1, 0xff];
        assert!(matches!(decode_header::<RequestHeader>(&invalid_utf8), Err(FrameError::InvalidUtf8)));
        let invalid_json = [0, 0, 0, 1, b'{'];
        assert!(matches!(decode_header::<RequestHeader>(&invalid_json), Err(FrameError::InvalidJson)));
    }

    #[test]
    fn rejects_unknown_fields_and_unsupported_versions() {
        let unknown_field = br#"{"version":1,"request_id":"r1","op":"files.list","unexpected":true}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(unknown_field.len() as u32).to_be_bytes());
        frame.extend_from_slice(unknown_field);
        assert!(matches!(decode_header::<RequestHeader>(&frame), Err(FrameError::InvalidJson)));

        let mut request = valid_request();
        request.version = 99;
        assert!(matches!(validate_request(&request), Err(FrameError::UnsupportedVersion)));
    }

    #[test]
    fn rejects_unknown_operations_and_bad_identifiers() {
        let mut request = valid_request();
        request.op = "filesystem.read-anything".to_owned();
        assert!(matches!(validate_request(&request), Err(FrameError::InvalidOperation)));
        request.op = "files.list".to_owned();
        request.request_id = "not valid".to_owned();
        assert!(matches!(validate_request(&request), Err(FrameError::InvalidRequestId)));
    }

    #[test]
    fn rejects_payload_length_over_file_limit() {
        let mut request = valid_request();
        request.payload_bytes = Some(2 * 1024 * 1024 * 1024 + 1);
        assert!(matches!(validate_request(&request), Err(FrameError::InvalidLength)));
    }
}

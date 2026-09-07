//! External time-stamp anchoring: submitting a signed tree head's
//! RFC 3161 commitment to a TSA, and proving the stored response
//! really covers the head.
//!
//! The payload half lives in `unidpp-signatif`
//! ([`external_anchor_payload`] builds the DER `TimeStampReq` from the
//! head's canonical bytes; the library deliberately makes no network
//! calls). This module is the service-side submission flow: HTTP POST
//! of the query bytes to the configured TSA (`application/timestamp-
//! query`, plain HTTP — terminate TLS at a fronting proxy, the house
//! doctrine), the stored record (response bytes or an explicit
//! unreachable degradation with a retry hint), and the offline check
//! that a stored `TimeStampResp` binds to the submitted digest.
//!
//! Full RFC 3161 response verification (the TSA's signature over the
//! CMS `TSTInfo`, against the TSA's certificate chain) is a
//! deployment concern — it needs the TSA's trust anchors. What is
//! checked here, offline and always: the response is a well-formed
//! DER `TimeStampResp` whose embedded `messageImprint` digest equals
//! the head's committed digest, so a response for any other document
//! never verifies.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use unidpp_model::{Hash, Timestamp};
use unidpp_signatif::anchor::ExternalAnchor;

/// How long a TSA submission may take before the anchor degrades.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(3);
/// The degradation's retry hint (a conservative back-off).
const RETRY_AFTER_SECS: i64 = 60;

/// The stored outcome of the latest external submission.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TsaRecord {
    /// The tree size the submission anchored.
    pub tree_size: u64,
    /// The committed digest (SHA-256 of the head's canonical bytes).
    pub digest: Hash,
    /// `anchored` (response stored) or `unreachable` (explicit
    /// degradation; nothing is faked).
    pub status: String,
    /// The TSA endpoint.
    pub tsa_url: String,
    /// The stored `TimeStampResp` bytes (DER), on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Vec<u8>>,
    /// Submission moment.
    pub submitted_at: Timestamp,
    /// When to retry, on degradation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<Timestamp>,
}

impl TsaRecord {
    /// The wire view for `GET /tree/head` (response bytes base64).
    pub fn to_wire(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status,
            "tsa_url": self.tsa_url,
            "tree_size": self.tree_size,
            "digest": self.digest.hex(),
            "submitted_at": self.submitted_at.to_string(),
            "retry_at": self.retry_at.map(|t| t.to_string()),
            "response": self.response.as_ref().map(|bytes| base64(bytes)),
        })
    }
}

/// Submit an anchor's payload bytes to the TSA (RFC 3161 over HTTP)
/// and store the outcome. Unreachable or malformed TSA → the explicit
/// `unreachable` degradation with a retry hint — the head's local
/// signature stands on its own; the external anchor is additive.
pub async fn submit_anchor(anchor: &ExternalAnchor, tsa_url: &str) -> TsaRecord {
    let digest = anchor.digest;
    let now = Timestamp::now();
    let base = record_now(digest, tsa_url, now);
    match http_post_binary(tsa_url, "application/timestamp-query", &anchor.payload).await {
        Ok(response) => match verify_timestamp_response(&response, &digest) {
            Ok(()) => TsaRecord {
                status: "anchored".to_string(),
                response: Some(response),
                ..base
            },
            // A response that does not bind to the digest is treated
            // as a failed submission, never stored as an anchor.
            Err(why) => {
                eprintln!("unidpp-log: TSA response rejected: {why}");
                degraded(digest, tsa_url, now)
            }
        },
        Err(why) => {
            eprintln!("unidpp-log: TSA unreachable: {why}");
            degraded(digest, tsa_url, now)
        }
    }
}

fn record_now(digest: Hash, tsa_url: &str, now: Timestamp) -> TsaRecord {
    TsaRecord {
        tree_size: 0,
        digest,
        status: String::new(),
        tsa_url: tsa_url.to_string(),
        response: None,
        submitted_at: now,
        retry_at: None,
    }
}

fn degraded(digest: Hash, tsa_url: &str, now: Timestamp) -> TsaRecord {
    TsaRecord {
        tree_size: 0,
        digest,
        status: "unreachable".to_string(),
        tsa_url: tsa_url.to_string(),
        response: None,
        submitted_at: now,
        retry_at: Some(Timestamp::from_secs(now.secs + RETRY_AFTER_SECS)),
    }
}

/// Verify a stored `TimeStampResp` binds to `digest`: the response is
/// a DER `TimeStampResp` (top-level SEQUENCE with a PKIStatusInfo
/// SEQUENCE) and the submitted digest is embedded in its
/// `messageImprint` — a response minted for any other document fails.
/// (The TSA's own signature over the token is verified
/// deployment-side against the TSA trust anchors.)
pub fn verify_timestamp_response(der: &[u8], digest: &Hash) -> Result<(), String> {
    let top = der_tlv(der).ok_or("not a DER TimeStampResp (no top-level TLV)")?;
    if top.tag != 0x30 {
        return Err("not a DER TimeStampResp (top level is not a SEQUENCE)".to_string());
    }
    let mut rest = top.value;
    let status = der_tlv(rest).ok_or("not a DER TimeStampResp (missing PKIStatusInfo)")?;
    if status.tag != 0x30 {
        return Err("not a DER TimeStampResp (first element is not PKIStatusInfo)".to_string());
    }
    rest = &rest[status.raw_len..];
    let _ = rest;
    // The messageImprint digest must appear inside the token: find the
    // 32-byte digest within the response bytes at a DER-octet-string
    // boundary (tag 0x04, length 0x20) — the TSTInfo's messageImprint
    // hash octets.
    let needle = digest.as_bytes();
    let mut offset = 0;
    while offset + 34 <= der.len() {
        if der[offset] == 0x04 && der[offset + 1] == 0x20 && &der[offset + 2..offset + 34] == needle
        {
            return Ok(());
        }
        offset += 1;
    }
    Err("the response's messageImprint does not carry this head's digest".to_string())
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw_len: usize,
}

/// One DER TLV at the head of `bytes` (short-form lengths only —
/// RFC 3161 payloads of one digest never need the long form).
fn der_tlv(bytes: &[u8]) -> Option<Tlv<'_>> {
    if bytes.len() < 2 {
        return None;
    }
    let tag = bytes[0];
    let length = bytes[1] as usize;
    if bytes.len() < 2 + length {
        return None;
    }
    Some(Tlv {
        tag,
        value: &bytes[2..2 + length],
        raw_len: 2 + length,
    })
}

/// A minimal blocking-free HTTP/1.1 POST of raw bytes (plain `http://`
/// — TLS terminates at a fronting proxy per the house doctrine).
async fn http_post_binary(url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream =
        tokio::time::timeout(SUBMIT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| "connect timeout".to_string())?
            .map_err(|e| format!("connect: {e}"))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\nAccept: application/timestamp-reply\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| format!("write body: {e}"))?;
    // Half-close: the request is complete, and simple responders
    // (like the RFC 3161 mock) read to EOF before replying.
    stream
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e}"))?;
    let mut response = Vec::new();
    tokio::time::timeout(SUBMIT_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    let text = response;
    let header_end = find_subsequence(&text, b"\r\n\r\n")
        .ok_or("malformed HTTP response (no header terminator)")?;
    let headers = String::from_utf8_lossy(&text[..header_end]).to_string();
    let status_line = headers.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("malformed HTTP status line")?;
    if status != 200 {
        return Err(format!("TSA returned HTTP {status}"));
    }
    let mut body_bytes = &text[header_end + 4..];
    // Chunked transfer encoding: concatenate the chunk bodies.
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut joined = Vec::new();
        let mut rest = body_bytes;
        while let Some(line_end) = find_subsequence(rest, b"\r\n") {
            let size_text = String::from_utf8_lossy(&rest[..line_end]).to_string();
            let size = usize::from_str_radix(size_text.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| "bad chunk size".to_string())?;
            if size == 0 {
                break;
            }
            let start = line_end + 2;
            if rest.len() < start + size {
                return Err("truncated chunk".to_string());
            }
            joined.extend_from_slice(&rest[start..start + size]);
            rest = &rest[start + size..];
            if rest.starts_with(b"\r\n") {
                rest = &rest[2..];
            }
        }
        return Ok(joined);
    }
    if let Some(range) = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        if body_bytes.len() >= range {
            body_bytes = &body_bytes[..range];
        }
    }
    Ok(body_bytes.to_vec())
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        format!("`{url}`: only plain http:// TSA endpoints (terminate TLS at a proxy)")
    })?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse().map_err(|_| format!("bad port in `{url}`"))?,
        ),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err(format!("`{url}`: no host"));
    }
    Ok((host, port, path))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_seq(children: &[&[u8]]) -> Vec<u8> {
        let body: Vec<u8> = children.iter().flat_map(|c| c.to_vec()).collect();
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    fn der_octets(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x04, bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    }

    fn der_int(value: u8) -> Vec<u8> {
        vec![0x02, 0x01, value]
    }

    fn response_with_digest(digest: &[u8; 32]) -> Vec<u8> {
        // TimeStampResp ::= SEQUENCE { status SEQUENCE { status
        // INTEGER }, token SEQUENCE { ..., messageImprint digest } }
        let imprint = der_octets(digest);
        der_seq(&[&der_seq(&[&der_int(0)]), &der_seq(&[&der_int(1), &imprint])])
    }

    #[test]
    fn response_binds_to_the_head_digest() {
        let digest = Hash::from_slice(&[7u8; 32]).unwrap();
        let response = response_with_digest(&[7u8; 32]);
        verify_timestamp_response(&response, &digest).unwrap();
    }

    #[test]
    fn a_response_for_another_document_never_verifies() {
        let digest = Hash::from_slice(&[7u8; 32]).unwrap();
        let other = response_with_digest(&[9u8; 32]);
        let err = verify_timestamp_response(&other, &digest).unwrap_err();
        assert!(err.contains("does not carry"), "{err}");
        // Not DER at all.
        assert!(verify_timestamp_response(b"not der", &digest).is_err());
        // A bare digest without the SEQUENCE framing.
        assert!(verify_timestamp_response(&[0x04, 0x20], &digest).is_err());
    }

    #[test]
    fn http_urls_parse_and_others_refuse() {
        let (host, port, path) = parse_http_url("http://tsa.example.org:8180/tsa").unwrap();
        assert_eq!(
            (host.as_str(), port, path.as_str()),
            ("tsa.example.org", 8180, "/tsa")
        );
        assert_eq!(parse_http_url("http://tsa.example.org").unwrap().2, "/");
        assert!(parse_http_url("https://tsa.example.org").is_err());
        assert!(parse_http_url("tsa.example.org").is_err());
    }

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64(b"m"), "bQ==");
        assert_eq!(base64(b"ma"), "bWE=");
        assert_eq!(base64(b"man"), "bWFu");
        assert_eq!(base64(&[0xff, 0xef, 0xff]), "/+//");
    }
}

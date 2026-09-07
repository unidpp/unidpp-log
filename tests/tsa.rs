//! External TSA anchoring, end to end: a mock RFC 3161 responder (a
//! raw TCP server that echoes the request's committed digest inside a
//! minimal `TimeStampResp`), the append-time submission, the stored
//! response binding to the head, and the explicit degradation when the
//! TSA is unreachable.

mod support;

use serde_json::Value;
use support::{get, json_of, json_request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use unidpp_log::{Config, TestServer};

// ---------------------------------------------------------------------------
// A mock RFC 3161 responder
// ---------------------------------------------------------------------------

/// Spawn a one-shot-ish mock TSA: every request's body contains the
/// committed digest as a DER OCTET STRING (tag 0x04, len 0x20) — echo
/// it inside a minimal TimeStampResp (PKIStatus granted + token with
/// the same messageImprint).
async fn spawn_mock_tsa() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock tsa");
    let addr = listener.local_addr().expect("tsa addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                if socket.read_to_end(&mut buffer).await.is_err() {
                    return;
                }
                let body = match split_http_body(&buffer) {
                    Some(body) => body,
                    None => return,
                };
                // Find the request's messageImprint digest (OCTET
                // STRING, 32 bytes) and echo it in the response.
                let digest = find_octet_string_32(body);
                let mut response = der_seq(&[&der_seq(&[&[0x02, 0x01, 0x00]])]);
                if let Some(digest) = digest {
                    let imprint = der_octets(&digest);
                    response = der_seq(&[&der_seq(&[&[0x02, 0x01, 0x00]]), &der_seq(&[&imprint])]);
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&response).await;
            });
        }
    });
    format!("http://{addr}/tsa")
}

fn split_http_body(raw: &[u8]) -> Option<&[u8]> {
    let start = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    Some(&raw[start..])
}

fn find_octet_string_32(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut offset = 0;
    while offset + 34 <= bytes.len() {
        if bytes[offset] == 0x04 && bytes[offset + 1] == 0x20 {
            return Some(bytes[offset + 2..offset + 34].try_into().unwrap());
        }
        offset += 1;
    }
    None
}

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

// ---------------------------------------------------------------------------
// The log side
// ---------------------------------------------------------------------------

async fn spawn_with_tsa(tsa_url: Option<String>) -> TestServer {
    TestServer::spawn(Config {
        external_tsa_url: tsa_url,
        ..Config::default()
    })
    .await
    .expect("spawn log")
}

async fn commit(base: &str, subject: &str) -> Value {
    let resp = json_request(
        "POST",
        &format!("{base}/commitments"),
        Some(&serde_json::json!({"subject": subject, "commitment": "00".repeat(32)}).to_string()),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    json_of(&resp)
}

fn base64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("bad base64"),
            } as u32;
            acc |= value << (18 - 6 * i);
        }
        for i in 0..chunk.len().saturating_sub(1) {
            out.push(((acc >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    out
}

#[tokio::test]
async fn tree_head_carries_a_verifiable_external_timestamp() {
    let tsa = spawn_mock_tsa().await;
    let server = spawn_with_tsa(Some(tsa)).await;
    commit(&server.base_url, "urn:unidpp:passport:tsa-1").await;

    let head = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
    let anchor = &head["external_anchor"];
    assert_eq!(anchor["method"], "rfc3161");
    assert_eq!(anchor["submission"]["status"], "anchored");
    assert!(anchor["digest"].as_str().unwrap().len() == 64);
    let response_b64 = anchor["submission"]["response"]
        .as_str()
        .expect("stored TimeStampResp");
    let der = base64_decode(response_b64);
    assert!(der.len() > 34, "a DER response, not a stub");

    // The stored response verifies against the head's digest: the
    // offline binding check a verifier runs.
    let digest = unidpp_model::Hash::from_hex(anchor["digest"].as_str().unwrap()).unwrap();
    unidpp_log::tsa::verify_timestamp_response(&der, &digest)
        .expect("the stored response binds to the head");

    // And it never verifies against a foreign digest.
    let foreign = unidpp_model::Hash::from_slice(&[0x99u8; 32]).unwrap();
    assert!(unidpp_log::tsa::verify_timestamp_response(&der, &foreign).is_err());
    server.stop().await;
}

#[tokio::test]
async fn unreachable_tsa_degrades_explicitly() {
    // A port that is up but refuses nothing: bind and drop the
    // listener so connects fail.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let server = spawn_with_tsa(Some(format!("http://{addr}/tsa"))).await;
    // The append still succeeds — the anchor is additive.
    let receipt = commit(&server.base_url, "urn:unidpp:passport:tsa-degraded").await;
    assert!(receipt["seq"].as_u64().is_some());

    let head = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
    let anchor = &head["external_anchor"];
    assert_eq!(anchor["submission"]["status"], "unreachable");
    assert!(anchor["submission"]["response"].is_null());
    assert!(
        anchor["submission"]["retry_at"].as_str().is_some(),
        "the degradation carries a retry hint"
    );
    // The head's own signature is intact (the local anchor stands).
    assert!(head["signature"]["value"].as_str().is_some());
    server.stop().await;
}

#[tokio::test]
async fn no_tsa_configured_reports_not_configured() {
    let server = spawn_with_tsa(None).await;
    commit(&server.base_url, "urn:unidpp:passport:tsa-none").await;
    let head = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
    assert_eq!(head["external_anchor"]["status"], "not-configured");
    server.stop().await;
}

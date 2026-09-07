//! Integration tests: real HTTP against servers spawned on ephemeral
//! ports. Covers the required behaviours: append → receipt verifies
//! against the head (operator signature + Merkle inclusion), heads are
//! monotonic and tied to older ones by consistency proofs, tamper
//! detection (a modified journal entry changes the root and breaks
//! previously-issued receipts), restart consistency (journal replay
//! reproduces byte-identical heads and receipts), auth, and input
//! validation.

mod support;

use std::path::PathBuf;

use serde_json::{json, Value};
use support::{get, json_of, json_request};
use unidpp_log::{Config, TestServer};
use unidpp_model::{sha256, Hash, Timestamp};
use unidpp_signatif::keyring::PublicKey;
use unidpp_signatif::sign::Suite;
use unidpp_signatif::{verify_consistency, verify_inclusion};

// ---------------------------------------------------------------------------
// Verifier-side helpers (exactly what an offline verifier / the CLI
// would do with a receipt + the operator's published key)
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

async fn operator_public_key(base: &str) -> PublicKey {
    let doc = json_of(&get(&format!("{base}/")).await);
    let hex = doc["operator"]["public_key_hex"]
        .as_str()
        .expect("public key");
    PublicKey::from_bytes(&hex_decode(hex)).expect("operator public key")
}

fn sth_from_view(v: &Value) -> unidpp_signatif::SignedTreeHead {
    unidpp_log::model::sth_from_json(v).expect("tree head from wire")
}

fn proof_from_view(v: &Value) -> unidpp_signatif::InclusionProof {
    unidpp_log::model::proof_from_json(v).expect("inclusion proof from wire")
}

/// The end-to-end receipt verification: STH signature under the
/// operator key + inclusion proof reconstructing the STH root.
fn verify_receipt(receipt: &Value, operator: &PublicKey) {
    let sth = sth_from_view(&receipt["tree_head"]);
    sth.verify(operator).expect("operator signature verifies");
    let proof = proof_from_view(&receipt["inclusion"]);
    let commitment =
        Hash::from_hex(receipt["commitment"].as_str().expect("commitment")).expect("hash");
    verify_inclusion(&commitment, &proof, &sth.root).expect("inclusion verifies");
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn commitment(i: u64) -> String {
    sha256(&[b"unidpp-log/it-commitment", &i.to_le_bytes()]).hex()
}

async fn spawn(config: Config) -> TestServer {
    TestServer::spawn(config).await.expect("spawn server")
}

fn journal_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unidpp-log-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test dir");
    dir.join("journal.jsonl")
}

async fn post_commitment(base: &str, i: u64, token: Option<&str>) -> support::HttpResponse {
    let body = json!({
        "subject": format!("urn:unidpp:passport:e8-{i}"),
        "commitment": commitment(i),
        "salt_ref": if i % 2 == 0 { Value::Null } else { json!(i) },
    });
    json_request(
        "POST",
        &format!("{base}/commitments"),
        Some(&body.to_string()),
        token,
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_healthz_and_empty_head() {
    let server = spawn(Config::default()).await;
    let base = &server.base_url;

    let doc = json_of(&get(&format!("{base}/")).await);
    assert_eq!(doc["service"], "unidpp-log");
    assert_eq!(doc["log_id"], "unidpp-log-1");
    assert_eq!(doc["operator"]["suite"], "ed25519");
    assert!(doc["operator"]["public_key_hex"].as_str().unwrap().len() == 64);
    assert!(doc["quorum"]["now"].as_str().unwrap().contains("M=1"));
    assert_eq!(get(&format!("{base}/healthz")).await.status, 200);

    // An empty log has a size-0 head with no root yet.
    let head = json_of(&get(&format!("{base}/tree/head")).await);
    assert_eq!(head["tree_size"], 0);
    assert!(head["root"].is_null());

    server.stop().await;
}

#[tokio::test]
async fn append_returns_a_receipt_that_verifies_against_the_head() {
    let server = spawn(Config::default()).await;
    let base = &server.base_url;
    let operator = operator_public_key(base).await;

    for i in 0..3u64 {
        let resp = post_commitment(base, i, None).await;
        assert_eq!(resp.status, 201, "commit {i}");
        let receipt = json_of(&resp);
        assert_eq!(receipt["seq"], i);
        assert_eq!(receipt["receipt_id"], i.to_string());
        assert_eq!(receipt["inclusion"]["leaf_index"], i);
        assert_eq!(receipt["inclusion"]["tree_size"], i + 1);
        assert_eq!(receipt["tree_head"]["tree_size"], i + 1);
        assert_eq!(receipt["commitment"], commitment(i).as_str());
        // Full verification against the operator key.
        verify_receipt(&receipt, &operator);
    }

    // The live head covers all entries and is signed.
    let head = json_of(&get(&format!("{base}/tree/head")).await);
    assert_eq!(head["tree_size"], 3);
    let sth = sth_from_view(&head);
    sth.verify(&operator).expect("head signature");
    assert_eq!(sth.root.hex(), head["root"].as_str().expect("root hex"));

    server.stop().await;
}

#[tokio::test]
async fn heads_are_monotonic_and_tied_by_consistency_proofs() {
    let server = spawn(Config::default()).await;
    let base = &server.base_url;
    let operator = operator_public_key(base).await;

    // Pin the head after the first append.
    post_commitment(base, 0, None).await;
    let old = json_of(&get(&format!("{base}/tree/head")).await);
    let old_sth = sth_from_view(&old);

    for i in 1..=6u64 {
        post_commitment(base, i, None).await;
    }
    let new = json_of(&get(&format!("{base}/tree/head")).await);
    let new_sth = sth_from_view(&new);
    assert_eq!(new_sth.tree_size, 7);
    assert!(new_sth.tree_size > old_sth.tree_size);
    new_sth.verify(&operator).expect("new head signature");

    // The pinned old root is tied to the current head by the
    // consistency proof (STH pinning: the log cannot rewrite history).
    let proof = json_of(&get(&format!("{base}/tree/consistency?from=1")).await);
    assert_eq!(proof["old_size"], 1);
    assert_eq!(proof["new_size"], 7);
    let path: Vec<Hash> = proof["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| Hash::from_hex(h.as_str().unwrap()).unwrap())
        .collect();
    verify_consistency(1, &old_sth.root, 7, &new_sth.root, &path).expect("consistency 1 -> 7");

    // From 0: the empty proof.
    let zero = json_of(&get(&format!("{base}/tree/consistency?from=0")).await);
    assert_eq!(zero["path"].as_array().unwrap().len(), 0);
    // Beyond the tree: rejected.
    assert_eq!(
        get(&format!("{base}/tree/consistency?from=99"))
            .await
            .status,
        400
    );
    assert_eq!(get(&format!("{base}/tree/consistency")).await.status, 400);

    server.stop().await;
}

#[tokio::test]
async fn receipts_are_reserved_and_validated() {
    let server = spawn(Config::default()).await;
    let base = &server.base_url;

    let created = json_of(&post_commitment(base, 0, None).await);
    let created2 = json_of(&post_commitment(base, 1, None).await);

    // GET re-serves byte-identical receipts.
    for (seq, created) in [(0u64, &created), (1, &created2)] {
        let resp = get(&format!("{base}/receipt/{seq}")).await;
        assert_eq!(resp.status, 200);
        assert_eq!(json_of(&resp), *created);
    }
    assert_eq!(get(&format!("{base}/receipt/9")).await.status, 404);
    assert_eq!(get(&format!("{base}/receipt/junk")).await.status, 400);

    // Validation.
    let bad = json_request(
        "POST",
        &format!("{base}/commitments"),
        Some(r#"{"subject": "x"}"#),
        None,
    )
    .await;
    assert_eq!(bad.status, 400);
    let bad = json_request(
        "POST",
        &format!("{base}/commitments"),
        Some(r#"{"subject": "x", "commitment": "deadbeef"}"#),
        None,
    )
    .await;
    assert_eq!(bad.status, 400);
    let bad = json_request(
        "POST",
        &format!("{base}/commitments"),
        Some(r#"{"subject": "x", "commitment": "not-hex", "salt_ref": "x"}"#),
        None,
    )
    .await;
    assert_eq!(bad.status, 400);
    let bad = json_request(
        "POST",
        &format!("{base}/commitments"),
        Some(r#"{"subject": "x", "commitment": "0000000000000000000000000000000000000000000000000000000000000000", "salt_ref": -3}"#),
        None,
    )
    .await;
    assert_eq!(bad.status, 400);

    server.stop().await;
}

#[tokio::test]
async fn append_token_guards_the_write_path() {
    let config = Config {
        append_token: Some("secret-token".into()),
        ..Config::default()
    };
    let server = spawn(config).await;
    let base = &server.base_url;

    let denied = post_commitment(base, 0, None).await;
    assert_eq!(denied.status, 401);
    // Reads stay open.
    assert_eq!(get(&format!("{base}/tree/head")).await.status, 200);
    let allowed = post_commitment(base, 0, Some("secret-token")).await;
    assert_eq!(allowed.status, 201);

    server.stop().await;
}

#[tokio::test]
async fn restart_replay_reproduces_identical_heads_and_receipts() {
    let journal = journal_path("restart");

    let (head_before, receipt_before) = {
        let config = Config {
            state_file: Some(journal.clone()),
            ..Config::default()
        };
        let server = spawn(config).await;
        for i in 0..5u64 {
            assert_eq!(post_commitment(&server.base_url, i, None).await.status, 201);
        }
        let head = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
        let receipt = json_of(&get(&format!("{}/receipt/2", server.base_url)).await);
        server.stop().await;
        (head, receipt)
    };
    assert_eq!(head_before["tree_size"], 5);

    // Restart on the same journal: the replayed state produces the
    // identical head (size, root, timestamp, signature) and receipts.
    {
        let config = Config {
            state_file: Some(journal.clone()),
            ..Config::default()
        };
        let server = spawn(config).await;
        let head_after = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
        assert_eq!(
            head_after, head_before,
            "head must be identical after replay"
        );
        let receipt_after = json_of(&get(&format!("{}/receipt/2", server.base_url)).await);
        assert_eq!(receipt_after, receipt_before);
        // Sequencing continues strictly monotonic.
        let next = json_of(&post_commitment(&server.base_url, 99, None).await);
        assert_eq!(next["seq"], 5);
        server.stop().await;
    }

    let _ = std::fs::remove_file(&journal);
}

#[tokio::test]
async fn tampered_journal_entry_breaks_issued_receipts() {
    let journal = journal_path("tamper");

    // Issue receipts against the honest log.
    let (operator, receipt, old_head) = {
        let config = Config {
            state_file: Some(journal.clone()),
            ..Config::default()
        };
        let server = spawn(config).await;
        for i in 0..4u64 {
            post_commitment(&server.base_url, i, None).await;
        }
        let operator = operator_public_key(&server.base_url).await;
        let receipt = json_of(&post_commitment(&server.base_url, 4, None).await);
        let head = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
        server.stop().await;
        (operator, receipt, head)
    };
    // Sanity: the receipt verifies on the honest log.
    verify_receipt(&receipt, &operator);

    // Tamper: rewrite entry 1's commitment in the journal (still valid
    // JSON, still seq 1 — an in-place rewrite of history).
    let text = std::fs::read_to_string(&journal).expect("journal");
    let original_line = text.lines().nth(1).expect("entry 1");
    let evil = sha256(&[b"evil-operator-rewrite"]).hex();
    let mut tampered_record: Value = serde_json::from_str(original_line).unwrap();
    tampered_record["commitment"] = json!(evil);
    let tampered_line = tampered_record.to_string();
    std::fs::write(&journal, text.replace(original_line, &tampered_line)).unwrap();

    // Restart: the replayed root differs, and the previously-issued
    // receipt's proof no longer reconstructs any honest root.
    {
        let config = Config {
            state_file: Some(journal.clone()),
            ..Config::default()
        };
        let server = spawn(config).await;
        let new_head = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
        assert_eq!(new_head["tree_size"], old_head["tree_size"]);
        assert_ne!(new_head["root"], old_head["root"]);

        // The old STH signature still verifies (it is a signature over
        // the *old* root — cryptography intact)...
        let old_sth = sth_from_view(&old_head);
        old_sth
            .verify(&operator)
            .expect("old signature still valid");
        // ...but the tampered tree no longer contains that root: the
        // consistency proof from the pinned size fails.
        let new_sth = sth_from_view(&new_head);
        let proof = json_of(&get(&format!("{}/tree/consistency?from=5", server.base_url)).await);
        let path: Vec<Hash> = proof["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| Hash::from_hex(h.as_str().unwrap()).unwrap())
            .collect();
        assert!(
            verify_consistency(5, &old_sth.root, 5, &new_sth.root, &path).is_err(),
            "tampered history must not be provable consistent"
        );
        // And the issued receipt's inclusion proof fails against the
        // tampered root.
        let receipt_proof = proof_from_view(&receipt["inclusion"]);
        assert!(verify_inclusion(
            &Hash::from_hex(receipt["commitment"].as_str().unwrap()).unwrap(),
            &receipt_proof,
            &new_sth.root
        )
        .is_err());
        server.stop().await;
    }

    let _ = std::fs::remove_file(&journal);
}

#[tokio::test]
async fn torn_journal_tail_is_survived_and_sequence_gaps_refuse_to_start() {
    // A crash mid-write (torn final line) replays the surviving
    // prefix.
    let journal = journal_path("torn");
    {
        let config = Config {
            state_file: Some(journal.clone()),
            ..Config::default()
        };
        let server = spawn(config).await;
        for i in 0..3u64 {
            post_commitment(&server.base_url, i, None).await;
        }
        server.stop().await;
    }
    let mut text = std::fs::read_to_string(&journal).unwrap();
    text.push_str("{\"seq\": 3, \"subject\": \"torn");
    std::fs::write(&journal, text).unwrap();
    {
        let config = Config {
            state_file: Some(journal.clone()),
            ..Config::default()
        };
        let server = TestServer::spawn(config).await.expect("torn tail replays");
        let head = json_of(&get(&format!("{}/tree/head", server.base_url)).await);
        assert_eq!(head["tree_size"], 3);
        let next = json_of(&post_commitment(&server.base_url, 3, None).await);
        assert_eq!(next["seq"], 3);
        server.stop().await;
    }

    // A gap in the sequence refuses to start (integrity failure, not a
    // silent skip).
    let journal2 = journal_path("gap");
    {
        let config = Config {
            state_file: Some(journal2.clone()),
            ..Config::default()
        };
        let server = spawn(config).await;
        post_commitment(&server.base_url, 0, None).await;
        server.stop().await;
    }
    let text = std::fs::read_to_string(&journal2).unwrap();
    std::fs::write(&journal2, text.replace("\"seq\":0", "\"seq\":7")).unwrap();
    {
        let config = Config {
            state_file: Some(journal2.clone()),
            ..Config::default()
        };
        assert!(TestServer::spawn(config).await.is_err(), "gap must refuse");
    }
    let _ = std::fs::remove_file(&journal);
    let _ = std::fs::remove_file(&journal2);
}

#[tokio::test]
async fn p256_operator_suite_is_configurable() {
    let mut config = Config::default();
    config.operator.suite = Suite::EcdsaP256;
    let server = spawn(config).await;
    let base = &server.base_url;

    let doc = json_of(&get(&format!("{base}/")).await);
    assert_eq!(doc["operator"]["suite"], "ecdsa-p256");
    let operator = operator_public_key(base).await;
    let receipt = json_of(&post_commitment(base, 0, None).await);
    verify_receipt(&receipt, &operator);
    server.stop().await;
}

#[tokio::test]
async fn timestamped_receipts_carry_the_journaled_instant() {
    let server = spawn(Config::default()).await;
    let base = &server.base_url;
    let before = Timestamp::now();
    let receipt = json_of(&post_commitment(base, 0, None).await);
    let after = Timestamp::now();
    let logged = Timestamp::parse(receipt["logged_at"].as_str().unwrap()).unwrap();
    assert!(logged >= before && logged <= after);
    assert_eq!(receipt["tree_head"]["timestamp"], receipt["logged_at"]);
    server.stop().await;
}

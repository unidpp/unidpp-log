//! The service's domain shapes: the sequenced commit record (the
//! journal's storage unit), the inclusion receipt (the verifiable
//! document a submitter walks away with), and their wire views.
//!
//! Model-driven by design: a receipt is *derived state*, never
//! journaled. Because sequencing is serial, the receipt for entry `m`
//! is fully determined by the entry record — its inclusion proof is
//! taken against the prefix of size `m + 1` (the tree exactly when the
//! entry was sequenced) and its signed tree head is signed over that
//! prefix's root, size, and the entry's journaled timestamp, under a
//! deterministic-signature suite (Ed25519 by construction, ECDSA-P256
//! via RFC 6979). Journal replay therefore reproduces byte-identical
//! receipts and heads — the property the restart tests pin.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use unidpp_model::{Hash, Timestamp};
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::{SignatureSlot, SigningDomain};
use unidpp_signatif::{InclusionProof, SignatifError, SignedTreeHead};

use crate::store::LogStore;

/// One sequenced entry in the append-only log — the JSONL journal's
/// storage unit and the replay input. The log anchors a *commitment*
/// (a salted hash the submitter computed); the `subject` identity and
/// the opaque `salt_ref` are the operator-side record-keeping around
/// it. No facts ride in the log (enumeration resistance, I12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRecord {
    /// Leaf index — the strictly monotonic sequence number.
    pub seq: u64,
    /// When the log sequenced the entry (server-stamped; journaled and
    /// preserved across replays).
    pub logged_at: Timestamp,
    /// The submitter's subject identity (informational; never hashed
    /// into the tree).
    pub subject: String,
    /// The anchored commitment (already salted by the submitter).
    pub commitment: Hash,
    /// Opaque owner-side salt reference, when the submitter supplied
    /// one (mirrors signatif's `LogEntry::salted`).
    pub salt_ref: Option<u64>,
}

impl CommitRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "seq": self.seq,
            "logged_at": self.logged_at.to_string(),
            "subject": self.subject,
            "commitment": self.commitment.hex(),
            "salt_ref": self.salt_ref,
        })
    }

    pub fn from_json(v: &Value) -> Result<CommitRecord, String> {
        let obj = v.as_object().ok_or("commit record must be an object")?;
        let seq = obj
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or("missing `seq`")?;
        let logged_at = obj
            .get("logged_at")
            .and_then(Value::as_str)
            .and_then(|s| Timestamp::parse(s).ok())
            .ok_or("missing/invalid `logged_at`")?;
        let subject = obj
            .get("subject")
            .and_then(Value::as_str)
            .ok_or("missing `subject`")?
            .to_string();
        let commitment = obj
            .get("commitment")
            .and_then(Value::as_str)
            .and_then(Hash::from_hex)
            .ok_or("missing/invalid `commitment` (64-char hex)")?;
        let salt_ref = match obj.get("salt_ref") {
            None | Some(Value::Null) => None,
            Some(Value::Number(n)) => Some(n.as_u64().ok_or("`salt_ref` must be a u64")?),
            Some(_) => return Err("`salt_ref` must be an unsigned integer".into()),
        };
        Ok(CommitRecord {
            seq,
            logged_at,
            subject,
            commitment,
            salt_ref,
        })
    }
}

/// A signed, sequenced inclusion receipt: what `POST /commitments`
/// returns and `GET /receipt/{seq}` re-serves (byte-identically).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub log_id: String,
    pub record: CommitRecord,
    pub inclusion: InclusionProof,
    pub tree_head: SignedTreeHead,
}

impl Receipt {
    /// Derive the receipt for entry `seq`: the inclusion proof against
    /// the prefix of size `seq + 1`, and a signed tree head over that
    /// prefix's root, size, and the entry's journaled timestamp.
    pub fn of(store: &LogStore, seq: u64, log_id: &str, operator: &KeyPair) -> Option<Receipt> {
        let record = store.record(seq)?.clone();
        let tree_size = seq + 1;
        let root = store.root_at_size(tree_size)?;
        let path = store.inclusion_path(seq, tree_size);
        let logged_at = record.logged_at;
        let signature = SignatureSlot::sign(
            operator,
            SigningDomain::TreeHead,
            &SignedTreeHead::canonical_bytes(log_id, tree_size, logged_at, &root),
        )
        .ok()?;
        Some(Receipt {
            log_id: log_id.to_string(),
            record,
            inclusion: InclusionProof {
                leaf_index: seq,
                tree_size,
                path,
            },
            tree_head: SignedTreeHead {
                log_id: log_id.to_string(),
                tree_size,
                timestamp: logged_at,
                root,
                signature,
            },
        })
    }

    /// Wire view. `operator_info` (from [`crate::keyring::Operator`])
    /// rides along so the receipt is self-contained for an offline
    /// verifier that trusts the operator key it already holds.
    pub fn to_json(&self, operator_info: &Value) -> Value {
        json!({
            "receipt_id": self.record.seq.to_string(),
            "log_id": self.log_id,
            "seq": self.record.seq,
            "subject": self.record.subject,
            "commitment": self.record.commitment.hex(),
            "salt_ref": self.record.salt_ref,
            "logged_at": self.record.logged_at.to_string(),
            "inclusion": proof_json(&self.inclusion, self.record.commitment),
            "tree_head": sth_json(&self.tree_head),
            "operator": operator_info,
        })
    }
}

/// The head minting: a signed tree head over the *current* tree, at
/// the timestamp of the latest append (heads are append-time
/// checkpoints — deterministic under replay; a larger log would also
/// checkpoint on a clock interval, which is a pure addition of more
/// valid heads, never a rewrite).
pub fn current_head(store: &LogStore, log_id: &str, operator: &KeyPair) -> Option<SignedTreeHead> {
    let last = store.size().checked_sub(1)?;
    let root = store.root()?;
    let timestamp = store.record(last)?.logged_at;
    let signature = SignatureSlot::sign(
        operator,
        SigningDomain::TreeHead,
        &SignedTreeHead::canonical_bytes(log_id, store.size(), timestamp, &root),
    )
    .ok()?;
    Some(SignedTreeHead {
        log_id: log_id.to_string(),
        tree_size: store.size(),
        timestamp,
        root,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Wire views (signature values as hex strings — serde's default Vec<u8>
// rendering would emit number arrays)
// ---------------------------------------------------------------------------

/// Minimal hex encode (signatures and keys are short; avoids a
/// dependency — mirrors the signatif keyring helper).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Minimal hex decode.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn signature_json(slot: &SignatureSlot) -> Value {
    let mut m = Map::new();
    m.insert("suite".into(), json!(slot.suite.as_str()));
    m.insert("key_id".into(), json!(slot.key_id.as_str()));
    m.insert(
        "value".into(),
        slot.signature
            .as_ref()
            .map(|v| json!(hex_encode(v)))
            .unwrap_or(Value::Null),
    );
    Value::Object(m)
}

fn sth_json(sth: &SignedTreeHead) -> Value {
    json!({
        "log_id": sth.log_id,
        "tree_size": sth.tree_size,
        "timestamp": sth.timestamp.to_string(),
        "root": sth.root.hex(),
        "signature": signature_json(&sth.signature),
    })
}

fn proof_json(proof: &InclusionProof, commitment: Hash) -> Value {
    json!({
        "leaf_index": proof.leaf_index,
        "tree_size": proof.tree_size,
        "leaf_hash": unidpp_signatif::anchor::leaf_hash(&commitment).hex(),
        "commitment": commitment.hex(),
        "path": proof
            .path
            .iter()
            .map(|n| json!({
                "sibling": n.sibling.hex(),
                "side": match n.side {
                    unidpp_signatif::Side::Left => "left",
                    unidpp_signatif::Side::Right => "right",
                },
            }))
            .collect::<Vec<_>>(),
    })
}

/// Rebuild a typed `SignedTreeHead` from its wire view (the verifier
/// path a CLI would implement; used by the tests to prove the wire is
/// sufficient for verification).
pub fn sth_from_json(v: &Value) -> Result<SignedTreeHead, String> {
    let obj = v.as_object().ok_or("tree head must be an object")?;
    let log_id = obj
        .get("log_id")
        .and_then(Value::as_str)
        .ok_or("missing `log_id`")?
        .to_string();
    let tree_size = obj
        .get("tree_size")
        .and_then(Value::as_u64)
        .ok_or("missing `tree_size`")?;
    let timestamp = obj
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|s| Timestamp::parse(s).ok())
        .ok_or("missing/invalid `timestamp`")?;
    let root = obj
        .get("root")
        .and_then(Value::as_str)
        .and_then(Hash::from_hex)
        .ok_or("missing/invalid `root`")?;
    let sig = obj
        .get("signature")
        .ok_or("missing `signature`")?
        .as_object()
        .ok_or("`signature` must be an object")?;
    let suite = unidpp_signatif::sign::Suite::parse_token(
        sig.get("suite")
            .and_then(Value::as_str)
            .ok_or("missing `signature.suite`")?,
    )
    .map_err(|e| e.to_string())?;
    let key_id = unidpp_signatif::keyring::KeyId::new(
        sig.get("key_id")
            .and_then(Value::as_str)
            .ok_or("missing `signature.key_id`")?,
    )
    .map_err(|e| e.to_string())?;
    let value = match sig.get("value") {
        Some(Value::String(s)) => hex_decode(s).ok_or("bad `signature.value` hex")?,
        _ => return Err("missing `signature.value`".into()),
    };
    Ok(SignedTreeHead {
        log_id,
        tree_size,
        timestamp,
        root,
        signature: SignatureSlot {
            suite,
            key_id,
            signature: Some(value),
        },
    })
}

/// Rebuild a typed `InclusionProof` from its wire view.
pub fn proof_from_json(v: &Value) -> Result<InclusionProof, String> {
    let obj = v.as_object().ok_or("inclusion must be an object")?;
    let leaf_index = obj
        .get("leaf_index")
        .and_then(Value::as_u64)
        .ok_or("missing `leaf_index`")?;
    let tree_size = obj
        .get("tree_size")
        .and_then(Value::as_u64)
        .ok_or("missing `tree_size`")?;
    let mut path = Vec::new();
    for node in obj
        .get("path")
        .and_then(Value::as_array)
        .ok_or("missing `path`")?
    {
        let sibling = node
            .get("sibling")
            .and_then(Value::as_str)
            .and_then(Hash::from_hex)
            .ok_or("bad `path[].sibling`")?;
        let side = match node.get("side").and_then(Value::as_str) {
            Some("left") => unidpp_signatif::Side::Left,
            Some("right") => unidpp_signatif::Side::Right,
            _ => return Err("bad `path[].side`".into()),
        };
        path.push(unidpp_signatif::ProofNode { sibling, side });
    }
    Ok(InclusionProof {
        leaf_index,
        tree_size,
        path,
    })
}

/// The errors the receipt layer surfaces (thin wrapper so handlers can
/// map them uniformly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptError(pub String);

impl From<SignatifError> for ReceiptError {
    fn from(e: SignatifError) -> ReceiptError {
        ReceiptError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LogStore;
    use unidpp_model::sha256;
    use unidpp_signatif::keyring::{KeyPair, PublicKey};
    use unidpp_signatif::sign::Suite;
    use unidpp_signatif::verify_inclusion;

    fn commitment(i: u64) -> Hash {
        sha256(&[&i.to_le_bytes()])
    }

    fn operator() -> KeyPair {
        KeyPair::seeded(Suite::Ed25519, b"unit-operator").unwrap()
    }

    fn store_with(n: u64) -> LogStore {
        let mut store = LogStore::open(None).unwrap();
        for i in 0..n {
            store
                .append(
                    format!("subject-{i}"),
                    commitment(i),
                    None,
                    Timestamp::from_secs(100 + i as i64),
                )
                .unwrap();
        }
        store
    }

    #[test]
    fn receipt_verifies_against_its_own_head() {
        let store = store_with(5);
        let key = operator();
        let receipt = Receipt::of(&store, 3, "unit-log", &key).unwrap();
        // Operator signature verifies under the operator key.
        assert!(receipt.tree_head.verify(key.public()).is_ok());
        // ...and the commitment's proof reconstructs the head's root.
        assert!(verify_inclusion(
            &receipt.record.commitment,
            &receipt.inclusion,
            &receipt.tree_head.root
        )
        .is_ok());
        assert_eq!(receipt.inclusion.leaf_index, 3);
        assert_eq!(receipt.inclusion.tree_size, 4);
        assert_eq!(receipt.tree_head.tree_size, 4);
        // A different operator's key fails.
        let other = KeyPair::seeded(Suite::EcdsaP256, b"other").unwrap();
        let other_public = PublicKey::from_bytes(other.public().as_bytes()).unwrap();
        assert!(receipt.tree_head.verify(&other_public).is_err());
    }

    #[test]
    fn wire_view_round_trips_into_verifiable_objects() {
        let store = store_with(6);
        let key = operator();
        let receipt = Receipt::of(&store, 2, "unit-log", &key).unwrap();
        // Embed the operator's wire info exactly as the service does.
        let operator_info = json!({
            "log_id": "unit-log",
            "suite": key.suite().as_str(),
            "key_id": key.key_id().as_str(),
            "public_key_hex": hex_encode(key.public().as_bytes()),
        });
        let view = receipt.to_json(&operator_info);
        // Rebuild from wire and verify exactly as an offline verifier
        // would (public key out of the operator info document).
        let sth = sth_from_json(&view["tree_head"]).unwrap();
        let proof = proof_from_json(&view["inclusion"]).unwrap();
        let commitment = Hash::from_hex(view["commitment"].as_str().unwrap()).unwrap();
        let public = PublicKey::from_bytes(
            &hex_decode(view["operator"]["public_key_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert!(sth.verify(&public).is_ok());
        assert!(verify_inclusion(&commitment, &proof, &sth.root).is_ok());
        assert_eq!(view["seq"], 2);
        assert_eq!(view["receipt_id"], "2");
    }

    #[test]
    fn record_json_round_trip() {
        let rec = CommitRecord {
            seq: 7,
            logged_at: Timestamp::parse("2026-09-07T10:11:12.5Z").unwrap(),
            subject: "urn:unidpp:passport:e8".into(),
            commitment: commitment(7),
            salt_ref: Some(11),
        };
        let v = rec.to_json();
        assert_eq!(CommitRecord::from_json(&v).unwrap(), rec);
        // No facts: the record carries the commitment, not a payload.
        assert!(!v.to_string().contains("battery"));
        assert!(CommitRecord::from_json(&serde_json::json!({"seq": 1})).is_err());
    }

    #[test]
    fn current_head_tracks_the_tree() {
        let store = store_with(4);
        let key = operator();
        let head = current_head(&store, "unit-log", &key).unwrap();
        assert_eq!(head.tree_size, 4);
        assert_eq!(head.root, store.root().unwrap());
        assert!(head.verify(key.public()).is_ok());
        // Empty store: no head (nothing to sign).
        let empty = LogStore::open(None).unwrap();
        assert!(current_head(&empty, "unit-log", &key).is_none());
    }
}

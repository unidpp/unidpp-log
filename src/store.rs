//! The log store: sequencing, the in-memory tree over sequenced
//! entries, and the JSONL append-only journal (the durability and
//! auditability mechanism — the registry's proven pattern: the log
//! *is* the storage, nothing is edited in place).
//!
//! Sequencing is strictly monotonic by construction: `append` assigns
//! `seq = entries.len()` under the caller's lock and never reuses a
//! number; the journal replays with the same discipline and refuses
//! any journal whose sequence numbers are not exactly 0, 1, 2, ….
//! Durability vs. torn writes: a crash mid-write can tear only the
//! *final* journal line; a torn tail is tolerated (warned), any
//! corruption earlier in the file is a hard error — the operator must
//! explain the hole, the service must not paper over it (a transparency
//! log's entire value is that it cannot quietly lose the middle).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use unidpp_model::{Hash, Timestamp};

use crate::model::CommitRecord;
use crate::tree::MerkleTree;

/// Store-level failures (journal integrity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The journal is not a valid sequenced log (gap, disorder, or
    /// corruption before the final line).
    Journal(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Journal(m) => write!(f, "journal integrity failure: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl std::fmt::Debug for LogStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogStore")
            .field("size", &self.entries.len())
            .field("journaled", &self.journal.is_some())
            .finish()
    }
}

/// The transparency log's durable state.
pub struct LogStore {
    tree: MerkleTree,
    entries: Vec<CommitRecord>,
    journal: Option<File>,
}

impl LogStore {
    /// Fresh store with an optional JSONL journal (opened for append;
    /// existing lines are replayed — a torn final line is tolerated,
    /// anything else is an integrity error).
    pub fn open(journal: Option<&Path>) -> Result<LogStore, StoreError> {
        let mut store = LogStore {
            tree: MerkleTree::new(),
            entries: Vec::new(),
            journal: None,
        };
        if let Some(path) = journal {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        StoreError::Journal(format!("cannot create journal dir: {e}"))
                    })?;
                }
            }
            if path.exists() {
                store.replay(path)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| StoreError::Journal(format!("cannot open journal: {e}")))?;
            store.journal = Some(file);
        }
        Ok(store)
    }

    fn replay(&mut self, path: &Path) -> Result<(), StoreError> {
        let file = File::open(path)
            .map_err(|e| StoreError::Journal(format!("cannot read journal: {e}")))?;
        let mut lines = BufReader::new(file).lines();
        let mut line_no = 0usize;
        // Read one line ahead so a parse failure on the *last* line can
        // be treated as a torn tail rather than corruption.
        let mut pending = lines
            .next()
            .transpose()
            .map_err(|e| StoreError::Journal(format!("journal read error: {e}")))?;
        while let Some(line) = pending.take() {
            line_no += 1;
            let next = lines
                .next()
                .transpose()
                .map_err(|e| StoreError::Journal(format!("journal read error: {e}")))?;
            let is_last = next.is_none();
            let parsed = serde_json::from_str::<serde_json::Value>(&line)
                .map_err(|e| e.to_string())
                .and_then(|v| CommitRecord::from_json(&v));
            match parsed {
                Ok(record) => {
                    if record.seq != self.entries.len() as u64 {
                        return Err(StoreError::Journal(format!(
                            "line {line_no}: seq {} is out of sequence (expected {})",
                            record.seq,
                            self.entries.len()
                        )));
                    }
                    self.apply(&record);
                }
                Err(e) if is_last && !line.trim().is_empty() => {
                    // Torn tail from a crash mid-write: tolerated loudly.
                    eprintln!(
                        "unidpp-log: journal ends with a torn line (kept {} entries): {e}",
                        self.entries.len()
                    );
                }
                Err(e) => {
                    return Err(StoreError::Journal(format!("line {line_no}: {e}")));
                }
            }
            pending = next;
        }
        Ok(())
    }

    /// Apply a record to the derived state (live append and replay
    /// share this path, so replays cannot drift from live behavior).
    fn apply(&mut self, record: &CommitRecord) {
        self.tree.append(&record.commitment);
        self.entries.push(record.clone());
    }

    /// Append one entry; the sequence number is assigned here and is
    /// strictly monotonic under the caller's lock.
    pub fn append(
        &mut self,
        subject: String,
        commitment: Hash,
        salt_ref: Option<u64>,
        logged_at: Timestamp,
    ) -> Result<CommitRecord, StoreError> {
        let record = CommitRecord {
            seq: self.entries.len() as u64,
            logged_at,
            subject,
            commitment,
            salt_ref,
        };
        if let Some(j) = self.journal.as_mut() {
            let line = serde_json::to_string(&record.to_json())
                .map_err(|e| StoreError::Journal(format!("cannot serialize record: {e}")))?;
            writeln!(j, "{line}")
                .and_then(|_| j.flush())
                .map_err(|e| StoreError::Journal(format!("journal write failed: {e}")))?;
        }
        self.apply(&record);
        Ok(record)
    }

    // -- reads -----------------------------------------------------------

    /// Number of sequenced entries (== the next sequence number).
    pub fn size(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The record at `seq`.
    pub fn record(&self, seq: u64) -> Option<&CommitRecord> {
        self.entries.get(seq as usize)
    }

    /// The current tree root (None when empty).
    pub fn root(&self) -> Option<Hash> {
        self.tree.root()
    }

    /// The root of the prefix of the first `s` entries.
    pub fn root_at_size(&self, s: u64) -> Option<Hash> {
        if s > self.size() {
            return None;
        }
        self.tree.root_at_size(s)
    }

    /// Inclusion proof for leaf `seq` against the prefix of size `s`.
    pub fn inclusion_path(&self, seq: u64, s: u64) -> Vec<unidpp_signatif::ProofNode> {
        self.tree.inclusion_path(seq, s)
    }

    /// Consistency proof from the `old_size` prefix to the current tree.
    pub fn consistency_path(&self, old_size: u64) -> Vec<Hash> {
        self.tree.consistency_path(old_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_model::sha256;

    fn commitment(i: u64) -> Hash {
        sha256(&[&i.to_le_bytes()])
    }

    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn journal_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("unidpp-log-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sequencing_is_strictly_monotonic() {
        let mut store = LogStore::open(None).unwrap();
        assert_eq!(store.size(), 0);
        let mut prev = None;
        for i in 0..5u64 {
            let rec = store
                .append(format!("s{i}"), commitment(i), Some(i), ts(100 + i as i64))
                .unwrap();
            assert_eq!(rec.seq, i);
            assert!(prev.map_or(true, |p: u64| rec.seq > p));
            prev = Some(rec.seq);
            assert_eq!(store.record(i).unwrap().subject, format!("s{i}"));
        }
        assert_eq!(store.size(), 5);
        assert!(store.record(5).is_none());
        // Root moves with every append.
        let r4 = store.root().unwrap();
        store
            .append("more".into(), commitment(9), None, ts(200))
            .unwrap();
        assert_ne!(store.root().unwrap(), r4);
    }

    #[test]
    fn journal_round_trip_reproduces_identical_state() {
        let dir = journal_dir("roundtrip");
        let path = dir.join("log.jsonl");
        let logged_at = [ts(1000), ts(1001), ts(1002)];
        {
            let mut store = LogStore::open(Some(&path)).unwrap();
            for i in 0..3u64 {
                store
                    .append(format!("s{i}"), commitment(i), None, logged_at[i as usize])
                    .unwrap();
            }
            assert_eq!(store.size(), 3);
        }
        let mut store = LogStore::open(Some(&path)).unwrap();
        assert_eq!(store.size(), 3);
        assert_eq!(store.root_at_size(3), store.root());
        for i in 0..3u64 {
            let rec = store.record(i).unwrap();
            assert_eq!(rec.seq, i);
            assert_eq!(rec.logged_at, logged_at[i as usize]);
        }
        // Appends continue the sequence after a restart.
        let rec = store
            .append("after".into(), commitment(42), None, ts(2000))
            .unwrap();
        assert_eq!(rec.seq, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_with_a_sequence_gap_is_refused() {
        let dir = journal_dir("gap");
        let path = dir.join("log.jsonl");
        {
            let mut store = LogStore::open(Some(&path)).unwrap();
            store
                .append("a".into(), commitment(0), None, ts(1))
                .unwrap();
        }
        // Tamper: rewrite the only line with seq 5.
        let line = std::fs::read_to_string(&path).unwrap();
        let tampered = line.replace("\"seq\":0", "\"seq\":5");
        std::fs::write(&path, tampered).unwrap();
        let err = LogStore::open(Some(&path)).unwrap_err();
        assert!(matches!(err, StoreError::Journal(_)));
        assert!(err.to_string().contains("out of sequence"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_with_mid_file_corruption_is_refused_but_a_torn_tail_is_tolerated() {
        let dir = journal_dir("torn");
        let path = dir.join("log.jsonl");
        {
            let mut store = LogStore::open(Some(&path)).unwrap();
            for i in 0..3u64 {
                store
                    .append(format!("s{i}"), commitment(i), None, ts(i as i64))
                    .unwrap();
            }
        }
        // Mid-file corruption (line 2 mangled): hard error.
        let good = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = good.lines().collect();
        lines[1] = "{\"seq\": 1, \"broken\""; // still not the last line
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(LogStore::open(Some(&path)).is_err());

        // Torn final line (crash mid-write): tolerated, earlier
        // entries replay.
        let mut lines: Vec<&str> = good.lines().collect();
        lines.push("{\"seq\": 3, \"subject\": \"s3\""); // no closing brace
        std::fs::write(&path, lines.join("\n")).unwrap();
        let mut store = LogStore::open(Some(&path)).unwrap();
        assert_eq!(store.size(), 3);
        // And the sequence continues from the survived prefix.
        let rec = store
            .append("next".into(), commitment(77), None, ts(9))
            .unwrap();
        assert_eq!(rec.seq, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proof_and_consistency_access_after_growth() {
        let mut store = LogStore::open(None).unwrap();
        for i in 0..6u64 {
            store
                .append(format!("s{i}"), commitment(i), None, ts(i as i64))
                .unwrap();
        }
        let head3 = store.root_at_size(3).unwrap();
        // Leaf 1 is still provable at its issuance prefix (size 2) and
        // at the current size.
        assert_eq!(store.inclusion_path(1, 2).len(), 1);
        assert_eq!(store.inclusion_path(1, 6).len(), 3);
        // Consistency from the pinned prefix to the current head.
        let path = store.consistency_path(3);
        assert!(
            unidpp_signatif::verify_consistency(3, &head3, 6, &store.root().unwrap(), &path)
                .is_ok()
        );
        // Prefix roots beyond the tree do not exist.
        assert_eq!(store.root_at_size(7), None);
    }
}

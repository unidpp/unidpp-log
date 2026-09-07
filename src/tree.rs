//! The append-only RFC 6962 Merkle tree with cached complete-subtree
//! levels — the operational core of the log service.
//!
//! All *semantics* are delegated to `unidpp-signatif::anchor` (the
//! Confium transparency-log specification constants `0x01`/`0x02`, the
//! [`SignedTreeHead`] shape and its canonical bytes, the
//! [`verify_inclusion`]/[`verify_consistency`] routines) so this service
//! composes with the signatif trust graph and, later, the Confium
//! `confium-transparency` binding. What the reference implementation
//! lacks — and this module supplies — is the service-shaped structure:
//!
//! - **appends are O(log n)**: complete-subtree hashes are cached per
//!   level as they form (the reference recomputes the whole tree per
//!   root, O(n) per append);
//! - **proofs are O(log n)** for *any* leaf against *any historical
//!   prefix* of the log — the levels are themselves append-only, so a
//!   prefix of the levels is exactly the tree at that size. This is
//!   what makes receipts durable: the receipt issued at append time can
//!   be re-derived byte-identically after a journal replay, and a
//!   consistency proof from any older head to the current one is always
//!   available (STH pinning).
//!
//! Level layout: `levels[k][j]` is the MTH of leaves `[j*2^k,
//! (j+1)*2^k)`; `levels[k]` holds exactly `size >> k` entries — complete
//! subtrees only, orphans are never stored, so every stored hash is a
//! valid MTH of its range and lookups need no shape checks. Correctness
//! is cross-checked against the signatif reference at every size, leaf
//! and prefix in the tests below.

use unidpp_model::Hash;
use unidpp_signatif::anchor::{leaf_hash, node_hash};
use unidpp_signatif::{ProofNode, Side};

/// The RFC 6962 split point: the largest power of two strictly smaller
/// than `n` (undefined for `n < 2`; mirrors the signatif reference).
fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (n - 1).ilog2()
}

/// An append-only Merkle tree over entry commitments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
    size: u64,
}

impl MerkleTree {
    /// New empty tree.
    pub fn new() -> MerkleTree {
        MerkleTree {
            levels: vec![Vec::new()],
            size: 0,
        }
    }

    /// Number of appended entries.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Append one entry commitment; O(log n).
    pub fn append(&mut self, entry: &Hash) {
        self.levels[0].push(leaf_hash(entry));
        self.size += 1;
        // Every trailing zero bit of the new size is a subtree that
        // just completed; fold them up level by level.
        let completed = self.size.trailing_zeros() as usize;
        if self.levels.len() <= completed {
            self.levels.resize_with(completed + 1, Vec::new);
        }
        for k in 0..completed {
            let lvl = &self.levels[k];
            let n = lvl.len();
            let h = node_hash(&lvl[n - 2], &lvl[n - 1]);
            self.levels[k + 1].push(h);
        }
    }

    /// The leaf hash of entry `seq`.
    pub fn leaf_hash_at(&self, seq: u64) -> Option<Hash> {
        (seq < self.size).then(|| self.levels[0][seq as usize])
    }

    /// The root of the whole tree (None when empty).
    pub fn root(&self) -> Option<Hash> {
        self.root_at_size(self.size)
    }

    /// The root of the prefix of the first `s` entries (None for
    /// `s == 0`). Folds the prefix's peaks high-to-low, exactly the
    /// RFC 6962 MTH recursion.
    pub fn root_at_size(&self, s: u64) -> Option<Hash> {
        debug_assert!(s <= self.size, "prefix larger than the tree");
        if s == 0 {
            return None;
        }
        let mut acc: Option<Hash> = None;
        for k in 0..64u32 {
            if (s >> k) & 1 == 0 {
                continue;
            }
            // The peak for set bit k covers [start, start + 2^k) where
            // start = ((s >> k) - 1) << k; its level index is (s>>k)-1.
            let h = self.levels[k as usize][(s >> k) as usize - 1];
            // Peaks fold low-to-high, right-nested — the RFC 6962 MTH
            // recursion MTH([0,n)) = H(MTH([0,k)), MTH([k,n))) with
            // each higher peak becoming the left operand of the
            // accumulated remainder (e.g. n=7:
            // H(p2, H(p1, p0))).
            acc = Some(match acc {
                None => h,
                Some(a) => node_hash(&h, &a),
            });
        }
        acc
    }

    /// Inclusion proof (siblings from the leaf up) for leaf `m` against
    /// the prefix tree of size `s` (`m < s <= size`). Any historical
    /// prefix is provable because the levels are append-only.
    pub fn inclusion_path(&self, m: u64, s: u64) -> Vec<ProofNode> {
        debug_assert!(m < s && s <= self.size, "proof range out of bounds");
        let mut path = Vec::new();
        self.path_into(m, 0, s, &mut path);
        path
    }

    /// Consistency proof (RFC 6962 SUBPROOF node list, deepest first)
    /// that the first `old_size` entries of the *current* tree hash to
    /// the old prefix root. `old_size == 0` yields the empty proof.
    pub fn consistency_path(&self, old_size: u64) -> Vec<Hash> {
        debug_assert!(old_size <= self.size, "consistency backwards");
        let mut path = Vec::new();
        if old_size > 0 {
            self.sub_proof(old_size, 0, self.size, true, &mut path);
        }
        path
    }

    // -- internals --------------------------------------------------------

    /// A cached complete subtree hash: leaves `[j*2^k, (j+1)*2^k)`.
    fn subtree_hash(&self, k: usize, j: u64) -> Hash {
        self.levels[k][j as usize]
    }

    /// MTH of `[lo, lo+len)`. Every call site keeps `lo` aligned to
    /// `split(len)` (the RFC 6962 recursion's right spine), so a
    /// power-of-two length is always an aligned complete subtree — a
    /// direct lookup; anything else splits once and recurses.
    fn range_hash(&self, lo: u64, len: u64) -> Hash {
        if len.is_power_of_two() {
            return self.subtree_hash(len.trailing_zeros() as usize, lo / len);
        }
        let k = split(len);
        let left = self.range_hash(lo, k);
        let right = self.range_hash(lo + k, len - k);
        node_hash(&left, &right)
    }

    /// Inclusion path recursion over `[lo, lo+len)`, pushing siblings
    /// leaf-up (the order `verify_inclusion` consumes).
    fn path_into(&self, m: u64, lo: u64, len: u64, path: &mut Vec<ProofNode>) {
        if len == 1 {
            return;
        }
        let k = split(len);
        if m - lo < k {
            self.path_into(m, lo, k, path);
            let sibling = self.range_hash(lo + k, len - k);
            path.push(ProofNode {
                sibling,
                side: Side::Right,
            });
        } else {
            self.path_into(m, lo + k, len - k, path);
            // The left sibling is the complete subtree [lo, lo+k):
            // level log2(k), index lo/k.
            let sibling = self.subtree_hash(k.trailing_zeros() as usize, lo / k);
            path.push(ProofNode {
                sibling,
                side: Side::Left,
            });
        }
    }

    /// SUBPROOF recursion over `[lo, lo+len)` proving the first `m` of
    /// its leaves, mirroring the signatif generator (which verifies
    /// against) — deepest-first pushes.
    fn sub_proof(&self, m: u64, lo: u64, len: u64, anchored: bool, path: &mut Vec<Hash>) {
        if m == len {
            if !anchored {
                path.push(self.range_hash(lo, len));
            }
            return;
        }
        let k = split(len);
        if m <= k {
            self.sub_proof(m, lo, k, anchored, path);
            path.push(self.range_hash(lo + k, len - k));
        } else {
            self.sub_proof(m - k, lo + k, len - k, false, path);
            path.push(self.range_hash(lo, k));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_model::sha256;
    use unidpp_signatif::anchor::{
        verify_consistency, verify_inclusion, LogEntry, TransparencyLog,
    };

    /// Distinct entry commitments for test trees.
    fn commitment(i: u64) -> Hash {
        sha256(&[b"unidpp-log/test-entry", &i.to_le_bytes()])
    }

    /// Build both trees over the first `n` commitments.
    fn both(n: u64) -> (MerkleTree, TransparencyLog) {
        let mut mine = MerkleTree::new();
        let mut reference = TransparencyLog::new("reference");
        for i in 0..n {
            mine.append(&commitment(i));
            reference.append(LogEntry::public(commitment(i)));
        }
        (mine, reference)
    }

    #[test]
    fn roots_match_the_reference_at_every_size() {
        // Empty tree: no root.
        assert_eq!(MerkleTree::new().root(), None);
        for n in 0..=33u64 {
            let (mine, reference) = both(n);
            assert_eq!(mine.size(), n);
            assert_eq!(mine.root(), reference.root(), "root mismatch at size {n}");
            // Every prefix root also matches (the levels are append-only).
            for s in 0..=n {
                assert_eq!(
                    mine.root_at_size(s),
                    reference.root_at_size(s).ok(),
                    "prefix root mismatch at size {s}/{n}"
                );
            }
        }
    }

    #[test]
    fn inclusion_paths_match_the_reference_for_every_leaf_and_prefix() {
        for n in 1..=17u64 {
            let (mine, _reference) = both(n);
            let root = mine.root().unwrap();
            for m in 0..n {
                for s in (m + 1)..=n {
                    let mine_proof = mine.inclusion_path(m, s);
                    let reference_proof = reference_inclusion_at(m, s);
                    assert_eq!(
                        mine_proof, reference_proof,
                        "inclusion path mismatch for leaf {m} at prefix {s} of {n}"
                    );
                }
                // The current-tree proof verifies with the signatif
                // verifier against the signatif root.
                let proof = mine.inclusion_path(m, n);
                assert!(verify_inclusion(&commitment(m), &wrap(m, n, proof), &root).is_ok());
                // Any other entry's commitment fails.
                if n > 1 {
                    let wrong = commitment((m + 1) % n);
                    let proof = mine.inclusion_path(m, n);
                    assert!(verify_inclusion(&wrong, &wrap(m, n, proof), &root).is_err());
                }
            }
        }
    }

    #[test]
    fn consistency_paths_match_the_reference_for_every_pair() {
        for n in 1..=17u64 {
            let (mine, reference) = both(n);
            let new_root = mine.root().unwrap();
            for old in 0..=n {
                let mine_path = mine.consistency_path(old);
                let reference_path = reference_consistency_at(&reference, old);
                assert_eq!(
                    mine_path, reference_path,
                    "consistency path mismatch for {old} of {n}"
                );
                let old_root = mine.root_at_size(old);
                let verified = verify_consistency(
                    old,
                    old_root.as_ref().unwrap_or(&Hash::ZERO),
                    n,
                    &new_root,
                    &mine_path,
                );
                assert!(verified.is_ok(), "consistency {old}->{n} must verify");
            }
        }
    }

    #[test]
    fn tampered_entries_change_the_root_and_break_proofs() {
        let (mut mine, _) = both(9);
        let root = mine.root().unwrap();
        let proof = mine.inclusion_path(4, 9);
        // A different entry appended later keeps the old proof valid
        // only against the old root; against the new root it fails.
        mine.append(&sha256(&[b"tamper"]));
        let new_root = mine.root().unwrap();
        assert_ne!(root, new_root);
        assert!(verify_inclusion(&commitment(4), &wrap(4, 9, proof.clone()), &new_root).is_err());
        // The old root is still the root of its prefix, and the
        // consistency proof ties it to the new head.
        assert_eq!(mine.root_at_size(9), Some(root));
        let path = mine.consistency_path(9);
        assert!(verify_consistency(9, &root, 10, &new_root, &path).is_ok());
    }

    #[test]
    fn append_cost_is_logarithmic_in_levels_growth() {
        // Structural check: levels[k] holds exactly size >> k entries,
        // so memory stays O(size) hashes (not O(size log size)).
        let mut tree = MerkleTree::new();
        for i in 0..100u64 {
            tree.append(&commitment(i));
            for (k, level) in tree.levels.iter().enumerate() {
                assert_eq!(
                    level.len(),
                    (tree.size() as usize) >> k,
                    "level {k} shape at size {}",
                    tree.size()
                );
            }
        }
        assert_eq!(tree.leaf_hash_at(0), Some(leaf_hash(&commitment(0))));
        assert_eq!(tree.leaf_hash_at(100), None);
    }

    /// Wrap generated nodes into a signatif `InclusionProof`.
    fn wrap(m: u64, s: u64, path: Vec<ProofNode>) -> unidpp_signatif::InclusionProof {
        unidpp_signatif::InclusionProof {
            leaf_index: m,
            tree_size: s,
            path,
        }
    }

    /// Rebuild the signatif reference at a prefix size for inclusion
    /// comparison (the public signatif API proves against the current
    /// tree only; the test rebuilds it at `s`).
    fn reference_inclusion_at(m: u64, s: u64) -> Vec<ProofNode> {
        let mut reference = TransparencyLog::new("prefix");
        for i in 0..s {
            reference.append(LogEntry::public(commitment(i)));
        }
        reference.inclusion_proof(m).unwrap().path
    }

    fn reference_consistency_at(log: &TransparencyLog, old: u64) -> Vec<Hash> {
        log.consistency_proof(old).unwrap().path
    }
}

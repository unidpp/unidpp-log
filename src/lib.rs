//! UniDPP transparency-log anchor service (crate `unidpp-log`).
//!
//! Part of UniDPP (github.com/unidpp): the *minimal credible*
//! transparency-log anchor. `POST /commitments` sequences a subject
//! identity + commitment hash and returns a **signed, sequenced
//! inclusion receipt** (Merkle leaf index, path, signed tree head);
//! `GET /tree/head` exposes the monotonic head; `GET /tree/consistency`
//! proves the current head extends any pinned prefix; `GET
//! /receipt/{seq}` re-serves receipts byte-identically. Makes
//! invariants I4 (append-only, log-anchored event sourcing) and I9
//! (graded trust with verdicts that say what was reachable)
//! demonstrable rather than asserted.
//!
//! Architecture (MECE by module):
//!
//! - [`tree`] — the append-only RFC 6962 Merkle tree with cached
//!   complete-subtree levels (O(log n) appends, roots, and proofs
//!   against any historical prefix); semantics (Confium constants
//!   0x01/0x02, verification routines) delegated to
//!   `unidpp-signatif::anchor`;
//! - [`store`] — sequencing, the JSONL append-only journal, replay
//!   with integrity checks (the registry's proven storage pattern:
//!   the journal *is* the storage);
//! - [`model`] — the commit record and the receipt (derived state:
//!   byte-identical under journal replay), plus wire views and the
//!   verifier-side rebuild helpers;
//! - [`keyring`] — the operator key (env-seeded; signatif
//!   deterministic key derivation) and its public discovery shape;
//! - [`api`] — the axum HTTP surface, `Config`, `TestServer`.
//!
//! One honest operator now (M=1 of K=1); the M-of-K log-of-logs quorum
//! is designed in the README and already computable via
//! `unidpp_signatif::LogOfLogs` / `verify_master_quorum`. Server
//! conventions mirror unidpp-registry / unidpp-resolver: axum over
//! tokio, dependency-light, no database.

// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]

pub mod api;
pub mod keyring;
pub mod model;
pub mod store;
pub mod tree;
pub mod tsa;

pub use api::{run, Config, TestServer};
pub use keyring::{Operator, OperatorConfig};
pub use model::{CommitRecord, Receipt};
pub use store::{LogStore, StoreError};
pub use tree::MerkleTree;

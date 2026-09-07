# unidpp-log

The UniDPP **transparency-log anchor service**: a minimal, honest
operator that sequences Merkle commitments and issues signed
inclusion receipts. Part of [UniDPP](https://github.com/unidpp);
part of UniDPP `10-remaining-tasks-definitive.md` item 21.
Apache-2.0.

## What this is (and what it deliberately is not)

This binary is **"one honest operator now"** (M-of-K with M=K=1) — a
single node that can vouch, provably and forever, for *the order and
membership* of any commitment someone gave it. It is the missing
trust-anchoring primitive that turns UniDPP's I4/I9 invariants
("append-only, log-anchored event sourcing"; "graded trust with
verdicts that say what was reachable") from assertions into
demonstrable facts.

This binary is **not** the final M-of-K quorum. operator-model §6
documents the Cloudflare succession path (Durable Objects for
sequencing + R2 for segments) and signatif already implements the
master-quorum verification (`unidpp_signatif::anchor::LogOfLogs`,
`verify_master_quorum`). When we are ready to federate, this binary
runs as one of the K independent witnesses and ships its STHs into
the master log; the protocol does not change.

## The B4 border moment

The exemplar's [story beat B4 — *the border moment (offline, degraded
origins)*](https://github.com/unidpp) is what this service exists to
back. Quoting from the exemplar:

> **Scene.** Customs / verification terminal, garden-variety offline
> window: Shenzhen host unreachable, EU registry mid-outage. The
> officer scans the frame QR / taps NFC.
>
> **System.** Tier-A carrier minimum (MRZ-analog bytes): identity,
> status, critical flags, validity, multi-suite compressed signatures.
> The **resolver's cached linkset** points at the national mirror;
> the **transparency-log inclusion proof** (from the mirror's log
> copy) substitutes for the origin. **Verdict: PASS, as-of stamped,
> coverage report states exactly what was not reachable**. The three
> readings named (cryptographic / evidentiary / current-state).

This service supplies the third piece — the *substitute for the
origin* — in three concrete steps:

1. When the issuer mints a passport it also POSTs a salted commitment
 to one (or many) transparency logs. Each service hands back a
 **signed inclusion receipt** bound to a specific operator key.
2. The verifier carries the passport's **Tier-A bytes** offline, plus
 the inclusion receipt and the log's operator public key (pinned in
 a discovery document the resolver published in advance, or held in
 the trust bundle). Cached locally — no network required.
3. As the underlying log grows (more issuers commit, more entries
 stream in), the receipt's pinned head moves out of date but its
 commitment does not: `GET /tree/consistency?from=<receipt_size>`
 returns the RFC 6962 consistency proof that ties the receipt's
 pinned root to the current signed tree head. Verification rebuilds
 without ever touching the issuer.

The result is a **verifier with offline origin**: the receipt is
self-verifying against the operator's published key, and a tamper by
the origin (or the mirror) breaks a *public, repudiable* consistency
proof rather than a silent wrong answer. Honesty is the feature — the
EN-only world gives either a red error page or a silently-trusting
green page. This one degrades explicitly.

## How a verifier uses a receipt

The full receipt is the JSON body of `POST /commitments` (or
`GET /receipt/{seq}`). It carries:

- `commitment` — the anchored 64-hex SHA-256 value (salted by the issuer);
- `inclusion` — the RFC 6962 inclusion proof at the issuance tree size
 (leaf index, tree size, leaf hash, sibling chain);
- `tree_head` — the operator's signed tree head at issuance
 (log id, tree size, timestamp, root, signature over all four);
- `operator` — the operator public key (suite, key id, raw hex +
 fingerprint) so the receipt is self-contained for an offline
 verifier that trusts the key it already holds.

Verification (the verifier's whole job):

```rust
// 1. The head's signature must verify under the operator key.
sth.verify(operator)?;
// 2. The inclusion proof must reconstruct the head's root.
verify_inclusion(commitment, proof, sth.root)?;
// 3. If the log has grown since issuance, verify the consistency
// proof from sth.tree_size ties sth.root to the current head.
verify_consistency(sth.tree_size, &sth.root, new_size, &new_root, &path)?;
```

All three primitives live in `unidpp-signatif::anchor`; the integration
test
`integration::append_returns_a_receipt_that_verifies_against_the_head`
is the executable form of the same check.

## Endpoints

Public (reads):

| Endpoint | Meaning |
|---|---|
| `GET /` | discovery document (endpoints, operator public key, conventions, M-of-K roadmap) |
| `GET /healthz` | liveness |
| `GET /tree/head` | the latest signed tree head (append-time checkpoint, monotonic in `tree_size`) |
| `GET /tree/consistency?from=N` | RFC 6962 consistency proof from the prefix of size `N` to the current head |
| `GET /receipt/{seq}` | re-serve the receipt for entry `seq` (byte-identical to its `POST /commitments` response) |

Authenticated (Bearer `UNIDPP_LOG_APPEND_TOKEN` when set; open in dev mode):

| Endpoint | Body | Meaning |
|---|---|---|
| `POST /commitments` | `{subject, commitment (64-hex), salt_ref?}` | sequence one commitment; return the signed inclusion receipt |

There is **deliberately no `GET /entries` or similar**: the log is
verifiable without being browsable (I12). The journal file (when
persisted) is the audit interface — it is operator-side material,
not a public enumeration surface.

## Service conventions

Axum 0.8 over tokio; dependency-light (axum, tokio, serde,
serde_json — plus the local `unidpp-model` and `unidpp-signatif`
crust for the hash/canonical/sth machinery). No tracing, no
metrics, no TLS stack, no database — the audit journal is the
storage (the registry's proven pattern: the log *is* the storage).

The Merkle tree is RFC 6962 with the Confium transparency-log
constants `0x01` (leaf domain) and `0x02` (internal node domain),
inherited from `unidpp-signatif::anchor`. STHs are signed with the
signatif `SigningDomain::TreeHead` over `SignedTreeHead::canonical_bytes`
— the same wire shape and verification routines the rest of the
trust graph uses.

The service exposes a single `/commitments` writer and an in-process
`Mutex<LogStore>` over it; sequencing is strictly monotonic by
construction (`append` assigns `seq = entries.len()` under the lock,
never reuses a number, refuses to start on a journal with a sequence
gap).

### Storage choice

In-memory tree plus an optional JSONL append-only journal
(`UNIDPP_LOG_STATE_FILE`, replayed on start). Rationale: the log
*is* the journal — every append is one line carrying the full record
(`{seq, logged_at, subject, commitment, salt_ref}`), so journal
replay reconstructs identical state. Sequence numbers, journaled
timestamps, and deterministic signature suites (Ed25519 is
deterministic by construction; ECDSA-P256 via RFC 6979) together
guarantee the restart test's property: **byte-identical heads and
receipts after replay**.

A torn **final** journal line (crash mid-write) is tolerated with a
loud warning; any corruption **earlier** in the file is a hard
integrity error — a transparency log's whole value is that it cannot
quietly lose the middle. Operator must explain the hole; the service
must not paper over it.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `UNIDPP_LOG_BIND` | `127.0.0.1:8092` | listen address |
| `UNIDPP_LOG_ID` | `unidpp-log-1` | the operator-assigned log identity (pinned in receipts and discovery) |
| `UNIDPP_LOG_SUITE` | `ed25519` | `ed25519` or `ecdsa-p256` (both real crypto via signatif); SM2 and ML-DSA are framing-only here |
| `UNIDPP_LOG_SEED` | `unidpp-log-dev-seed-v1` | **DEV-ONLY seed** that drives `KeyPair::seeded`; the README warns this is unsafe for production (every consumer produces the same key). Production keys must come from a CSPRNG and live in an HSM. |
| `UNIDPP_LOG_STATE_FILE` | unset (in-memory) | path to the JSONL journal |
| `UNIDPP_LOG_APPEND_TOKEN` | unset (open) | Bearer token required on `POST /commitments` when set |

## M-of-K quorum design (the succession story)

operator-model §6 sketches the Cloudflare deployment
(`<https://unidpp.org>` zone active, platform greenfield). The
phased target:

1. **Now (this binary)**: M=1 of K=1. One honest operator. Receipts
 are verifiable against one key, forever; the journal does not
 lie about what the operator sequenced.
2. **Wave 4c**: M-of-K independent witness logs. This binary runs
 as one of the K witnesses, signs the same STHs into a Cloudflare
 **Durable Object** (the per-log sequencer) and writes sealed
 segments into **R2** (the durable, append-only store); the
 uniformity of the append shape (`{seq, logged_at, commitment}`)
 means the R2 segment files are identical in format to the JSONL
 journal here — it is a storage-port, not a model-port.
3. **Master list**: the witnesses' STHs are anchored into a master
 log (`unidpp_signatif::LogOfLogs`, `verify_master_quorum`).
 Admission, rotation, and ejection are threshold ceremonies;
 distrust windows cascade correctly (void-ab-initio semantics
 implemented and tested in unidpp-signatif). Verifiers pin M of
 the K distinct witnesses and check the master root, the same way
 they currently pin this single operator.

The wire formats — STH bytes, inclusion proof shape, journal line
schema — are all chosen so step 1's receipts are *already* reusable
as witness material in step 3. The semantic upgrade is the
*multi-signature quorum*, not the receipt.

## Build & test

```
cargo fmt --check # clean
cargo build # zero warnings (RUSTFLAGS="-D warnings" passes)
cargo test # 17 unit + 10 integration, zero warnings
cargo clippy --all-targets -- -D warnings # clean
```

Unit tests cover the model semantics (receipt assembly → STH
signature verifies under operator key → inclusion proof reconstructs
the root; the tamper and wire-round-trip stories); the in-memory
store (strictly monotonic sequencing, journal round-trip,
sequence-gap refusal, torn-tail tolerance, journal replay
reproduces identical roots and proofs at any historical prefix);
and the Merkle tree (root/inclusion/consistency paths equal the
signatif reference at every size up to 33, every leaf and every
prefix, O(log n) level structure verified at every step).

Integration tests speak real HTTP against servers spawned on
ephemeral ports: discovery + healthz + empty-head; append → receipt
verifies against the operator key and against the head; monotonic
heads tied by consistency proofs; `GET /receipt/{seq}` reservations
and validation; Bearer auth on `POST /commitments`; restart-replay
byte-identical heads and receipts; tamper detection (a journaled
entry rewritten in place → new head root differs, the issued
receipt's inclusion proof no longer reconstructs any honest root,
the pinned STH still verifies cryptographically but the
consistency proof from the pinned size fails); torn-tail tolerated,
sequence gaps refused; ECDSA-P256 operator suite; receipt
timestamps match journal stamps.

## Deviations from the rubric (documented)

- **No `GET /entries` or equivalents.** I12 (enumeration resistance):
 a transparency log is verifiable without being browsable.
 Submitters carry their subject identity; the log carries only the
 commitment + the opaque `salt_ref` they supplied.
- **No clock-interval checkpointing.** Heads are signed at append
 time only; a larger deployment would checkpoint on a clock
 interval in addition (a pure addition of more valid heads; the
 verification protocol does not change).
- **No M-of-K today.** The master-quorum verification is implemented
 in `unidpp-signatif` and composed into this binary's wire formats
 (STH, inclusion proof, log-of-logs commitment); running multiple
 instances and aggregating is a deployment step, not a code step.
- **Logs anchor commitments, not facts.** The submitter's `subject`
 field is operator-side record-keeping and rides in the journal but
 is *never* hashed into the tree (the UniDPP design framework enumeration resistance).

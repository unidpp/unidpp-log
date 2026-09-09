//! HTTP surface: axum router, handlers, `Config`, `TestServer`.
//!
//! Endpoints (the UniDPP service design — the minimal credible anchor):
//!
//! - `POST /commitments` — sequence a subject identity + commitment
//!   hash; returns the signed inclusion receipt;
//! - `GET /tree/head` — the latest signed tree head (append-time
//!   checkpoint, monotonic in size);
//! - `GET /tree/consistency?from=` — consistency proof from a pinned
//!   prefix to the current head (what lets a receipt stay valid as the
//!   tree grows);
//! - `GET /receipt/{seq}` — re-serve a receipt byte-identically;
//! - `GET /` — discovery (incl. the operator public key);
//! - `GET /healthz` — liveness.
//!
//! Deliberately absent: any enumeration surface (no "list entries") —
//! a transparency log is verifiable without being browsable (I12). The
//! journal file and receipts are the audit interfaces.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::keyring::{Operator, OperatorConfig};
use crate::model::{current_head, hex_encode, Receipt};
use crate::store::{LogStore, StoreError};
use unidpp_model::{Hash, Timestamp};

/// Deployment configuration (environment-driven; see `main.rs`).
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub operator: OperatorConfig,
    /// Optional Bearer token guarding appends; `None` = open (dev).
    pub append_token: Option<String>,
    /// Optional JSONL journal file (append-only, replayed on start).
    pub state_file: Option<PathBuf>,
    /// Optional RFC 3161 TSA endpoint (`UNIDPP_LOG_EXTERNAL_TSA_URL`):
    /// every append's tree head is also anchored externally. An
    /// unreachable TSA degrades explicitly — never silently skipped.
    pub external_tsa_url: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8092".parse().unwrap(),
            operator: OperatorConfig {
                log_id: OperatorConfig::default_log_id(),
                suite: unidpp_signatif::sign::Suite::Ed25519,
                seed: OperatorConfig::default_dev_seed(),
            },
            append_token: None,
            state_file: None,
            external_tsa_url: None,
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let mut c = Config::default();
        if let Ok(bind) = std::env::var("UNIDPP_LOG_BIND") {
            match bind.parse() {
                Ok(addr) => c.bind = addr,
                Err(_) => eprintln!("unidpp-log: ignoring bad UNIDPP_LOG_BIND `{bind}`"),
            }
        }
        c.operator = OperatorConfig::from_env()?;
        if let Ok(token) = std::env::var("UNIDPP_LOG_APPEND_TOKEN") {
            if !token.is_empty() {
                c.append_token = Some(token);
            }
        }
        if let Ok(path) = std::env::var("UNIDPP_LOG_STATE_FILE") {
            if !path.is_empty() {
                c.state_file = Some(PathBuf::from(path));
            }
        }
        if let Ok(url) = std::env::var("UNIDPP_LOG_EXTERNAL_TSA_URL") {
            if !url.trim().is_empty() {
                c.external_tsa_url = Some(url.trim().to_string());
            }
        }
        Ok(c)
    }
}

/// Shared application state: the operator keyring and the log store
/// (mutex-guarded; sequencing is strictly monotonic under the lock).
pub struct AppState {
    pub config: Config,
    pub operator: Operator,
    pub store: Mutex<LogStore>,
    /// The latest external-anchor submission (anchored response or the
    /// explicit unreachable degradation).
    pub tsa: Mutex<Option<crate::tsa::TsaRecord>>,
}

impl AppState {
    pub fn new(config: Config) -> Result<AppState, StoreError> {
        let operator =
            Operator::from_config(config.operator.clone()).map_err(StoreError::Journal)?;
        let store = LogStore::open(config.state_file.as_deref())?;
        Ok(AppState {
            config,
            operator,
            store: Mutex::new(store),
            tsa: Mutex::new(None),
        })
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn build_response(status: StatusCode, headers: Vec<(String, String)>, body: String) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    build_response(
        status,
        vec![("content-type".into(), "application/json".into())],
        serde_json::to_string_pretty(body).unwrap(),
    )
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    json_response(status, &json!({ "error": msg }))
}

fn bad_request(msg: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, msg)
}

fn not_found(msg: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, msg)
}

fn unauthorized() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn store_error(e: StoreError) -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

// ---------------------------------------------------------------------------
// Body parsing
// ---------------------------------------------------------------------------

fn parse_body(body: &str) -> Result<Value, Response> {
    serde_json::from_str(body).map_err(|e| bad_request(&format!("invalid JSON body: {e}")))
}

fn req_str(v: &Value, key: &str) -> Result<String, Response> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| bad_request(&format!("`{key}` is required")))
}

fn opt_u64(v: &Value, key: &str) -> Result<Option<u64>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| bad_request(&format!("`{key}` must be an unsigned integer"))),
        Some(_) => Err(bad_request(&format!("`{key}` must be an unsigned integer"))),
    }
}

fn req_commitment(v: &Value) -> Result<Hash, Response> {
    req_str(v, "commitment").and_then(|s| {
        Hash::from_hex(&s)
            .ok_or_else(|| bad_request("`commitment` must be a 64-character hex SHA-256 value"))
    })
}

fn require_append(app: &AppState, headers: &HeaderMap) -> Option<Response> {
    let token = app.config.append_token.as_ref()?;
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if got == Some(token.as_str()) {
        None
    } else {
        Some(unauthorized())
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn discovery(State(app): State<Arc<AppState>>) -> Response {
    let doc = json!({
        "service": "unidpp-log",
        "version": env!("CARGO_PKG_VERSION"),
        "build_id": option_env!("UNIDPP_BUILD_ID").unwrap_or("dev"),
        "description": "UniDPP transparency-log anchor: sequenced Merkle commitments with signed inclusion receipts and monotonic signed tree heads",
        "log_id": app.operator.log_id(),
        "tree": "RFC 6962 Merkle tree over sequenced commitment leaves (Confium transparency-log constants 0x01/0x02, via unidpp-signatif)",
        "endpoints": {
            "commit": "POST /commitments",
            "tree_head": "GET /tree/head",
            "consistency": "GET /tree/consistency?from=",
            "receipt": "GET /receipt/{seq}",
            "health": "GET /healthz"
        },
        "operator": app.operator.info(),
        "receipt_verification": [
            "1. verify tree_head.signature against the operator public key (this document)",
            "2. verify the inclusion proof reconstructs tree_head.root from the anchored commitment",
            "3. as the tree grows, GET /tree/consistency?from=<receipt tree_size> and verify it ties the receipt's pinned root to the current head"
        ],
        "invariants": {
            "sequencing": "sequence numbers are strictly monotonic (0, 1, 2, ...); the journal replays with the same discipline",
            "heads": "a head is signed at append time over tree_size + root + timestamp; heads never move backwards",
            "enumeration": "none (I12): no endpoint lists subjects or commitments; the log is verifiable without being browsable"
        },
        "quorum": {
            "now": "M=1 of K=1 — one honest operator (see README)",
            "later": "M-of-K log-of-logs per the UniDPP operator model 6; unidpp-signatif already implements the master quorum verification",
            "deployment": "Durable Objects (sequencing) + R2 segments on Cloudflare is the documented succession path"
        }
    });
    json_response(StatusCode::OK, &doc)
}

async fn healthz() -> Response {
    build_response(
        StatusCode::OK,
        vec![("content-type".into(), "text/plain".into())],
        "ok".into(),
    )
}

/// POST /commitments — `{subject, commitment (64-hex), salt_ref?}` →
/// the signed, sequenced inclusion receipt.
async fn commit(State(app): State<Arc<AppState>>, headers: HeaderMap, body: String) -> Response {
    if let Some(deny) = require_append(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let subject = match req_str(&v, "subject") {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if subject.len() > 512 {
        return bad_request("`subject` must be at most 512 characters");
    }
    let commitment = match req_commitment(&v) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let salt_ref = match opt_u64(&v, "salt_ref") {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let outcome = {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .append(subject, commitment, salt_ref, Timestamp::now())
            .map(|record| {
                Receipt::of(
                    &store,
                    record.seq,
                    app.operator.log_id(),
                    app.operator.key(),
                )
                .expect("the just-appended entry is always provable")
                .to_json(&app.operator.info())
            })
    };
    // The external anchor is additive and best-effort-by-degradation:
    // it never gates the append, and its outcome (anchored response or
    // explicit unreachable) is stored for the head view.
    if let Some(tsa_url) = app.config.external_tsa_url.clone() {
        let head = {
            let store = app.store.lock().expect("store poisoned");
            current_head(&store, app.operator.log_id(), app.operator.key())
        };
        if let Some(sth) = head {
            let anchored = sth.clone().anchored_externally(
                unidpp_signatif::anchor::ExternalAnchorMethod::Rfc3161 {
                    tsa_url: tsa_url.clone(),
                },
            );
            let Some(anchor) = anchored.external_anchor.as_ref() else {
                unreachable!("anchored_externally attaches the anchor");
            };
            let mut record = crate::tsa::submit_anchor(anchor, &tsa_url).await;
            record.tree_size = sth.tree_size;
            *app.tsa.lock().expect("tsa poisoned") = Some(record);
        }
    }
    match outcome {
        Ok(receipt) => json_response(StatusCode::CREATED, &receipt),
        Err(e) => store_error(e),
    }
}

/// GET /tree/head — the latest signed tree head (append-time
/// checkpoint; monotonic in size; byte-identical across restarts).
async fn tree_head(State(app): State<Arc<AppState>>) -> Response {
    let outcome = {
        let store = app.store.lock().expect("store poisoned");
        current_head(&store, app.operator.log_id(), app.operator.key())
    };
    let body = match outcome {
        Some(sth) => json!({
            "log_id": sth.log_id,
            "tree_size": sth.tree_size,
            "timestamp": sth.timestamp.to_string(),
            "root": sth.root.hex(),
            "signature": {
                "suite": sth.signature.suite.as_str(),
                "key_id": sth.signature.key_id.as_str(),
                "value": sth.signature
                    .signature
                    .as_ref()
                    .map(|v| hex_encode(v))
                    .unwrap_or_default()
            },
            "external_anchor": external_anchor_view(&app, &sth),
            "operator": app.operator.info(),
        }),
        None => json!({
            "log_id": app.operator.log_id(),
            "tree_size": 0,
            "timestamp": Value::Null,
            "root": Value::Null,
            "signature": Value::Null,
            "operator": app.operator.info(),
        }),
    };
    json_response(StatusCode::OK, &body)
}

/// The external-anchor view for the head response: the RFC 3161
/// commitment (digest + payload, from the signatif anchor) plus the
/// submission record — `anchored` with the stored response, or the
/// explicit `unreachable` degradation with its retry hint.
fn external_anchor_view(
    app: &Arc<AppState>,
    sth: &unidpp_signatif::anchor::SignedTreeHead,
) -> Value {
    let record = app.tsa.lock().expect("tsa poisoned").clone();
    let Some(record) = record else {
        return json!({ "status": "not-configured" });
    };
    if record.tree_size != sth.tree_size {
        // A stale record (an older head's submission): report it as
        // such rather than claiming this head is anchored.
        return json!({
            "status": "stale",
            "anchored_tree_size": record.tree_size,
            "detail": "the record anchors an earlier head",
        });
    }
    json!({
        "method": "rfc3161",
        "digest": record.digest.hex(),
        "submission": record.to_wire(),
    })
}

/// GET /tree/consistency?from=N — RFC 6962 consistency proof from the
/// prefix of size N to the current head (verify with
/// `unidpp_signatif::verify_consistency` against the pinned old root
/// and the current head's root).
async fn tree_consistency(
    State(app): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let from = match params.get("from").map(|s| s.trim()) {
        None | Some("") => return bad_request("`from` is required (the pinned tree size)"),
        Some(s) => match s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return bad_request("`from` must be an unsigned integer"),
        },
    };
    let outcome = {
        let store = app.store.lock().expect("store poisoned");
        if from > store.size() {
            Err(format!(
                "`from` ({from}) is larger than the current tree size ({})",
                store.size()
            ))
        } else {
            Ok((
                store.size(),
                store.root(),
                store.root_at_size(from),
                store.consistency_path(from),
            ))
        }
    };
    match outcome {
        Ok((size, root, old_root, path)) => json_response(
            StatusCode::OK,
            &json!({
                "log_id": app.operator.log_id(),
                "old_size": from,
                "old_root": old_root.map(|h| h.hex()),
                "new_size": size,
                "new_root": root.map(|h| h.hex()),
                "path": path.iter().map(|h| h.hex()).collect::<Vec<_>>(),
                "operator": app.operator.info(),
            }),
        ),
        Err(msg) => bad_request(&msg),
    }
}

/// GET /receipt/{seq} — re-serve a receipt (byte-identical to the
/// POST /commitments response; derived state, deterministic under
/// journal replay).
async fn receipt(State(app): State<Arc<AppState>>, Path(seq): Path<String>) -> Response {
    let seq: u64 = match seq.trim().parse() {
        Ok(n) => n,
        Err(_) => return bad_request("`seq` must be an unsigned integer"),
    };
    let outcome = {
        let store = app.store.lock().expect("store poisoned");
        Receipt::of(&store, seq, app.operator.log_id(), app.operator.key())
    };
    match outcome {
        Some(r) => json_response(StatusCode::OK, &r.to_json(&app.operator.info())),
        None => not_found(&format!("no receipt for seq {seq}")),
    }
}

// ---------------------------------------------------------------------------
// Route wiring
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/commitments", post(commit))
        .route("/tree/head", get(tree_head))
        .route("/tree/consistency", get(tree_consistency))
        .route("/receipt/{seq}", get(receipt))
        .with_state(app)
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let app = Arc::new(AppState::new(config.clone())?);
    let listener = TcpListener::bind(config.bind).await?;
    eprintln!(
        "unidpp-log listening on http://{} (log_id `{}`, tree_size {})",
        config.bind,
        app.operator.log_id(),
        app.store.lock().expect("store poisoned").size()
    );
    axum::serve(listener, router(app)).await?;
    Ok(())
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    pub addr: SocketAddr,
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    pub async fn spawn(config: Config) -> Result<TestServer, StoreError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| StoreError::Journal(format!("cannot bind test listener: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| StoreError::Journal(format!("no local addr: {e}")))?;
        let app = Arc::new(AppState::new(config)?);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-log: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    /// Stop the server and wait until its task has exited.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

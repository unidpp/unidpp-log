//! Operator keyring: the single trust anchor the log service exposes.
//!
//! `unidpp-signatif` owns the key material (signed seed derivation,
//! content-derived key ids) and supplies two real-crypto suites
//! (Ed25519, ECDSA-P256). This module wraps the operator key with the
//! deployment-time configuration (log id, suite, seed material) and
//! the public-facing discovery shape (raw public key + key id +
//! fingerprint) verifiers need to validate signed tree heads.
//!
//! **Production keys must come from a CSPRNG and live in an HSM** (the
//! signatif `KeyPair::seeded` model is exactly the test/ceremony
//! discipline); this module's env-driven seed is the boot path, with a
//! clearly-labelled dev default that the README warns against.

use serde_json::{json, Value};
use unidpp_signatif::keyring::{KeyId, KeyPair, PublicKey};
use unidpp_signatif::sign::Suite;

/// All configuration needed to bring up the operator key at start.
#[derive(Debug, Clone)]
pub struct OperatorConfig {
    pub log_id: String,
    pub suite: Suite,
    /// Seed material (hashed by `KeyPair::seeded`). The cleartext seed
    /// never leaves the secret boundary — the public discovery shape
    /// is the only thing published.
    pub seed: String,
}

impl OperatorConfig {
    /// Parse `UNIDPP_LOG_SUITE` (default `ed25519`).
    pub fn parse_suite(token: &str) -> Result<Suite, String> {
        Suite::parse_token(token).map_err(|e| format!("`{}`: {e}", OperatorConfig::suite_env()))
    }

    /// Parse the full operator config from environment, or return
    /// `Err` with a human-readable reason (so `main` can print and exit
    /// without crashing on bad config).
    pub fn from_env() -> Result<OperatorConfig, String> {
        let log_id = std::env::var(OperatorConfig::id_env())
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(OperatorConfig::default_log_id);
        if log_id.len() > 64 || !log_id.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return Err(format!(
                "`{}` must be 1-64 printable ASCII characters",
                OperatorConfig::id_env()
            ));
        }
        let suite = match std::env::var(OperatorConfig::suite_env()) {
            Ok(s) if !s.trim().is_empty() => OperatorConfig::parse_suite(&s)?,
            _ => Suite::Ed25519,
        };
        let seed = std::env::var(OperatorConfig::seed_env())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(OperatorConfig::default_dev_seed);
        Ok(OperatorConfig {
            log_id,
            suite,
            seed,
        })
    }

    /// Env var naming (collected here so the README and `main` stay in
    /// sync with the loader).
    pub fn id_env() -> &'static str {
        "UNIDPP_LOG_ID"
    }
    pub fn suite_env() -> &'static str {
        "UNIDPP_LOG_SUITE"
    }
    pub fn seed_env() -> &'static str {
        "UNIDPP_LOG_SEED"
    }

    pub fn default_log_id() -> String {
        "unidpp-log-1".to_string()
    }
    /// A clearly-labelled dev seed — the README warns it is unsafe for
    /// production (every consumer produces the same key).
    pub fn default_dev_seed() -> String {
        "unidpp-log-dev-seed-v1".to_string()
    }
}

/// The operator: the parsed config and the resulting deterministic
/// key pair. Cheap to build; constructed once at start.
pub struct Operator {
    config: OperatorConfig,
    key: KeyPair,
    public: PublicKey,
}

impl Operator {
    pub fn from_config(config: OperatorConfig) -> Result<Operator, String> {
        let key = KeyPair::seeded(config.suite, config.seed.as_bytes())
            .map_err(|e| format!("could not derive the operator key: {e}"))?;
        let public = *key.public();
        Ok(Operator {
            config,
            key,
            public,
        })
    }

    pub fn key(&self) -> &KeyPair {
        &self.key
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn log_id(&self) -> &str {
        &self.config.log_id
    }

    pub fn suite(&self) -> Suite {
        self.config.suite
    }

    pub fn key_id(&self) -> &KeyId {
        self.key.key_id()
    }

    /// Public-facing operator description for the discovery document
    /// and receipt headers: verifiers call into this to verify signed
    /// tree heads against the running operator.
    pub fn info(&self) -> Value {
        let mut hex = String::with_capacity(self.public.as_bytes().len() * 2);
        for byte in self.public.as_bytes() {
            hex.push_str(&format!("{byte:02x}"));
        }
        json!({
            "log_id": self.config.log_id,
            "suite": self.config.suite.as_str(),
            "key_id": self.key.key_id().as_str(),
            "public_key_hex": hex,
            "fingerprint": self.public.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_signatif::keyring::KeyPair;

    /// The dev default seed is reproducible — the tests assert that so
    /// a passing restart yields the same operator (and so the same
    /// operator key shows up in the discovery document across runs
    /// unless the seed changes).
    #[test]
    fn default_seed_is_reproducible() {
        let k1 = KeyPair::seeded(
            Suite::Ed25519,
            OperatorConfig::default_dev_seed().as_bytes(),
        )
        .unwrap();
        let k2 = KeyPair::seeded(
            Suite::Ed25519,
            OperatorConfig::default_dev_seed().as_bytes(),
        )
        .unwrap();
        assert_eq!(k1.key_id(), k2.key_id());
        assert_eq!(k1.public(), k2.public());
    }

    #[test]
    fn bad_suite_is_rejected() {
        let err = OperatorConfig::parse_suite("nope").unwrap_err();
        assert!(err.contains("suite"));
    }

    #[test]
    fn info_carries_the_raw_public_key() {
        let cfg = OperatorConfig {
            log_id: "t".into(),
            suite: Suite::Ed25519,
            seed: "unit-test-seed".into(),
        };
        let op = Operator::from_config(cfg).unwrap();
        let info = op.info();
        // The hex decodes back to the same public key (any verifier can
        // reconstruct PublicKey::from_bytes from the discovery doc).
        let hex = info["public_key_hex"].as_str().unwrap();
        let bytes = decode_hex(hex);
        let restored = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(restored, *op.public());
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
}

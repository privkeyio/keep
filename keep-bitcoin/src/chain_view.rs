// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Chain-view abstraction for responder-side prevout validation (#502).
//!
//! A responder trusts the proposer to hand it a PSBT whose `witness_utxo`
//! values reflect the real on-chain UTXOs it is being asked to spend.
//! BIP-341 taproot signatures commit to every input's prevout amount, so an
//! understated amount produces a signature that is valid on-chain but
//! bypasses every fee cap the responder computed against the (lied about)
//! claim: the destination check in `validate_migration_sweep_destination`
//! catches the receiving script, but a proposer can still drain the delta
//! between the honest amount and the declared amount into fees.
//!
//! [`ChainView`] is the read-only interface responders use to fetch the
//! authoritative amount+script for each PSBT input. Implementations can
//! back it with an esplora/blockstream HTTP endpoint (the built-in
//! [`EsploraChainView`], gated on the `esplora-chain-view` feature), a
//! bitcoind JSON-RPC client, or a mock for tests.
//!
//! Signing sites invoke [`validate_prevout_amounts_against_chain`] before
//! forwarding a PSBT sighash. A mismatch aborts the signing with the same
//! shape of `REFUSED:` error the destination guard uses, so operators see
//! the two defenses side by side.

use bitcoin::{OutPoint, Psbt, ScriptBuf, TxOut};

/// Read-only view resolving an outpoint's committed `(value, script_pubkey)`
/// for #502 prevout validation.
///
/// Implementations MUST return the exact `(value_sats, script_pubkey)` the
/// outpoint's transaction commits to, so a responder can compare it against
/// the PSBT's proposer-supplied `witness_utxo`. Amounts and scripts are
/// committed to the txid, so this is authoritative for the amount check.
/// It does NOT prove the outpoint is unspent or confirmed. Returning a
/// stale or approximate value defeats the check.
pub trait ChainView {
    /// Fetch the committed `(value, script_pubkey)` of `outpoint`. Returns
    /// `ChainViewError::NotFound` when the transaction or output does not
    /// exist on the chain view's backing endpoint (itself refusal-worthy:
    /// the responder cannot run the amount check without an authoritative
    /// prevout). The returned amount is authoritative because it is
    /// committed to the txid; this does not attest that the output is
    /// unspent.
    fn get_prevout(&self, outpoint: OutPoint) -> Result<TxOut, ChainViewError>;
}

/// Errors surfaced by a [`ChainView`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum ChainViewError {
    /// The requested outpoint is not visible on the chain view's endpoint.
    #[error("outpoint {txid}:{vout} not found on chain view")]
    NotFound { txid: bitcoin::Txid, vout: u32 },
    /// Network / transport error contacting the backing endpoint. Callers
    /// MUST NOT treat this as "no divergence"; it's an inconclusive read and
    /// the responder is expected to refuse signing.
    #[error("chain view transport error: {0}")]
    Transport(String),
    /// The backing endpoint returned a malformed response the client could
    /// not decode.
    #[error("chain view response decode error: {0}")]
    Decode(String),
    /// The chain view was misconfigured (e.g. an invalid base URL).
    #[error("chain view configuration error: {0}")]
    Config(String),
}

/// Recompute-and-compare the proposer-declared prevout amount and script of
/// every PSBT input against the authoritative chain view. Returns `Ok(())`
/// only when every input's `witness_utxo` matches on both fields.
///
/// Amount mismatch is the #502 threat. A script mismatch is refusal-worthy
/// for a different reason (the PSBT is signing over a UTXO the responder
/// does not actually control), and the same defense catches both cheaply.
///
/// `Err` messages are shaped `REFUSED: ...` so operators see them
/// alongside `validate_migration_sweep_destination`'s output.
pub fn validate_prevout_amounts_against_chain(
    psbt: &Psbt,
    chain: &dyn ChainView,
) -> Result<(), String> {
    if psbt.inputs.is_empty() {
        return Err(
            "REFUSED: PSBT has no inputs; cannot validate prevout amounts against chain view."
                .to_string(),
        );
    }
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(format!(
            "REFUSED: PSBT input record count ({}) does not match unsigned tx input count ({}); refusing to sign.",
            psbt.inputs.len(),
            psbt.unsigned_tx.input.len(),
        ));
    }
    for (idx, (psbt_input, tx_input)) in psbt
        .inputs
        .iter()
        .zip(psbt.unsigned_tx.input.iter())
        .enumerate()
    {
        let claimed = psbt_input.witness_utxo.as_ref().ok_or_else(|| {
            format!(
                "REFUSED: PSBT input {idx} has no witness_utxo; #502 amount validation requires \
                 witness_utxo on every input. Refusing to sign."
            )
        })?;
        let outpoint = tx_input.previous_output;
        let actual = chain.get_prevout(outpoint).map_err(|e| {
            format!(
                "REFUSED: chain view could not resolve input {idx} outpoint {}:{}: {e}. \
                 Refusing to sign without an authoritative prevout amount check.",
                outpoint.txid, outpoint.vout,
            )
        })?;
        if actual.value != claimed.value {
            return Err(format!(
                "REFUSED: input {idx} outpoint {}:{} amount mismatch. \
                 Proposer declared {} sats but chain view says {} sats. \
                 A BIP-341 sighash over an understated prevout amount defeats every fee cap; \
                 refusing to sign.",
                outpoint.txid,
                outpoint.vout,
                claimed.value.to_sat(),
                actual.value.to_sat(),
            ));
        }
        if actual.script_pubkey != claimed.script_pubkey {
            return Err(format!(
                "REFUSED: input {idx} outpoint {}:{} script_pubkey mismatch. \
                 Proposer declared a different script than the chain view reports; \
                 refusing to sign.",
                outpoint.txid, outpoint.vout,
            ));
        }
    }
    Ok(())
}

/// Environment variable operators set to point every keep binary at a
/// shared chain-view endpoint (`https://blockstream.info/api`,
/// `https://mempool.space/api`, or a self-hosted esplora / mempool
/// instance). Binaries that support #502 read this at signing time.
pub const KEEP_CHAIN_URL_ENV: &str = "KEEP_CHAIN_URL";

/// A [`ChainView`] impl backed by an esplora / mempool.space HTTP API,
/// available under the `esplora-chain-view` feature. The endpoint is the
/// same shape both providers ship (`GET /tx/{txid}` returning a full tx
/// with `vout[].value`).
#[cfg(feature = "esplora-chain-view")]
pub struct EsploraChainView {
    base_url: url::Url,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "esplora-chain-view")]
fn is_loopback_url(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(h)) => h.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(feature = "esplora-chain-view")]
impl EsploraChainView {
    /// Construct an Esplora chain view against a base URL of the form
    /// `https://blockstream.info/api` (no trailing slash required). The
    /// resulting client blocks on each request; call it from a non-async
    /// thread or wrap with `tokio::task::block_in_place`.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ChainViewError> {
        // Normalize with a trailing slash so downstream `Url::join("tx/...")`
        // treats the base as a directory rather than dropping its final
        // segment. `blockstream.info/api` and `blockstream.info/api/` behave
        // identically to the operator; making that identity explicit here
        // avoids a silent 404 that would look like "outpoint not found".
        let raw = base_url.as_ref();
        let normalized = if raw.ends_with('/') {
            raw.to_string()
        } else {
            format!("{raw}/")
        };
        let base_url = url::Url::parse(&normalized).map_err(|e| {
            ChainViewError::Config(format!("invalid chain view base URL {raw:?}: {e}"))
        })?;
        // MITM guard: the whole #502 check reduces to trusting this endpoint,
        // so require https except for loopback (self-hosted / regtest esplora),
        // where plaintext to localhost carries no network exposure.
        if base_url.scheme() != "https" && !is_loopback_url(&base_url) {
            return Err(ChainViewError::Config(format!(
                "refusing non-https chain view URL {raw:?}: use https or a loopback host \
                 (127.0.0.1, ::1, localhost) for plaintext."
            )));
        }
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!(
                "keep/",
                env!("CARGO_PKG_VERSION"),
                " esplora-chain-view"
            ))
            .timeout(std::time::Duration::from_secs(15))
            // Refuse redirects that downgrade https -> a non-https, non-loopback
            // next hop; a redirecting endpoint must not strip transport security.
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let next = attempt.url();
                if next.scheme() == "https" || is_loopback_url(next) {
                    if attempt.previous().len() >= 10 {
                        attempt.error("too many redirects")
                    } else {
                        attempt.follow()
                    }
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|e| ChainViewError::Config(format!("build reqwest client: {e}")))?;
        Ok(Self { base_url, client })
    }
}

/// Construct the built-in Esplora chain view from the `KEEP_CHAIN_URL`
/// environment variable, applying the responder's fail-closed policy: a
/// missing or invalid endpoint yields a `REFUSED:` error rather than signing
/// without an authoritative amount check. Both the CLI and desktop responder
/// paths call this so their behavior and error messages stay identical.
#[cfg(feature = "esplora-chain-view")]
pub fn esplora_chain_view_from_env() -> Result<EsploraChainView, String> {
    let chain_url = std::env::var(KEEP_CHAIN_URL_ENV).map_err(|_| {
        format!(
            "REFUSED: {KEEP_CHAIN_URL_ENV} is not set. Set it to an esplora / mempool.space \
             endpoint (e.g. https://blockstream.info/api) so #502 prevout amount validation \
             can run. Refusing to sign without an authoritative amount check."
        )
    })?;
    EsploraChainView::new(&chain_url)
        .map_err(|e| format!("REFUSED: invalid {KEEP_CHAIN_URL_ENV}={chain_url:?}: {e}"))
}

#[cfg(feature = "esplora-chain-view")]
#[derive(serde::Deserialize)]
struct EsploraVout {
    value: u64,
    scriptpubkey: String,
}

#[cfg(feature = "esplora-chain-view")]
#[derive(serde::Deserialize)]
struct EsploraTx {
    txid: String,
    vout: Vec<EsploraVout>,
}

#[cfg(feature = "esplora-chain-view")]
impl ChainView for EsploraChainView {
    fn get_prevout(&self, outpoint: OutPoint) -> Result<TxOut, ChainViewError> {
        let path = format!("tx/{}", outpoint.txid);
        let url = self
            .base_url
            .join(&path)
            .map_err(|e| ChainViewError::Config(format!("join path {path}: {e}")))?;
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| ChainViewError::Transport(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ChainViewError::NotFound {
                txid: outpoint.txid,
                vout: outpoint.vout,
            });
        }
        if !resp.status().is_success() {
            return Err(ChainViewError::Transport(format!(
                "HTTP {} from chain view",
                resp.status()
            )));
        }
        // Bound the response body: a single tx JSON is far smaller than 2 MiB,
        // and an unbounded read lets a hostile/compromised endpoint exhaust
        // memory on the signing host. Enforce the cap during the read via a
        // limited reader so a chunked or content-length-lying response cannot
        // buffer past the limit before we check it.
        use std::io::Read as _;
        const MAX_BODY: u64 = 2 * 1024 * 1024;
        if let Some(len) = resp.content_length() {
            if len > MAX_BODY {
                return Err(ChainViewError::Decode(format!(
                    "chain view response too large ({len} bytes > {MAX_BODY} cap)"
                )));
            }
        }
        // Read at most MAX_BODY + 1 bytes: the extra byte lets us detect an
        // over-cap body without ever holding more than the cap plus one in
        // memory, regardless of what the endpoint claimed in Content-Length.
        let mut body = Vec::new();
        resp.take(MAX_BODY + 1)
            .read_to_end(&mut body)
            .map_err(|e| ChainViewError::Transport(e.to_string()))?;
        if body.len() as u64 > MAX_BODY {
            return Err(ChainViewError::Decode(format!(
                "chain view response exceeds {MAX_BODY} byte cap"
            )));
        }
        let tx: EsploraTx = serde_json::from_slice(&body)
            .map_err(|e| ChainViewError::Decode(format!("parse esplora tx: {e}")))?;
        // Verify the endpoint returned the transaction we asked for; a
        // redirecting / caching / compromised endpoint must not substitute a
        // different tx's vout under our requested txid.
        if !tx.txid.eq_ignore_ascii_case(&outpoint.txid.to_string()) {
            return Err(ChainViewError::Decode(format!(
                "chain view returned txid {} but {} was requested; refusing to trust a \
                 substituted transaction.",
                tx.txid, outpoint.txid,
            )));
        }
        let vout_idx = outpoint.vout as usize;
        let vout = tx.vout.get(vout_idx).ok_or(ChainViewError::NotFound {
            txid: outpoint.txid,
            vout: outpoint.vout,
        })?;
        let script_bytes = hex::decode(&vout.scriptpubkey)
            .map_err(|e| ChainViewError::Decode(format!("decode scriptpubkey hex: {e}")))?;
        Ok(TxOut {
            value: bitcoin::Amount::from_sat(vout.value),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, Txid, Witness};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Test-only in-memory chain view; maps outpoints to canned TxOuts.
    struct MockChainView {
        entries: Mutex<HashMap<OutPoint, TxOut>>,
    }

    impl MockChainView {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, op: OutPoint, out: TxOut) {
            self.entries.lock().unwrap().insert(op, out);
        }
    }

    impl ChainView for MockChainView {
        fn get_prevout(&self, outpoint: OutPoint) -> Result<TxOut, ChainViewError> {
            self.entries
                .lock()
                .unwrap()
                .get(&outpoint)
                .cloned()
                .ok_or(ChainViewError::NotFound {
                    txid: outpoint.txid,
                    vout: outpoint.vout,
                })
        }
    }

    fn make_outpoint(nonce: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::Hash::hash(&[nonce])),
            vout: 0,
        }
    }

    fn make_psbt(inputs: Vec<(OutPoint, TxOut)>) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(op, _)| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (idx, (_, prev)) in inputs.into_iter().enumerate() {
            psbt.inputs[idx].witness_utxo = Some(prev);
        }
        psbt
    }

    fn taproot_script() -> ScriptBuf {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let (xonly, _) = sk.x_only_public_key(&secp);
        ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            xonly,
        ))
    }

    /// #502 happy path: PSBT amounts match chain view -> Ok.
    #[test]
    fn matching_witness_utxo_amount_verifies() {
        let chain = MockChainView::new();
        let op = make_outpoint(1);
        let prev = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: taproot_script(),
        };
        chain.insert(op, prev.clone());
        let psbt = make_psbt(vec![(op, prev)]);
        validate_prevout_amounts_against_chain(&psbt, &chain).unwrap();
    }

    /// #502 core: proposer understates the input amount, responder catches
    /// the divergence and refuses. This is the exact attack the issue calls
    /// out: an understated `witness_utxo.value` defeats every fee cap.
    #[test]
    fn understated_witness_utxo_amount_refuses() {
        let chain = MockChainView::new();
        let op = make_outpoint(2);
        let real = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: taproot_script(),
        };
        chain.insert(op, real);
        let lied = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: taproot_script(),
        };
        let psbt = make_psbt(vec![(op, lied)]);
        let err = validate_prevout_amounts_against_chain(&psbt, &chain)
            .expect_err("understated amount must be refused");
        assert!(err.contains("amount mismatch"), "err was: {err}");
    }

    /// A PSBT input whose declared script does not match the chain view is
    /// refused, catching a UTXO-substitution proposal.
    #[test]
    fn script_mismatch_refuses() {
        let chain = MockChainView::new();
        let op = make_outpoint(3);
        let real = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: taproot_script(),
        };
        chain.insert(op, real);
        let claimed = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0xAB, 0xCD]),
        };
        let psbt = make_psbt(vec![(op, claimed)]);
        let err = validate_prevout_amounts_against_chain(&psbt, &chain)
            .expect_err("script mismatch must be refused");
        assert!(err.contains("script_pubkey mismatch"), "err was: {err}");
    }

    /// An input without witness_utxo cannot be validated; refuse rather
    /// than silently pass or fall back to a claim of "unknown".
    #[test]
    fn missing_witness_utxo_refuses() {
        let chain = MockChainView::new();
        let op = make_outpoint(4);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let err = validate_prevout_amounts_against_chain(&psbt, &chain)
            .expect_err("missing witness_utxo must be refused");
        assert!(err.contains("witness_utxo"), "err was: {err}");
    }

    /// A chain-view transport error is refusal-worthy: an inconclusive read
    /// MUST NOT be interpreted as "no divergence".
    #[test]
    fn transport_error_refuses() {
        struct FailingChain;
        impl ChainView for FailingChain {
            fn get_prevout(&self, _: OutPoint) -> Result<TxOut, ChainViewError> {
                Err(ChainViewError::Transport("simulated".into()))
            }
        }
        let op = make_outpoint(5);
        let claim = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: taproot_script(),
        };
        let psbt = make_psbt(vec![(op, claim)]);
        let err = validate_prevout_amounts_against_chain(&psbt, &FailingChain)
            .expect_err("transport error must be refused");
        assert!(err.contains("chain view"), "err was: {err}");
    }

    /// Empty PSBT is refused before any chain call is made.
    #[test]
    fn empty_psbt_refuses() {
        let chain = MockChainView::new();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert!(validate_prevout_amounts_against_chain(&psbt, &chain).is_err());
    }

    /// A 2-input PSBT where only input[1] diverges is refused, guarding the
    /// zip/enumerate loop against an off-by-one that would only check input[0].
    #[test]
    fn second_input_amount_divergence_refuses() {
        let chain = MockChainView::new();
        let op0 = make_outpoint(7);
        let op1 = make_outpoint(8);
        let real0 = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: taproot_script(),
        };
        let real1 = TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey: taproot_script(),
        };
        chain.insert(op0, real0.clone());
        chain.insert(op1, real1);
        let lied1 = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: taproot_script(),
        };
        let psbt = make_psbt(vec![(op0, real0), (op1, lied1)]);
        let err = validate_prevout_amounts_against_chain(&psbt, &chain)
            .expect_err("input[1] divergence must be refused");
        assert!(err.contains("amount mismatch"), "err was: {err}");
        assert!(err.contains("input 1"), "should identify input 1: {err}");
    }

    /// A PSBT whose input-record count exceeds its unsigned-tx input count is
    /// refused before any chain call, guarding the zip against a truncated walk.
    #[test]
    fn input_count_mismatch_refuses() {
        let chain = MockChainView::new();
        let op = make_outpoint(9);
        let prev = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: taproot_script(),
        };
        chain.insert(op, prev.clone());
        let mut psbt = make_psbt(vec![(op, prev)]);
        psbt.inputs.push(bitcoin::psbt::Input::default());
        let err = validate_prevout_amounts_against_chain(&psbt, &chain)
            .expect_err("input count mismatch must be refused");
        assert!(
            err.contains("does not match unsigned tx input count"),
            "err was: {err}"
        );
    }

    /// `EsploraChainView::new` normalizes with and without a trailing slash.
    #[cfg(feature = "esplora-chain-view")]
    #[test]
    fn esplora_new_normalizes_trailing_slash() {
        EsploraChainView::new("https://blockstream.info/api").expect("no trailing slash ok");
        EsploraChainView::new("https://blockstream.info/api/").expect("trailing slash ok");
    }

    /// `EsploraChainView::new` refuses plaintext http except to loopback hosts.
    #[cfg(feature = "esplora-chain-view")]
    #[test]
    fn esplora_new_enforces_https_except_loopback() {
        assert!(
            EsploraChainView::new("http://evil.example/api").is_err(),
            "non-loopback http must be refused"
        );
        EsploraChainView::new("http://127.0.0.1:3000/api").expect("loopback http ok");
    }
}

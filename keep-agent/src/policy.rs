// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The agent gateway's deny-by-default policy. A request is allowed only when
//! the credential's grant names it explicitly; anything the grant does not
//! cover, or any context the decision needs and lacks, is denied.
//!
//! Times are Unix seconds from a clock that only advances with elapsed time:
//! the caller derives it from a monotonic clock while running, so stepping the
//! wall clock cannot age spends out of a budget early.

use std::collections::BTreeSet;
use std::fmt;

use keep_bitcoin::{Network, PsbtAnalysis};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::{AgentError, Result};
use crate::scope::{canonical_allowlist, check_outputs, Operation, OutputRejection};

/// The length of a spend budget's rolling window.
pub const BUDGET_WINDOW_SECS: u64 = 24 * 60 * 60;

/// The most spends one credential's ledger holds within its window.
pub const MAX_CREDENTIAL_ENTRIES: usize = 1_000;

/// The most spends the wallet's ledger holds within its window, across every
/// credential. Well above one credential's cap, so no single credential can
/// fill it.
pub const MAX_WALLET_ENTRIES: usize = 10_000;

/// Kinds outside the replaceable and ephemeral ranges that move funds or
/// rewrite or destroy the owner's data. They always need an approval.
pub const APPROVAL_KINDS: &[u16] = &[
    0,     // profile metadata
    3,     // contact list
    5,     // deletion
    62,    // NIP-62 request to vanish
    7374,  // NIP-60 quote
    7375,  // NIP-60 ecash tokens
    7376,  // NIP-60 spending history
    9321,  // NIP-61 nutzap
    37375, // legacy NIP-60 wallet
];

/// Replaceable kinds (10000-19999) overwrite the owner's previous state, such
/// as relay lists and the NIP-60 wallet. Ephemeral kinds (20000-29999) carry
/// payment, auth and remote-signing requests. Both always need an approval.
/// Addressable kinds (30000-39999) are named content, such as articles and app
/// data, that a grant may list like any other kind; the one that holds a
/// wallet key is in `APPROVAL_KINDS`.
const APPROVAL_RANGE: std::ops::Range<u16> = 10_000..30_000;

fn kind_needs_approval(kind: u16) -> bool {
    APPROVAL_KINDS.contains(&kind) || APPROVAL_RANGE.contains(&kind)
}

/// What a credential may do. Every field is an explicit allowance: an empty set
/// allows nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The vault keys (x-only public keys) the credential may use: the key a
    /// request signs or encrypts with, or whose wallet a PSBT spends from. NIP-44
    /// with any of these as the counterparty counts as the owner's own payload.
    pub keys: BTreeSet<[u8; 32]>,
    pub operations: BTreeSet<Operation>,
    pub event_kinds: BTreeSet<u16>,
    /// Counterparty x-only public keys for NIP-44 encrypt and decrypt.
    pub nip44_peers: BTreeSet<[u8; 32]>,
    pub bitcoin: Option<BitcoinGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinGrant {
    pub network: Network,
    /// What one PSBT may take out of the wallet, fee included.
    pub per_psbt_sats: u64,
    /// What the credential may take out of the wallet in any window.
    pub window_sats: u64,
    /// Once this credential's spends within the window, counting the request,
    /// exceed this, each spend needs an approval.
    pub approval_above_sats: Option<u64>,
    /// When set, every output but recognized change must pay one of these
    /// (canonical) addresses.
    pub address_allowlist: Option<BTreeSet<String>>,
}

impl Grant {
    /// The grant a credential may be issued with: it names its keys, each
    /// operation has what it needs to ever be allowed, and allowlisted addresses
    /// are on the grant's network (stored canonically).
    pub fn validated(mut self) -> Result<Self> {
        let refuse = |m: &str| Err(AgentError::ScopeViolation(m.into()));
        let has = |op| self.operations.contains(&op);
        if self.keys.is_empty() {
            return refuse("a grant needs the keys it may use");
        }
        if has(Operation::SignNostrEvent) && self.event_kinds.is_empty() {
            return refuse("sign_nostr_event needs an explicit list of event kinds");
        }
        if has(Operation::Nip44Encrypt) && self.nip44_peers.is_empty() {
            return refuse("nip44_encrypt needs the counterparties it may use");
        }
        if has(Operation::Nip44Decrypt) && self.nip44_peers.is_empty() {
            return refuse("nip44_decrypt needs the counterparties it may use");
        }
        if has(Operation::SignPsbt) && self.bitcoin.is_none() {
            return refuse("sign_psbt needs a Bitcoin grant");
        }
        if has(Operation::GetBitcoinAddress) && self.bitcoin.is_none() {
            return refuse("get_bitcoin_address needs a Bitcoin grant");
        }
        if let Some(btc) = self.bitcoin.as_mut() {
            if btc.per_psbt_sats > btc.window_sats {
                return refuse("per_psbt_sats cannot exceed window_sats");
            }
            if let Some(allowlist) = btc.address_allowlist.take() {
                if allowlist.is_empty() {
                    return refuse("an address allowlist needs at least one address");
                }
                btc.address_allowlist = Some(canonical_allowlist(&allowlist, btc.network)?);
            }
        }
        Ok(self)
    }
}

/// A request, with every fact the decision depends on.
#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    GetPublicKey,
    SignNostrEvent {
        kind: u16,
    },
    Nip44Encrypt {
        peer: [u8; 32],
    },
    Nip44Decrypt {
        peer: [u8; 32],
    },
    GetBitcoinAddress {
        network: Network,
    },
    /// The analysis carries the signer's network.
    SignPsbt {
        analysis: &'a PsbtAnalysis,
    },
}

impl Request<'_> {
    fn operation(&self) -> Operation {
        match self {
            Request::GetPublicKey => Operation::GetPublicKey,
            Request::SignNostrEvent { .. } => Operation::SignNostrEvent,
            Request::Nip44Encrypt { .. } => Operation::Nip44Encrypt,
            Request::Nip44Decrypt { .. } => Operation::Nip44Decrypt,
            Request::GetBitcoinAddress { .. } => Operation::GetBitcoinAddress,
            Request::SignPsbt { .. } => Operation::SignPsbt,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum Decision {
    /// Allowed, with nothing reserved.
    Allow,
    /// An allowed spend, already reserved in the credential's and the wallet's
    /// ledgers. Persist both ledgers in one transaction before signing; release
    /// the reservation if no signature leaves the gateway.
    Spend(Reservation),
    Deny(DenyReason),
    RequireApproval(ApprovalReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    KeyNotGranted,
    OperationNotGranted(Operation),
    KindNotGranted(u16),
    PeerNotGranted,
    NoBitcoinGrant,
    NetworkMismatch {
        requested: Network,
        granted: Network,
    },
    PerPsbtExceeded {
        requested: u64,
        limit: u64,
    },
    AddressNotAllowed(String),
    OutputWithoutAddress(usize),
    CredentialBudgetExceeded {
        requested: u64,
        spent: u64,
        limit: u64,
    },
    WalletBudgetExceeded {
        requested: u64,
        spent: u64,
        limit: u64,
    },
    LedgerFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalReason {
    Kind(u16),
    EncryptToOwnKey,
    DecryptOwnPayload,
    AboveThreshold {
        requested: u64,
        spent: u64,
        threshold: u64,
    },
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotGranted => write!(f, "that key is not granted"),
            Self::OperationNotGranted(op) => write!(f, "{} is not granted", op.as_str()),
            Self::KindNotGranted(k) => write!(f, "event kind {k} is not granted"),
            Self::PeerNotGranted => write!(f, "that counterparty is not granted"),
            Self::NoBitcoinGrant => write!(f, "no Bitcoin grant"),
            Self::NetworkMismatch { requested, granted } => {
                write!(f, "network {requested} does not match the grant's {granted}")
            }
            Self::PerPsbtExceeded { requested, limit } => {
                write!(f, "{requested} sats leave the wallet, over the {limit} sat limit per PSBT")
            }
            Self::AddressNotAllowed(a) => write!(f, "address {a} is not allowlisted"),
            Self::OutputWithoutAddress(i) => {
                write!(f, "output {i} has no address to check against the allowlist")
            }
            Self::CredentialBudgetExceeded { requested, spent, limit } => write!(
                f,
                "{requested} sats on top of {spent} already spent exceeds the {limit} sat budget"
            ),
            Self::WalletBudgetExceeded { requested, spent, limit } => write!(
                f,
                "{requested} sats on top of {spent} already spent exceeds the wallet's {limit} sat budget"
            ),
            Self::LedgerFull => write!(f, "too many spends in the budget window"),
        }
    }
}

impl fmt::Display for ApprovalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kind(k) => write!(f, "event kind {k} always needs approval"),
            Self::EncryptToOwnKey => write!(f, "encrypting to the key itself needs approval"),
            Self::DecryptOwnPayload => write!(f, "decrypting the key's own payload needs approval"),
            Self::AboveThreshold { requested, spent, threshold } => write!(
                f,
                "{requested} sats on top of {spent} already spent is above the {threshold} sat approval threshold"
            ),
        }
    }
}

/// Spends within the rolling window, persisted with the credential (or the
/// wallet) so a restart does not reset a budget.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    spends: Vec<Spend>,
    /// The latest time the ledger has seen. Spends are stamped no earlier, so a
    /// clock stepped back neither frees nor shortens them.
    last_seen: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Spend {
    id: u64,
    at: u64,
    sats: u64,
}

impl Ledger {
    /// Sats spent within the window ending at `now`. Does not change the
    /// ledger. Every entry it holds is within the window of the latest time it
    /// has seen, so a `now` behind that counts them all.
    pub fn spent(&self, now: u64) -> u64 {
        let start = now.saturating_sub(BUDGET_WINDOW_SECS);
        self.spends
            .iter()
            .filter(|s| s.at > start)
            .map(|s| s.sats)
            .fold(0, u64::saturating_add)
    }

    fn advance(&mut self, now: u64) -> u64 {
        self.last_seen = self.last_seen.max(now);
        let start = self.last_seen.saturating_sub(BUDGET_WINDOW_SECS);
        self.spends.retain(|s| s.at > start);
        self.last_seen
    }

    fn release(&mut self, id: u64) {
        self.spends.retain(|s| s.id != id);
    }
}

/// The ledgers a spend is counted against: the credential's own, and the
/// wallet's across every credential.
pub struct Budgets<'a> {
    pub credential: &'a mut Ledger,
    pub wallet: &'a mut Ledger,
    pub wallet_window_sats: u64,
}

/// A spend reserved by an allowed `SignPsbt`. It is consumed by `release`, so
/// one reservation can return its spend only once.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "release the reservation if no signature leaves the gateway"]
pub struct Reservation {
    id: u64,
    sats: u64,
}

impl Reservation {
    /// The sats reserved.
    pub fn sats(&self) -> u64 {
        self.sats
    }

    /// Return the spend to both ledgers, for a request that produced no
    /// signature. Only valid before any signature (or FROST share) leaves.
    pub fn release(self, credential: &mut Ledger, wallet: &mut Ledger) {
        credential.release(self.id);
        wallet.release(self.id);
    }
}

/// Decide `request` made with the key `key` under `grant`. A spend it allows is
/// reserved in `budgets` before this returns, so callers serialize decisions
/// and persist the ledgers before signing.
pub fn evaluate(
    grant: &Grant,
    key: &[u8; 32],
    request: &Request<'_>,
    budgets: &mut Budgets<'_>,
    now: u64,
) -> Decision {
    decide(grant, key, request, budgets, now, false)
}

/// Decide a request a human has approved. Everything is checked again except
/// what only needed the approval (risky kinds, own-key NIP-44 and the spend
/// threshold); hard limits and budgets still apply, and an approved spend is
/// reserved like any other. The caller must hold an approval bound to this
/// exact request (its hash) and consume it, so one approval clears one request.
pub fn evaluate_approved(
    grant: &Grant,
    key: &[u8; 32],
    request: &Request<'_>,
    budgets: &mut Budgets<'_>,
    now: u64,
) -> Decision {
    decide(grant, key, request, budgets, now, true)
}

fn decide(
    grant: &Grant,
    key: &[u8; 32],
    request: &Request<'_>,
    budgets: &mut Budgets<'_>,
    now: u64,
    approved: bool,
) -> Decision {
    if !grant.keys.contains(key) {
        return Decision::Deny(DenyReason::KeyNotGranted);
    }
    let op = request.operation();
    if !grant.operations.contains(&op) {
        return Decision::Deny(DenyReason::OperationNotGranted(op));
    }
    let needs = |reason| {
        if approved {
            Decision::Allow
        } else {
            Decision::RequireApproval(reason)
        }
    };
    match *request {
        Request::GetPublicKey => Decision::Allow,
        Request::SignNostrEvent { kind } => {
            if !grant.event_kinds.contains(&kind) {
                Decision::Deny(DenyReason::KindNotGranted(kind))
            } else if kind_needs_approval(kind) {
                needs(ApprovalReason::Kind(kind))
            } else {
                Decision::Allow
            }
        }
        Request::Nip44Encrypt { peer } | Request::Nip44Decrypt { peer } => {
            if !grant.nip44_peers.contains(&peer) {
                Decision::Deny(DenyReason::PeerNotGranted)
            } else if !grant.keys.contains(&peer) {
                Decision::Allow
            } else if op == Operation::Nip44Encrypt {
                needs(ApprovalReason::EncryptToOwnKey)
            } else {
                needs(ApprovalReason::DecryptOwnPayload)
            }
        }
        Request::GetBitcoinAddress { network } => match bitcoin_grant(grant, network) {
            Ok(_) => Decision::Allow,
            Err(reason) => Decision::Deny(reason),
        },
        Request::SignPsbt { analysis } => match bitcoin_grant(grant, analysis.network) {
            Ok(btc) => spend_decision(btc, analysis, budgets, now, approved),
            Err(reason) => Decision::Deny(reason),
        },
    }
}

fn bitcoin_grant(
    grant: &Grant,
    requested: Network,
) -> std::result::Result<&BitcoinGrant, DenyReason> {
    let btc = grant.bitcoin.as_ref().ok_or(DenyReason::NoBitcoinGrant)?;
    if btc.network != requested {
        return Err(DenyReason::NetworkMismatch {
            requested,
            granted: btc.network,
        });
    }
    Ok(btc)
}

fn spend_decision(
    btc: &BitcoinGrant,
    analysis: &PsbtAnalysis,
    budgets: &mut Budgets<'_>,
    now: u64,
    approved: bool,
) -> Decision {
    let allowed = btc
        .address_allowlist
        .as_ref()
        .map(|set| move |a: &str| set.contains(a));
    if let Err(rejection) = check_outputs(
        analysis,
        btc.per_psbt_sats,
        allowed.as_ref().map(|f| f as _),
    ) {
        return Decision::Deny(match rejection {
            OutputRejection::OverLimit { requested, limit } => {
                DenyReason::PerPsbtExceeded { requested, limit }
            }
            OutputRejection::NotAllowed(a) => DenyReason::AddressNotAllowed(a),
            OutputRejection::NoAddress(i) => DenyReason::OutputWithoutAddress(i),
        });
    }
    let requested = analysis.leaving_wallet_sats();
    // Nothing leaves the wallet, so there is nothing to count or approve, and
    // recording it would only fill the ledgers.
    if requested == 0 {
        return Decision::Allow;
    }
    let at = budgets
        .credential
        .advance(now)
        .max(budgets.wallet.advance(now));
    let spent = budgets.credential.spent(at);
    if spent.saturating_add(requested) > btc.window_sats {
        return Decision::Deny(DenyReason::CredentialBudgetExceeded {
            requested,
            spent,
            limit: btc.window_sats,
        });
    }
    let wallet_spent = budgets.wallet.spent(at);
    if wallet_spent.saturating_add(requested) > budgets.wallet_window_sats {
        return Decision::Deny(DenyReason::WalletBudgetExceeded {
            requested,
            spent: wallet_spent,
            limit: budgets.wallet_window_sats,
        });
    }
    if let Some(threshold) = btc.approval_above_sats {
        if !approved && spent.saturating_add(requested) > threshold {
            return Decision::RequireApproval(ApprovalReason::AboveThreshold {
                requested,
                spent,
                threshold,
            });
        }
    }
    if budgets.credential.spends.len() >= MAX_CREDENTIAL_ENTRIES
        || budgets.wallet.spends.len() >= MAX_WALLET_ENTRIES
    {
        return Decision::Deny(DenyReason::LedgerFull);
    }
    let id = rand::rng().next_u64();
    for ledger in [&mut *budgets.credential, &mut *budgets.wallet] {
        ledger.spends.push(Spend {
            id,
            at,
            sats: requested,
        });
    }
    Decision::Spend(Reservation {
        id,
        sats: requested,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_bitcoin::psbt::OutputInfo;

    const KEY: [u8; 32] = [1; 32];
    const PEER: [u8; 32] = [2; 32];
    const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const OTHER: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    const T0: u64 = 1_800_000_000;
    const W: u64 = BUDGET_WINDOW_SECS;

    fn grant() -> Grant {
        Grant {
            keys: [KEY].into(),
            operations: [
                Operation::GetPublicKey,
                Operation::SignNostrEvent,
                Operation::Nip44Encrypt,
                Operation::Nip44Decrypt,
                Operation::GetBitcoinAddress,
                Operation::SignPsbt,
            ]
            .into(),
            event_kinds: [1, 7, 23194].into(),
            nip44_peers: [PEER, KEY].into(),
            bitcoin: Some(BitcoinGrant {
                network: Network::Bitcoin,
                per_psbt_sats: 10_000,
                window_sats: 25_000,
                approval_above_sats: None,
                address_allowlist: None,
            }),
        }
    }

    fn btc(g: &mut Grant) -> &mut BitcoinGrant {
        g.bitcoin.as_mut().unwrap()
    }

    fn analysis(outputs: &[(u64, Option<&str>, bool)], fee_sats: u64) -> PsbtAnalysis {
        let outputs: Vec<OutputInfo> = outputs
            .iter()
            .enumerate()
            .map(|(index, &(amount_sats, address, is_change))| OutputInfo {
                index,
                address: address.map(str::to_string),
                amount_sats,
                is_change,
            })
            .collect();
        let total_output_sats = outputs.iter().map(|o| o.amount_sats).sum::<u64>();
        PsbtAnalysis {
            num_inputs: 1,
            num_outputs: outputs.len(),
            total_input_sats: total_output_sats + fee_sats,
            total_output_sats,
            fee_sats,
            input_sats: vec![total_output_sats + fee_sats],
            outputs,
            signable_inputs: vec![0],
            network: Network::Bitcoin,
        }
    }

    /// A PSBT taking `sats` out of the wallet: a payment plus a 100 sat fee,
    /// with change back.
    fn spend(sats: u64) -> PsbtAnalysis {
        analysis(
            &[(sats - 100, Some(ADDR), false), (50_000, None, true)],
            100,
        )
    }

    fn sign(a: &PsbtAnalysis) -> Request<'_> {
        Request::SignPsbt { analysis: a }
    }

    struct State {
        credential: Ledger,
        wallet: Ledger,
        wallet_window_sats: u64,
    }

    impl State {
        fn new() -> Self {
            Self {
                credential: Ledger::default(),
                wallet: Ledger::default(),
                wallet_window_sats: 100_000,
            }
        }

        fn budgets(&mut self) -> Budgets<'_> {
            Budgets {
                credential: &mut self.credential,
                wallet: &mut self.wallet,
                wallet_window_sats: self.wallet_window_sats,
            }
        }

        fn decide(&mut self, g: &Grant, request: Request<'_>, now: u64) -> Decision {
            evaluate(g, &KEY, &request, &mut self.budgets(), now)
        }

        fn approved(&mut self, g: &Grant, request: Request<'_>, now: u64) -> Decision {
            evaluate_approved(g, &KEY, &request, &mut self.budgets(), now)
        }

        fn spends(&mut self, g: &Grant, sats: u64, now: u64) -> bool {
            matches!(self.decide(g, sign(&spend(sats)), now), Decision::Spend(r) if r.sats() == sats)
        }
    }

    #[test]
    fn a_key_outside_the_grant_is_denied() {
        let mut s = State::new();
        let d = evaluate(
            &grant(),
            &PEER,
            &Request::GetPublicKey,
            &mut s.budgets(),
            T0,
        );
        assert_eq!(d, Decision::Deny(DenyReason::KeyNotGranted));
        let a = spend(1_000);
        let d = evaluate_approved(&grant(), &PEER, &sign(&a), &mut s.budgets(), T0);
        assert_eq!(d, Decision::Deny(DenyReason::KeyNotGranted));
        assert_eq!(s.credential.spent(T0), 0);
    }

    #[test]
    fn an_operation_outside_the_grant_is_denied() {
        let mut g = grant();
        g.operations = [Operation::GetPublicKey].into();
        let mut s = State::new();
        assert_eq!(s.decide(&g, Request::GetPublicKey, T0), Decision::Allow);
        assert_eq!(
            s.decide(&g, Request::SignNostrEvent { kind: 1 }, T0),
            Decision::Deny(DenyReason::OperationNotGranted(Operation::SignNostrEvent))
        );
        let a = spend(1_000);
        assert_eq!(
            s.approved(&g, sign(&a), T0),
            Decision::Deny(DenyReason::OperationNotGranted(Operation::SignPsbt))
        );
        assert_eq!(s.credential.spent(T0), 0);
    }

    #[test]
    fn only_listed_kinds_are_signed_and_risky_kinds_need_approval() {
        let mut s = State::new();
        let g = grant();
        assert_eq!(
            s.decide(&g, Request::SignNostrEvent { kind: 1 }, T0),
            Decision::Allow
        );
        assert_eq!(
            s.decide(&g, Request::SignNostrEvent { kind: 4 }, T0),
            Decision::Deny(DenyReason::KindNotGranted(4))
        );
        assert_eq!(
            s.approved(&g, Request::SignNostrEvent { kind: 4 }, T0),
            Decision::Deny(DenyReason::KindNotGranted(4)),
            "an approval does not grant a kind"
        );
        // Explicit kinds, both ends of the ranges, and the kinds the ranges are
        // there for: relay and DM relay lists, the NIP-60 wallet, nutzap info,
        // relay auth, NWC, NIP-46, Blossom and HTTP auth.
        let risky = [
            0, 3, 5, 62, 7_374, 7_375, 7_376, 9_321, 37_375, 10_000, 10_002, 10_019, 10_050,
            17_375, 19_999, 20_000, 22_242, 23_194, 24_133, 24_242, 27_235, 29_999,
        ];
        for kind in risky {
            let mut g = grant();
            g.event_kinds = [kind].into();
            assert_eq!(
                s.decide(&g, Request::SignNostrEvent { kind }, T0),
                Decision::RequireApproval(ApprovalReason::Kind(kind)),
                "{kind}"
            );
            assert_eq!(
                s.approved(&g, Request::SignNostrEvent { kind }, T0),
                Decision::Allow
            );
        }
        for kind in [1, 4, 7, 1_059, 9_999, 30_000, 30_023] {
            let mut g = grant();
            g.event_kinds = [kind].into();
            assert_eq!(
                s.decide(&g, Request::SignNostrEvent { kind }, T0),
                Decision::Allow,
                "{kind}"
            );
        }
    }

    #[test]
    fn nip44_is_scoped_to_granted_peers_and_the_own_key_needs_approval() {
        let mut s = State::new();
        let g = grant();
        assert_eq!(
            s.decide(&g, Request::Nip44Encrypt { peer: PEER }, T0),
            Decision::Allow
        );
        assert_eq!(
            s.decide(&g, Request::Nip44Decrypt { peer: PEER }, T0),
            Decision::Allow
        );
        for request in [
            Request::Nip44Encrypt { peer: [3; 32] },
            Request::Nip44Decrypt { peer: [3; 32] },
        ] {
            assert_eq!(
                s.decide(&g, request, T0),
                Decision::Deny(DenyReason::PeerNotGranted)
            );
            assert_eq!(
                s.approved(&g, request, T0),
                Decision::Deny(DenyReason::PeerNotGranted)
            );
        }
        assert_eq!(
            s.decide(&g, Request::Nip44Encrypt { peer: KEY }, T0),
            Decision::RequireApproval(ApprovalReason::EncryptToOwnKey)
        );
        assert_eq!(
            s.decide(&g, Request::Nip44Decrypt { peer: KEY }, T0),
            Decision::RequireApproval(ApprovalReason::DecryptOwnPayload)
        );
        assert_eq!(
            s.approved(&g, Request::Nip44Decrypt { peer: KEY }, T0),
            Decision::Allow
        );

        // Another key of the same grant is the owner too.
        let mut g = grant();
        g.keys.insert(PEER);
        assert_eq!(
            s.decide(&g, Request::Nip44Decrypt { peer: PEER }, T0),
            Decision::RequireApproval(ApprovalReason::DecryptOwnPayload)
        );
        assert_eq!(
            s.decide(&g, Request::Nip44Encrypt { peer: PEER }, T0),
            Decision::RequireApproval(ApprovalReason::EncryptToOwnKey)
        );
    }

    #[test]
    fn bitcoin_requests_must_be_on_the_granted_network() {
        let mut s = State::new();
        let mut g = grant();
        assert_eq!(
            s.decide(
                &g,
                Request::GetBitcoinAddress {
                    network: Network::Testnet
                },
                T0
            ),
            Decision::Deny(DenyReason::NetworkMismatch {
                requested: Network::Testnet,
                granted: Network::Bitcoin
            })
        );
        let mut testnet = spend(1_000);
        testnet.network = Network::Testnet;
        assert!(matches!(
            s.approved(&g, sign(&testnet), T0),
            Decision::Deny(DenyReason::NetworkMismatch { .. })
        ));
        g.bitcoin = None;
        assert_eq!(
            s.decide(&g, sign(&spend(1_000)), T0),
            Decision::Deny(DenyReason::NoBitcoinGrant)
        );
        assert_eq!(s.credential.spent(T0), 0);
    }

    #[test]
    fn the_per_psbt_limit_counts_the_fee_even_when_approved() {
        let mut s = State::new();
        let g = grant();
        let a = analysis(&[(9_000, Some(ADDR), false), (50_000, None, true)], 1_000);
        assert!(matches!(s.decide(&g, sign(&a), T0), Decision::Spend(_)));
        let a = analysis(&[(9_000, Some(ADDR), false)], 1_001);
        let over = Decision::Deny(DenyReason::PerPsbtExceeded {
            requested: 10_001,
            limit: 10_000,
        });
        assert_eq!(s.decide(&g, sign(&a), T0), over);
        assert_eq!(s.approved(&g, sign(&a), T0), over);
    }

    #[test]
    fn the_allowlist_fails_closed() {
        let mut s = State::new();
        let mut g = grant();
        btc(&mut g).address_allowlist = Some([ADDR.to_string()].into());
        let g = g.validated().unwrap();
        assert!(s.spends(&g, 1_000, T0));
        let a = analysis(&[(1_000, Some(OTHER), false)], 100);
        assert_eq!(
            s.approved(&g, sign(&a), T0),
            Decision::Deny(DenyReason::AddressNotAllowed(OTHER.into()))
        );
        let a = analysis(&[(1_000, Some(ADDR), false), (1_000, None, false)], 100);
        assert_eq!(
            s.decide(&g, sign(&a), T0),
            Decision::Deny(DenyReason::OutputWithoutAddress(1))
        );
    }

    #[test]
    fn spends_accumulate_against_the_window_and_age_out() {
        let mut s = State::new();
        let g = grant();
        assert!(s.spends(&g, 10_000, T0));
        assert!(s.spends(&g, 10_000, T0));
        assert!(s.spends(&g, 5_000, T0 + 1));
        let one_sat = analysis(&[(1, Some(ADDR), false)], 0);
        let over = Decision::Deny(DenyReason::CredentialBudgetExceeded {
            requested: 1,
            spent: 25_000,
            limit: 25_000,
        });
        assert_eq!(s.decide(&g, sign(&one_sat), T0 + 2), over);
        assert_eq!(
            s.approved(&g, sign(&one_sat), T0 + 2),
            over,
            "an approval does not lift the budget"
        );
        assert_eq!(
            s.credential.spent(T0 + 2),
            25_000,
            "a denial reserves nothing"
        );
        assert_eq!(s.credential.spent(T0 + W - 1), 25_000);
        assert_eq!(s.credential.spent(T0 + W), 5_000);
        assert!(s.spends(&g, 10_000, T0 + W));
    }

    #[test]
    fn spent_does_not_change_the_ledger() {
        let mut s = State::new();
        let g = grant();
        assert!(s.spends(&g, 10_000, T0));
        let before = s.credential.clone();
        assert_eq!(s.credential.spent(T0 + 10 * W), 0);
        assert_eq!(s.credential, before);
        assert_eq!(s.credential.spent(T0), 10_000);
        assert_eq!(s.credential.spent(T0 - 10 * W), 10_000);
    }

    #[test]
    fn a_clock_stepped_back_neither_frees_nor_shortens_spends() {
        let mut s = State::new();
        let g = grant();
        let later = T0 + W;
        assert!(s.spends(&g, 10_000, later));
        // A whole window back: the earlier spend still counts, and this one is
        // stamped at the latest time seen, so it does not age out early.
        assert!(s.spends(&g, 10_000, T0));
        assert!(s.credential.spends.iter().all(|sp| sp.at == later));
        assert!(matches!(
            s.decide(&g, sign(&spend(10_000)), T0),
            Decision::Deny(DenyReason::CredentialBudgetExceeded { spent: 20_000, .. })
        ));
        assert_eq!(s.credential.spent(later + W - 1), 20_000);
    }

    #[test]
    fn a_spend_is_stamped_at_the_later_of_both_ledgers_clocks() {
        let mut s = State::new();
        let g = grant();
        assert!(s.spends(&g, 10_000, T0 + W));
        // A fresh credential whose ledger has seen no time spends against the
        // same wallet: its wallet entry must not be stamped in the past.
        s.credential = Ledger::default();
        assert!(s.spends(&g, 10_000, T0));
        assert!(s.wallet.spends.iter().all(|sp| sp.at == T0 + W));
        assert!(s.credential.spends.iter().all(|sp| sp.at == T0 + W));
    }

    #[test]
    fn the_wallet_budget_spans_credentials() {
        let mut s = State::new();
        s.wallet_window_sats = 15_000;
        let g = grant();
        assert!(s.spends(&g, 10_000, T0));
        s.credential = Ledger::default();
        assert!(s.spends(&g, 5_000, T0), "exactly at the wallet budget");
        s.credential = Ledger::default();
        let one_sat = analysis(&[(1, Some(ADDR), false)], 0);
        assert_eq!(
            s.decide(&g, sign(&one_sat), T0),
            Decision::Deny(DenyReason::WalletBudgetExceeded {
                requested: 1,
                spent: 15_000,
                limit: 15_000
            })
        );
        assert_eq!(s.credential.spent(T0), 0);
    }

    #[test]
    fn the_approval_threshold_is_cumulative_and_approved_spends_count() {
        let mut s = State::new();
        let mut g = grant();
        btc(&mut g).approval_above_sats = Some(12_000);
        assert!(s.spends(&g, 8_000, T0));
        assert!(s.spends(&g, 4_000, T0), "exactly at the threshold");
        let a = spend(5_000);
        assert_eq!(
            s.decide(&g, sign(&a), T0),
            Decision::RequireApproval(ApprovalReason::AboveThreshold {
                requested: 5_000,
                spent: 12_000,
                threshold: 12_000
            })
        );
        assert_eq!(
            s.credential.spent(T0),
            12_000,
            "an approval request reserves nothing"
        );
        assert!(matches!(s.approved(&g, sign(&a), T0), Decision::Spend(r) if r.sats() == 5_000));
        assert_eq!(s.credential.spent(T0), 17_000);
        assert_eq!(s.wallet.spent(T0), 17_000);
        assert!(matches!(
            s.approved(&g, sign(&spend(9_000)), T0),
            Decision::Deny(DenyReason::CredentialBudgetExceeded { spent: 17_000, .. })
        ));
        let change_only = analysis(&[(5_000, None, true)], 0);
        assert_eq!(
            s.decide(&g, sign(&change_only), T0),
            Decision::Allow,
            "moving nothing out needs no approval past the threshold"
        );
    }

    #[test]
    fn a_spend_of_nothing_is_allowed_without_a_ledger_entry() {
        let mut s = State::new();
        let mut g = grant();
        btc(&mut g).window_sats = 10_000;
        assert!(s.spends(&g, 10_000, T0));
        let change_only = analysis(&[(5_000, None, true)], 0);
        for _ in 0..MAX_WALLET_ENTRIES + 1 {
            assert_eq!(s.decide(&g, sign(&change_only), T0), Decision::Allow);
        }
        assert_eq!(s.credential.spends.len(), 1);
        assert_eq!(s.wallet.spends.len(), 1);
    }

    #[test]
    fn full_ledgers_refuse_instead_of_forgetting() {
        let mut s = State::new();
        let mut g = grant();
        btc(&mut g).window_sats = u64::MAX;
        btc(&mut g).per_psbt_sats = u64::MAX;
        s.wallet_window_sats = u64::MAX;
        let one_sat = analysis(&[(1, Some(ADDR), false)], 0);
        for _ in 0..MAX_CREDENTIAL_ENTRIES {
            assert!(matches!(
                s.decide(&g, sign(&one_sat), T0),
                Decision::Spend(_)
            ));
        }
        assert_eq!(
            s.decide(&g, sign(&one_sat), T0),
            Decision::Deny(DenyReason::LedgerFull)
        );
        assert_eq!(s.credential.spent(T0), MAX_CREDENTIAL_ENTRIES as u64);

        // Other credentials fill the wallet's ledger, which then refuses too.
        while s.wallet.spends.len() < MAX_WALLET_ENTRIES {
            s.credential = Ledger::default();
            assert!(matches!(
                s.decide(&g, sign(&one_sat), T0),
                Decision::Spend(_)
            ));
        }
        s.credential = Ledger::default();
        assert_eq!(
            s.decide(&g, sign(&one_sat), T0),
            Decision::Deny(DenyReason::LedgerFull)
        );
        assert_eq!(s.credential.spent(T0), 0);

        // Once the window passes, the spends age out and make room again.
        assert!(matches!(
            s.decide(&g, sign(&one_sat), T0 + W),
            Decision::Spend(_)
        ));
        assert_eq!(s.wallet.spends.len(), 1);
    }

    #[test]
    fn a_reservation_is_released_from_both_ledgers_once() {
        let mut s = State::new();
        let g = grant();
        let Decision::Spend(first) = s.decide(&g, sign(&spend(5_000)), T0) else {
            panic!("expected a spend");
        };
        assert!(
            s.spends(&g, 5_000, T0),
            "a second spend of the same size, same second"
        );
        first.release(&mut s.credential, &mut s.wallet);
        assert_eq!(
            s.credential.spent(T0),
            5_000,
            "only the released spend is returned"
        );
        assert_eq!(s.wallet.spent(T0), 5_000);
    }

    #[test]
    fn validation_requires_what_each_operation_needs() {
        let refused = |g: Grant| match g.validated() {
            Err(AgentError::ScopeViolation(m)) => m,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(grant().validated().is_ok());
        let only = |op| {
            let mut g = grant();
            g.operations = [op].into();
            g
        };
        let mut g = grant();
        g.keys.clear();
        assert!(refused(g).contains("keys"));
        let mut g = only(Operation::SignNostrEvent);
        g.event_kinds.clear();
        assert!(refused(g).contains("event kinds"));
        for op in [Operation::Nip44Encrypt, Operation::Nip44Decrypt] {
            let mut g = only(op);
            g.nip44_peers.clear();
            assert!(refused(g).contains(op.as_str()));
        }
        for op in [Operation::SignPsbt, Operation::GetBitcoinAddress] {
            let mut g = only(op);
            g.bitcoin = None;
            assert!(refused(g).contains(op.as_str()));
        }
        let mut g = grant();
        btc(&mut g).per_psbt_sats = 25_001;
        assert!(refused(g).contains("per_psbt_sats"));
        let mut g = grant();
        btc(&mut g).address_allowlist = Some(BTreeSet::new());
        assert!(refused(g).contains("at least one address"));
        let mut g = grant();
        btc(&mut g).address_allowlist =
            Some(["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into()].into());
        assert!(refused(g).contains("not an address on"));
        let mut g = grant();
        btc(&mut g).address_allowlist = Some([ADDR.to_uppercase()].into());
        let g = g.validated().unwrap();
        assert!(g.bitcoin.unwrap().address_allowlist.unwrap().contains(ADDR));
    }

    #[test]
    fn grants_and_ledgers_round_trip_through_serde() {
        let g = grant();
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(serde_json::from_str::<Grant>(&json).unwrap(), g);
        let mut s = State::new();
        assert!(s.spends(&g, 5_000, T0));
        let json = serde_json::to_string(&s.credential).unwrap();
        assert_eq!(serde_json::from_str::<Ledger>(&json).unwrap(), s.credential);
    }
}

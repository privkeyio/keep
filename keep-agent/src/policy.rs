// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The agent gateway's deny-by-default policy. A request is allowed only when
//! the credential's grant names it explicitly; anything the grant does not
//! cover, or any context the decision needs and lacks, is denied.

use std::collections::BTreeSet;
use std::fmt;

use keep_bitcoin::{Network, PsbtAnalysis};
use serde::{Deserialize, Serialize};

use crate::error::{AgentError, Result};
use crate::scope::{canonical_address, Operation};

/// The length of a spend budget's rolling window.
pub const BUDGET_WINDOW_SECS: u64 = 24 * 60 * 60;

/// The most spends a ledger holds within its window; a full ledger refuses
/// further spends rather than forgetting earlier ones.
pub const MAX_LEDGER_ENTRIES: usize = 10_000;

/// Kinds that move funds, authenticate, or rewrite the owner's identity. An
/// agent never signs these on its grant alone: each one needs an approval.
pub const APPROVAL_KINDS: &[u16] = &[
    0,     // profile metadata
    3,     // contact list
    5,     // deletion
    7375,  // NIP-60 ecash tokens
    7376,  // NIP-60 spending history
    9321,  // NIP-61 nutzap
    10002, // relay list
    22242, // NIP-42 relay auth
    23194, // NIP-47 wallet request (pay_invoice)
    24133, // NIP-46 remote signing
    27235, // NIP-98 HTTP auth
];

/// What a credential may do. Every field is an explicit allowance: an empty set
/// allows nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub operations: BTreeSet<Operation>,
    pub nostr_kinds: BTreeSet<u16>,
    /// Counterparty x-only public keys for NIP-44 encrypt and decrypt.
    pub nip44_peers: BTreeSet<[u8; 32]>,
    pub bitcoin: Option<BitcoinGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinGrant {
    pub network: Network,
    /// What one PSBT may take out of the wallet, fee included.
    pub per_psbt_sats: u64,
    /// What the credential may take out of the wallet in any rolling window.
    pub window_sats: u64,
    /// Above this much leaving the wallet within the window, counting the
    /// request, each spend needs an approval.
    pub approval_above_sats: Option<u64>,
    /// When set, every output but recognized change must pay one of these
    /// (canonical) addresses.
    pub address_allowlist: Option<BTreeSet<String>>,
}

impl Grant {
    /// The grant a credential may be issued with: each operation has what it
    /// needs to ever be allowed, and allowlisted addresses are on the grant's
    /// network (stored canonically).
    pub fn validated(mut self) -> Result<Self> {
        let refuse = |m: &str| Err(AgentError::ScopeViolation(m.into()));
        let has = |op| self.operations.contains(&op);
        if has(Operation::SignNostrEvent) && self.nostr_kinds.is_empty() {
            return refuse("sign_nostr_event needs an explicit list of event kinds");
        }
        if (has(Operation::Nip44Encrypt) || has(Operation::Nip44Decrypt))
            && self.nip44_peers.is_empty()
        {
            return refuse("NIP-44 operations need the counterparties they may use");
        }
        if (has(Operation::SignPsbt) || has(Operation::GetBitcoinAddress)) && self.bitcoin.is_none()
        {
            return refuse("Bitcoin operations need a Bitcoin grant");
        }
        if let Some(btc) = self.bitcoin.as_mut() {
            if let Some(allowlist) = btc.address_allowlist.take() {
                let canonical = allowlist
                    .iter()
                    .map(|a| {
                        canonical_address(a, btc.network).ok_or_else(|| {
                            AgentError::ScopeViolation(format!(
                                "Allowlist entry '{a}' is not an address on {}",
                                btc.network
                            ))
                        })
                    })
                    .collect::<Result<_>>()?;
                btc.address_allowlist = Some(canonical);
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
    SignPsbt {
        network: Network,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed. A spend has been reserved in the ledgers already.
    Allow,
    Deny(DenyReason),
    RequireApproval(ApprovalReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
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
    WindowBudgetExceeded {
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
            Self::WindowBudgetExceeded { requested, spent, limit } => write!(
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
    /// The latest time the ledger has seen, so a clock stepped backward cannot
    /// reopen the window.
    last_seen: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Spend {
    at: u64,
    sats: u64,
}

impl Ledger {
    fn now(&mut self, now: u64) -> u64 {
        self.last_seen = self.last_seen.max(now);
        self.last_seen
    }

    fn prune(&mut self, now: u64) {
        let start = now.saturating_sub(BUDGET_WINDOW_SECS);
        self.spends.retain(|s| s.at > start);
    }

    /// Sats spent within the window ending at `now`.
    pub fn spent(&mut self, now: u64) -> u64 {
        let now = self.now(now);
        self.prune(now);
        self.spends
            .iter()
            .map(|s| s.sats)
            .fold(0, u64::saturating_add)
    }

    fn has_room(&self) -> bool {
        self.spends.len() < MAX_LEDGER_ENTRIES
    }

    fn reserve(&mut self, at: u64, sats: u64) {
        self.spends.push(Spend { at, sats });
    }

    /// Return a reservation for a spend that produced no signature.
    pub fn release(&mut self, at: u64, sats: u64) {
        if let Some(i) = self.spends.iter().rposition(|s| *s == Spend { at, sats }) {
            self.spends.remove(i);
        }
    }
}

/// The ledgers a spend is counted against: the credential's own, and the
/// wallet's across every credential.
pub struct Budgets<'a> {
    pub credential: &'a mut Ledger,
    pub wallet: &'a mut Ledger,
    pub wallet_window_sats: u64,
}

/// A spend reserved by an allowed `SignPsbt`, to `release` from both ledgers if
/// no signature comes of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    pub at: u64,
    pub sats: u64,
}

impl Reservation {
    pub fn release(self, budgets: &mut Budgets<'_>) {
        budgets.credential.release(self.at, self.sats);
        budgets.wallet.release(self.at, self.sats);
    }
}

/// Decide `request` made with the key `key` under `grant`. An allowed spend is
/// reserved in `budgets` before this returns, so callers serialize decisions
/// and persist the ledgers before signing.
pub fn evaluate(
    grant: &Grant,
    key: &[u8; 32],
    request: &Request<'_>,
    budgets: &mut Budgets<'_>,
    now: u64,
) -> (Decision, Option<Reservation>) {
    let op = request.operation();
    if !grant.operations.contains(&op) {
        return (Decision::Deny(DenyReason::OperationNotGranted(op)), None);
    }
    let decision = match *request {
        Request::GetPublicKey => Decision::Allow,
        Request::SignNostrEvent { kind } => {
            if !grant.nostr_kinds.contains(&kind) {
                Decision::Deny(DenyReason::KindNotGranted(kind))
            } else if APPROVAL_KINDS.contains(&kind) {
                Decision::RequireApproval(ApprovalReason::Kind(kind))
            } else {
                Decision::Allow
            }
        }
        Request::Nip44Encrypt { peer } => peer_decision(grant, &peer, false),
        Request::Nip44Decrypt { peer } => peer_decision(grant, &peer, peer == *key),
        Request::GetBitcoinAddress { network } => match bitcoin_grant(grant, network) {
            Ok(_) => Decision::Allow,
            Err(reason) => Decision::Deny(reason),
        },
        Request::SignPsbt { network, analysis } => match bitcoin_grant(grant, network) {
            Ok(btc) => return spend_decision(btc, analysis, budgets, now),
            Err(reason) => Decision::Deny(reason),
        },
    };
    (decision, None)
}

fn peer_decision(grant: &Grant, peer: &[u8; 32], own_payload: bool) -> Decision {
    if !grant.nip44_peers.contains(peer) {
        Decision::Deny(DenyReason::PeerNotGranted)
    } else if own_payload {
        Decision::RequireApproval(ApprovalReason::DecryptOwnPayload)
    } else {
        Decision::Allow
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
) -> (Decision, Option<Reservation>) {
    let deny = |reason| (Decision::Deny(reason), None);
    let requested = analysis.leaving_wallet_sats();
    if requested > btc.per_psbt_sats {
        return deny(DenyReason::PerPsbtExceeded {
            requested,
            limit: btc.per_psbt_sats,
        });
    }
    if let Some(allowlist) = &btc.address_allowlist {
        for output in analysis.outputs.iter().filter(|o| !o.is_change) {
            match &output.address {
                Some(a) if allowlist.contains(a) => {}
                Some(a) => return deny(DenyReason::AddressNotAllowed(a.clone())),
                None => return deny(DenyReason::OutputWithoutAddress(output.index)),
            }
        }
    }
    let at = budgets.credential.now(now).max(budgets.wallet.now(now));
    let spent = budgets.credential.spent(at);
    if spent.saturating_add(requested) > btc.window_sats {
        return deny(DenyReason::WindowBudgetExceeded {
            requested,
            spent,
            limit: btc.window_sats,
        });
    }
    let wallet_spent = budgets.wallet.spent(at);
    if wallet_spent.saturating_add(requested) > budgets.wallet_window_sats {
        return deny(DenyReason::WalletBudgetExceeded {
            requested,
            spent: wallet_spent,
            limit: budgets.wallet_window_sats,
        });
    }
    if let Some(threshold) = btc.approval_above_sats {
        if spent.saturating_add(requested) > threshold {
            let reason = ApprovalReason::AboveThreshold {
                requested,
                spent,
                threshold,
            };
            return (Decision::RequireApproval(reason), None);
        }
    }
    if !budgets.credential.has_room() || !budgets.wallet.has_room() {
        return deny(DenyReason::LedgerFull);
    }
    budgets.credential.reserve(at, requested);
    budgets.wallet.reserve(at, requested);
    (
        Decision::Allow,
        Some(Reservation {
            at,
            sats: requested,
        }),
    )
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

    fn grant() -> Grant {
        Grant {
            operations: [
                Operation::GetPublicKey,
                Operation::SignNostrEvent,
                Operation::Nip44Encrypt,
                Operation::Nip44Decrypt,
                Operation::GetBitcoinAddress,
                Operation::SignPsbt,
            ]
            .into(),
            nostr_kinds: [1, 7, 23194].into(),
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
        }
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

        fn decide(&mut self, grant: &Grant, request: Request<'_>, now: u64) -> Decision {
            self.decide_reserving(grant, request, now).0
        }

        fn decide_reserving(
            &mut self,
            grant: &Grant,
            request: Request<'_>,
            now: u64,
        ) -> (Decision, Option<Reservation>) {
            let mut budgets = Budgets {
                credential: &mut self.credential,
                wallet: &mut self.wallet,
                wallet_window_sats: self.wallet_window_sats,
            };
            evaluate(grant, &KEY, &request, &mut budgets, now)
        }
    }

    fn spend(sats: u64) -> PsbtAnalysis {
        analysis(
            &[(sats - 100, Some(ADDR), false), (50_000, None, true)],
            100,
        )
    }

    fn sign(a: &PsbtAnalysis) -> Request<'_> {
        Request::SignPsbt {
            network: Network::Bitcoin,
            analysis: a,
        }
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
            s.decide(&g, sign(&a), T0),
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
            s.decide(&g, Request::SignNostrEvent { kind: 23194 }, T0),
            Decision::RequireApproval(ApprovalReason::Kind(23194))
        );
        for &kind in APPROVAL_KINDS {
            let mut g = grant();
            g.nostr_kinds = [kind].into();
            assert_eq!(
                s.decide(&g, Request::SignNostrEvent { kind }, T0),
                Decision::RequireApproval(ApprovalReason::Kind(kind)),
                "{kind}"
            );
        }
    }

    #[test]
    fn nip44_is_scoped_to_granted_peers_and_own_payloads_need_approval() {
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
        assert_eq!(
            s.decide(&g, Request::Nip44Decrypt { peer: [3; 32] }, T0),
            Decision::Deny(DenyReason::PeerNotGranted)
        );
        assert_eq!(
            s.decide(&g, Request::Nip44Decrypt { peer: KEY }, T0),
            Decision::RequireApproval(ApprovalReason::DecryptOwnPayload)
        );
        assert_eq!(
            s.decide(&g, Request::Nip44Encrypt { peer: KEY }, T0),
            Decision::Allow
        );
    }

    #[test]
    fn bitcoin_requests_must_name_the_granted_network() {
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
        let a = spend(1_000);
        let testnet = Request::SignPsbt {
            network: Network::Testnet,
            analysis: &a,
        };
        assert!(matches!(
            s.decide(&g, testnet, T0),
            Decision::Deny(DenyReason::NetworkMismatch { .. })
        ));
        g.bitcoin = None;
        assert_eq!(
            s.decide(&g, sign(&a), T0),
            Decision::Deny(DenyReason::NoBitcoinGrant)
        );
        assert_eq!(s.credential.spent(T0), 0);
    }

    #[test]
    fn the_per_psbt_limit_counts_the_fee() {
        let mut s = State::new();
        let g = grant();
        let a = analysis(&[(9_000, Some(ADDR), false), (50_000, None, true)], 1_000);
        assert_eq!(s.decide(&g, sign(&a), T0), Decision::Allow);
        let a = analysis(&[(9_000, Some(ADDR), false)], 1_001);
        assert_eq!(
            s.decide(&g, sign(&a), T0),
            Decision::Deny(DenyReason::PerPsbtExceeded {
                requested: 10_001,
                limit: 10_000
            })
        );
    }

    #[test]
    fn the_allowlist_fails_closed() {
        let mut s = State::new();
        let mut g = grant();
        g.bitcoin.as_mut().unwrap().address_allowlist = Some([ADDR.to_string()].into());
        let g = g.validated().unwrap();
        assert_eq!(s.decide(&g, sign(&spend(1_000)), T0), Decision::Allow);
        let a = analysis(&[(1_000, Some(OTHER), false)], 100);
        assert_eq!(
            s.decide(&g, sign(&a), T0),
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
        for _ in 0..2 {
            assert_eq!(s.decide(&g, sign(&spend(10_000)), T0), Decision::Allow);
        }
        assert_eq!(s.decide(&g, sign(&spend(5_000)), T0 + 1), Decision::Allow);
        let one_sat = analysis(&[(1, Some(ADDR), false)], 0);
        assert_eq!(
            s.decide(&g, sign(&one_sat), T0 + 2),
            Decision::Deny(DenyReason::WindowBudgetExceeded {
                requested: 1,
                spent: 25_000,
                limit: 25_000
            })
        );
        assert_eq!(
            s.credential.spent(T0 + 2),
            25_000,
            "a denial reserves nothing"
        );
        let later = T0 + BUDGET_WINDOW_SECS;
        assert_eq!(s.credential.spent(later), 5_000);
        assert_eq!(s.decide(&g, sign(&spend(10_000)), later), Decision::Allow);
    }

    #[test]
    fn a_clock_stepped_back_neither_frees_nor_shortens_spends() {
        let mut s = State::new();
        let g = grant();
        let later = T0 + BUDGET_WINDOW_SECS;
        assert_eq!(s.decide(&g, sign(&spend(10_000)), later), Decision::Allow);
        // The clock steps back a whole window: the earlier spend still counts,
        // and this one is stamped at the latest time seen, so it does not age
        // out early once the clock catches up.
        let (decision, reservation) = s.decide_reserving(&g, sign(&spend(10_000)), T0);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(reservation.unwrap().at, later);
        assert!(matches!(
            s.decide(&g, sign(&spend(10_000)), T0),
            Decision::Deny(DenyReason::WindowBudgetExceeded { spent: 20_000, .. })
        ));
        assert_eq!(s.credential.spent(later + BUDGET_WINDOW_SECS - 1), 20_000);
    }

    #[test]
    fn the_wallet_budget_spans_credentials() {
        let mut s = State::new();
        s.wallet_window_sats = 15_000;
        let g = grant();
        assert_eq!(s.decide(&g, sign(&spend(10_000)), T0), Decision::Allow);
        s.credential = Ledger::default();
        assert_eq!(
            s.decide(&g, sign(&spend(10_000)), T0),
            Decision::Deny(DenyReason::WalletBudgetExceeded {
                requested: 10_000,
                spent: 10_000,
                limit: 15_000
            })
        );
        assert_eq!(s.credential.spent(T0), 0);
    }

    #[test]
    fn the_approval_threshold_is_cumulative() {
        let mut s = State::new();
        let mut g = grant();
        g.bitcoin.as_mut().unwrap().approval_above_sats = Some(12_000);
        assert_eq!(s.decide(&g, sign(&spend(8_000)), T0), Decision::Allow);
        assert_eq!(
            s.decide(&g, sign(&spend(5_000)), T0),
            Decision::RequireApproval(ApprovalReason::AboveThreshold {
                requested: 5_000,
                spent: 8_000,
                threshold: 12_000
            })
        );
        assert_eq!(
            s.credential.spent(T0),
            8_000,
            "an approval request reserves nothing"
        );
    }

    #[test]
    fn a_full_ledger_refuses_instead_of_forgetting() {
        let mut s = State::new();
        let mut g = grant();
        g.bitcoin.as_mut().unwrap().window_sats = u64::MAX;
        s.wallet_window_sats = u64::MAX;
        for i in 0..MAX_LEDGER_ENTRIES as u64 {
            s.credential.reserve(T0 + i % 60, 1);
        }
        let a = analysis(&[(1, Some(ADDR), false)], 0);
        assert_eq!(
            s.decide(&g, sign(&a), T0 + 60),
            Decision::Deny(DenyReason::LedgerFull)
        );
        assert_eq!(s.credential.spent(T0 + 60), MAX_LEDGER_ENTRIES as u64);
    }

    #[test]
    fn a_reservation_is_released_from_both_ledgers() {
        let mut s = State::new();
        let g = grant();
        let (decision, reservation) = s.decide_reserving(&g, sign(&spend(10_000)), T0);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(s.wallet.spent(T0), 10_000);
        let mut budgets = Budgets {
            credential: &mut s.credential,
            wallet: &mut s.wallet,
            wallet_window_sats: 100_000,
        };
        reservation.unwrap().release(&mut budgets);
        assert_eq!(s.credential.spent(T0), 0);
        assert_eq!(s.wallet.spent(T0), 0);
    }

    #[test]
    fn validation_requires_what_each_operation_needs() {
        let refused = |g: Grant| match g.validated() {
            Err(AgentError::ScopeViolation(m)) => m,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(grant().validated().is_ok());
        let mut g = grant();
        g.nostr_kinds.clear();
        assert!(refused(g).contains("event kinds"));
        let mut g = grant();
        g.nip44_peers.clear();
        assert!(refused(g).contains("counterparties"));
        let mut g = grant();
        g.bitcoin = None;
        assert!(refused(g).contains("Bitcoin grant"));
        let mut g = grant();
        g.bitcoin.as_mut().unwrap().address_allowlist =
            Some(["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into()].into());
        assert!(refused(g).contains("not an address on"));
        let mut g = grant();
        g.bitcoin.as_mut().unwrap().address_allowlist = Some([ADDR.to_uppercase()].into());
        let g = g.validated().unwrap();
        assert!(g.bitcoin.unwrap().address_allowlist.unwrap().contains(ADDR));
    }

    #[test]
    fn a_grant_round_trips_through_serde() {
        let g = grant();
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(serde_json::from_str::<Grant>(&json).unwrap(), g);
        let mut ledger = Ledger::default();
        ledger.reserve(T0, 5);
        let json = serde_json::to_string(&ledger).unwrap();
        assert_eq!(serde_json::from_str::<Ledger>(&json).unwrap(), ledger);
    }
}

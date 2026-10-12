// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The request hash: what binds a decision to one request, one gateway and
//! one credential, and the checks an approver runs on a request before
//! showing it.
//!
//! ```text
//! request_hash = tagged("keep/approval/request/v1",
//!     u8   version            = 1
//!     32   channel_pubkey     (x-only)
//!     16   credential_id      (zero when the request names no credential)
//!     32   request_id
//!     u8   op
//!     32   key                (zero when the op has no key)
//!     u8   network
//!     u32  payload_len
//!     ...  payload
//! )
//! ```
//!
//! All integers are little-endian. Every field has a fixed length or a
//! length prefix, so two different requests never encode the same.

use nostr::{EventId, Kind, PublicKey, Tag, Tags, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::change::Change;
use crate::messages::{AnchorState, Budget, CredentialRef, Reason, Request, V1};
use crate::psbt::{put_u32, PsbtPayload, PsbtView};
use crate::{invalid, malformed, sha256, tagged_hash, Hex32, Result};

/// The tag of the request hash.
pub const REQUEST_TAG: &str = "keep/approval/request/v1";

/// The shortest and longest deadline a request may carry, in seconds.
pub const DEADLINE_SECS: std::ops::RangeInclusive<u64> = 30..=120;

/// The deadline when none is configured.
pub const DEFAULT_DEADLINE_SECS: u64 = 120;

/// What a request asks to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    SignNostrEvent,
    SignPsbt,
    Nip44Encrypt,
    Nip44Decrypt,
    Management,
}

impl Op {
    /// The op byte the request hash covers. Codes 5 to 15 are reserved for
    /// future operations (inject, ssh, reveal).
    pub fn code(self) -> u8 {
        match self {
            Op::SignNostrEvent => 1,
            Op::SignPsbt => 2,
            Op::Nip44Encrypt => 3,
            Op::Nip44Decrypt => 4,
            Op::Management => 16,
        }
    }
}

/// The network a request is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    /// The network byte the request hash covers; 0 is no network.
    pub fn code(self) -> u8 {
        match self {
            Network::Mainnet => 1,
            Network::Testnet3 => 2,
            Network::Testnet4 => 3,
            Network::Signet => 4,
            Network::Regtest => 5,
        }
    }

    /// The bitcoin crate's network.
    pub fn bitcoin(self) -> bitcoin::Network {
        match self {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet3 => bitcoin::Network::Testnet,
            Network::Testnet4 => bitcoin::Network::Testnet4,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// From the bitcoin crate's network.
    pub fn from_bitcoin(network: bitcoin::Network) -> Self {
        match network {
            bitcoin::Network::Bitcoin => Network::Mainnet,
            bitcoin::Network::Testnet => Network::Testnet3,
            bitcoin::Network::Testnet4 => Network::Testnet4,
            bitcoin::Network::Signet => Network::Signet,
            bitcoin::Network::Regtest => Network::Regtest,
        }
    }
}

/// The unsigned event a `sign_nostr_event` request will sign, exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedEventFields {
    pub pubkey: Hex32,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl UnsignedEventFields {
    /// The NIP-01 id of the event.
    pub fn event_id(&self) -> Result<[u8; 32]> {
        let pubkey =
            PublicKey::from_slice(&self.pubkey.0).map_err(|_| malformed("event pubkey"))?;
        let tags = self
            .tags
            .iter()
            .map(|t| Tag::parse(t.clone()).map_err(|_| malformed("event tag")))
            .collect::<Result<Vec<Tag>>>()?;
        let id = EventId::new(
            &pubkey,
            &Timestamp::from_secs(self.created_at),
            &Kind::from(self.kind),
            &Tags::from_list(tags),
            &self.content,
        );
        Ok(id.to_bytes())
    }
}

/// `payload` of a `sign_nostr_event` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NostrPayload {
    pub event: UnsignedEventFields,
}

/// `payload` of a `nip44_encrypt` request. Its `Debug` leaves out the
/// plaintext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nip44EncryptPayload {
    pub peer: Hex32,
    pub plaintext: String,
}

impl Drop for Nip44EncryptPayload {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.plaintext);
    }
}

impl Drop for Nip44DecryptPayload {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.plaintext);
    }
}

impl std::fmt::Debug for Nip44EncryptPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nip44EncryptPayload")
            .field("peer", &self.peer)
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

/// `payload` of a `nip44_decrypt` request: the gateway decrypts first and
/// shows the approver what the agent would get. Its `Debug` leaves out the
/// plaintext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nip44DecryptPayload {
    pub peer: Hex32,
    /// SHA-256 of the NIP-44 payload exactly as the agent sent it.
    pub ciphertext_sha256: Hex32,
    pub plaintext: String,
}

impl std::fmt::Debug for Nip44DecryptPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nip44DecryptPayload")
            .field("peer", &self.peer)
            .field("ciphertext_sha256", &self.ciphertext_sha256)
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

/// `payload` of a `management` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagementWire {
    change: Value,
}

/// A request's payload, by op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Nostr(NostrPayload),
    Psbt(PsbtPayload),
    Nip44Encrypt(Nip44EncryptPayload),
    Nip44Decrypt(Nip44DecryptPayload),
    Management(Change),
}

impl Payload {
    /// The op this payload belongs to.
    pub fn op(&self) -> Op {
        match self {
            Payload::Nostr(_) => Op::SignNostrEvent,
            Payload::Psbt(_) => Op::SignPsbt,
            Payload::Nip44Encrypt(_) => Op::Nip44Encrypt,
            Payload::Nip44Decrypt(_) => Op::Nip44Decrypt,
            Payload::Management(_) => Op::Management,
        }
    }

    /// Parse the payload of a request with `op`, strictly.
    pub fn parse(op: Op, value: &Value) -> Result<Self> {
        let typed = |e: serde_json::Error| malformed(format!("payload: {e}"));
        Ok(match op {
            Op::SignNostrEvent => {
                Payload::Nostr(serde_json::from_value(value.clone()).map_err(typed)?)
            }
            Op::SignPsbt => Payload::Psbt(serde_json::from_value(value.clone()).map_err(typed)?),
            Op::Nip44Encrypt => {
                Payload::Nip44Encrypt(serde_json::from_value(value.clone()).map_err(typed)?)
            }
            Op::Nip44Decrypt => {
                Payload::Nip44Decrypt(serde_json::from_value(value.clone()).map_err(typed)?)
            }
            Op::Management => {
                let wire: ManagementWire = serde_json::from_value(value.clone()).map_err(typed)?;
                Payload::Management(Change::parse(&wire.change)?)
            }
        })
    }

    /// The payload as a JSON value, as a request carries it.
    pub fn to_value(&self) -> Value {
        let value = match self {
            Payload::Nostr(p) => serde_json::to_value(p),
            Payload::Psbt(p) => serde_json::to_value(p),
            Payload::Nip44Encrypt(p) => serde_json::to_value(p),
            Payload::Nip44Decrypt(p) => serde_json::to_value(p),
            Payload::Management(c) => serde_json::to_value(ManagementWire {
                change: c.to_value(),
            }),
        };
        value.expect("payloads always serialize")
    }

    /// The canonical payload bytes the request hash covers.
    pub fn binding_bytes(&self, network: Option<Network>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Payload::Nostr(p) => {
                out.extend_from_slice(&p.event.event_id()?);
                out.extend_from_slice(&p.event.pubkey.0);
            }
            Payload::Psbt(p) => {
                let network = network.ok_or_else(|| invalid("a PSBT request needs a network"))?;
                out = p.binding_bytes(network)?;
            }
            Payload::Nip44Encrypt(p) => {
                out.extend_from_slice(&p.peer.0);
                out.extend_from_slice(&sha256(p.plaintext.as_bytes()));
            }
            Payload::Nip44Decrypt(p) => {
                out.extend_from_slice(&p.peer.0);
                out.extend_from_slice(&p.ciphertext_sha256.0);
                out.extend_from_slice(&sha256(p.plaintext.as_bytes()));
            }
            Payload::Management(c) => {
                out.push(c.type_code());
                out.extend_from_slice(&c.digest());
            }
        }
        Ok(out)
    }
}

/// Everything the request hash binds.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    pub channel: [u8; 32],
    pub credential: Option<[u8; 16]>,
    pub request_id: [u8; 32],
    pub key: Option<[u8; 32]>,
    pub network: Option<Network>,
    pub payload: &'a Payload,
}

impl Binding<'_> {
    /// The bytes the tagged hash covers.
    pub fn preimage(&self) -> Result<Vec<u8>> {
        let payload = self.payload.binding_bytes(self.network)?;
        let mut m = Vec::with_capacity(119 + payload.len());
        m.push(crate::VERSION);
        m.extend_from_slice(&self.channel);
        m.extend_from_slice(&self.credential.unwrap_or([0; 16]));
        m.extend_from_slice(&self.request_id);
        m.push(self.payload.op().code());
        m.extend_from_slice(&self.key.unwrap_or([0; 32]));
        m.push(self.network.map_or(0, Network::code));
        put_u32(
            &mut m,
            u32::try_from(payload.len()).map_err(|_| malformed("payload too long"))?,
        );
        m.extend_from_slice(&payload);
        Ok(m)
    }

    /// The request hash.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(tagged_hash(REQUEST_TAG, &self.preimage()?))
    }
}

/// What the gateway fills in to make a request; [`RequestDraft::finish`]
/// checks it as an approver will and computes its hash.
#[derive(Debug, Clone)]
pub struct RequestDraft {
    pub request_id: [u8; 32],
    pub created_at: u64,
    pub deadline_secs: u64,
    pub credential: Option<CredentialRef>,
    pub key: Option<[u8; 32]>,
    pub network: Option<Network>,
    pub reason: Reason,
    pub payload: Payload,
    pub budget: Option<Budget>,
    pub anchor: AnchorState,
}

impl RequestDraft {
    /// The request, with its hash, after the checks an approver runs and the
    /// size limit, so the gateway never sends one an approver would refuse
    /// or a wrap could not carry.
    pub fn finish(self, channel: &[u8; 32]) -> Result<(Request, [u8; 32])> {
        let hash = Binding {
            channel: *channel,
            credential: self.credential.as_ref().map(|c| c.id.0),
            request_id: self.request_id,
            key: self.key,
            network: self.network,
            payload: &self.payload,
        }
        .hash()?;
        let request = Request {
            v: V1,
            request_id: Hex32(self.request_id),
            request_hash: Hex32(hash),
            created_at: self.created_at,
            deadline_secs: self.deadline_secs,
            credential: self.credential,
            op: self.payload.op(),
            key: self.key.map(Hex32),
            network: self.network,
            reason: self.reason,
            payload: self.payload.to_value(),
            budget: self.budget,
            anchor: self.anchor,
        };
        check_request(&request, channel)?;
        crate::wrap::check_rumor_size(
            crate::kind::REQUEST,
            &crate::messages::to_text(&request),
            request.created_at,
        )?;
        Ok((request, hash))
    }
}

/// A request that passed every check, with its parsed payload.
#[derive(Debug, Clone)]
pub struct CheckedRequest {
    pub payload: Payload,
    /// The recomputed figures, for a PSBT.
    pub psbt: Option<PsbtView>,
}

/// The checks an approver runs on a request from `channel` before showing
/// it: the payload parses for its op; the key, network, credential, budget
/// and reason fit the op and the payload; the deadline is in range; an
/// event is not of the protocol's kinds; a PSBT's figures add up and its
/// reason's figures are the payload's and the budget's; and the request
/// hash is the one these fields give.
pub fn check_request(request: &Request, channel: &[u8; 32]) -> Result<CheckedRequest> {
    if !DEADLINE_SECS.contains(&request.deadline_secs) {
        return Err(invalid("deadline out of range"));
    }
    let payload = Payload::parse(request.op, &request.payload)?;
    let key = request.key.map(|k| k.0);
    let needs_key = request.op != Op::Management;
    if key.is_some() != needs_key {
        return Err(invalid("the key does not fit the op"));
    }
    if request.network.is_some() != (request.op == Op::SignPsbt) {
        return Err(invalid("the network does not fit the op"));
    }
    if request.budget.is_some() != (request.op == Op::SignPsbt) {
        return Err(invalid("the budget does not fit the op"));
    }
    let mut psbt = None;
    match (&payload, request.reason) {
        (Payload::Nostr(p), Reason::Kind { kind }) => {
            if Some(p.event.pubkey.0) != key {
                return Err(invalid("the event's pubkey is not the request's key"));
            }
            if p.event.kind != kind {
                return Err(invalid("the reason names another kind"));
            }
            if crate::kind::is_protocol_kind(kind) {
                return Err(invalid(
                    "the protocol's kinds are never signed for an agent",
                ));
            }
        }
        (
            Payload::Psbt(p),
            Reason::AboveThreshold {
                requested,
                spent,
                threshold,
            },
        ) => {
            let view = p.check(request.network.expect("checked above"))?;
            let budget = request.budget.expect("checked above");
            if requested != view.leaving_wallet || spent != budget.credential_spent {
                return Err(invalid("the reason's figures are not the request's"));
            }
            if spent.checked_add(requested).is_none_or(|t| t <= threshold) {
                return Err(invalid("the spend is not above the threshold"));
            }
            psbt = Some(view);
        }
        (Payload::Nip44Encrypt(_), Reason::EncryptToOwnKey) => {}
        (Payload::Nip44Decrypt(_), Reason::DecryptOwnPayload) => {}
        (Payload::Management(c), Reason::Management) => check_management(c, &request.credential)?,
        _ => return Err(invalid("the reason does not fit the op")),
    }
    if request.op != Op::Management && request.credential.is_none() {
        return Err(invalid("an agent request names its credential"));
    }
    if let Some(c) = &request.credential {
        crate::change::check_label(&c.name, "credential name")?;
    }
    let hash = Binding {
        channel: *channel,
        credential: request.credential.as_ref().map(|c| c.id.0),
        request_id: request.request_id.0,
        key,
        network: request.network,
        payload: &payload,
    }
    .hash()?;
    if hash != request.request_hash.0 {
        return Err(invalid("the request hash does not match its fields"));
    }
    Ok(CheckedRequest { payload, psbt })
}

/// A management request names the credential its change is about, and no
/// other: the new one for `issue_credential`, the one unfrozen for a
/// credential's unfreeze, none otherwise.
fn check_management(change: &Change, credential: &Option<CredentialRef>) -> Result<()> {
    use crate::change::Scope;
    let fits = match (change, credential) {
        (Change::IssueCredential { id, name, uid, .. }, Some(c)) => {
            c.id == *id && c.name == *name && u64::from(c.uid) == uid.0
        }
        (
            Change::Unfreeze {
                scope: Scope::Credential(id),
                ..
            },
            Some(c),
        ) => c.id == *id,
        (
            Change::Unfreeze {
                scope: Scope::All, ..
            },
            None,
        )
        | (Change::AddApprover { .. }, None)
        | (Change::RemoveApprover { .. }, None) => true,
        _ => false,
    };
    if fits {
        Ok(())
    } else {
        Err(invalid("the credential does not fit the change"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::change::{ChangeBitcoin, ChangeGrant, ChangeLimits, Decimal, Scope};
    use crate::messages::{LogPoint, WalletAnchor, WalletName};
    use crate::{Hex16, Hex32, Hex33};

    pub const CHANNEL: [u8; 32] = [0x11; 32];
    pub const KEY: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    pub fn credential() -> CredentialRef {
        CredentialRef {
            id: Hex16([0x22; 16]),
            name: "writer".into(),
            uid: 1001,
        }
    }

    pub fn anchor() -> AnchorState {
        AnchorState {
            seq: 4210,
            head: Hex32([0x33; 32]),
            prev: Some(LogPoint {
                seq: 4170,
                head: Hex32([0x32; 32]),
            }),
            wallets: vec![WalletAnchor {
                wallet: WalletName::new(true, &KEY),
                seq: 88,
                spent: 40_000,
                window: 100_000,
            }],
        }
    }

    pub fn grant() -> ChangeGrant {
        ChangeGrant {
            keys: vec![Hex32(KEY)],
            operations: vec!["sign_nostr_event".into(), "sign_psbt".into()],
            event_kinds: vec![Decimal(0), Decimal(1)],
            nip44_peers: vec![],
            bitcoin: Some(ChangeBitcoin {
                network: "bitcoin".into(),
                per_psbt_sats: Decimal(50_000),
                window_sats: Decimal(100_000),
                approval_above_sats: Some(Decimal(20_000)),
                address_allowlist: None,
            }),
            limits: ChangeLimits {
                per_minute: Decimal(10),
                per_hour: Decimal(100),
                per_day: Decimal(1000),
            },
        }
    }

    /// One draft of every kind of request.
    pub fn drafts() -> Vec<RequestDraft> {
        let base = |payload: Payload,
                    reason: Reason,
                    key: Option<[u8; 32]>,
                    network: Option<Network>,
                    credential: Option<CredentialRef>| RequestDraft {
            request_id: [0x44; 32],
            created_at: 1_791_580_000,
            deadline_secs: 120,
            credential,
            key,
            network,
            reason,
            payload,
            budget: None,
            anchor: anchor(),
        };
        let event = UnsignedEventFields {
            pubkey: Hex32(KEY),
            created_at: 1_791_580_000,
            kind: 0,
            tags: vec![vec!["p".into(), "aa".repeat(32)]],
            content: "{\"name\":\"agent\"}".into(),
        };
        let mut psbt = base(
            Payload::Psbt(crate::psbt::tests::sample_payload()),
            Reason::AboveThreshold {
                requested: 31_000,
                spent: 10_000,
                threshold: 20_000,
            },
            Some(KEY),
            Some(Network::Mainnet),
            Some(credential()),
        );
        psbt.budget = Some(Budget {
            credential_spent: 10_000,
            credential_window: 100_000,
            wallet_spent: 40_000,
            wallet_window: 200_000,
        });
        vec![
            base(
                Payload::Nostr(NostrPayload { event }),
                Reason::Kind { kind: 0 },
                Some(KEY),
                None,
                Some(credential()),
            ),
            psbt,
            base(
                Payload::Nip44Encrypt(Nip44EncryptPayload {
                    peer: Hex32(KEY),
                    plaintext: "note to self".into(),
                }),
                Reason::EncryptToOwnKey,
                Some(KEY),
                None,
                Some(credential()),
            ),
            base(
                Payload::Nip44Decrypt(Nip44DecryptPayload {
                    peer: Hex32(KEY),
                    ciphertext_sha256: Hex32([0x55; 32]),
                    plaintext: "{\"token\":\"cashu...\"}".into(),
                }),
                Reason::DecryptOwnPayload,
                Some(KEY),
                None,
                Some(credential()),
            ),
            base(
                Payload::Management(Change::IssueCredential {
                    id: Hex16([0x22; 16]),
                    name: "writer".into(),
                    uid: Decimal(1001),
                    created_at: Decimal(1_791_580_000),
                    expires_at: Decimal(1_794_172_000),
                    grant: grant(),
                }),
                Reason::Management,
                None,
                None,
                Some(credential()),
            ),
            base(
                Payload::Management(Change::Unfreeze {
                    scope: Scope::All,
                    epoch: Decimal(41),
                }),
                Reason::Management,
                None,
                None,
                None,
            ),
            base(
                Payload::Management(Change::Unfreeze {
                    scope: Scope::Credential(Hex16([0x22; 16])),
                    epoch: Decimal(41),
                }),
                Reason::Management,
                None,
                None,
                Some(credential()),
            ),
            base(
                Payload::Management(Change::AddApprover {
                    transport: Hex32([0x66; 32]),
                    approver: Hex33([0x02; 33]),
                    label: "My phone".into(),
                    fingerprint: crate::sig::fingerprint(&[0x66; 32], &[0x02; 33]),
                }),
                Reason::Management,
                None,
                None,
                None,
            ),
            base(
                Payload::Management(Change::RemoveApprover {
                    transport: Hex32([0x66; 32]),
                    approver: Hex33([0x02; 33]),
                }),
                Reason::Management,
                None,
                None,
                None,
            ),
        ]
    }

    #[test]
    fn every_kind_of_request_checks_out_and_round_trips() {
        for draft in drafts() {
            let (request, hash) = draft.finish(&CHANNEL).unwrap();
            assert_eq!(request.request_hash.0, hash);
            let text = crate::messages::to_text(&request);
            let parsed: Request = crate::messages::parse(&text).unwrap();
            assert_eq!(parsed, request);
            check_request(&parsed, &CHANNEL).unwrap();
            // Another gateway's channel key gives another hash.
            assert!(check_request(&parsed, &[0x12; 32]).is_err());
        }
    }

    fn breaks(request: &Request, f: impl Fn(&mut Request)) -> bool {
        let mut r = request.clone();
        f(&mut r);
        check_request(&r, &CHANNEL).is_err()
    }

    /// Each field the hash binds or the checks cover, changed on its own,
    /// is refused.
    #[test]
    fn changing_any_field_is_refused() {
        let requests: Vec<Request> = drafts()
            .into_iter()
            .map(|d| d.finish(&CHANNEL).unwrap().0)
            .collect();
        for r in &requests {
            assert!(breaks(r, |r| r.request_id.0[0] ^= 1), "request id");
            assert!(breaks(r, |r| r.request_hash.0[0] ^= 1), "hash");
            assert!(breaks(r, |r| r.deadline_secs = 29), "deadline low");
            assert!(breaks(r, |r| r.deadline_secs = 121), "deadline high");
            assert!(
                breaks(r, |r| r.op = if r.op == Op::Management {
                    Op::SignNostrEvent
                } else {
                    Op::Management
                }),
                "op"
            );
            if r.credential.is_some() {
                assert!(
                    breaks(r, |r| r.credential.as_mut().unwrap().id.0[0] ^= 1),
                    "credential id"
                );
            }
            if r.key.is_some() {
                assert!(breaks(r, |r| r.key = Some(Hex32([0x99; 32]))), "key");
                assert!(breaks(r, |r| r.key = None), "key dropped");
            } else {
                assert!(breaks(r, |r| r.key = Some(Hex32(KEY))), "key added");
            }
            if r.network.is_some() {
                assert!(
                    breaks(r, |r| r.network = Some(Network::Testnet4)),
                    "network"
                );
            } else {
                assert!(
                    breaks(r, |r| r.network = Some(Network::Mainnet)),
                    "network added"
                );
            }
        }
        let nostr = &requests[0];
        assert!(
            breaks(nostr, |r| r.payload["event"]["content"] = "{}".into()),
            "content"
        );
        assert!(
            breaks(nostr, |r| r.payload["event"]["created_at"] = 1.into()),
            "created_at"
        );
        assert!(
            breaks(nostr, |r| r.payload["event"]["tags"] =
                serde_json::json!([])),
            "tags"
        );
        assert!(
            breaks(nostr, |r| r.reason = Reason::Kind { kind: 1 }),
            "reason kind"
        );
        assert!(breaks(nostr, |r| r.reason = Reason::Management), "reason");
        let psbt = &requests[1];
        assert!(
            breaks(psbt, |r| r.payload["prevouts"][0]["amount"] = 40_001.into()),
            "prevout"
        );
        assert!(
            breaks(psbt, |r| r.payload["change"] = serde_json::json!([])),
            "change"
        );
        let enc = &requests[2];
        assert!(
            breaks(enc, |r| r.payload["plaintext"] = "other".into()),
            "plaintext"
        );
        assert!(
            breaks(enc, |r| r.payload["peer"] = "99".repeat(32).into()),
            "peer"
        );
        let dec = &requests[3];
        assert!(
            breaks(dec, |r| r.payload["ciphertext_sha256"] =
                "99".repeat(32).into()),
            "ciphertext"
        );
        assert!(
            breaks(dec, |r| r.payload["plaintext"] = "other".into()),
            "decrypted plaintext"
        );
        let issue = &requests[4];
        assert!(
            breaks(issue, |r| r.payload["change"]["grant"]["limits"]
                ["per_day"] = "999".into()),
            "grant"
        );
        assert!(
            breaks(issue, |r| r.credential.as_mut().unwrap().name =
                "other".into()),
            "credential name"
        );
        assert!(
            breaks(issue, |r| r.credential.as_mut().unwrap().uid = 1002),
            "credential uid"
        );
        assert!(breaks(issue, |r| r.credential = None), "credential dropped");
        let unfreeze_all = &requests[5];
        assert!(
            breaks(unfreeze_all, |r| r.credential = Some(credential())),
            "credential added"
        );
        assert!(
            breaks(unfreeze_all, |r| r.payload["change"]["epoch"] = "42".into()),
            "epoch"
        );
        let add = &requests[7];
        assert!(
            breaks(add, |r| r.payload["change"]["approver"] =
                "03".repeat(33).into()),
            "approver"
        );
    }

    /// A request whose hash matches its fields but whose fields do not fit
    /// together (what a gateway bug would send) is refused, and the gateway
    /// itself refuses to finish such a draft.
    #[test]
    fn consistent_hashes_of_inconsistent_requests_are_refused() {
        fn rehashed(mut r: Request) -> Request {
            let payload = Payload::parse(r.op, &r.payload).unwrap();
            r.request_hash = Hex32(
                Binding {
                    channel: CHANNEL,
                    credential: r.credential.as_ref().map(|c| c.id.0),
                    request_id: r.request_id.0,
                    key: r.key.map(|k| k.0),
                    network: r.network,
                    payload: &payload,
                }
                .hash()
                .unwrap(),
            );
            r
        }
        let requests: Vec<Request> = drafts()
            .into_iter()
            .map(|d| d.finish(&CHANNEL).unwrap().0)
            .collect();
        let refused = |r: &Request, f: &dyn Fn(&mut Request), what: &str| {
            let mut r = r.clone();
            f(&mut r);
            assert!(check_request(&rehashed(r), &CHANNEL).is_err(), "{what}");
        };
        refused(
            &requests[5],
            &|r| r.key = Some(Hex32(KEY)),
            "management with a key",
        );
        refused(&requests[0], &|r| r.key = None, "nostr without a key");
        refused(
            &requests[0],
            &|r| r.network = Some(Network::Mainnet),
            "nostr with a network",
        );
        refused(
            &requests[0],
            &|r| r.key = Some(Hex32([0x99; 32])),
            "event pubkey not the key",
        );
        refused(
            &requests[0],
            &|r| r.credential = None,
            "agent request without a credential",
        );
        refused(
            &requests[2],
            &|r| r.credential = None,
            "encrypt without a credential",
        );
        refused(
            &requests[6],
            &|r| r.credential.as_mut().unwrap().id = Hex16([0x23; 16]),
            "unfreeze of another credential",
        );
        refused(
            &requests[7],
            &|r| r.credential = Some(credential()),
            "approver change naming a credential",
        );
        refused(
            &requests[1],
            &|r| r.budget = None,
            "a spend without a budget",
        );
        refused(
            &requests[0],
            &|r| r.budget = requests[1].budget,
            "a budget on a request that spends nothing",
        );
        let threshold = |requested, spent, threshold| {
            move |r: &mut Request| {
                r.reason = Reason::AboveThreshold {
                    requested,
                    spent,
                    threshold,
                }
            }
        };
        refused(
            &requests[1],
            &threshold(31_001, 10_000, 20_000),
            "requested",
        );
        refused(&requests[1], &threshold(31_000, 9_999, 20_000), "spent");
        refused(
            &requests[1],
            &threshold(31_000, 10_000, 41_000),
            "threshold",
        );
        refused(
            &requests[1],
            &|r| r.budget.as_mut().unwrap().credential_spent = 9_999,
            "budget spent",
        );
        for kind in [
            crate::kind::REQUEST,
            crate::kind::DECISION,
            crate::kind::OUTCOME,
        ] {
            refused(
                &requests[0],
                &|r| {
                    r.payload["event"]["kind"] = kind.into();
                    r.reason = Reason::Kind { kind };
                },
                "a protocol kind",
            );
        }

        let mut bad = drafts().remove(5);
        bad.key = Some(KEY);
        assert!(bad.finish(&CHANNEL).is_err(), "draft with a key");
        let mut bad = drafts().remove(0);
        bad.credential = None;
        assert!(bad.finish(&CHANNEL).is_err(), "draft without a credential");
    }

    /// A request is checked against the size a wrap can carry before it is
    /// sent, exactly: the largest that fits is finished, one byte more is
    /// refused.
    #[test]
    fn finish_refuses_a_request_too_large_to_wrap() {
        let with = |n: usize| {
            let mut d = drafts().remove(2);
            d.payload = Payload::Nip44Encrypt(Nip44EncryptPayload {
                peer: Hex32(KEY),
                plaintext: "x".repeat(n),
            });
            d.finish(&CHANNEL)
        };
        // The largest plaintext that fits, by bisection.
        let (mut fits, mut too_big) = (0, crate::wrap::MAX_RUMOR_BYTES);
        assert!(with(fits).is_ok() && with(too_big).is_err());
        while too_big - fits > 1 {
            let mid = (fits + too_big) / 2;
            if with(mid).is_ok() {
                fits = mid;
            } else {
                too_big = mid;
            }
        }
        assert!(fits > crate::wrap::MAX_RUMOR_BYTES - 3_000, "{fits}");
        assert!(matches!(with(fits + 1), Err(crate::Error::TooLarge(_))));
        // What fits is what wrap() carries.
        let (request, _) = with(fits).unwrap();
        let device = nostr::Keys::generate();
        let gateway = nostr::Keys::generate();
        let key = crate::wrap::TagKey::gateway(&gateway, &device.public_key().to_bytes()).unwrap();
        assert!(crate::wrap::wrap(
            &gateway,
            &device.public_key().to_bytes(),
            &key,
            crate::kind::REQUEST,
            &crate::messages::to_text(&request),
            request.created_at,
        )
        .is_ok());
    }

    #[test]
    fn a_psbt_request_carries_its_recomputed_view() {
        let (request, _) = drafts().remove(1).finish(&CHANNEL).unwrap();
        let checked = check_request(&request, &CHANNEL).unwrap();
        let view = checked.psbt.unwrap();
        assert_eq!((view.fee, view.leaving_wallet), (1_000, 31_000));
        assert!(
            check_request(&drafts().remove(0).finish(&CHANNEL).unwrap().0, &CHANNEL)
                .unwrap()
                .psbt
                .is_none()
        );
    }

    /// Debug output of a request, its payload or its checked form never
    /// shows a plaintext.
    #[test]
    fn debug_output_leaves_out_plaintexts() {
        for draft in drafts().into_iter().skip(2).take(2) {
            let plaintext = match &draft.payload {
                Payload::Nip44Encrypt(p) => p.plaintext.clone(),
                Payload::Nip44Decrypt(p) => p.plaintext.clone(),
                _ => unreachable!(),
            };
            let (request, _) = draft.clone().finish(&CHANNEL).unwrap();
            let checked = check_request(&request, &CHANNEL).unwrap();
            for shown in [
                format!("{draft:?}"),
                format!("{request:?}"),
                format!("{checked:?}"),
            ] {
                assert!(!shown.contains(&plaintext), "{shown}");
                assert!(
                    !shown.contains("cashu") && !shown.contains("note to self"),
                    "{shown}"
                );
                assert!(shown.contains("plaintext_len") || shown.contains("Request"));
            }
        }
    }

    /// Payload parsing is strict for every op.
    #[test]
    fn payloads_refuse_unknown_fields() {
        let requests: Vec<Request> = drafts()
            .into_iter()
            .map(|d| d.finish(&CHANNEL).unwrap().0)
            .collect();
        let mut nostr = requests[0].payload.clone();
        nostr["event"]["sig"] = "00".into();
        assert!(Payload::parse(Op::SignNostrEvent, &nostr).is_err());
        let mut top = requests[0].payload.clone();
        top["extra"] = "x".into();
        assert!(Payload::parse(Op::SignNostrEvent, &top).is_err());
        for (i, op) in [
            (1, Op::SignPsbt),
            (2, Op::Nip44Encrypt),
            (3, Op::Nip44Decrypt),
            (4, Op::Management),
        ] {
            let mut v = requests[i].payload.clone();
            v["extra"] = "x".into();
            assert!(Payload::parse(op, &v).is_err(), "{op:?}");
        }
    }

    /// A null key or credential hashes as all zeros, so it is
    /// `check_request`, not the hash, that fixes which nullable fields each
    /// op carries: the all-zero form of a field the op lacks is refused, and
    /// so is a missing field the op has.
    #[test]
    fn the_op_fixes_which_nullable_fields_are_present() {
        let drafts = drafts();
        let management = &drafts[5];
        let with = |key: Option<[u8; 32]>, credential: Option<[u8; 16]>| {
            Binding {
                channel: CHANNEL,
                credential,
                request_id: management.request_id,
                key,
                network: None,
                payload: &management.payload,
            }
            .hash()
            .unwrap()
        };
        assert_eq!(with(None, None), with(Some([0; 32]), None));
        assert_eq!(with(None, None), with(None, Some([0; 16])));
        let (request, _) = management.clone().finish(&CHANNEL).unwrap();
        let mut zero_key = request.clone();
        zero_key.key = Some(Hex32([0; 32]));
        assert_eq!(
            check_request(&zero_key, &CHANNEL).unwrap_err(),
            invalid("the key does not fit the op")
        );
        let mut zero_credential = request.clone();
        zero_credential.credential = Some(CredentialRef {
            id: Hex16([0; 16]),
            name: "zero".into(),
            uid: 0,
        });
        assert!(check_request(&zero_credential, &CHANNEL).is_err());
        // Each op's fields, in turn: the key, the network and the budget are
        // present exactly when the op has them.
        for draft in drafts {
            let op = draft.payload.op();
            let (request, _) = draft.finish(&CHANNEL).unwrap();
            let mut r = request.clone();
            r.key = if r.key.is_some() {
                None
            } else {
                Some(Hex32([0; 32]))
            };
            assert!(check_request(&r, &CHANNEL).is_err(), "{op:?} key");
            let mut r = request.clone();
            r.network = if r.network.is_some() {
                None
            } else {
                Some(Network::Mainnet)
            };
            assert!(check_request(&r, &CHANNEL).is_err(), "{op:?} network");
            let mut r = request.clone();
            r.budget = if r.budget.is_some() {
                None
            } else {
                Some(Budget {
                    credential_spent: 0,
                    credential_window: 0,
                    wallet_spent: 0,
                    wallet_window: 0,
                })
            };
            assert!(check_request(&r, &CHANNEL).is_err(), "{op:?} budget");
        }
    }

    /// A credential's name is shown as the gateway's word, so it follows
    /// the label rules.
    #[test]
    fn a_credential_name_that_could_hide_text_is_refused() {
        let (request, _) = drafts().remove(0).finish(&CHANNEL).unwrap();
        for name in ["", "writer\u{202e}", &"x".repeat(65)] {
            let mut r = request.clone();
            r.credential.as_mut().unwrap().name = name.to_string();
            assert!(check_request(&r, &CHANNEL).is_err(), "{name:?}");
        }
    }

    /// The preimage puts every field at its fixed place.
    #[test]
    fn preimage_layout() {
        let draft = drafts().remove(5);
        let binding = Binding {
            channel: CHANNEL,
            credential: None,
            request_id: draft.request_id,
            key: None,
            network: None,
            payload: &draft.payload,
        };
        let m = binding.preimage().unwrap();
        assert_eq!(m[0], 1);
        assert_eq!(&m[1..33], &CHANNEL);
        assert_eq!(&m[33..49], &[0u8; 16]);
        assert_eq!(&m[49..81], &[0x44; 32]);
        assert_eq!(m[81], 16);
        assert_eq!(&m[82..114], &[0u8; 32]);
        assert_eq!(m[114], 0);
        assert_eq!(&m[115..119], &33u32.to_le_bytes());
        assert_eq!(m[119], 2);
        assert_eq!(m.len(), 119 + 33);
    }
}

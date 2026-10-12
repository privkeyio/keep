// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Requests parked for an approver, and the approval that clears one.
//!
//! A request sent to the approvers is parked as a [`Parked`]: the exact
//! object to sign or apply, and the request built from that object, with its
//! hash, so what the approver is shown and what is carried out cannot
//! differ. An [`Approval`] is made only by [`Approval::verify`], which checks
//! the approver's signed decision over that request's id and hash, and it
//! carries the parked request, so [`crate::policy::evaluate_approved`]
//! evaluates exactly what was approved, and only once.

use keep_approval::binding::{
    Network as WireNetwork, NostrPayload, Payload, RequestDraft, UnsignedEventFields,
};
use keep_approval::change::Change;
use keep_approval::messages::{
    AnchorState, Budget, CredentialRef, Decision as SignedDecision, Reason, Request as WireRequest,
    Verdict,
};
use keep_approval::psbt::PsbtPayload;
use keep_approval::sig::{self, Device};
use keep_approval::Hex64;
use keep_bitcoin::bitcoin::Psbt;
use keep_bitcoin::PsbtAnalysis;

use crate::error::{AgentError, Result};
use crate::policy::Request;

/// What a parked request signs or applies once approved, exactly.
pub enum ParkedObject {
    /// The unsigned event signed as it is.
    NostrEvent(UnsignedEventFields),
    /// The PSBT signed unchanged with `key`'s wallet, with the analysis the
    /// policy decided on and the change outputs it verified, each with the
    /// last step of its derivation path.
    Psbt {
        psbt: Box<Psbt>,
        analysis: PsbtAnalysis,
        key: [u8; 32],
        change: Vec<(usize, u32)>,
    },
    /// A management change, applied as it is.
    Management(Change),
}

impl std::fmt::Debug for ParkedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NostrEvent(e) => write!(f, "NostrEvent(kind {})", e.kind),
            Self::Psbt { psbt, .. } => {
                write!(f, "Psbt({})", psbt.unsigned_tx.compute_txid())
            }
            Self::Management(c) => write!(f, "Management(type {})", c.type_code()),
        }
    }
}

/// Everything a request carries besides its object: who asks, when, and
/// the context the approver is shown.
#[derive(Debug, Clone)]
pub struct ParkRequest {
    pub request_id: [u8; 32],
    pub created_at: u64,
    pub deadline_secs: u64,
    pub credential: Option<CredentialRef>,
    pub reason: Reason,
    pub budget: Option<Budget>,
    pub anchor: AnchorState,
}

/// A request waiting for an approver: the object, and the request built
/// from it with its hash.
#[derive(Debug)]
pub struct Parked {
    object: Box<ParkedObject>,
    request: Box<WireRequest>,
    hash: [u8; 32],
}

impl Parked {
    /// Build the request for `object` as the gateway `channel` sends it, with
    /// every check an approver runs and the size limit, and its hash.
    pub fn new(object: ParkedObject, info: ParkRequest, channel: &[u8; 32]) -> Result<Self> {
        let refuse = |e: keep_approval::Error| match e {
            keep_approval::Error::TooLarge(_) => {
                AgentError::PolicyDenied("the request is too large to approve".into())
            }
            e => AgentError::Other(format!("the approval request cannot be built: {e}")),
        };
        let (payload, key, network) = match &object {
            ParkedObject::NostrEvent(event) => (
                Payload::Nostr(NostrPayload {
                    event: event.clone(),
                }),
                Some(event.pubkey.0),
                None,
            ),
            ParkedObject::Psbt {
                psbt,
                analysis,
                key,
                change,
            } => {
                let network = WireNetwork::from_bitcoin(analysis.network);
                let payload =
                    PsbtPayload::from_psbt(psbt, &analysis.signable_inputs, change, network)
                        .map_err(refuse)?;
                (Payload::Psbt(payload), Some(*key), Some(network))
            }
            ParkedObject::Management(change) => (Payload::Management(change.clone()), None, None),
        };
        let draft = RequestDraft {
            request_id: info.request_id,
            created_at: info.created_at,
            deadline_secs: info.deadline_secs,
            credential: info.credential,
            key,
            network,
            reason: info.reason,
            payload,
            budget: info.budget,
            anchor: info.anchor,
        };
        let (request, hash) = draft.finish(channel).map_err(refuse)?;
        Ok(Self {
            object: Box::new(object),
            request: Box::new(request),
            hash,
        })
    }

    /// The request as approvers are sent it.
    pub fn request(&self) -> &WireRequest {
        &self.request
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.request.request_id.0
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The credential the request is about, if any.
    pub fn credential(&self) -> Option<[u8; 16]> {
        self.request.credential.as_ref().map(|c| c.id.0)
    }

    /// When the request was made, on the gateway's calendar clock.
    pub fn created_at(&self) -> u64 {
        self.request.created_at
    }

    pub fn object(&self) -> &ParkedObject {
        &self.object
    }

    /// The key and the policy request an approved agent request is evaluated
    /// as; `None` for a management change.
    pub(crate) fn policy_request(&self) -> Option<([u8; 32], Request<'_>)> {
        match self.object.as_ref() {
            ParkedObject::NostrEvent(event) => {
                Some((event.pubkey.0, Request::SignNostrEvent { kind: event.kind }))
            }
            ParkedObject::Psbt { analysis, key, .. } => {
                Some((*key, Request::SignPsbt { analysis }))
            }
            ParkedObject::Management(_) => None,
        }
    }
}

/// An approver's approval of one parked request. Only [`Approval::verify`]
/// makes one, from a decision that verifies; it is consumed by
/// [`crate::policy::evaluate_approved`] or, for a management change, by
/// [`Approval::into_management`].
#[derive(Debug)]
pub struct Approval {
    approved: Box<Approved>,
}

/// An approved request, handed back once its approval is used: what to sign
/// or apply, and who approved it with which signature.
#[derive(Debug)]
pub struct Approved {
    parked: Parked,
    device: Device,
    sig: Hex64,
}

impl Approval {
    /// Make the approval of `parked` from `decision`, sealed by `device`'s
    /// transport key: it must name the parked request's id and hash, say
    /// approve, and carry a signature by the device's approver key over the
    /// gateway's `channel` key, the approver key, that hash and the verdict.
    /// Anything else hands the parked request back with the reason.
    pub fn verify(
        decision: &SignedDecision,
        channel: &[u8; 32],
        device: &Device,
        parked: Parked,
    ) -> std::result::Result<Self, (Parked, String)> {
        match sig::check_decision(
            decision,
            channel,
            device,
            &parked.request_id(),
            &parked.hash,
        ) {
            Ok(Verdict::Approve) => Ok(Self {
                approved: Box::new(Approved {
                    parked,
                    device: *device,
                    sig: decision.sig,
                }),
            }),
            Ok(Verdict::Deny) => Err((parked, "the decision denies the request".into())),
            Err(e) => Err((parked, e.to_string())),
        }
    }

    pub(crate) fn into_approved(self) -> Approved {
        *self.approved
    }

    /// The approved management change, to apply as it is; an agent request
    /// is handed back, to go through [`crate::policy::evaluate_approved`].
    pub fn into_management(self) -> std::result::Result<Approved, Self> {
        match self.approved.parked.object.as_ref() {
            ParkedObject::Management(_) => Ok(*self.approved),
            _ => Err(self),
        }
    }

    /// The parked request this approves.
    pub fn parked(&self) -> &Parked {
        &self.approved.parked
    }
}

impl Approved {
    pub fn parked(&self) -> &Parked {
        &self.parked
    }

    /// The device whose approver key signed the approval.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// The decision's signature, kept in the audit log as the proof.
    pub fn signature(&self) -> &Hex64 {
        &self.sig
    }

    pub fn into_parked(self) -> Parked {
        self.parked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        evaluate_approved, Budgets, Decision, DenyReason, Grant, Ledger, RequestLimits,
    };
    use crate::scope::Operation;
    use keep_approval::messages::V1;
    use keep_approval::Hex32;
    use nostr_sdk::prelude::Keys;

    struct Fixture {
        channel: [u8; 32],
        transport: Keys,
        approver: Keys,
        device: Device,
        key: [u8; 32],
    }

    fn fixture() -> Fixture {
        let transport = Keys::generate();
        let approver = Keys::generate();
        let device = Device {
            transport: transport.public_key().to_bytes(),
            approver: approver.public_key().to_bytes(),
        };
        Fixture {
            channel: Keys::generate().public_key().to_bytes(),
            transport,
            approver,
            device,
            key: Keys::generate().public_key().to_bytes(),
        }
    }

    fn info(id: u8) -> ParkRequest {
        ParkRequest {
            request_id: [id; 32],
            created_at: 1_791_580_000,
            deadline_secs: 120,
            credential: Some(CredentialRef {
                id: keep_approval::Hex16([7; 16]),
                name: "writer".into(),
                uid: 1001,
            }),
            reason: Reason::Kind { kind: 0 },
            budget: None,
            anchor: AnchorState {
                seq: 1,
                head: Hex32([0; 32]),
                wallets: vec![],
            },
        }
    }

    fn event(f: &Fixture, content: &str) -> ParkedObject {
        ParkedObject::NostrEvent(UnsignedEventFields {
            pubkey: Hex32(f.key),
            created_at: 1_791_580_000,
            kind: 0,
            tags: vec![],
            content: content.into(),
        })
    }

    fn decision(f: &Fixture, signer: &Keys, parked: &Parked, verdict: Verdict) -> SignedDecision {
        let digest = sig::decision_digest(&f.channel, &sig::xonly(signer), &parked.hash(), verdict);
        SignedDecision {
            v: V1,
            request_id: Hex32(parked.request_id()),
            request_hash: Hex32(parked.hash()),
            decision: verdict,
            sig: sig::sign(signer, &digest),
        }
    }

    fn grant(f: &Fixture) -> Grant {
        Grant {
            keys: [f.key].into(),
            operations: [Operation::SignNostrEvent].into(),
            event_kinds: [0].into(),
            nip44_peers: Default::default(),
            bitcoin: None,
            limits: RequestLimits::default(),
        }
    }

    /// An approval comes only from the device's approver key approving this
    /// request; evaluated, it allows exactly the parked event.
    #[test]
    fn only_a_verified_approve_makes_an_approval() {
        let f = fixture();
        let parked = Parked::new(event(&f, "{}"), info(1), &f.channel).unwrap();
        let other = Parked::new(event(&f, "{}"), info(2), &f.channel).unwrap();
        // The transport key, another request's decision, a denial.
        let by_transport = decision(&f, &f.transport, &parked, Verdict::Approve);
        let (parked, why) =
            Approval::verify(&by_transport, &f.channel, &f.device, parked).unwrap_err();
        assert!(why.contains("signature"), "{why}");
        let for_other = decision(&f, &f.approver, &other, Verdict::Approve);
        let (parked, _) = Approval::verify(&for_other, &f.channel, &f.device, parked).unwrap_err();
        let deny = decision(&f, &f.approver, &parked, Verdict::Deny);
        let (parked, why) = Approval::verify(&deny, &f.channel, &f.device, parked).unwrap_err();
        assert!(why.contains("denies"));

        let approve = decision(&f, &f.approver, &parked, Verdict::Approve);
        let approval = Approval::verify(&approve, &f.channel, &f.device, parked).unwrap();
        assert_eq!(approval.parked().request_id(), [1; 32]);
        let approval = approval.into_management().unwrap_err();
        let (mut c, mut w) = (Ledger::default(), Ledger::default());
        let mut budgets = Budgets {
            credential: &mut c,
            wallet: &mut w,
            wallet_window_sats: 0,
        };
        let (decision, approved) = evaluate_approved(approval, &grant(&f), &mut budgets, 0);
        assert_eq!(decision, Decision::Allow);
        assert_eq!(approved.signature(), &approve.sig);
        assert_eq!(approved.device(), &f.device);
        assert!(matches!(
            approved.into_parked().object(),
            ParkedObject::NostrEvent(e) if e.content == "{}"
        ));
    }

    /// A management change is applied through `into_management`, and
    /// evaluated as an agent request it is denied.
    #[test]
    fn a_management_approval_is_no_agent_request() {
        let f = fixture();
        let mut i = info(3);
        i.credential = None;
        i.reason = Reason::Management;
        let change = Change::Unfreeze {
            scope: keep_approval::change::Scope::All,
            epoch: keep_approval::change::Decimal(4),
        };
        let parked = Parked::new(ParkedObject::Management(change.clone()), i, &f.channel).unwrap();
        let approve = decision(&f, &f.approver, &parked, Verdict::Approve);
        let approval = Approval::verify(&approve, &f.channel, &f.device, parked).unwrap();
        let (mut c, mut w) = (Ledger::default(), Ledger::default());
        let mut budgets = Budgets {
            credential: &mut c,
            wallet: &mut w,
            wallet_window_sats: 0,
        };
        let parked = Parked::new(
            ParkedObject::Management(change.clone()),
            {
                let mut i = info(4);
                i.credential = None;
                i.reason = Reason::Management;
                i
            },
            &f.channel,
        )
        .unwrap();
        let approve2 = decision(&f, &f.approver, &parked, Verdict::Approve);
        let second = Approval::verify(&approve2, &f.channel, &f.device, parked).unwrap();
        let (d, _) = evaluate_approved(second, &grant(&f), &mut budgets, 0);
        assert_eq!(d, Decision::Deny(DenyReason::ManagementChange));
        let approved = approval.into_management().unwrap();
        assert!(matches!(
            approved.parked().object(),
            ParkedObject::Management(c) if *c == change
        ));
    }

    /// A request whose rumor would not fit a wrap is refused as too large to
    /// approve.
    #[test]
    fn a_request_too_large_to_wrap_is_refused() {
        let f = fixture();
        let big = "x".repeat(keep_approval::wrap::MAX_RUMOR_BYTES);
        let err = Parked::new(event(&f, &big), info(5), &f.channel).unwrap_err();
        assert!(err.to_string().contains("too large to approve"), "{err}");
    }
}

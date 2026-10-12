// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! What an approver keeps between messages, and the alerts it raises.
//!
//! - [`AnchorTracker`]: the last anchor seen. Anchors arrive out of order and
//!   can be replayed, so only one whose `at` is later than the last kept is
//!   compared; it alerts when the audit log's count goes down, or stays with
//!   another head, when a wallet ledger's count goes down or the ledger
//!   disappears, and when the freeze epoch goes down. It also tracks
//!   silence (no newer anchor for an hour), the phone's own freezes until an
//!   anchor shows them, and freezes cleared with no `unfreeze` reaching the
//!   phone.
//! - [`RequestGate`]: drops a request already seen, and one the gateway has
//!   already expired by the latest gateway time the approver holds.
//!
//! Both are plain data the approver persists between runs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::change::Scope;
use crate::messages::{AnchorState, Frozen, Request};
use crate::wrap::WINDOW_PAST_SECS;
use crate::{invalid, Hex32, Result};

/// How long without a newer anchor before the approver alerts. Anchors come
/// every 15 minutes.
pub const SILENCE_SECS: u64 = 3_600;

/// How far the gateway's clock may be from the approver's before it warns.
pub const SKEW_WARNING_SECS: u64 = 300;

/// How long the phone waits for an anchor to show its own freeze before it
/// alerts. It resends the freeze every [`FREEZE_RESEND_SECS`] meanwhile.
pub const FREEZE_SHOWN_SECS: u64 = 120;

/// How often the phone resends a freeze no anchor has shown yet.
pub const FREEZE_RESEND_SECS: u64 = 15;

/// How long a freeze seen cleared waits for the `unfreeze` that explains it
/// before the phone alerts. The outcome and the anchor are separate wraps,
/// which relays can deliver in either order.
pub const CLEARED_GRACE_SECS: u64 = 120;

/// Something the approver must show the owner, prominently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alert {
    /// The audit log's count went down: a rollback or truncation.
    AuditCountWentBack { from: u64, to: u64 },
    /// The audit log's count stayed but its head changed: a rewrite.
    AuditHeadChanged { seq: u64 },
    /// A wallet ledger's count went down: a rolled-back ledger.
    WalletCountWentBack { wallet: String, from: u64, to: u64 },
    /// A wallet ledger the gateway reported before is gone.
    WalletMissing { wallet: String },
    /// The freeze epoch went down.
    EpochWentBack { from: u64, to: u64 },
    /// The phone's own freeze has not shown in an anchor after
    /// [`FREEZE_SHOWN_SECS`]: a relay may be withholding it.
    OwnFreezeNotShown { scope: Scope },
    /// A freeze was cleared and no `unfreeze` reached the phone.
    FreezeCleared { scope: Scope },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Kept {
    at: u64,
    anchor: AnchorState,
    /// The last freeze state seen, from this anchor or an earlier one.
    frozen: Option<Frozen>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SentFreeze {
    scope: Scope,
    /// The epoch the freeze carried: an anchor shows it once its epoch is
    /// later, since the gateway adds one on every freeze.
    epoch: u64,
    /// The approver's clock at the first send.
    sent_at: u64,
    alerted: bool,
}

/// The last anchor an approver kept, and when it arrived.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorTracker {
    kept: Option<Kept>,
    /// The approver's clock when the kept anchor arrived.
    received_at: Option<u64>,
    /// The latest gateway time from any anchor or request accepted.
    latest_gateway_time: u64,
    /// The phone's own freezes no anchor has shown yet.
    sent_freezes: Vec<SentFreeze>,
    /// Unfreezes that reached the phone and no anchor has shown yet, with
    /// the approver's clock when each arrived.
    unfreezes: Vec<(Scope, u64)>,
    /// Freezes seen cleared with no unfreeze yet, with the approver's clock
    /// when each was seen.
    cleared: Vec<(Scope, u64)>,
}

/// Whether `frozen` freezes `scope`.
fn freezes(frozen: &Frozen, scope: Scope) -> bool {
    match scope {
        Scope::All => frozen.all,
        Scope::Credential(id) => frozen.all || frozen.credentials.contains(&id),
    }
}

/// The scopes frozen in `old` and not in `new`.
fn cleared(old: &Frozen, new: &Frozen) -> Vec<Scope> {
    let mut out = Vec::new();
    if old.all && !new.all {
        out.push(Scope::All);
    }
    for id in &old.credentials {
        if !new.credentials.contains(id) {
            out.push(Scope::Credential(*id));
        }
    }
    out
}

/// Whether an unfreeze of `unfrozen` explains `scope` being cleared: an
/// unfreeze of the whole gateway clears every freeze.
fn explains(unfrozen: Scope, scope: Scope) -> bool {
    unfrozen == Scope::All || unfrozen == scope
}

impl AnchorTracker {
    /// Keep the anchor a `paired` message carries, which has no time of its
    /// own, as the first one: every later anchor is compared with it. Does
    /// nothing once an anchor is kept.
    pub fn baseline(&mut self, anchor: &AnchorState, frozen: &Frozen, local_now: u64) {
        if self.kept.is_none() {
            self.observe(0, anchor, Some(frozen), local_now);
        }
    }

    /// Note the phone's own freeze of `scope`, carrying `epoch`, sent at the
    /// approver's `local_now`. A resend keeps the first send's time.
    pub fn freeze_sent(&mut self, scope: Scope, epoch: u64, local_now: u64) {
        if let Some(sent) = self.sent_freezes.iter_mut().find(|f| f.scope == scope) {
            sent.epoch = sent.epoch.min(epoch);
        } else {
            self.sent_freezes.push(SentFreeze {
                scope,
                epoch,
                sent_at: local_now,
                alerted: false,
            });
        }
    }

    /// The phone's own freezes no anchor has shown yet, to resend.
    pub fn freezes_to_resend(&self) -> Vec<Scope> {
        self.sent_freezes.iter().map(|f| f.scope).collect()
    }

    /// Note an unfreeze of `scope` reaching the phone: an `approved` outcome
    /// of an `unfreeze` request, or the phone's own unfreeze accepted. It
    /// explains a freeze of that scope seen cleared, before or after.
    pub fn unfreeze_seen(&mut self, scope: Scope, local_now: u64) {
        let before = self.cleared.len();
        self.cleared.retain(|(c, _)| !explains(scope, *c));
        if self.cleared.len() == before {
            self.unfreezes.push((scope, local_now));
        }
    }

    /// The alerts that are due by the approver's clock: each own freeze not
    /// shown after [`FREEZE_SHOWN_SECS`] (once), and each freeze cleared with
    /// no unfreeze after [`CLEARED_GRACE_SECS`].
    pub fn due_alerts(&mut self, local_now: u64) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for sent in &mut self.sent_freezes {
            if !sent.alerted && local_now.saturating_sub(sent.sent_at) >= FREEZE_SHOWN_SECS {
                sent.alerted = true;
                alerts.push(Alert::OwnFreezeNotShown { scope: sent.scope });
            }
        }
        self.cleared.retain(|(scope, at)| {
            let due = local_now.saturating_sub(*at) >= CLEARED_GRACE_SECS;
            if due {
                alerts.push(Alert::FreezeCleared { scope: *scope });
            }
            !due
        });
        self.unfreezes
            .retain(|(_, at)| local_now.saturating_sub(*at) <= WINDOW_PAST_SECS);
        alerts
    }

    fn observe_frozen(&mut self, old: Option<&Frozen>, new: &Frozen, local_now: u64) {
        self.sent_freezes
            .retain(|sent| !(new.epoch > sent.epoch && freezes(new, sent.scope)));
        let Some(old) = old else {
            return;
        };
        let cleared = cleared(old, new);
        if cleared.is_empty() {
            return;
        }
        // An unfreeze of everything explains every freeze cleared with it.
        if let Some(i) = self.unfreezes.iter().position(|(u, _)| *u == Scope::All) {
            self.unfreezes.remove(i);
            return;
        }
        for scope in cleared {
            if let Some(i) = self.unfreezes.iter().position(|(u, _)| *u == scope) {
                self.unfreezes.remove(i);
            } else {
                self.cleared.push((scope, local_now));
            }
        }
    }

    /// Note an anchor taken at gateway time `at`, from an anchor message
    /// (with `frozen`) or a request (without), arriving at the approver's
    /// `local_now`. An anchor not later than the last one kept is ignored,
    /// and does not reset the silence timer.
    pub fn observe(
        &mut self,
        at: u64,
        anchor: &AnchorState,
        frozen: Option<&Frozen>,
        local_now: u64,
    ) -> Vec<Alert> {
        self.latest_gateway_time = self.latest_gateway_time.max(at);
        let mut alerts = Vec::new();
        if let Some(kept) = &self.kept {
            if at <= kept.at {
                return alerts;
            }
            let last = &kept.anchor;
            if anchor.seq < last.seq {
                alerts.push(Alert::AuditCountWentBack {
                    from: last.seq,
                    to: anchor.seq,
                });
            } else if anchor.seq == last.seq && anchor.head != last.head {
                alerts.push(Alert::AuditHeadChanged { seq: anchor.seq });
            }
            for old in &last.wallets {
                match anchor.wallets.iter().find(|w| w.wallet == old.wallet) {
                    Some(new) if new.seq < old.seq => alerts.push(Alert::WalletCountWentBack {
                        wallet: old.wallet.clone(),
                        from: old.seq,
                        to: new.seq,
                    }),
                    Some(_) => {}
                    None => alerts.push(Alert::WalletMissing {
                        wallet: old.wallet.clone(),
                    }),
                }
            }
            if let (Some(from), Some(to)) = (
                kept.frozen.as_ref().map(|f| f.epoch),
                frozen.map(|f| f.epoch),
            ) {
                if to < from {
                    alerts.push(Alert::EpochWentBack { from, to });
                }
            }
        }
        let old = self.kept.as_ref().and_then(|k| k.frozen.clone());
        if let Some(new) = frozen {
            self.observe_frozen(old.as_ref(), new, local_now);
        }
        self.kept = Some(Kept {
            at,
            anchor: anchor.clone(),
            frozen: frozen.cloned().or(old),
        });
        self.received_at = Some(local_now);
        alerts
    }

    /// Whether no newer anchor has arrived for an hour by the approver's
    /// clock: the gateway is down, cut off, or its messages are withheld.
    pub fn silent(&self, local_now: u64) -> bool {
        self.received_at
            .is_some_and(|at| local_now.saturating_sub(at) >= SILENCE_SECS)
    }

    /// The latest gateway time from any anchor or request accepted.
    pub fn latest_gateway_time(&self) -> u64 {
        self.latest_gateway_time
    }

    /// The freeze epoch of the last anchor kept that carried one.
    pub fn epoch(&self) -> Option<u64> {
        self.frozen().map(|f| f.epoch)
    }

    /// The freeze state of the last anchor kept that carried one.
    pub fn frozen(&self) -> Option<&Frozen> {
        self.kept.as_ref().and_then(|k| k.frozen.as_ref())
    }
}

/// Whether the gateway's time `at` is far enough from the approver's
/// `local_now` to warn about. The approver never decides by comparing them.
pub fn clock_skew(at: u64, local_now: u64) -> bool {
    at.abs_diff(local_now) > SKEW_WARNING_SECS
}

/// The requests an approver has seen, so it shows each once and never one
/// the gateway has already expired.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestGate {
    /// Request ids, with the approver's clock when each arrived; kept for
    /// the wrap time window.
    seen: BTreeMap<Hex32, u64>,
}

impl RequestGate {
    /// Admit a request arriving at `local_now`: refused when seen before, or
    /// when `created_at + deadline_secs` is earlier than the latest gateway
    /// time `tracker` holds. An admitted request's anchor is then observed
    /// with the tracker by the caller.
    pub fn admit(
        &mut self,
        request: &Request,
        tracker: &AnchorTracker,
        local_now: u64,
    ) -> Result<()> {
        self.seen
            .retain(|_, at| local_now.saturating_sub(*at) <= WINDOW_PAST_SECS);
        if self.seen.contains_key(&request.request_id) {
            return Err(invalid("request already seen"));
        }
        let expires = request.created_at.saturating_add(request.deadline_secs);
        if expires < tracker.latest_gateway_time() {
            return Err(invalid("the gateway has already expired this request"));
        }
        self.seen.insert(request.request_id, local_now);
        Ok(())
    }
}

/// The most characters of agent-written text an approver shows.
pub const AGENT_TEXT_CHARS: usize = 2_000;

/// Agent-written text as an approver shows it, apart from everything else:
/// escaped (a backslash doubled, newlines, carriage returns and tabs as
/// visible escapes), with control, format, bidi and invisible characters
/// removed, truncated to [`AGENT_TEXT_CHARS`], with the full length in
/// characters stated.
pub fn agent_text(text: &str) -> (String, usize) {
    let full = text.chars().count();
    let mut out = String::new();
    for c in text.chars().take(AGENT_TEXT_CHARS) {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_hidden(c) => {}
            c => out.push(c),
        }
    }
    (out, full)
}

/// Characters that could hide or reorder what the owner reads: controls
/// (Cc), every format character (Cf, bidi controls among them), the line
/// and paragraph separators (Zl, Zp), and the other default-ignorable
/// characters that render as nothing (fillers, variation selectors).
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(c,
            // Cf
            '\u{00ad}'                     // soft hyphen
            | '\u{0600}'..='\u{0605}'     // Arabic number signs
            | '\u{061c}'                   // Arabic letter mark
            | '\u{06dd}'                   // Arabic end of ayah
            | '\u{070f}'                   // Syriac abbreviation mark
            | '\u{0890}'..='\u{0891}'     // Arabic pound and piastre marks above
            | '\u{08e2}'                   // Arabic disputed end of ayah
            | '\u{180e}'                   // Mongolian vowel separator
            | '\u{200b}'..='\u{200f}'     // zero-width spaces and joiners, LRM, RLM
            | '\u{202a}'..='\u{202e}'     // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'     // word joiner and invisible operators
            | '\u{2066}'..='\u{206f}'     // bidi isolates, deprecated format characters
            | '\u{feff}'                   // byte order mark
            | '\u{fff9}'..='\u{fffb}'     // interlinear annotations
            | '\u{110bd}' | '\u{110cd}'   // Kaithi number signs
            | '\u{13430}'..='\u{1343f}'   // Egyptian hieroglyph format controls
            | '\u{1bca0}'..='\u{1bca3}'   // shorthand format controls
            | '\u{1d173}'..='\u{1d17a}'   // musical symbol format controls
            | '\u{e0000}'..='\u{e0fff}'   // tags, variation selectors supplement
            // Zl, Zp
            | '\u{2028}' | '\u{2029}'
            // Other characters that render as nothing
            | '\u{034f}'                   // combining grapheme joiner
            | '\u{115f}' | '\u{1160}'     // Hangul choseong and jungseong fillers
            | '\u{17b4}' | '\u{17b5}'     // Khmer inherent vowels
            | '\u{3164}'                   // Hangul filler
            | '\u{fe00}'..='\u{fe0f}'     // variation selectors
            | '\u{ffa0}'                   // halfwidth Hangul filler
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::WalletAnchor;

    fn anchor(seq: u64, head: u8, wallets: &[(&str, u64)]) -> AnchorState {
        AnchorState {
            seq,
            head: Hex32([head; 32]),
            wallets: wallets
                .iter()
                .map(|(w, s)| WalletAnchor {
                    wallet: (*w).into(),
                    seq: *s,
                    spent: 0,
                    window: 0,
                })
                .collect(),
        }
    }

    fn frozen(epoch: u64) -> Frozen {
        Frozen {
            epoch,
            all: false,
            credentials: vec![],
        }
    }

    #[test]
    fn only_newer_anchors_are_compared() {
        let mut t = AnchorTracker::default();
        assert!(t
            .observe(100, &anchor(10, 1, &[]), Some(&frozen(3)), 1000)
            .is_empty());
        // An older anchor with a lower count, replayed: ignored.
        assert!(t
            .observe(90, &anchor(5, 2, &[]), Some(&frozen(1)), 1001)
            .is_empty());
        // A newer one with a lower count: a rollback.
        assert_eq!(
            t.observe(110, &anchor(9, 3, &[]), None, 1002),
            [Alert::AuditCountWentBack { from: 10, to: 9 }]
        );
    }

    #[test]
    fn each_rollback_alerts() {
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &anchor(10, 1, &[("main:aa", 5), ("test:bb", 2)]),
            Some(&frozen(3)),
            0,
        );
        assert_eq!(
            t.observe(
                101,
                &anchor(10, 2, &[("main:aa", 5), ("test:bb", 2)]),
                None,
                0
            ),
            [Alert::AuditHeadChanged { seq: 10 }]
        );
        assert_eq!(
            t.observe(
                102,
                &anchor(11, 2, &[("main:aa", 4), ("test:bb", 2)]),
                None,
                0
            ),
            [Alert::WalletCountWentBack {
                wallet: "main:aa".into(),
                from: 5,
                to: 4
            }]
        );
        assert_eq!(
            t.observe(103, &anchor(12, 2, &[("main:aa", 4)]), None, 0),
            [Alert::WalletMissing {
                wallet: "test:bb".into()
            }]
        );
        assert_eq!(
            t.observe(104, &anchor(13, 2, &[("main:aa", 4)]), Some(&frozen(2)), 0),
            [Alert::EpochWentBack { from: 3, to: 2 }]
        );
        // Counts going up and a new wallet are fine.
        assert!(t
            .observe(
                105,
                &anchor(14, 9, &[("main:aa", 6), ("test:cc", 1)]),
                Some(&frozen(4)),
                0
            )
            .is_empty());
        assert_eq!(t.epoch(), Some(4));
    }

    #[test]
    fn silence_counts_from_the_last_newer_anchor() {
        let mut t = AnchorTracker::default();
        assert!(!t.silent(10_000));
        t.observe(100, &anchor(1, 1, &[]), None, 1_000);
        assert!(!t.silent(1_000 + SILENCE_SECS - 1));
        assert!(t.silent(1_000 + SILENCE_SECS));
        // A replayed older anchor does not reset the timer.
        t.observe(50, &anchor(1, 1, &[]), None, 4_000);
        assert!(t.silent(1_000 + SILENCE_SECS));
        // A newer one does.
        t.observe(200, &anchor(2, 2, &[]), None, 4_000);
        assert!(!t.silent(4_000 + SILENCE_SECS - 1));
        assert!(t.silent(4_000 + SILENCE_SECS));
        assert!(clock_skew(1000, 1000 + SKEW_WARNING_SECS + 1));
        assert!(!clock_skew(1000, 1000 + SKEW_WARNING_SECS));
    }

    fn frozen_with(epoch: u64, all: bool, credentials: &[u8]) -> Frozen {
        Frozen {
            epoch,
            all,
            credentials: credentials.iter().map(|b| crate::Hex16([*b; 16])).collect(),
        }
    }

    /// The anchor in `paired`, which has no time, is the first kept, and
    /// any later anchor is compared with it.
    #[test]
    fn the_paired_anchor_is_the_baseline() {
        let mut t = AnchorTracker::default();
        t.baseline(&anchor(10, 1, &[]), &frozen(3), 1_000);
        assert_eq!(t.epoch(), Some(3));
        assert!(!t.silent(1_000 + SILENCE_SECS - 1));
        assert_eq!(
            t.observe(1, &anchor(9, 1, &[]), None, 1_001),
            [Alert::AuditCountWentBack { from: 10, to: 9 }]
        );
        // A second baseline changes nothing.
        t.baseline(&anchor(1, 1, &[]), &frozen(1), 1_002);
        assert_eq!(t.epoch(), Some(3));
    }

    /// The phone's own freeze is shown by a later anchor with a later epoch
    /// that freezes its scope; until then it is resent, and after two
    /// minutes the phone alerts, once.
    #[test]
    fn an_own_freeze_alerts_until_an_anchor_shows_it() {
        let c = |b: u8| Scope::Credential(crate::Hex16([b; 16]));
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &anchor(1, 1, &[]),
            Some(&frozen_with(5, false, &[])),
            0,
        );
        t.freeze_sent(Scope::All, 5, 1_000);
        t.freeze_sent(Scope::All, 5, 1_015);
        assert_eq!(t.freezes_to_resend(), [Scope::All]);
        assert!(t.due_alerts(1_000 + FREEZE_SHOWN_SECS - 1).is_empty());
        // An anchor freezing something else, at the same epoch or a later
        // one, does not show it.
        t.observe(
            101,
            &anchor(2, 1, &[]),
            Some(&frozen_with(5, false, &[7])),
            1_050,
        );
        t.observe(
            102,
            &anchor(3, 1, &[]),
            Some(&frozen_with(6, false, &[7])),
            1_060,
        );
        assert_eq!(t.freezes_to_resend(), [Scope::All]);
        assert_eq!(
            t.due_alerts(1_000 + FREEZE_SHOWN_SECS),
            [Alert::OwnFreezeNotShown { scope: Scope::All }]
        );
        assert!(t.due_alerts(1_000 + FREEZE_SHOWN_SECS + 1).is_empty());
        // A credential's freeze shows once that credential, or everything,
        // is frozen at a later epoch.
        t.freeze_sent(c(8), 6, 1_100);
        t.observe(
            103,
            &anchor(4, 1, &[]),
            Some(&frozen_with(7, true, &[7])),
            1_110,
        );
        assert!(t.freezes_to_resend().is_empty());
        assert!(t.due_alerts(5_000).is_empty());

        // An anchor freezing the scope, but at the freeze's own epoch, is
        // from before the freeze and does not show it.
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &anchor(1, 1, &[]),
            Some(&frozen_with(5, false, &[])),
            0,
        );
        t.freeze_sent(c(9), 5, 0);
        t.observe(
            101,
            &anchor(2, 1, &[]),
            Some(&frozen_with(5, false, &[9])),
            10,
        );
        assert_eq!(t.freezes_to_resend(), [c(9)]);
        t.observe(
            102,
            &anchor(3, 1, &[]),
            Some(&frozen_with(6, false, &[9])),
            20,
        );
        assert!(t.freezes_to_resend().is_empty());
    }

    /// A freeze seen cleared needs an unfreeze reaching the phone, before
    /// the anchor or within the grace after it; otherwise the phone alerts.
    #[test]
    fn a_freeze_cleared_without_an_unfreeze_alerts() {
        let c = |b: u8| Scope::Credential(crate::Hex16([b; 16]));
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[7, 8])),
            0,
        );
        // The unfreeze of credential 7 arrives first; everything else is
        // cleared with nothing to explain it.
        t.unfreeze_seen(c(7), 10);
        t.observe(
            101,
            &anchor(2, 1, &[]),
            Some(&frozen_with(6, false, &[])),
            20,
        );
        assert!(t.due_alerts(20 + CLEARED_GRACE_SECS - 1).is_empty());
        let mut due = t.due_alerts(20 + CLEARED_GRACE_SECS);
        due.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(
            due,
            [
                Alert::FreezeCleared { scope: Scope::All },
                Alert::FreezeCleared { scope: c(8) }
            ]
        );
        // An unfreeze arriving after the anchor, within the grace, explains
        // it; an unfreeze of everything explains every freeze.
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[7])),
            0,
        );
        t.observe(
            101,
            &anchor(2, 1, &[]),
            Some(&frozen_with(6, false, &[])),
            20,
        );
        t.unfreeze_seen(Scope::All, 30);
        assert!(t.due_alerts(1_000).is_empty());
        // Before the anchor, too.
        t.observe(
            102,
            &anchor(3, 1, &[]),
            Some(&frozen_with(7, true, &[7])),
            1_000,
        );
        t.unfreeze_seen(Scope::All, 1_010);
        t.observe(
            103,
            &anchor(4, 1, &[]),
            Some(&frozen_with(8, false, &[])),
            1_020,
        );
        assert!(t.due_alerts(2_000).is_empty());
        // The unfreeze is used up: a later clear alerts.
        t.observe(
            104,
            &anchor(5, 1, &[]),
            Some(&frozen_with(9, true, &[])),
            2_000,
        );
        t.observe(
            105,
            &anchor(6, 1, &[]),
            Some(&frozen_with(10, false, &[])),
            2_010,
        );
        assert_eq!(
            t.due_alerts(2_010 + CLEARED_GRACE_SECS),
            [Alert::FreezeCleared { scope: Scope::All }]
        );
        // An anchor from a request, with no freeze state, clears nothing.
        let mut t = AnchorTracker::default();
        t.observe(100, &anchor(1, 1, &[]), Some(&frozen_with(5, true, &[])), 0);
        t.observe(101, &anchor(2, 1, &[]), None, 10);
        assert!(t.due_alerts(1_000).is_empty());
        assert_eq!(t.frozen().map(|f| f.all), Some(true));
    }

    fn request(id: u8, created_at: u64, deadline: u64) -> Request {
        Request {
            v: crate::messages::V1,
            request_id: Hex32([id; 32]),
            request_hash: Hex32([0; 32]),
            created_at,
            deadline_secs: deadline,
            credential: None,
            op: crate::binding::Op::Management,
            key: None,
            network: None,
            reason: crate::messages::Reason::Management,
            payload: serde_json::Value::Null,
            budget: None,
            anchor: anchor(1, 1, &[]),
        }
    }

    #[test]
    fn agent_text_is_stripped_and_truncated() {
        let (shown, full) = agent_text("pay\u{202e}lla\u{200b}\u{0007}\nok\u{2066}");
        assert_eq!(shown, "paylla\\nok");
        assert_eq!(full, 13);
        let long = "é".repeat(AGENT_TEXT_CHARS + 5);
        let (shown, full) = agent_text(&long);
        assert_eq!(shown.chars().count(), AGENT_TEXT_CHARS);
        assert_eq!(full, AGENT_TEXT_CHARS + 5);
        // A backslash is escaped, so a literal "\n" cannot pass for a newline.
        assert_eq!(agent_text("a\\nb\r").0, "a\\\\nb\\r");
        for c in [
            '\u{00ad}',
            '\u{0600}',
            '\u{061c}',
            '\u{180e}',
            '\u{200b}',
            '\u{200f}',
            '\u{202a}',
            '\u{2028}',
            '\u{2029}',
            '\u{2069}',
            '\u{206f}',
            '\u{034f}',
            '\u{115f}',
            '\u{3164}',
            '\u{fe0f}',
            '\u{feff}',
            '\u{ffa0}',
            '\u{1d173}',
            '\u{e0041}',
            '\u{e0100}',
            '\u{1b}',
            '\u{85}',
        ] {
            assert_eq!(agent_text(&format!("a{c}b")).0, "ab", "{:x}", c as u32);
        }
    }

    #[test]
    fn the_gate_drops_repeats_and_expired_requests() {
        let mut gate = RequestGate::default();
        let mut t = AnchorTracker::default();
        t.observe(1_000, &anchor(1, 1, &[]), None, 0);
        assert!(gate.admit(&request(1, 900, 120), &t, 0).is_ok());
        assert!(gate.admit(&request(1, 900, 120), &t, 1).is_err());
        assert!(gate.admit(&request(2, 870, 120), &t, 1).is_err());
        assert!(gate.admit(&request(3, 880, 120), &t, 1).is_ok());
        // Seen ids are forgotten after the window, so the set stays bounded.
        assert!(gate
            .admit(&request(1, 2_000, 120), &t, WINDOW_PAST_SECS + 1)
            .is_ok());
    }
}

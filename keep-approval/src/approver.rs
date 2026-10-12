// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! What an approver keeps between messages, and the alerts it raises.
//!
//! - [`AnchorTracker`]: the last anchor seen. Anchors arrive out of order and
//!   can be replayed, so only one later than the last kept, by `(at, seq)`,
//!   is compared; it alerts when the audit log's count goes down, or stays
//!   with another head, when the anchor before it (`prev`) is older than the
//!   one kept, when a wallet ledger's count goes down or the ledger
//!   disappears, and when the freeze epoch goes down. It also tracks
//!   silence (no newer anchor for an hour), the phone's own freezes until an
//!   anchor shows them, and freezes cleared with no unfreeze to explain them.
//! - [`RequestGate`]: drops a request already seen, and one the gateway has
//!   already expired by the latest gateway time the approver holds.
//! - [`shown`]: every string from the gateway or an agent, as a phone shows
//!   it.
//!
//! All of it is plain data the approver persists between runs.

use std::collections::BTreeMap;
use unicode_normalization::char::{canonical_combining_class, is_combining_mark};

use serde::{Deserialize, Serialize};

use crate::change::Scope;
use crate::messages::{AnchorState, Frozen, Request};
use crate::wrap::{WINDOW_FUTURE_SECS, WINDOW_PAST_SECS};

/// How long an id is remembered to refuse a replay: as long as a wrap
/// carrying it can still be accepted, one dated up to the future limit
/// included.
const REPLAY_KEEP_SECS: u64 = WINDOW_PAST_SECS + WINDOW_FUTURE_SECS;
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

/// How long a freeze seen cleared waits for the `unfreeze` outcome that
/// explains it before the phone alerts. The outcome and the anchor are
/// separate wraps, which relays can deliver in either order.
pub const CLEARED_GRACE_SECS: u64 = 120;

/// Something the approver must show the owner, prominently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alert {
    /// The audit log's count went down: a rollback or truncation.
    AuditCountWentBack { from: u64, to: u64 },
    /// The audit log's count stayed but its head changed: a rewrite.
    AuditHeadChanged { seq: u64 },
    /// The anchor the gateway says it sent before this one is older than
    /// the one kept: the vault or `keep.db` was put back to an earlier copy
    /// and written past the kept count since.
    PrevWentBack { kept: u64, prev: u64 },
    /// The anchor before this one has the kept count but another head.
    PrevHeadChanged { seq: u64 },
    /// An anchor names no anchor before it, after one was kept: the record
    /// of anchors sent is gone.
    PrevMissing,
    /// A wallet ledger's count went down: a rolled-back ledger.
    WalletCountWentBack { wallet: String, from: u64, to: u64 },
    /// A wallet ledger the gateway reported before is gone.
    WalletMissing { wallet: String },
    /// The freeze epoch went down.
    EpochWentBack { from: u64, to: u64 },
    /// The phone's own freeze has not shown in an anchor after
    /// [`FREEZE_SHOWN_SECS`]: a relay may be withholding it.
    OwnFreezeNotShown { scope: Scope },
    /// A freeze was cleared and no unfreeze explains it.
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
    /// The outcomes already taken, by request id, with the approver's clock
    /// when each arrived; kept for the wrap time window, so a replayed
    /// outcome counts once.
    outcomes: BTreeMap<Hex32, u64>,
    /// The same for `approved` unfreeze outcomes, apart from `outcomes` so
    /// taking an outcome with [`Self::outcome_seen`] first never makes its
    /// unfreeze look replayed.
    unfreeze_outcomes: BTreeMap<Hex32, u64>,
    /// Unfreezes approved through a request, whose outcome reached the
    /// phone and no anchor has shown yet, with the approver's clock when
    /// each arrived.
    unfreezes: Vec<(Scope, u64)>,
    /// Freezes seen cleared with nothing to explain them yet, with the
    /// approver's clock when each was seen.
    cleared: Vec<(Scope, u64)>,
}

/// Whether `frozen` shows `scope` frozen: the gateway's global freeze, or
/// that credential in its list. A credential's own freeze is shown only by
/// the list, since unfreezing everything clears only the global freeze.
fn freezes(frozen: &Frozen, scope: Scope) -> bool {
    match scope {
        Scope::All => frozen.all,
        Scope::Credential(id) => frozen.credentials.contains(&id),
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

/// Whether `new` lists an unfreeze of `scope` applied after `old`'s epoch:
/// the gateway's own word that the freeze was lifted, whichever phone or
/// approval lifted it.
fn listed(old: &Frozen, new: &Frozen, scope: Scope) -> bool {
    new.unfrozen
        .iter()
        .any(|u| u.scope == scope && u.epoch > old.epoch && u.epoch <= new.epoch)
}

/// Whether `request_id` is new to `seen`, which forgets ids older than the
/// wrap time window; notes it if so.
fn first_time(seen: &mut BTreeMap<Hex32, u64>, request_id: Hex32, local_now: u64) -> bool {
    seen.retain(|_, at| local_now.saturating_sub(*at) <= REPLAY_KEEP_SECS);
    if seen.contains_key(&request_id) {
        return false;
    }
    seen.insert(request_id, local_now);
    true
}

impl AnchorTracker {
    /// Keep the anchor a `paired` message carries, which has no time of its
    /// own, as the first one: every later anchor is compared with it. Taken
    /// at time 0, it changes nothing once an anchor is kept.
    pub fn baseline(&mut self, anchor: &AnchorState, frozen: &Frozen, local_now: u64) {
        self.observe(0, anchor, Some(frozen), local_now);
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

    /// Take the outcome of request `request_id`, arriving at `local_now`:
    /// whether it is the first time. A replayed outcome is taken once.
    pub fn outcome_seen(&mut self, request_id: Hex32, local_now: u64) -> bool {
        first_time(&mut self.outcomes, request_id, local_now)
    }

    /// Note the `approved` outcome of request `request_id`, an `unfreeze`
    /// of `scope`, reaching the phone: it explains a freeze of that scope
    /// seen cleared, before or after. A replayed outcome explains nothing.
    pub fn unfreeze_seen(&mut self, request_id: Hex32, scope: Scope, local_now: u64) {
        if !first_time(&mut self.unfreeze_outcomes, request_id, local_now) {
            return;
        }
        let before = self.cleared.len();
        self.cleared.retain(|(c, _)| *c != scope);
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
        for scope in cleared(old, new) {
            if listed(old, new, scope) {
                continue;
            }
            if let Some(i) = self.unfreezes.iter().position(|(u, _)| *u == scope) {
                self.unfreezes.remove(i);
            } else {
                self.cleared.push((scope, local_now));
            }
        }
    }

    /// Note an anchor taken at gateway time `at`, from an anchor message
    /// (with `frozen`) or a request (without), arriving at the approver's
    /// `local_now`. An anchor not later than the last one kept, by `at` and
    /// then by `seq`, is ignored, and does not reset the silence timer.
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
            if (at, anchor.seq) <= (kept.at, kept.anchor.seq) {
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
            match anchor.prev {
                Some(prev) if prev.seq < last.seq => alerts.push(Alert::PrevWentBack {
                    kept: last.seq,
                    prev: prev.seq,
                }),
                Some(prev) if prev.seq == last.seq && prev.head != last.head => {
                    alerts.push(Alert::PrevHeadChanged { seq: prev.seq })
                }
                // Higher: anchors were missed in between; the counts above
                // are all there is to check.
                Some(_) => {}
                None => alerts.push(Alert::PrevMissing),
            }
            for old in &last.wallets {
                match anchor.wallets.iter().find(|w| w.wallet == old.wallet) {
                    Some(new) if new.seq < old.seq => alerts.push(Alert::WalletCountWentBack {
                        wallet: old.wallet.to_string(),
                        from: old.seq,
                        to: new.seq,
                    }),
                    Some(_) => {}
                    None => alerts.push(Alert::WalletMissing {
                        wallet: old.wallet.to_string(),
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
            .retain(|_, at| local_now.saturating_sub(*at) <= REPLAY_KEEP_SECS);
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

/// The most characters of any other gateway string an approver shows (a
/// refusal's reason, say). Names and labels are held to
/// [`crate::change::MAX_LABEL_CHARS`] before they get here.
pub const GATEWAY_TEXT_CHARS: usize = 256;

/// A string as an approver shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    /// The text to show: hidden characters removed, escaped, cut to the
    /// limit with the escapes counted in it.
    pub text: String,
    /// The original's length in characters.
    pub chars: usize,
    /// How many hidden characters were removed, which the phone states.
    pub removed: usize,
    /// Whether the text was cut short.
    pub truncated: bool,
}

/// The most combining marks shown on one character; more would draw over
/// the lines around it.
pub const MAX_COMBINING_RUN: usize = 4;

/// `text` as an approver shows it, in at most `limit` characters: every
/// hidden character (see [`is_hidden`]) and every combining mark past
/// [`MAX_COMBINING_RUN`] on one character removed first and counted, then a
/// backslash doubled and newlines, carriage returns and tabs shown as
/// visible escapes, then cut to the limit, each escape counting as the
/// characters it shows. Used for every string from the gateway, and for
/// agent-written text with [`AGENT_TEXT_CHARS`].
pub fn shown(text: &str, limit: usize) -> Shown {
    let mut out = String::new();
    let (mut used, mut chars, mut removed, mut truncated) = (0, 0, 0, false);
    let mut run = 0;
    for c in text.chars() {
        chars += 1;
        if is_hidden(c) && !matches!(c, '\n' | '\r' | '\t') {
            removed += 1;
            continue;
        }
        run = if is_combining_mark(c) { run + 1 } else { 0 };
        if run > MAX_COMBINING_RUN {
            removed += 1;
            continue;
        }
        let piece: &str = match c {
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            _ => "",
        };
        let width = if piece.is_empty() { 1 } else { 2 };
        if truncated || used + width > limit {
            truncated = true;
            continue;
        }
        used += width;
        if piece.is_empty() {
            out.push(c);
        } else {
            out.push_str(piece);
        }
    }
    Shown {
        text: out,
        chars,
        removed,
        truncated,
    }
}

/// Agent-written text as an approver shows it, apart from everything else:
/// [`shown`] with [`AGENT_TEXT_CHARS`].
pub fn agent_text(text: &str) -> Shown {
    shown(text, AGENT_TEXT_CHARS)
}

/// Characters that could hide or reorder what the owner reads: controls
/// (Cc), every format character (Cf, bidi controls among them), the line
/// and paragraph separators (Zl, Zp), the other default-ignorable
/// characters that render as nothing (fillers, variation selectors,
/// unassigned default-ignorables), the enclosing marks, and the combining
/// overlays (canonical combining class 1) that strike through or slash the
/// character before them.
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || canonical_combining_class(c) == 1
        || matches!(c,
            // Cf
            '\u{00ad}'                     // soft hyphen
            | '\u{0600}'..='\u{0605}'     // Arabic number signs
            | '\u{061c}'                   // Arabic letter mark
            | '\u{06dd}'                   // Arabic end of ayah
            | '\u{070f}'                   // Syriac abbreviation mark
            | '\u{0890}'..='\u{0891}'     // Arabic pound and piastre marks above
            | '\u{08e2}'                   // Arabic disputed end of ayah
            | '\u{180b}'..='\u{180f}'     // Mongolian free variation selectors, vowel separator
            | '\u{200b}'..='\u{200f}'     // zero-width spaces and joiners, LRM, RLM
            | '\u{202a}'..='\u{202e}'     // bidi embeddings and overrides
            | '\u{2060}'..='\u{206f}'     // word joiner, invisible operators, bidi isolates,
                                           // deprecated format characters, U+2065
            | '\u{feff}'                   // byte order mark
            | '\u{fff0}'..='\u{fffb}'     // unassigned default-ignorables, interlinear annotations
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
            // Enclosing marks, which draw around or over the character before
            | '\u{0488}'..='\u{0489}'
            | '\u{1abe}'
            | '\u{20dd}'..='\u{20e0}'
            | '\u{20e2}'..='\u{20e4}'
            | '\u{a670}'..='\u{a672}'
            // Combining overlays: every mark of canonical combining class 1
            | '\u{0334}'..='\u{0338}'     // tilde, stroke and solidus overlays
            | '\u{1cd4}'                   // Vedic tone midline svarita
            | '\u{1ce2}'..='\u{1ce8}'     // Vedic overlay signs
            | '\u{20d2}'..='\u{20d3}'     // long and short vertical line overlays
            | '\u{20d8}'..='\u{20da}'     // ring overlays
            | '\u{20e5}'..='\u{20e6}'     // reverse solidus and double vertical stroke overlays
            | '\u{20ea}'..='\u{20eb}'     // leftwards arrow and long double solidus overlays
            | '\u{10a39}'                  // Kharoshthi cauda
            | '\u{16af0}'..='\u{16af4}'   // Bassa Vah combining marks
            | '\u{1bc9e}'                  // Duployan double mark
            | '\u{1d167}'..='\u{1d169}'   // musical tremolos
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{LogPoint, Unfrozen, WalletAnchor, WalletName};

    /// `main:aa` stands for `main:` and `aa` repeated to 64 characters.
    fn w(name: &str) -> String {
        let (prefix, byte) = name.split_once(':').unwrap();
        format!("{prefix}:{}", byte.repeat(32))
    }

    /// An anchor whose `prev` is `prev`.
    fn anchor_after(
        prev: Option<(u64, u8)>,
        seq: u64,
        head: u8,
        wallets: &[(&str, u64)],
    ) -> AnchorState {
        AnchorState {
            seq,
            head: Hex32([head; 32]),
            prev: prev.map(|(seq, head)| LogPoint {
                seq,
                head: Hex32([head; 32]),
            }),
            wallets: wallets
                .iter()
                .map(|(name, s)| WalletAnchor {
                    wallet: WalletName::parse(&w(name)).unwrap(),
                    seq: *s,
                    spent: 0,
                    window: 0,
                })
                .collect(),
        }
    }

    /// A gateway's anchors in order, each naming the one before it.
    #[derive(Default)]
    struct Gateway {
        last: Option<(u64, u8)>,
    }

    impl Gateway {
        fn anchor(&mut self, seq: u64, head: u8, wallets: &[(&str, u64)]) -> AnchorState {
            let a = anchor_after(self.last, seq, head, wallets);
            self.last = Some((seq, head));
            a
        }
    }

    fn frozen_with(epoch: u64, all: bool, credentials: &[u8]) -> Frozen {
        Frozen {
            epoch,
            all,
            credentials: credentials.iter().map(|b| crate::Hex16([*b; 16])).collect(),
            unfrozen: vec![],
        }
    }

    fn frozen(epoch: u64) -> Frozen {
        frozen_with(epoch, false, &[])
    }

    fn c(b: u8) -> Scope {
        Scope::Credential(crate::Hex16([b; 16]))
    }

    #[test]
    fn only_newer_anchors_are_compared() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        let first = g.anchor(10, 1, &[]);
        assert!(t.observe(100, &first, Some(&frozen(3)), 1000).is_empty());
        // An older anchor with a lower count, replayed: ignored.
        assert!(t
            .observe(90, &anchor_after(None, 5, 2, &[]), Some(&frozen(1)), 1001)
            .is_empty());
        // A newer one with a lower count: a rollback.
        assert_eq!(
            t.observe(110, &anchor_after(Some((10, 1)), 9, 3, &[]), None, 1002),
            [Alert::AuditCountWentBack { from: 10, to: 9 }]
        );
    }

    /// Anchors are ordered by their time and then their count: one with the
    /// same time and a higher count is newer, and its freeze state is kept.
    #[test]
    fn anchors_with_the_same_time_are_ordered_by_count() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(100, &g.anchor(10, 1, &[]), Some(&frozen(3)), 0);
        let later = g.anchor(11, 2, &[]);
        assert!(t
            .observe(100, &later, Some(&frozen_with(4, true, &[])), 1)
            .is_empty());
        assert_eq!(t.frozen().map(|f| f.all), Some(true));
        // The same time and count again: not newer, ignored.
        assert!(t
            .observe(
                100,
                &anchor_after(Some((10, 1)), 11, 9, &[]),
                Some(&frozen(5)),
                2
            )
            .is_empty());
        assert_eq!(t.epoch(), Some(4));
    }

    #[test]
    fn each_rollback_alerts() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(10, 1, &[("main:aa", 5), ("test:bb", 2)]),
            Some(&frozen(3)),
            0,
        );
        assert_eq!(
            t.observe(
                101,
                &g.anchor(10, 2, &[("main:aa", 5), ("test:bb", 2)]),
                None,
                0
            ),
            [Alert::AuditHeadChanged { seq: 10 }]
        );
        assert_eq!(
            t.observe(
                102,
                &g.anchor(11, 2, &[("main:aa", 4), ("test:bb", 2)]),
                None,
                0
            ),
            [Alert::WalletCountWentBack {
                wallet: w("main:aa"),
                from: 5,
                to: 4
            }]
        );
        assert_eq!(
            t.observe(103, &g.anchor(12, 2, &[("main:aa", 4)]), None, 0),
            [Alert::WalletMissing {
                wallet: w("test:bb")
            }]
        );
        assert_eq!(
            t.observe(
                104,
                &g.anchor(13, 2, &[("main:aa", 4)]),
                Some(&frozen(2)),
                0
            ),
            [Alert::EpochWentBack { from: 3, to: 2 }]
        );
        // Counts going up and a new wallet are fine.
        assert!(t
            .observe(
                105,
                &g.anchor(14, 9, &[("main:aa", 6), ("test:cc", 1)]),
                Some(&frozen(4)),
                0
            )
            .is_empty());
        assert_eq!(t.epoch(), Some(4));
    }

    /// A vault put back to an earlier copy and then written past the count
    /// the phone kept shows only in `prev`: the copy's record of the anchor
    /// before is older than the one the phone kept. Missed anchors (a
    /// higher `prev`) are fine, a missing `prev` after one was kept is not.
    #[test]
    fn prev_catches_a_rollback_written_past_the_kept_count() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(100, &g.anchor(10, 1, &[]), Some(&frozen(3)), 0);
        t.observe(200, &g.anchor(20, 2, &[]), Some(&frozen(3)), 0);
        // The copy from seq 10, written up to 25: its prev is (10, 1).
        assert_eq!(
            t.observe(300, &anchor_after(Some((10, 1)), 25, 3, &[]), None, 0),
            [Alert::PrevWentBack { kept: 20, prev: 10 }]
        );
        // The kept count with another head.
        assert_eq!(
            t.observe(301, &anchor_after(Some((25, 7)), 26, 3, &[]), None, 0),
            [Alert::PrevHeadChanged { seq: 25 }]
        );
        // Anchors the phone missed: prev ahead of the kept one.
        let mut t = AnchorTracker::default();
        t.observe(100, &anchor_after(None, 10, 1, &[]), None, 0);
        assert!(t
            .observe(200, &anchor_after(Some((15, 4)), 20, 2, &[]), None, 0)
            .is_empty());
        assert_eq!(
            t.observe(300, &anchor_after(None, 30, 3, &[]), None, 0),
            [Alert::PrevMissing]
        );
        // The first anchor kept may have no prev.
        let mut t = AnchorTracker::default();
        assert!(t
            .observe(100, &anchor_after(None, 1, 1, &[]), None, 0)
            .is_empty());
    }

    #[test]
    fn silence_counts_from_the_last_newer_anchor() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        assert!(!t.silent(10_000));
        t.observe(100, &g.anchor(1, 1, &[]), None, 1_000);
        assert!(!t.silent(1_000 + SILENCE_SECS - 1));
        assert!(t.silent(1_000 + SILENCE_SECS));
        // A replayed older anchor does not reset the timer.
        t.observe(50, &anchor_after(None, 1, 1, &[]), None, 4_000);
        assert!(t.silent(1_000 + SILENCE_SECS));
        // A newer one does.
        t.observe(200, &g.anchor(2, 2, &[]), None, 4_000);
        assert!(!t.silent(4_000 + SILENCE_SECS - 1));
        assert!(t.silent(4_000 + SILENCE_SECS));
        assert!(clock_skew(1000, 1000 + SKEW_WARNING_SECS + 1));
        assert!(!clock_skew(1000, 1000 + SKEW_WARNING_SECS));
    }

    /// The anchor in `paired`, which has no time, is the first kept, and
    /// any later anchor is compared with it.
    #[test]
    fn the_paired_anchor_is_the_baseline() {
        let mut t = AnchorTracker::default();
        t.baseline(&anchor_after(None, 10, 1, &[]), &frozen(3), 1_000);
        assert_eq!(t.epoch(), Some(3));
        assert!(!t.silent(1_000 + SILENCE_SECS - 1));
        assert_eq!(
            t.observe(1, &anchor_after(Some((10, 1)), 9, 1, &[]), None, 1_001),
            [Alert::AuditCountWentBack { from: 10, to: 9 }]
        );
        // A second baseline changes nothing.
        t.baseline(&anchor_after(None, 1, 1, &[]), &frozen(1), 1_002);
        assert_eq!(t.epoch(), Some(3));
    }

    /// The phone's own freeze is shown by a later anchor with a later epoch
    /// that freezes its scope; until then it is resent, and after two
    /// minutes the phone alerts, once.
    #[test]
    fn an_own_freeze_alerts_until_an_anchor_shows_it() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(100, &g.anchor(1, 1, &[]), Some(&frozen(5)), 0);
        t.freeze_sent(Scope::All, 5, 1_000);
        t.freeze_sent(Scope::All, 5, 1_015);
        assert_eq!(t.freezes_to_resend(), [Scope::All]);
        assert!(t.due_alerts(1_000 + FREEZE_SHOWN_SECS - 1).is_empty());
        // An anchor freezing something else, at the same epoch or a later
        // one, does not show it.
        t.observe(
            101,
            &g.anchor(2, 1, &[]),
            Some(&frozen_with(5, false, &[7])),
            1_050,
        );
        t.observe(
            102,
            &g.anchor(3, 1, &[]),
            Some(&frozen_with(6, false, &[7])),
            1_060,
        );
        assert_eq!(t.freezes_to_resend(), [Scope::All]);
        assert_eq!(
            t.due_alerts(1_000 + FREEZE_SHOWN_SECS),
            [Alert::OwnFreezeNotShown { scope: Scope::All }]
        );
        assert!(t.due_alerts(1_000 + FREEZE_SHOWN_SECS + 1).is_empty());
        // A credential's freeze shows once that credential is listed at a
        // later epoch; everything frozen does not show it, since unfreezing
        // everything would leave it unfrozen.
        t.freeze_sent(c(8), 6, 1_100);
        t.observe(
            103,
            &g.anchor(4, 1, &[]),
            Some(&frozen_with(7, true, &[7])),
            1_110,
        );
        assert_eq!(t.freezes_to_resend(), [c(8)]);
        t.observe(
            104,
            &g.anchor(5, 1, &[]),
            Some(&frozen_with(8, true, &[7, 8])),
            1_120,
        );
        assert!(t.freezes_to_resend().is_empty());
        assert!(t.due_alerts(5_000).is_empty());

        // An anchor freezing the scope, but at the freeze's own epoch, is
        // from before the freeze and does not show it.
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(100, &g.anchor(1, 1, &[]), Some(&frozen(5)), 0);
        t.freeze_sent(c(9), 5, 0);
        t.observe(
            101,
            &g.anchor(2, 1, &[]),
            Some(&frozen_with(5, false, &[9])),
            10,
        );
        assert_eq!(t.freezes_to_resend(), [c(9)]);
        t.observe(
            102,
            &g.anchor(3, 1, &[]),
            Some(&frozen_with(6, false, &[9])),
            20,
        );
        assert!(t.freezes_to_resend().is_empty());
    }

    /// A freeze seen cleared needs an unfreeze: an approved `unfreeze`
    /// outcome reaching the phone before the anchor or within the grace
    /// after it, or the anchor's own list of unfreezes; otherwise the phone
    /// alerts.
    #[test]
    fn a_freeze_cleared_without_an_unfreeze_alerts() {
        let id = |b: u8| Hex32([b; 32]);
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[7, 8])),
            0,
        );
        // The unfreeze of credential 7 arrives first; everything else is
        // cleared with nothing to explain it.
        t.unfreeze_seen(id(1), c(7), 10);
        t.observe(101, &g.anchor(2, 1, &[]), Some(&frozen(6)), 20);
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
        // it.
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[])),
            0,
        );
        t.observe(101, &g.anchor(2, 1, &[]), Some(&frozen(6)), 20);
        t.unfreeze_seen(id(2), Scope::All, 30);
        assert!(t.due_alerts(1_000).is_empty());
        // Before the anchor, too; and it is used up: a later clear alerts.
        t.observe(
            102,
            &g.anchor(3, 1, &[]),
            Some(&frozen_with(7, true, &[])),
            1_000,
        );
        t.unfreeze_seen(id(3), Scope::All, 1_010);
        t.observe(103, &g.anchor(4, 1, &[]), Some(&frozen(8)), 1_020);
        assert!(t.due_alerts(2_000).is_empty());
        t.observe(
            104,
            &g.anchor(5, 1, &[]),
            Some(&frozen_with(9, true, &[])),
            2_000,
        );
        t.observe(105, &g.anchor(6, 1, &[]), Some(&frozen(10)), 2_010);
        assert_eq!(
            t.due_alerts(2_010 + CLEARED_GRACE_SECS),
            [Alert::FreezeCleared { scope: Scope::All }]
        );
        // An unfreeze explains only its own scope.
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, false, &[7, 8])),
            0,
        );
        t.observe(101, &g.anchor(2, 1, &[]), Some(&frozen(6)), 10);
        t.unfreeze_seen(id(4), c(7), 20);
        assert_eq!(
            t.due_alerts(10 + CLEARED_GRACE_SECS),
            [Alert::FreezeCleared { scope: c(8) }]
        );
        // An anchor from a request, with no freeze state, clears nothing.
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[])),
            0,
        );
        t.observe(101, &g.anchor(2, 1, &[]), None, 10);
        assert!(t.due_alerts(1_000).is_empty());
        assert_eq!(t.frozen().map(|f| f.all), Some(true));
    }

    /// Unfreezing everything clears only the global freeze, as the gateway
    /// does: it explains no credential's freeze cleared with it.
    #[test]
    fn an_unfreeze_of_everything_explains_no_credential() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[7])),
            0,
        );
        t.unfreeze_seen(Hex32([1; 32]), Scope::All, 10);
        t.observe(101, &g.anchor(2, 1, &[]), Some(&frozen(6)), 20);
        assert_eq!(
            t.due_alerts(20 + CLEARED_GRACE_SECS),
            [Alert::FreezeCleared { scope: c(7) }]
        );
    }

    /// An outcome is taken once by its request id: a replayed old
    /// `approved` outcome cannot explain a later clear.
    #[test]
    fn a_replayed_outcome_explains_nothing() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[])),
            0,
        );
        t.unfreeze_seen(Hex32([1; 32]), Scope::All, 10);
        t.observe(101, &g.anchor(2, 1, &[]), Some(&frozen(6)), 20);
        assert!(t.due_alerts(1_000).is_empty());
        // Frozen again, then cleared with only the old outcome replayed.
        t.observe(
            102,
            &g.anchor(3, 1, &[]),
            Some(&frozen_with(7, true, &[])),
            2_000,
        );
        t.unfreeze_seen(Hex32([1; 32]), Scope::All, 2_010);
        t.observe(103, &g.anchor(4, 1, &[]), Some(&frozen(8)), 2_020);
        assert_eq!(
            t.due_alerts(2_020 + CLEARED_GRACE_SECS),
            [Alert::FreezeCleared { scope: Scope::All }]
        );
        // Remembered for the wrap time window, then forgotten.
        // Still remembered while a wrap carrying it could be accepted.
        t.unfreeze_seen(Hex32([1; 32]), Scope::All, 10 + WINDOW_PAST_SECS + 1);
        assert!(!t
            .unfreezes
            .contains(&(Scope::All, 10 + WINDOW_PAST_SECS + 1)));
        t.unfreeze_seen(Hex32([1; 32]), Scope::All, 10 + REPLAY_KEEP_SECS + 1);
        assert!(t
            .unfreezes
            .contains(&(Scope::All, 10 + REPLAY_KEEP_SECS + 1)));
    }

    /// Taking an outcome with `outcome_seen` first does not make its
    /// unfreeze look replayed.
    #[test]
    fn an_outcome_taken_first_still_explains_its_unfreeze() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[])),
            0,
        );
        assert!(t.outcome_seen(Hex32([1; 32]), 10));
        assert!(!t.outcome_seen(Hex32([1; 32]), 11));
        t.unfreeze_seen(Hex32([1; 32]), Scope::All, 10);
        t.observe(101, &g.anchor(2, 1, &[]), Some(&frozen(6)), 20);
        assert!(t.due_alerts(20 + CLEARED_GRACE_SECS).is_empty());
    }

    /// An unfreeze in the anchor's list explains only a clear of its own
    /// scope, applied after the kept anchor and not after the new one.
    #[test]
    fn a_listed_unfreeze_explains_only_its_scope_and_epochs() {
        for (unfrozen, explained) in [
            (
                Unfrozen {
                    scope: Scope::All,
                    epoch: 6,
                },
                true,
            ),
            (
                Unfrozen {
                    scope: c(7),
                    epoch: 6,
                },
                false,
            ),
            (
                Unfrozen {
                    scope: Scope::All,
                    epoch: 5,
                },
                false,
            ),
            (
                Unfrozen {
                    scope: Scope::All,
                    epoch: 7,
                },
                false,
            ),
        ] {
            let mut g = Gateway::default();
            let mut t = AnchorTracker::default();
            t.observe(
                100,
                &g.anchor(1, 1, &[]),
                Some(&frozen_with(5, true, &[])),
                0,
            );
            let mut after = frozen(6);
            after.unfrozen = vec![unfrozen];
            t.observe(101, &g.anchor(2, 1, &[]), Some(&after), 10);
            let alerts = t.due_alerts(10 + CLEARED_GRACE_SECS);
            if explained {
                assert!(alerts.is_empty(), "{unfrozen:?}");
            } else {
                assert_eq!(
                    alerts,
                    [Alert::FreezeCleared { scope: Scope::All }],
                    "{unfrozen:?}"
                );
            }
        }
    }

    /// An unfreeze sent by another phone reaches this one only as the
    /// anchor's list of unfreezes, which explains the freeze it cleared,
    /// and only an unfreeze applied since the last anchor kept.
    #[test]
    fn another_phones_unfreeze_is_explained_by_the_anchor() {
        let mut g = Gateway::default();
        let mut t = AnchorTracker::default();
        t.observe(
            100,
            &g.anchor(1, 1, &[]),
            Some(&frozen_with(5, true, &[7])),
            0,
        );
        let mut after = frozen_with(7, false, &[]);
        after.unfrozen = vec![
            Unfrozen {
                scope: Scope::All,
                epoch: 6,
            },
            Unfrozen {
                scope: c(7),
                epoch: 7,
            },
        ];
        t.observe(101, &g.anchor(2, 1, &[]), Some(&after), 10);
        assert!(t.due_alerts(10 + CLEARED_GRACE_SECS).is_empty());
        // An unfreeze listed from before the kept anchor's epoch explains
        // nothing new.
        t.observe(
            102,
            &g.anchor(3, 1, &[]),
            Some(&frozen_with(8, true, &[])),
            20,
        );
        let mut stale = frozen_with(9, false, &[]);
        stale.unfrozen = after.unfrozen.clone();
        t.observe(103, &g.anchor(4, 1, &[]), Some(&stale), 30);
        assert_eq!(
            t.due_alerts(30 + CLEARED_GRACE_SECS),
            [Alert::FreezeCleared { scope: Scope::All }]
        );
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
            anchor: anchor_after(None, 1, 1, &[]),
        }
    }

    #[test]
    fn agent_text_is_stripped_escaped_and_truncated() {
        let s = agent_text("pay\u{202e}lla\u{200b}\u{0007}\nok\u{2066}");
        assert_eq!(s.text, "paylla\\nok");
        assert_eq!((s.chars, s.removed, s.truncated), (13, 4, false));
        let long = "é".repeat(AGENT_TEXT_CHARS + 5);
        let s = agent_text(&long);
        assert_eq!(s.text.chars().count(), AGENT_TEXT_CHARS);
        assert_eq!((s.chars, s.truncated), (AGENT_TEXT_CHARS + 5, true));
        // A backslash is escaped, so a literal "\n" cannot pass for a newline.
        assert_eq!(agent_text("a\\nb\r").text, "a\\\\nb\\r");
        for c in [
            '\u{00ad}',
            '\u{0600}',
            '\u{061c}',
            '\u{180b}',
            '\u{180c}',
            '\u{180d}',
            '\u{180e}',
            '\u{180f}',
            '\u{200b}',
            '\u{200f}',
            '\u{202a}',
            '\u{2028}',
            '\u{2029}',
            '\u{2065}',
            '\u{2069}',
            '\u{206f}',
            '\u{034f}',
            '\u{0334}',
            '\u{0338}',
            '\u{20d2}',
            '\u{20d3}',
            '\u{20e5}',
            '\u{20e6}',
            '\u{115f}',
            '\u{3164}',
            '\u{fe0f}',
            '\u{feff}',
            '\u{fff0}',
            '\u{fff8}',
            '\u{ffa0}',
            '\u{1d173}',
            '\u{e0041}',
            '\u{e0100}',
            '\u{1b}',
            '\u{85}',
        ] {
            assert_eq!(agent_text(&format!("a{c}b")).text, "ab", "{:x}", c as u32);
        }
    }

    /// Hidden characters are removed before the limit is applied, and the
    /// escapes count inside it: 2,000 zero-width spaces cannot push what
    /// follows out of view, and backslashes cannot double the text shown.
    #[test]
    fn overlays_are_hidden_and_stacked_marks_capped() {
        for c in [
            '\u{0338}',
            '\u{20eb}',
            '\u{20d8}',
            '\u{1ce2}',
            '\u{1d167}',
            '\u{16af0}',
        ] {
            assert!(is_hidden(c), "{c:?}");
        }
        assert!(!is_hidden('\u{0301}'));
        let s = shown(&format!("a{}b\u{0301}", "\u{0301}".repeat(9)), 100);
        assert_eq!(
            s.text,
            format!("a{}b\u{0301}", "\u{0301}".repeat(MAX_COMBINING_RUN))
        );
        assert_eq!(s.removed, 9 - MAX_COMBINING_RUN);
        // A hidden character does not break up a run.
        let s = shown(
            &format!("a{}\u{200b}{}", "\u{0301}".repeat(3), "\u{0301}".repeat(3)),
            100,
        );
        assert_eq!(s.text, format!("a{}", "\u{0301}".repeat(MAX_COMBINING_RUN)));
        // Marks from every block count, mixed or alone.
        let mixed = format!("a{}", "\u{0301}\u{0483}\u{0592}".repeat(10));
        assert_eq!(
            shown(&mixed, 100).text.chars().count(),
            1 + MAX_COMBINING_RUN
        );
        let cyrillic = format!("a{}", "\u{0483}".repeat(50));
        assert_eq!(
            shown(&cyrillic, 100).text.chars().count(),
            1 + MAX_COMBINING_RUN
        );
        // Enclosing marks are hidden.
        for c in ['\u{20e0}', '\u{20dd}', '\u{1abe}', '\u{0488}', '\u{a670}'] {
            assert!(is_hidden(c), "{c:?}");
        }
    }

    #[test]
    fn hidden_characters_cannot_push_text_out_of_view() {
        let text = format!(
            "{}{{\"lud16\":\"attacker@example.com\"}}",
            "\u{200b}".repeat(AGENT_TEXT_CHARS)
        );
        let s = agent_text(&text);
        assert_eq!(s.text, "{\"lud16\":\"attacker@example.com\"}");
        assert_eq!(s.removed, AGENT_TEXT_CHARS);
        assert!(!s.truncated);
        let s = agent_text(&"\\".repeat(AGENT_TEXT_CHARS));
        assert_eq!(s.text.chars().count(), AGENT_TEXT_CHARS);
        assert!(s.truncated);
        // A short limit, as for a gateway string.
        let s = shown("abc\ndef", 4);
        assert_eq!((s.text.as_str(), s.truncated), ("abc", true));
    }

    #[test]
    fn the_gate_drops_repeats_and_expired_requests() {
        let mut gate = RequestGate::default();
        let mut t = AnchorTracker::default();
        t.observe(1_000, &anchor_after(None, 1, 1, &[]), None, 0);
        assert!(gate.admit(&request(1, 900, 120), &t, 0).is_ok());
        assert!(gate.admit(&request(1, 900, 120), &t, 1).is_err());
        assert!(gate.admit(&request(2, 870, 120), &t, 1).is_err());
        assert!(gate.admit(&request(3, 880, 120), &t, 1).is_ok());
        // Seen ids are forgotten after the window, so the set stays bounded.
        assert!(gate
            .admit(&request(1, 2_000, 120), &t, REPLAY_KEEP_SECS)
            .is_err());
        assert!(gate
            .admit(&request(1, 2_000, 120), &t, REPLAY_KEEP_SECS + 1)
            .is_ok());
    }
}

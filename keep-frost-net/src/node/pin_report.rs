// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Pin failures during connect happen before any subscriber exists, and a
//! broadcast send with no receiver drops the event. Hold those until the first
//! [`KfpNode::subscribe`](super::KfpNode::subscribe), and send later ones
//! straight onto the bus.

use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::audit::SigningAuditLog;
use crate::error::FrostNetError;
use crate::pinning::{acceptable_relay_host, PinFailureHook, PinRejection};

use super::KfpNodeEvent;

struct Queued {
    host: String,
    reason: PinRejection,
    audited: bool,
}

struct Inner {
    pending: Vec<Queued>,
    tx: Option<broadcast::Sender<KfpNodeEvent>>,
    audit: Option<Arc<SigningAuditLog>>,
}

pub(crate) struct PinReports {
    inner: Mutex<Inner>,
}

impl PinReports {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                pending: Vec::new(),
                tx: None,
                audit: None,
            }),
        }
    }

    pub(crate) fn hook(self: &Arc<Self>) -> PinFailureHook {
        let reports = Arc::clone(self);
        Arc::new(move |host, reason| reports.report(host, reason))
    }

    pub(crate) fn report(&self, host: &str, reason: PinRejection) {
        if !acceptable_relay_host(host) {
            return;
        }
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let audited = guard
            .audit
            .as_ref()
            .is_some_and(|audit| audit.log_relay_pin_rejection(host, reason));
        let event = KfpNodeEvent::RelayPinRejected {
            relay_host: host.to_string(),
            reason,
        };
        if let Some(tx) = guard.tx.clone() {
            if tx.receiver_count() > 0 && tx.send(event).is_ok() {
                return;
            }
        }
        guard.pending.push(Queued {
            host: host.to_string(),
            reason,
            audited,
        });
    }

    pub(crate) fn attach(&self, tx: broadcast::Sender<KfpNodeEvent>, audit: Arc<SigningAuditLog>) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        for queued in &mut guard.pending {
            if !queued.audited {
                queued.audited = audit.log_relay_pin_rejection(&queued.host, queued.reason);
            }
        }
        guard.audit = Some(audit);
        guard.tx = Some(tx);
    }

    /// Rejections still held, for a connect attempt that is about to return
    /// before [`Self::attach`]. A node that never starts has no audit log, so
    /// the caller's error is the only place the refusal can be read.
    pub(crate) fn annotate(&self, err: FrostNetError) -> FrostNetError {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if guard.pending.is_empty() {
            return err;
        }
        let detail = guard
            .pending
            .iter()
            .map(|queued| format!("{} refused: {}", queued.host, queued.reason.explanation()))
            .collect::<Vec<_>>()
            .join("; ");
        let msg = match &err {
            FrostNetError::Transport(msg) => format!("{msg} ({detail})"),
            other => format!("{other} ({detail})"),
        };
        FrostNetError::Transport(msg)
    }

    /// Deliver anything still held. A later call does not send those events again.
    pub(crate) fn flush(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(tx) = guard.tx.clone() else {
            return;
        };
        if tx.receiver_count() == 0 {
            return;
        }
        let queued = std::mem::take(&mut guard.pending);
        let mut held = Vec::new();
        for item in queued {
            let event = KfpNodeEvent::RelayPinRejected {
                relay_host: item.host.clone(),
                reason: item.reason,
            };
            if tx.send(event).is_err() {
                held.push(item);
            }
        }
        guard.pending = held;
    }
}

#[cfg(test)]
mod tests {
    use super::super::KfpNodeEvent;
    use super::*;
    use crate::audit::SigningAuditLog;
    use crate::pinning::PinRejection;
    use tokio::sync::broadcast;

    fn attached() -> (
        Arc<PinReports>,
        broadcast::Sender<KfpNodeEvent>,
        Arc<SigningAuditLog>,
    ) {
        let reports = Arc::new(PinReports::new());
        let (tx, _rx) = broadcast::channel(8);
        let audit = Arc::new(SigningAuditLog::new([3u8; 32]));
        reports.attach(tx.clone(), Arc::clone(&audit));
        (reports, tx, audit)
    }

    #[test]
    fn a_rejection_before_anyone_is_listening_is_audited_and_delivered_once() {
        let reports = Arc::new(PinReports::new());
        reports.report("relay.example.com", PinRejection::Mismatch);
        reports.report("not a host", PinRejection::Mismatch);

        let (tx, _early) = broadcast::channel(8);
        let audit = Arc::new(SigningAuditLog::new([3u8; 32]));
        reports.attach(tx.clone(), Arc::clone(&audit));
        assert_eq!(audit.relay_pin_rejections().len(), 1);
        assert!(audit.verify_all());

        let mut rx = tx.subscribe();
        reports.flush();
        reports.flush();
        match rx.try_recv().unwrap() {
            KfpNodeEvent::RelayPinRejected { relay_host, reason } => {
                assert_eq!(relay_host, "relay.example.com");
                assert_eq!(reason, PinRejection::Mismatch);
            }
            other => panic!("expected a pin rejection, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "a second flush must not repeat it");
    }

    #[test]
    fn a_rejection_after_subscribe_is_delivered_without_waiting() {
        let (reports, tx, audit) = attached();
        let mut rx = tx.subscribe();
        reports.report("relay.example.com", PinRejection::Missing);
        match rx.try_recv().unwrap() {
            KfpNodeEvent::RelayPinRejected { reason, .. } => {
                assert_eq!(reason, PinRejection::Missing);
            }
            other => panic!("expected a pin rejection, got {other:?}"),
        }
        assert_eq!(audit.relay_pin_rejections().len(), 1);
        reports.flush();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_failed_connect_names_the_rejected_relay() {
        let reports = PinReports::new();
        let timeout = FrostNetError::Transport("Timed out waiting for relay connection".into());
        assert_eq!(
            reports.annotate(timeout).to_string(),
            "Transport error: Timed out waiting for relay connection"
        );

        reports.report("relay.example.com", PinRejection::Mismatch);
        reports.report("not a host", PinRejection::Mismatch);
        let err = reports.annotate(FrostNetError::Transport(
            "Timed out waiting for relay connection".into(),
        ));
        let text = err.to_string();
        assert!(text.contains("Timed out waiting for relay connection"));
        assert!(text
            .contains("relay.example.com refused: its certificate does not match the pinned key"));
        assert!(!text.contains("not a host"));
    }
}

// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

use std::sync::OnceLock;

use iced::Task;

use crate::approver_service::TestApprover;
use crate::message::Message;
use crate::screen::approver::{self, push_log, Event};
use crate::screen::Screen;

use super::App;

/// Made on first use, on a blocking thread, since it holds keep-mobile's
/// runtime.
fn approver(slot: &OnceLock<TestApprover>) -> Result<&TestApprover, String> {
    if slot.get().is_none() {
        let _ = slot.set(TestApprover::new()?);
    }
    slot.get()
        .ok_or_else(|| "the test approver could not start".to_string())
}

fn run(a: &TestApprover, event: Event) -> Result<String, String> {
    match event {
        Event::Pair(uri) => a
            .pair(&uri)
            .map(|fp| format!("Pairing sent. Compare fingerprint {fp} with the gateway's.")),
        Event::Approve(id) => a.approve(&id).map(|()| format!("Approved {id}")),
        Event::Deny(id) => a.deny(&id).map(|()| format!("Denied {id}")),
        Event::FreezeAll => a.freeze_all().map(|()| "Freeze of every agent sent".into()),
        Event::UnfreezeAll => a
            .unfreeze_all()
            .map(|()| "Unfreeze of every agent sent".into()),
        Event::Forget => a
            .forget()
            .map(|()| "Pairing forgotten on this approver".into()),
    }
}

impl App {
    pub(crate) fn handle_navigate_approver(&mut self) -> Task<Message> {
        if matches!(self.screen, Screen::Approver(_)) {
            return Task::none();
        }
        self.distribute_state = None;
        self.distribute_export_id = None;
        self.stop_scanner();
        self.copy_feedback_until = None;
        let mut state = approver::State::new(None, Vec::new(), self.approver_log.clone());
        if let Some(outcome) = &self.approver_outcome {
            state.action_done(outcome.clone());
        }
        state.busy = self.approver_busy;
        self.screen = Screen::Approver(state);
        self.refresh_approver();
        Task::none()
    }

    pub(crate) fn refresh_approver(&mut self) {
        let Some(a) = self.approver.get() else {
            return;
        };
        let snapshot = a.snapshot();
        push_log(&mut self.approver_log, snapshot.log);
        if let Screen::Approver(s) = &mut self.screen {
            s.status = Some(snapshot.status);
            s.waiting = snapshot.waiting;
            s.log = self.approver_log.clone();
        }
    }

    pub(crate) fn handle_approver_message(&mut self, msg: approver::Message) -> Task<Message> {
        let Screen::Approver(s) = &mut self.screen else {
            return Task::none();
        };
        let Some(event) = s.update(msg) else {
            return Task::none();
        };
        self.approver_busy = true;
        self.approver_outcome = None;
        let slot = self.approver.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || run(approver(&slot)?, event))
                    .await
                    .map_err(|_| "Background task failed".to_string())?
            },
            Message::ApproverResult,
        )
    }

    pub(crate) fn handle_approver_result(
        &mut self,
        result: Result<String, String>,
    ) -> Task<Message> {
        self.approver_busy = false;
        self.approver_outcome = Some(result.clone());
        if let Screen::Approver(s) = &mut self.screen {
            s.action_done(result);
        }
        self.refresh_approver();
        Task::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(app: &App) -> &approver::State {
        match &app.screen {
            Screen::Approver(s) => s,
            _ => panic!("not on the approver screen"),
        }
    }

    fn leave(app: &mut App) {
        app.screen = Screen::Unlock(crate::screen::unlock::State::new(false));
    }

    #[test]
    fn an_action_in_flight_survives_navigating_away() {
        let mut app = App::test_new(super::super::Settings::default(), false);
        let _ = app.handle_navigate_approver();
        let _ = app.handle_approver_message(approver::Message::FreezeAll);
        assert!(screen(&app).busy);

        leave(&mut app);
        let _ = app.handle_navigate_approver();
        assert!(screen(&app).busy, "the buttons came back while busy");

        leave(&mut app);
        let _ = app.handle_approver_result(Err("no relay".into()));
        let _ = app.handle_navigate_approver();
        assert!(!screen(&app).busy);
        assert_eq!(screen(&app).error.as_deref(), Some("no relay"));
    }
}

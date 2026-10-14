// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The task that carries `http_request`s to inject workers, outside the
//! state lock: for each request it connects to the worker socket (whose
//! directory and peer must be the expected owner's), writes the request,
//! reads the answer, checks it again, and hands the outcome back under the
//! lock. A withdrawn request drops its connection, which stops its worker.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use super::server::{connect_verified, with_state, LineReader, Shared};
use super::state::{checked_response, InjectJob, InjectOutcome, InjectSettings};
use crate::inject::wire::{Cause, WorkerAnswer, MAX_ANSWER_LINE};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a worker may take to answer: past its own limit, so a worker's
/// timeout comes back as its answer rather than a dropped connection.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(40);

/// Serve `jobs` until the gateway stops; requests still running then are
/// dropped with the task, which closes their workers' connections.
pub(crate) async fn inject_task(
    mut jobs: mpsc::Receiver<InjectJob>,
    settings: InjectSettings,
    state: Shared,
    stop: watch::Sender<bool>,
) {
    let mut running = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            job = jobs.recv() => match job {
                Some(job) => {
                    running.spawn(run(job, settings.clone(), state.clone(), stop.clone()));
                }
                None => break,
            },
            Some(_) = running.join_next(), if !running.is_empty() => {}
        }
    }
    running.shutdown().await;
}

async fn run(job: InjectJob, settings: InjectSettings, state: Shared, stop: watch::Sender<bool>) {
    let InjectJob {
        id,
        line,
        secret,
        mut cancel,
    } = job;
    let outcome = tokio::select! {
        biased;
        _ = &mut cancel => return,
        outcome = exchange(settings.socket, settings.owner, &line, &secret) => outcome,
    };
    with_state(&state, &stop, move |s| s.finish_inject(id, outcome)).await;
}

/// One request to one worker and its answer, checked again.
async fn exchange(
    socket: std::path::PathBuf,
    owner: u32,
    line: &[u8],
    secret: &Zeroizing<Vec<u8>>,
) -> InjectOutcome {
    let connected = tokio::task::spawn_blocking(move || {
        connect_verified(&socket, owner, CONNECT_TIMEOUT)
            .ok()
            .and_then(|s| s.set_nonblocking(true).ok().map(|()| s))
    })
    .await
    .ok()
    .flatten();
    let Some(stream) = connected.and_then(|s| tokio::net::UnixStream::from_std(s).ok()) else {
        tracing::warn!("no inject worker could be reached");
        return InjectOutcome::Failed(Cause::Unavailable);
    };
    let (read, mut write) = stream.into_split();
    let wrote = tokio::time::timeout(WRITE_TIMEOUT, write.write_all(line)).await;
    if !matches!(wrote, Ok(Ok(()))) {
        return InjectOutcome::Failed(Cause::Unavailable);
    }
    // The write side stays open: closing it is how a withdrawn request
    // stops its worker.
    let mut reader = LineReader::new(read, MAX_ANSWER_LINE);
    let answer: Zeroizing<Vec<u8>> =
        match tokio::time::timeout(ANSWER_TIMEOUT, reader.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(_) => return InjectOutcome::Failed(Cause::Unavailable),
            Err(_) => return InjectOutcome::Failed(Cause::Timeout),
        };
    drop(write);
    match serde_json::from_slice::<WorkerAnswer>(&answer) {
        Ok(WorkerAnswer::Failed(failure)) => InjectOutcome::Failed(failure.error),
        Ok(WorkerAnswer::Response(response)) => {
            let secret = secret.clone();
            tokio::task::spawn_blocking(move || checked_response(response, &secret))
                .await
                .unwrap_or(InjectOutcome::Failed(Cause::Http))
        }
        Err(_) => InjectOutcome::Failed(Cause::Http),
    }
}

// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// Serves relay NIP-46 requests from different apps at once, while each app's
// own requests are handled one at a time in the order they arrived.
//
// Handled one at a time overall, a request waiting on an approval prompt held
// up every later request from every app for up to the prompt's timeout. The
// handler is safe to call concurrently (its rate limiter and permission
// decisions each run under one lock, and only one approval prompt opens at a
// time), so only the per-app order needs keeping: a client that sends a
// connect and then a sign still has them handled in that order.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use nostr_sdk::prelude::{Event, PublicKey};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tracing::{error, warn};

// Requests handled at the same time, across all apps.
pub(crate) const MAX_CONCURRENT_REQUESTS: usize = 16;
// Apps with requests queued or in flight. A request from a further app is
// dropped, so a flood of fresh keys cannot grow this without bound. An app
// leaves as soon as its last request is handled, so requests that fail fast
// hold a slot only for as long as they take.
pub(crate) const MAX_QUEUED_APPS: usize = 64;
// Requests one app may have waiting behind the one being handled. Past this
// its requests are dropped and the client times out and retries.
pub(crate) const APP_QUEUE_DEPTH: usize = 8;
pub(crate) type Serve =
    Arc<dyn Fn(Event) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

type Queues = Arc<Mutex<HashMap<PublicKey, mpsc::Sender<Event>>>>;

// Dropping it aborts every worker.
pub(crate) struct AppScheduler {
    queues: Queues,
    permits: Arc<Semaphore>,
    workers: JoinSet<()>,
    serve: Serve,
}

impl AppScheduler {
    pub(crate) fn new(serve: Serve) -> Self {
        Self {
            queues: Arc::default(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            workers: JoinSet::new(),
            serve,
        }
    }

    // Queues `event` behind its app's earlier requests, or drops it when its
    // app's queue or the set of queued apps is full.
    pub(crate) fn dispatch(&mut self, event: Event) {
        let app = event.pubkey;
        let app_id = &app.to_hex()[..8];
        let mut queues = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        let mut event = event;
        if let Some(tx) = queues.get(&app) {
            // A worker leaves only with its queue empty and under this lock, and
            // a panic in `serve` does not end it, so a closed queue is not
            // expected. Should one appear, the app gets a new worker rather
            // than having every request dropped.
            match tx.try_send(event) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        app_id,
                        "dropping a NIP-46 request: this app has too many waiting"
                    );
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    queues.remove(&app);
                    event = returned;
                }
            }
        }
        if queues.len() >= MAX_QUEUED_APPS {
            warn!(
                app_id,
                "dropping a NIP-46 request: too many apps have requests waiting"
            );
            return;
        }
        let (tx, rx) = mpsc::channel(APP_QUEUE_DEPTH);
        let _ = tx.try_send(event);
        queues.insert(app, tx);
        drop(queues);

        while self.workers.try_join_next().is_some() {}
        self.workers.spawn(worker(
            app,
            rx,
            Arc::clone(&self.queues),
            Arc::clone(&self.permits),
            Arc::clone(&self.serve),
        ));
    }
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn worker(
    app: PublicKey,
    mut rx: mpsc::Receiver<Event>,
    queues: Queues,
    permits: Arc<Semaphore>,
    serve: Serve,
) {
    // Only entered with a request queued, so `recv` never waits.
    while let Some(event) = rx.recv().await {
        {
            let Ok(_permit) = permits.acquire().await else {
                return;
            };
            // Run on its own task so a panic ends that request and not this
            // worker, whose queued requests would otherwise be lost. Aborted
            // with the worker, so dropping the scheduler still cancels it.
            let request = tokio::spawn(serve(event));
            let _cancel = AbortOnDrop(request.abort_handle());
            if let Err(e) = request.await {
                if e.is_panic() {
                    error!("a NIP-46 request handler panicked");
                }
            }
        }
        // Checked under the lock `dispatch` sends under, so nothing can be
        // queued between finding the queue empty and leaving.
        let mut queues = queues.lock().unwrap_or_else(|e| e.into_inner());
        if rx.is_empty() {
            queues.remove(&app);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, Keys, Kind};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::time::Duration;

    fn request(keys: &Keys, n: u32) -> Event {
        EventBuilder::new(Kind::NostrConnect, n.to_string())
            .sign_with_keys(keys)
            .unwrap()
    }

    async fn until(what: impl Fn() -> bool) {
        for _ in 0..500 {
            if what() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached");
    }

    // One app's request held open does not stop another app's being served.
    #[tokio::test]
    async fn a_held_request_does_not_block_another_app() {
        let held = Arc::new(tokio::sync::Notify::new());
        let served = Arc::new(Mutex::new(Vec::<String>::new()));
        let slow = Keys::generate();
        let slow_pk = slow.public_key();
        let serve: Serve = {
            let held = Arc::clone(&held);
            let served = Arc::clone(&served);
            Arc::new(move |event: Event| {
                let held = Arc::clone(&held);
                let served = Arc::clone(&served);
                Box::pin(async move {
                    if event.pubkey == slow_pk {
                        held.notified().await;
                    }
                    served.lock().unwrap().push(event.content.clone());
                })
            })
        };
        let mut scheduler = AppScheduler::new(serve);
        scheduler.dispatch(request(&slow, 1));
        scheduler.dispatch(request(&Keys::generate(), 2));
        until(|| served.lock().unwrap().as_slice() == ["2"]).await;
        held.notify_one();
        until(|| served.lock().unwrap().len() == 2).await;
    }

    // An app's requests are handled one at a time, in the order they came.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_apps_requests_are_handled_in_order_one_at_a_time() {
        let served = Arc::new(Mutex::new(Vec::<u32>::new()));
        let open = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let serve: Serve = {
            let served = Arc::clone(&served);
            let open = Arc::clone(&open);
            let most = Arc::clone(&most);
            Arc::new(move |event: Event| {
                let served = Arc::clone(&served);
                let open = Arc::clone(&open);
                let most = Arc::clone(&most);
                Box::pin(async move {
                    most.fetch_max(open.fetch_add(1, SeqCst) + 1, SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    served.lock().unwrap().push(event.content.parse().unwrap());
                    open.fetch_sub(1, SeqCst);
                })
            })
        };
        let mut scheduler = AppScheduler::new(serve);
        let app = Keys::generate();
        for n in 0..APP_QUEUE_DEPTH as u32 {
            scheduler.dispatch(request(&app, n));
        }
        until(|| served.lock().unwrap().len() == APP_QUEUE_DEPTH).await;
        let expected: Vec<u32> = (0..APP_QUEUE_DEPTH as u32).collect();
        assert_eq!(*served.lock().unwrap(), expected);
        assert_eq!(most.load(SeqCst), 1);
    }

    // Past an app's queue depth, and past the number of apps, requests are
    // dropped rather than queued without bound.
    #[tokio::test]
    async fn queues_are_bounded() {
        let held = Arc::new(tokio::sync::Semaphore::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let serve: Serve = {
            let held = Arc::clone(&held);
            let started = Arc::clone(&started);
            Arc::new(move |_event: Event| {
                let held = Arc::clone(&held);
                let started = Arc::clone(&started);
                Box::pin(async move {
                    started.fetch_add(1, SeqCst);
                    let _ = held.acquire().await.unwrap();
                })
            })
        };
        let mut scheduler = AppScheduler::new(serve);

        let app = Keys::generate();
        scheduler.dispatch(request(&app, 0));
        until(|| started.load(SeqCst) == 1).await;
        for n in 1..=APP_QUEUE_DEPTH as u32 + 3 {
            scheduler.dispatch(request(&app, n));
        }
        {
            let queues = scheduler.queues.lock().unwrap();
            let tx = &queues[&app.public_key()];
            assert_eq!(tx.max_capacity() - tx.capacity(), APP_QUEUE_DEPTH);
        }

        for n in 1..MAX_QUEUED_APPS as u32 + 5 {
            scheduler.dispatch(request(&Keys::generate(), n));
        }
        assert_eq!(scheduler.queues.lock().unwrap().len(), MAX_QUEUED_APPS);
        until(|| started.load(SeqCst) == MAX_CONCURRENT_REQUESTS).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(started.load(SeqCst), MAX_CONCURRENT_REQUESTS);

        held.add_permits(10_000);
        until(|| started.load(SeqCst) == APP_QUEUE_DEPTH + MAX_QUEUED_APPS).await;
    }

    // A request whose handler panics ends alone: the requests its app queued
    // behind it are still served, in order.
    #[tokio::test]
    async fn a_panicking_request_does_not_lose_the_apps_queued_requests() {
        let held = Arc::new(tokio::sync::Notify::new());
        let served = Arc::new(Mutex::new(Vec::<String>::new()));
        let serve: Serve = {
            let held = Arc::clone(&held);
            let served = Arc::clone(&served);
            Arc::new(move |event: Event| {
                let held = Arc::clone(&held);
                let served = Arc::clone(&served);
                Box::pin(async move {
                    if event.content == "0" {
                        held.notified().await;
                        panic!("handler failed");
                    }
                    served.lock().unwrap().push(event.content.clone());
                })
            })
        };
        let mut scheduler = AppScheduler::new(serve);
        let app = Keys::generate();
        for n in 0..3 {
            scheduler.dispatch(request(&app, n));
        }
        held.notify_one();
        until(|| served.lock().unwrap().len() == 2).await;
        assert_eq!(*served.lock().unwrap(), ["1", "2"]);
        until(|| scheduler.queues.lock().unwrap().is_empty()).await;
    }

    // Dropping the scheduler cancels a request still being handled.
    #[tokio::test]
    async fn dropping_the_scheduler_cancels_requests_in_flight() {
        struct Dropped(Arc<AtomicUsize>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.fetch_add(1, SeqCst);
            }
        }
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let serve: Serve = {
            let started = Arc::clone(&started);
            let dropped = Arc::clone(&dropped);
            Arc::new(move |_event: Event| {
                let started = Arc::clone(&started);
                let guard = Dropped(Arc::clone(&dropped));
                Box::pin(async move {
                    let _guard = guard;
                    started.fetch_add(1, SeqCst);
                    std::future::pending::<()>().await;
                })
            })
        };
        let mut scheduler = AppScheduler::new(serve);
        scheduler.dispatch(request(&Keys::generate(), 0));
        until(|| started.load(SeqCst) == 1).await;
        drop(scheduler);
        until(|| dropped.load(SeqCst) == 1).await;
    }

    // An app's slot is freed once its requests are handled, so apps whose
    // requests fail fast cannot hold every slot and lock out a new app.
    #[tokio::test]
    async fn a_served_app_frees_its_slot() {
        let served = Arc::new(AtomicUsize::new(0));
        let serve: Serve = {
            let served = Arc::clone(&served);
            Arc::new(move |_event: Event| {
                let served = Arc::clone(&served);
                Box::pin(async move {
                    served.fetch_add(1, SeqCst);
                })
            })
        };
        let mut scheduler = AppScheduler::new(serve);
        for n in 0..MAX_QUEUED_APPS as u32 {
            scheduler.dispatch(request(&Keys::generate(), n));
        }
        until(|| served.load(SeqCst) == MAX_QUEUED_APPS).await;
        until(|| scheduler.queues.lock().unwrap().is_empty()).await;
        scheduler.dispatch(request(&Keys::generate(), 0));
        until(|| served.load(SeqCst) == MAX_QUEUED_APPS + 1).await;
    }
}

//! Shared test-support helpers for building synthetic TPM quote evidence.
//!
//! Gated behind `cfg(test)` for this crate's own unit tests and the `testing`
//! feature for the integration-test binary, so the `TPMS_ATTEST` wire format
//! lives in exactly one place. A divergence between the verifier's unit tests
//! and the end-to-end attestation tests would otherwise let a quote builder
//! drift silently, masking a real attestation regression.

use p256::ecdsa::SigningKey;

/// Marshalled `TPML_PCR_SELECTION` for the SHA-256 bank over a single PCR.
pub fn one_pcr_selection() -> Vec<u8> {
    hex::decode("00000001000b03800000").unwrap()
}

/// Build a self-consistent, signed `TPMS_ATTEST` quote over one PCR bound to
/// `nonce`, signed with `sk`. Mirrors the producer's exact wire format.
pub fn build_signed_quote(
    nonce: &[u8],
    pcr_select: &[u8],
    pcr_value: &[u8; 32],
    sk: &SigningKey,
) -> (Vec<u8>, Vec<u8>) {
    use p256::ecdsa::{signature::Signer, Signature};
    use sha2::{Digest, Sha256};

    let mut attest = Vec::new();
    attest.extend_from_slice(&0xFF54_4347u32.to_be_bytes()); // TPM_GENERATED
    attest.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    attest.extend_from_slice(&0u16.to_be_bytes()); // TPM2B_NAME qualifiedSigner: empty
    attest.extend_from_slice(&(nonce.len() as u16).to_be_bytes()); // TPM2B_DATA extraData
    attest.extend_from_slice(nonce);
    attest.extend_from_slice(&[0u8; 17]); // TPMS_CLOCK_INFO
    attest.extend_from_slice(&[0u8; 8]); // firmwareVersion
    attest.extend_from_slice(pcr_select); // TPML_PCR_SELECTION (== pinned selection)
    let digest = Sha256::digest(pcr_value);
    attest.extend_from_slice(&(digest.len() as u16).to_be_bytes()); // TPM2B_DIGEST pcrDigest
    attest.extend_from_slice(&digest);

    let sig: Signature = sk.sign(&attest); // ECDSA-P256 over SHA-256(attest)
    (attest, sig.to_bytes().to_vec())
}

/// In-process [`CosignTransport`] bus for deterministic multi-node tests.
///
/// Peers share one [`MemoryBus`]; [`MemoryBus::transport`] hands each node its
/// own [`MemoryTransport`]. A `send_event` fans the event out to every *other*
/// peer whose subscribed filters match, mirroring nostr's rule that a client
/// never receives its own events. No sockets, no relay, no timing races.
#[cfg(feature = "testing")]
mod memory_transport {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use nostr_sdk::prelude::*;
    use tokio::sync::broadcast;

    use crate::error::Result;
    use crate::node::CosignTransport;

    struct MemoryPeer {
        sender: broadcast::Sender<RelayPoolNotification>,
        filters: Vec<Filter>,
    }

    /// Shared in-process event bus. Clone to hand copies around; all clones
    /// observe the same peers and retained event log.
    #[derive(Clone)]
    pub struct MemoryBus {
        peers: Arc<Mutex<Vec<Arc<Mutex<MemoryPeer>>>>>,
        log: Arc<Mutex<Vec<Event>>>,
    }

    impl Default for MemoryBus {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MemoryBus {
        pub fn new() -> Self {
            Self {
                peers: Arc::new(Mutex::new(Vec::new())),
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Register a fresh peer and return its transport handle.
        pub fn transport(&self) -> Arc<MemoryTransport> {
            let (sender, _) = broadcast::channel(1000);
            let me = Arc::new(Mutex::new(MemoryPeer {
                sender,
                filters: Vec::new(),
            }));
            self.peers.lock().unwrap().push(me.clone());
            Arc::new(MemoryTransport {
                bus: self.clone(),
                me,
            })
        }
    }

    /// One node's view onto a [`MemoryBus`].
    pub struct MemoryTransport {
        bus: MemoryBus,
        me: Arc<Mutex<MemoryPeer>>,
    }

    fn dummy_relay_url() -> RelayUrl {
        RelayUrl::parse("wss://memory.invalid").unwrap()
    }

    fn dummy_subscription_id() -> SubscriptionId {
        SubscriptionId::new("memory")
    }

    impl CosignTransport for MemoryTransport {
        fn send_event<'a>(
            &'a self,
            event: &'a Event,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.bus.log.lock().unwrap().push(event.clone());

                let peers = self.bus.peers.lock().unwrap().clone();
                for peer in peers {
                    if Arc::ptr_eq(&peer, &self.me) {
                        continue; // a client never receives its own events
                    }
                    let guard = peer.lock().unwrap();
                    let matches = guard
                        .filters
                        .iter()
                        .any(|f| f.match_event(event, MatchEventOptions::default()));
                    if matches {
                        let _ = guard.sender.send(RelayPoolNotification::Event {
                            relay_url: dummy_relay_url(),
                            subscription_id: dummy_subscription_id(),
                            event: Box::new(event.clone()),
                        });
                    }
                }
                Ok(())
            })
        }

        fn subscribe<'a>(
            &'a self,
            filter: Filter,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.me.lock().unwrap().filters.push(filter);
                Ok(())
            })
        }

        fn fetch_events<'a>(
            &'a self,
            filter: Filter,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Event>>> + Send + 'a>> {
            Box::pin(async move {
                let log = self.bus.log.lock().unwrap();
                Ok(log
                    .iter()
                    .filter(|e| filter.match_event(e, MatchEventOptions::default()))
                    .cloned()
                    .collect())
            })
        }

        fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
            self.me.lock().unwrap().sender.subscribe()
        }
    }
}

#[cfg(feature = "testing")]
pub use memory_transport::{MemoryBus, MemoryTransport};

#[cfg(all(test, feature = "testing"))]
mod memory_transport_tests {
    use super::MemoryBus;
    use crate::node::CosignTransport;
    use nostr_sdk::prelude::*;
    use std::sync::Arc;
    use tokio::sync::broadcast::error::TryRecvError;

    #[tokio::test]
    async fn delivers_to_subscribers_but_not_sender() {
        let bus = MemoryBus::new();
        let a: Arc<dyn CosignTransport> = bus.transport();
        let b: Arc<dyn CosignTransport> = bus.transport();

        b.subscribe(Filter::new()).await.unwrap();

        let mut a_rx = a.notifications();
        let mut b_rx = b.notifications();

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "hello")
            .sign_with_keys(&keys)
            .unwrap();

        a.send_event(&event).await.unwrap();

        match b_rx.try_recv() {
            Ok(RelayPoolNotification::Event { event: got, .. }) => {
                assert_eq!(got.id, event.id);
            }
            other => panic!("expected B to receive the event, got {other:?}"),
        }

        assert!(matches!(a_rx.try_recv(), Err(TryRecvError::Empty)));
    }
}

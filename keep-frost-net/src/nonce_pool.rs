// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Pre-exchanged FROST round-1 nonce pool.
//!
//! To avoid the interactive commitment round on every signing request, each
//! participant can pre-generate FROST round-1 nonces and broadcast the matching
//! commitments to peers ahead of time. A pooled commitment is identified by a
//! random `nonce_id`.
//!
//! Secret [`SigningNonces`] live in memory only and are never persisted: pools
//! are rebuilt by idle replenishment after a restart. Commitments are public
//! and may be shared freely.
//!
//! Single-use is strictly enforced for secret material: the local secret
//! nonces are *removed* on consume. Peer commitments are public and may be
//! authenticated against an echoed copy without consuming (see
//! [`NoncePool::matches_peer`]); they are removed on reservation/consume so a
//! given pooled commitment is bound to one session.

use std::collections::HashMap;
use std::sync::Arc;

use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
use parking_lot::Mutex;

use crate::error::{FrostNetError, Result};

/// Identifier for a single pre-exchanged nonce/commitment pair.
pub type NonceId = [u8; 32];

/// Serialize a FROST round-1 commitment into wire bytes, mapping the library
/// error into a [`FrostNetError`].
pub fn serialize_commitment(commitment: &SigningCommitments) -> Result<Vec<u8>> {
    commitment
        .serialize()
        .map(|b| b.to_vec())
        .map_err(|e| FrostNetError::Crypto(format!("Serialize commitment: {e}")))
}

/// Default number of nonces a node keeps pre-generated and available.
pub const DEFAULT_POOL_TARGET: usize = 16;

/// Hard cap on stored entries (own nonces or total peer commitments) to bound
/// memory against a misbehaving or chatty peer.
pub const MAX_POOL_ENTRIES: usize = 256;

/// Per-peer cap on stored commitments. Bounds how much of the shared peer pool
/// a single peer can occupy so one chatty or hostile peer cannot evict every
/// other peer's pre-exchanged commitments (soft DoS on instant signing).
pub const MAX_POOL_ENTRIES_PER_PEER: usize = 32;

#[derive(Default)]
struct PoolInner {
    /// Our own secret nonces, keyed by the `nonce_id` we advertised.
    own: HashMap<NonceId, SigningNonces>,
    /// Order in which our own nonces were generated, for FIFO eviction.
    own_order: Vec<NonceId>,
    /// Commitments received from peers, keyed by `(share_index, nonce_id)`.
    peer: HashMap<(u16, NonceId), SigningCommitments>,
    /// Order in which peer commitments were received, for FIFO eviction.
    peer_order: Vec<(u16, NonceId)>,
}

/// In-memory pool of pre-exchanged FROST round-1 material.
#[derive(Clone)]
pub struct NoncePool {
    inner: Arc<Mutex<PoolInner>>,
    target: usize,
}

impl NoncePool {
    pub fn new() -> Self {
        Self::with_target(DEFAULT_POOL_TARGET)
    }

    pub fn with_target(target: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolInner::default())),
            target: target.min(MAX_POOL_ENTRIES),
        }
    }

    /// Target number of available own nonces.
    pub fn target(&self) -> usize {
        self.target
    }

    /// Store a freshly generated own nonce under `nonce_id`. Evicts the oldest
    /// own nonce if the pool exceeds [`MAX_POOL_ENTRIES`].
    pub fn store_own(&self, nonce_id: NonceId, nonces: SigningNonces) {
        let mut inner = self.inner.lock();
        if inner.own.insert(nonce_id, nonces).is_none() {
            inner.own_order.push(nonce_id);
        }
        while inner.own_order.len() > MAX_POOL_ENTRIES {
            let oldest = inner.own_order.remove(0);
            inner.own.remove(&oldest);
        }
    }

    /// Number of own nonces currently available (not yet consumed).
    pub fn own_available(&self) -> usize {
        self.inner.lock().own.len()
    }

    /// How many additional own nonces should be generated to reach the target.
    pub fn own_deficit(&self) -> usize {
        self.target.saturating_sub(self.own_available())
    }

    /// Whether an own nonce with `nonce_id` is currently available, without
    /// consuming it. Used to validate a sign request before burning the
    /// single-use secret nonce.
    pub fn contains_own(&self, nonce_id: &NonceId) -> bool {
        self.inner.lock().own.contains_key(nonce_id)
    }

    /// Consume our own pre-generated nonce, removing it from the pool.
    ///
    /// Returns `None` if no nonce with `nonce_id` is available (already
    /// consumed or never stored), in which case the caller must fall back to
    /// the interactive round.
    pub fn consume_own(&self, nonce_id: &NonceId) -> Option<SigningNonces> {
        let mut inner = self.inner.lock();
        let nonces = inner.own.remove(nonce_id)?;
        inner.own_order.retain(|id| id != nonce_id);
        Some(nonces)
    }

    /// Record a peer's pre-exchanged commitment. Enforces a per-peer cap
    /// ([`MAX_POOL_ENTRIES_PER_PEER`]) so one peer cannot crowd out others, then
    /// the global cap ([`MAX_POOL_ENTRIES`]); oldest entries are evicted first.
    pub fn store_peer(&self, share_index: u16, nonce_id: NonceId, commitment: SigningCommitments) {
        let mut inner = self.inner.lock();
        let key = (share_index, nonce_id);
        if inner.peer.insert(key, commitment).is_none() {
            inner.peer_order.push(key);
        }
        while inner
            .peer_order
            .iter()
            .filter(|(idx, _)| *idx == share_index)
            .count()
            > MAX_POOL_ENTRIES_PER_PEER
        {
            if let Some(pos) = inner
                .peer_order
                .iter()
                .position(|(idx, _)| *idx == share_index)
            {
                let evict = inner.peer_order.remove(pos);
                inner.peer.remove(&evict);
            } else {
                break;
            }
        }
        while inner.peer_order.len() > MAX_POOL_ENTRIES {
            let evict = inner.peer_order.remove(0);
            inner.peer.remove(&evict);
        }
    }

    /// Number of pooled commitments available for a given peer.
    pub fn peer_available(&self, share_index: u16) -> usize {
        self.inner
            .lock()
            .peer
            .keys()
            .filter(|(idx, _)| *idx == share_index)
            .count()
    }

    /// Whether the pool already holds a commitment for `(share_index, nonce_id)`.
    pub fn contains_peer(&self, share_index: u16, nonce_id: &NonceId) -> bool {
        self.inner
            .lock()
            .peer
            .contains_key(&(share_index, *nonce_id))
    }

    /// Whether the pool holds a commitment for `(share_index, nonce_id)` whose
    /// serialized bytes equal `commitment_bytes`. Used to authenticate echoed
    /// commitments against what the peer actually advertised to us, without
    /// consuming the pooled entry.
    pub fn matches_peer(
        &self,
        share_index: u16,
        nonce_id: &NonceId,
        commitment_bytes: &[u8],
    ) -> bool {
        let inner = self.inner.lock();
        match inner.peer.get(&(share_index, *nonce_id)) {
            Some(c) => c
                .serialize()
                .map(|b| b.as_slice() == commitment_bytes)
                .unwrap_or(false),
            None => false,
        }
    }

    /// Consume a peer's pre-exchanged commitment, removing it from the pool.
    ///
    /// Returns `None` if no matching commitment is available.
    pub fn consume_peer(&self, share_index: u16, nonce_id: &NonceId) -> Option<SigningCommitments> {
        let mut inner = self.inner.lock();
        let key = (share_index, *nonce_id);
        let commitment = inner.peer.remove(&key)?;
        inner.peer_order.retain(|k| k != &key);
        Some(commitment)
    }

    /// Reserve one available commitment per requested peer for a signing
    /// request, returning the chosen `nonce_id`s. The commitments are *removed*
    /// from the pool so they cannot be reused.
    ///
    /// Returns `None` (consuming nothing) unless every requested peer has at
    /// least one pooled commitment, so the caller can cleanly fall back to the
    /// interactive round.
    pub fn reserve_for(&self, peers: &[u16]) -> Option<Vec<(u16, NonceId, SigningCommitments)>> {
        let mut inner = self.inner.lock();

        let mut chosen: Vec<(u16, NonceId)> = Vec::with_capacity(peers.len());
        for &idx in peers {
            let next = inner
                .peer_order
                .iter()
                .find(|(i, id)| *i == idx && !chosen.contains(&(*i, *id)))
                .copied();
            match next {
                Some(key) => chosen.push(key),
                None => return None,
            }
        }

        let mut reserved = Vec::with_capacity(chosen.len());
        for key in chosen {
            if let Some(commitment) = inner.peer.remove(&key) {
                inner.peer_order.retain(|k| k != &key);
                reserved.push((key.0, key.1, commitment));
            } else {
                return None;
            }
        }
        Some(reserved)
    }
}

impl Default for NoncePool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1_tr::keys::{generate_with_dealer, IdentifierList, KeyPackage};
    use frost_secp256k1_tr::rand_core::OsRng;

    fn make_pair() -> (SigningNonces, SigningCommitments) {
        let (shares, _pubkeys) =
            generate_with_dealer(2, 2, IdentifierList::Default, OsRng).unwrap();
        let secret = shares.into_values().next().unwrap();
        let kp = KeyPackage::try_from(secret).unwrap();
        frost_secp256k1_tr::round1::commit(kp.signing_share(), &mut OsRng)
    }

    #[test]
    fn own_store_and_single_use_consume() {
        let pool = NoncePool::new();
        let (nonces, _commitment) = make_pair();
        let id = [7u8; 32];

        pool.store_own(id, nonces);
        assert_eq!(pool.own_available(), 1);

        assert!(pool.consume_own(&id).is_some());
        assert_eq!(pool.own_available(), 0);
        // Strict single-use: second consume yields nothing.
        assert!(pool.consume_own(&id).is_none());
    }

    #[test]
    fn peer_store_and_single_use_consume() {
        let pool = NoncePool::new();
        let (_n, commitment) = make_pair();
        let id = [9u8; 32];

        pool.store_peer(2, id, commitment);
        assert_eq!(pool.peer_available(2), 1);

        assert!(pool.consume_peer(2, &id).is_some());
        assert_eq!(pool.peer_available(2), 0);
        assert!(pool.consume_peer(2, &id).is_none());
    }

    #[test]
    fn reserve_requires_all_peers() {
        let pool = NoncePool::new();
        let (_n, c1) = make_pair();
        pool.store_peer(2, [1u8; 32], c1);

        // Peer 3 has nothing: reservation fails and consumes nothing.
        assert!(pool.reserve_for(&[2, 3]).is_none());
        assert_eq!(pool.peer_available(2), 1);

        let (_n2, c2) = make_pair();
        pool.store_peer(3, [2u8; 32], c2);

        let reserved = pool.reserve_for(&[2, 3]).expect("both peers available");
        assert_eq!(reserved.len(), 2);
        // Reserved commitments are removed (single-use).
        assert_eq!(pool.peer_available(2), 0);
        assert_eq!(pool.peer_available(3), 0);
    }

    #[test]
    fn matches_peer_authenticates_echoed_commitment() {
        let pool = NoncePool::new();
        let (_n, commitment) = make_pair();
        let id = [5u8; 32];
        let bytes = commitment.serialize().unwrap().to_vec();
        pool.store_peer(2, id, commitment);

        assert!(pool.matches_peer(2, &id, &bytes));
        // Wrong bytes, wrong id, and wrong index all fail.
        assert!(!pool.matches_peer(2, &id, &[0u8; 33]));
        assert!(!pool.matches_peer(2, &[6u8; 32], &bytes));
        assert!(!pool.matches_peer(3, &id, &bytes));
    }

    #[test]
    fn peer_eviction_bounds_total_memory() {
        // Spread entries across enough peers that the global cap binds before
        // the per-peer cap (16 peers * 32 per-peer = 512 > 256 global).
        let pool = NoncePool::new();
        for i in 0..(MAX_POOL_ENTRIES + 10) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let idx = (i % 16) as u16 + 1;
            let (_n, c) = make_pair();
            pool.store_peer(idx, id, c);
        }
        let total: usize = (1..=16).map(|idx| pool.peer_available(idx)).sum();
        assert_eq!(total, MAX_POOL_ENTRIES);
    }

    #[test]
    fn per_peer_cap_prevents_one_peer_crowding_out() {
        let pool = NoncePool::new();
        // One peer floods well past the per-peer cap.
        for i in 0..(MAX_POOL_ENTRIES_PER_PEER + 50) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let (_n, c) = make_pair();
            pool.store_peer(2, id, c);
        }
        assert_eq!(pool.peer_available(2), MAX_POOL_ENTRIES_PER_PEER);

        // A second peer's commitments are unaffected by the first peer's flood.
        let (_n, c) = make_pair();
        pool.store_peer(3, [255u8; 32], c);
        assert_eq!(pool.peer_available(3), 1);
        assert_eq!(pool.peer_available(2), MAX_POOL_ENTRIES_PER_PEER);
    }

    #[test]
    fn reserve_consumes_oldest_first() {
        let pool = NoncePool::new();
        let (_n1, c1) = make_pair();
        let (_n2, c2) = make_pair();
        pool.store_peer(2, [1u8; 32], c1);
        pool.store_peer(2, [2u8; 32], c2);

        let reserved = pool.reserve_for(&[2]).expect("peer available");
        assert_eq!(reserved[0].1, [1u8; 32]);
    }

    #[test]
    fn deficit_tracks_target() {
        let pool = NoncePool::with_target(4);
        assert_eq!(pool.own_deficit(), 4);
        let (nonces, _c) = make_pair();
        pool.store_own([1u8; 32], nonces);
        assert_eq!(pool.own_deficit(), 3);
    }

    #[test]
    fn own_eviction_bounds_memory() {
        let pool = NoncePool::with_target(MAX_POOL_ENTRIES);
        for i in 0..(MAX_POOL_ENTRIES + 10) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let (nonces, _c) = make_pair();
            pool.store_own(id, nonces);
        }
        assert_eq!(pool.own_available(), MAX_POOL_ENTRIES);
    }
}

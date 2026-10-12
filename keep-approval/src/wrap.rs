// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Gift wraps carrying the protocol's messages.
//!
//! Every message is a NIP-59 gift wrap (kind 1059) to one recipient: an
//! unsigned rumor from the sender's real key, sealed (kind 13, signed by
//! that key) and wrapped by a fresh ephemeral key. Anyone can send a gift
//! wrap to a key, and opening one costs a NIP-44 decryption before the
//! sender is known, so every wrap also carries a tag `["kt", <hex>]` the
//! recipient checks with one HMAC first:
//!
//! ```text
//! tag     = HMAC-SHA256(tag_key, wrap_pubkey || SHA256(wrap_content)), first 16 bytes
//! tag_key = HKDF-SHA256(salt = "keep/approval/wrap-tag/v1",
//!                       ikm = x of ECDH(channel key, transport key))
//!           or, for `pair`, ikm = the pairing secret
//! ```
//!
//! A wrap with no tag matching an expected sender, or outside the time
//! window, is dropped unopened.

use std::collections::HashMap;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use nostr::nips::nip44;
use nostr::{
    Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, TagKind, Timestamp, UnsignedEvent,
};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{invalid, kind, malformed, sha256, Error, Result};

/// The salt of the tag key's HKDF.
pub const TAG_SALT: &[u8] = b"keep/approval/wrap-tag/v1";
/// The tag's name.
pub const TAG_NAME: &str = "kt";
/// The largest serialized rumor the protocol carries.
pub const MAX_RUMOR_BYTES: usize = 24 * 1024;
/// The largest wrap content opened. A rumor at the limit, sealed and wrapped
/// with NIP-44 padding and base64 twice, stays well under it.
pub const MAX_WRAP_CONTENT: usize = 64 * 1024;
/// How far into the past senders randomize `created_at`, as NIP-59 says.
pub const TWEAK_SECS: u64 = 2 * 86_400;
/// How far in the past a wrap's `created_at` may be: the tweak plus a day
/// for delivery.
pub const WINDOW_PAST_SECS: u64 = 3 * 86_400;
/// How far in the future a wrap's `created_at` may be.
pub const WINDOW_FUTURE_SECS: u64 = 600;

/// The key a wrap tag is computed with.
pub struct TagKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for TagKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TagKey(..)")
    }
}

impl TagKey {
    fn from_ikm(ikm: &[u8]) -> Self {
        let mut okm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(TAG_SALT), ikm)
            .expand(&[], okm.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        Self(okm)
    }

    /// The tag key between `ours` and `peer`: the gateway's channel key and
    /// a device's transport key, from either side.
    pub fn for_peer(ours: &Keys, peer: &[u8; 32]) -> Result<Self> {
        let peer = PublicKey::from_slice(peer).map_err(|_| malformed("peer key"))?;
        let shared = Zeroizing::new(
            nostr::util::generate_shared_key(ours.secret_key(), &peer)
                .map_err(|_| invalid("ECDH"))?,
        );
        Ok(Self::from_ikm(shared.as_ref()))
    }

    /// The tag key of a pairing session.
    pub fn for_pairing(secret: &[u8; 32]) -> Self {
        Self::from_ikm(secret)
    }

    fn mac(&self, wrap_pubkey: &[u8; 32], content_hash: &[u8; 32]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.as_ref())
            .expect("HMAC takes any key length");
        mac.update(wrap_pubkey);
        mac.update(content_hash);
        mac
    }

    /// The tag of a wrap with ephemeral key `wrap_pubkey` and `content`.
    pub fn tag(&self, wrap_pubkey: &[u8; 32], content: &str) -> [u8; 16] {
        let full = self
            .mac(wrap_pubkey, &sha256(content.as_bytes()))
            .finalize()
            .into_bytes();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full[..16]);
        tag
    }

    /// Whether `tag` is this key's tag of the wrap, in constant time.
    pub fn matches(&self, wrap_pubkey: &[u8; 32], content: &str, tag: &[u8]) -> bool {
        self.matches_hash(wrap_pubkey, &sha256(content.as_bytes()), tag)
    }

    fn matches_hash(&self, wrap_pubkey: &[u8; 32], content_hash: &[u8; 32], tag: &[u8]) -> bool {
        tag.len() == 16
            && self
                .mac(wrap_pubkey, content_hash)
                .verify_truncated_left(tag)
                .is_ok()
    }
}

/// Whether a wrap's `created_at` is inside the window, by the receiver's
/// clock `now`.
pub fn within_window(created_at: u64, now: u64) -> bool {
    created_at >= now.saturating_sub(WINDOW_PAST_SECS)
        && created_at <= now.saturating_add(WINDOW_FUTURE_SECS)
}

fn rumor(author: PublicKey, kind: u16, content: &str, created_at: u64) -> UnsignedEvent {
    let mut rumor = EventBuilder::new(Kind::from(kind), content)
        .custom_created_at(Timestamp::from_secs(created_at))
        .build(author);
    rumor.ensure_id();
    rumor
}

/// Refuse a message whose rumor would exceed [`MAX_RUMOR_BYTES`]. The size
/// does not depend on the author, so a sender can check before wrapping.
pub fn check_rumor_size(kind: u16, content: &str, created_at: u64) -> Result<()> {
    // Any valid key: the rumor's length is the same for every author.
    let author = Keys::new(nostr::SecretKey::from_slice(&[1; 32]).expect("valid secret key"));
    let len = rumor(author.public_key(), kind, content, created_at)
        .as_json()
        .len();
    if len > MAX_RUMOR_BYTES {
        return Err(Error::TooLarge(format!(
            "a message of {len} bytes exceeds {MAX_RUMOR_BYTES}"
        )));
    }
    Ok(())
}

fn tweaked(now: u64) -> Timestamp {
    let back = nostr::secp256k1::rand::random::<u64>() % (TWEAK_SECS + 1);
    Timestamp::from_secs(now.saturating_sub(back))
}

/// Wrap a message of `kind` with `content` from `sender` to `receiver`,
/// tagged with `tag_key`. `now` is the sender's clock.
pub fn wrap(
    sender: &Keys,
    receiver: &[u8; 32],
    tag_key: &TagKey,
    kind: u16,
    content: &str,
    now: u64,
) -> Result<Event> {
    if !kind::is_protocol_kind(kind) {
        return Err(malformed("not a protocol kind"));
    }
    let receiver = PublicKey::from_slice(receiver).map_err(|_| malformed("receiver key"))?;
    let rumor_json = rumor(sender.public_key(), kind, content, now).as_json();
    if rumor_json.len() > MAX_RUMOR_BYTES {
        return Err(Error::TooLarge(format!(
            "a message of {} bytes exceeds {MAX_RUMOR_BYTES}",
            rumor_json.len()
        )));
    }
    let sealed = nip44::encrypt(
        sender.secret_key(),
        &receiver,
        &rumor_json,
        nip44::Version::V2,
    )
    .map_err(|e| invalid(format!("seal: {e}")))?;
    let seal = EventBuilder::new(Kind::Seal, sealed)
        .custom_created_at(tweaked(now))
        .sign_with_keys(sender)
        .map_err(|e| invalid(format!("seal: {e}")))?;
    let ephemeral = Keys::generate();
    let wrapped = nip44::encrypt(
        ephemeral.secret_key(),
        &receiver,
        seal.as_json(),
        nip44::Version::V2,
    )
    .map_err(|e| invalid(format!("wrap: {e}")))?;
    let tag = tag_key.tag(&ephemeral.public_key().to_bytes(), &wrapped);
    EventBuilder::new(Kind::GiftWrap, wrapped)
        .tags([
            Tag::public_key(receiver),
            Tag::custom(TagKind::custom(TAG_NAME), [hex::encode(tag)]),
        ])
        .custom_created_at(tweaked(now))
        .sign_with_keys(&ephemeral)
        .map_err(|e| invalid(format!("wrap: {e}")))
}

/// A sender the recipient expects, with the tag key its wraps carry.
#[derive(Debug)]
pub struct Candidate<T> {
    /// The caller's name for the sender (a device, a pairing session).
    pub id: T,
    pub tag_key: TagKey,
    /// The key the seal must be signed by, when known (a registered device's
    /// transport key, the paired channel key); `None` for a pairing session,
    /// whose sender is the new device and whose only message is `pair`.
    pub sender: Option<[u8; 32]>,
}

/// A message opened from a wrap. Its `Debug` leaves out the content.
#[derive(Clone, PartialEq, Eq)]
pub struct Opened<T> {
    /// Which candidate's tag the wrap carried.
    pub from: T,
    /// The key that signed the seal and authored the rumor.
    pub sender: [u8; 32],
    pub kind: u16,
    pub content: String,
    pub wrap_id: [u8; 32],
    pub wrap_created_at: u64,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Opened<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("from", &self.from)
            .field("sender", &hex::encode(self.sender))
            .field("kind", &self.kind)
            .field("content_len", &self.content.len())
            .field("wrap_id", &hex::encode(self.wrap_id))
            .field("wrap_created_at", &self.wrap_created_at)
            .finish()
    }
}

/// The candidate whose tag `event` carries, checked with one HMAC per
/// candidate and nothing decrypted, after the kind, the time window and the
/// size. Anything else is [`Error::NotOurs`], to be dropped unopened.
pub fn match_tag<'a, T>(
    event: &Event,
    candidates: &'a [Candidate<T>],
    now: u64,
) -> Result<&'a Candidate<T>> {
    if event.kind != Kind::GiftWrap
        || !within_window(event.created_at.as_secs(), now)
        || event.content.len() > MAX_WRAP_CONTENT
    {
        return Err(Error::NotOurs);
    }
    let mut tags = event
        .tags
        .iter()
        .filter(|t| t.kind() == TagKind::custom(TAG_NAME));
    let (Some(tag), None) = (tags.next(), tags.next()) else {
        return Err(Error::NotOurs);
    };
    let tag = match tag.as_slice() {
        [_, value] => hex::decode(value).map_err(|_| Error::NotOurs)?,
        _ => return Err(Error::NotOurs),
    };
    let wrap_pubkey = event.pubkey.to_bytes();
    let content_hash = sha256(event.content.as_bytes());
    candidates
        .iter()
        .find(|c| c.tag_key.matches_hash(&wrap_pubkey, &content_hash, &tag))
        .ok_or(Error::NotOurs)
}

/// Open a wrap addressed to `recipient`: the tag must match a candidate,
/// the wrap's signature must check out and the wrap must not be in `seen`
/// (a replay is [`Error::NotOurs`], dropped before any decryption), then
/// the seal (kind 13, signed, untagged, by the expected sender) and the
/// rumor (one of the protocol's kinds, `pair` from a pairing session,
/// authored by the seal's signer, untagged, within the size limit) must all
/// check out.
pub fn open<T: Clone>(
    recipient: &Keys,
    event: &Event,
    candidates: &[Candidate<T>],
    seen: &mut SeenWraps,
    now: u64,
) -> Result<Opened<T>> {
    let candidate = match_tag(event, candidates, now)?;
    event.verify().map_err(|_| invalid("wrap signature"))?;
    if !seen.first_time(event.id.to_bytes(), event.created_at.as_secs(), now) {
        return Err(Error::NotOurs);
    }
    let seal_json = nip44::decrypt(recipient.secret_key(), &event.pubkey, &event.content)
        .map_err(|_| invalid("wrap"))?;
    let seal = Event::from_json(&seal_json).map_err(|_| malformed("seal"))?;
    if seal.kind != Kind::Seal || !seal.tags.is_empty() {
        return Err(invalid("not a seal"));
    }
    seal.verify().map_err(|_| invalid("seal signature"))?;
    let sender = seal.pubkey.to_bytes();
    if candidate.sender.is_some_and(|expected| expected != sender) {
        return Err(invalid("sealed by another key"));
    }
    let rumor_json = nip44::decrypt(recipient.secret_key(), &seal.pubkey, &seal.content)
        .map_err(|_| invalid("seal"))?;
    if rumor_json.len() > MAX_RUMOR_BYTES {
        return Err(Error::TooLarge("rumor".into()));
    }
    let rumor = UnsignedEvent::from_json(&rumor_json).map_err(|_| malformed("rumor"))?;
    if rumor.pubkey != seal.pubkey {
        return Err(invalid("the rumor's author is not the seal's signer"));
    }
    rumor.verify_id().map_err(|_| invalid("rumor id"))?;
    let kind = rumor.kind.as_u16();
    if !kind::is_protocol_kind(kind) || !rumor.tags.is_empty() {
        return Err(invalid("not a protocol message"));
    }
    if candidate.sender.is_none() && kind != kind::PAIRING {
        return Err(invalid("a pairing session carries only pair"));
    }
    Ok(Opened {
        from: candidate.id.clone(),
        sender,
        kind,
        content: rumor.content,
        wrap_id: event.id.to_bytes(),
        wrap_created_at: event.created_at.as_secs(),
    })
}

/// How often [`SeenWraps`] drops wraps that have left the window.
pub const PRUNE_EVERY_SECS: u64 = 60;

/// The wraps already opened, so a replayed wrap is dropped before any
/// decryption. It holds only wraps inside the time window: one outside it is
/// never first-seen, and an entry is dropped once its wrap leaves the window.
#[derive(Debug, Default, Clone)]
pub struct SeenWraps {
    seen: HashMap<[u8; 32], u64>,
    pruned_at: u64,
}

impl SeenWraps {
    /// Record a wrap, returning whether it is seen for the first time and
    /// inside the window.
    pub fn first_time(&mut self, wrap_id: [u8; 32], created_at: u64, now: u64) -> bool {
        if now.abs_diff(self.pruned_at) >= PRUNE_EVERY_SECS {
            self.seen.retain(|_, at| within_window(*at, now));
            self.pruned_at = now;
        }
        if !within_window(created_at, now) {
            return false;
        }
        self.seen.insert(wrap_id, created_at).is_none()
    }

    /// How many wraps are held.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether none are held.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_791_580_000;

    struct Pair {
        gateway: Keys,
        device: Keys,
    }

    fn pair() -> Pair {
        Pair {
            gateway: Keys::generate(),
            device: Keys::generate(),
        }
    }

    fn device_candidates(p: &Pair) -> Vec<Candidate<&'static str>> {
        vec![Candidate {
            id: "phone",
            tag_key: TagKey::for_peer(&p.gateway, &p.device.public_key().to_bytes()).unwrap(),
            sender: Some(p.device.public_key().to_bytes()),
        }]
    }

    fn from_device(p: &Pair, content: &str) -> Event {
        let key = TagKey::for_peer(&p.device, &p.gateway.public_key().to_bytes()).unwrap();
        wrap(
            &p.device,
            &p.gateway.public_key().to_bytes(),
            &key,
            kind::DECISION,
            content,
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn a_wrap_round_trips_and_both_sides_derive_the_same_tag_key() {
        let p = pair();
        let event = from_device(&p, "{\"x\":1}");
        let opened = open(
            &p.gateway,
            &event,
            &device_candidates(&p),
            &mut SeenWraps::default(),
            NOW,
        )
        .unwrap();
        assert_eq!(opened.from, "phone");
        assert_eq!(opened.sender, p.device.public_key().to_bytes());
        assert_eq!(opened.kind, kind::DECISION);
        assert_eq!(opened.content, "{\"x\":1}");
        assert!(within_window(event.created_at.as_secs(), NOW));
        assert!(event.created_at.as_secs() <= NOW);
    }

    /// A tag copied onto other content, or onto another wrap key, does not
    /// match; nor does a missing tag, a tag from another pair of keys, or
    /// two tags.
    #[test]
    fn the_tag_binds_content_and_wrap_key() {
        let p = pair();
        let event = from_device(&p, "{}");
        let candidates = device_candidates(&p);
        let tag = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::custom(TAG_NAME))
            .unwrap()
            .clone();
        // The same tag on a new wrap with other content and another key.
        let other = from_device(&p, "{\"y\":2}");
        let forged = EventBuilder::new(Kind::GiftWrap, other.content.clone())
            .tags([Tag::public_key(p.gateway.public_key()), tag.clone()])
            .custom_created_at(other.created_at)
            .sign_with_keys(&Keys::generate())
            .unwrap();
        assert_eq!(
            match_tag(&forged, &candidates, NOW).unwrap_err(),
            Error::NotOurs
        );
        // The same tag and key, other content: rebuild with the original
        // ephemeral key is impossible, so check the HMAC directly.
        let key = &candidates[0].tag_key;
        let t = key.tag(&event.pubkey.to_bytes(), &event.content);
        assert!(key.matches(&event.pubkey.to_bytes(), &event.content, &t));
        assert!(!key.matches(&event.pubkey.to_bytes(), "other", &t));
        assert!(!key.matches(&[1; 32], &event.content, &t));
        assert!(!key.matches(&event.pubkey.to_bytes(), &event.content, &t[..15]));
        // No tag, two tags.
        let untagged = EventBuilder::new(Kind::GiftWrap, event.content.clone())
            .tags([Tag::public_key(p.gateway.public_key())])
            .sign_with_keys(&Keys::generate())
            .unwrap();
        assert_eq!(
            match_tag(&untagged, &candidates, NOW).unwrap_err(),
            Error::NotOurs
        );
        // A stranger's wrap.
        let stranger = pair();
        let theirs = from_device(
            &Pair {
                gateway: Keys::new(p.gateway.secret_key().clone()),
                device: stranger.device,
            },
            "{}",
        );
        assert_eq!(
            match_tag(&theirs, &candidates, NOW).unwrap_err(),
            Error::NotOurs
        );
    }

    #[test]
    fn the_time_window_is_three_days_back_and_ten_minutes_ahead() {
        assert!(within_window(NOW - WINDOW_PAST_SECS, NOW));
        assert!(!within_window(NOW - WINDOW_PAST_SECS - 1, NOW));
        assert!(within_window(NOW + WINDOW_FUTURE_SECS, NOW));
        assert!(!within_window(NOW + WINDOW_FUTURE_SECS + 1, NOW));
        let p = pair();
        let event = from_device(&p, "{}");
        let later = event.created_at.as_secs() + WINDOW_PAST_SECS + 1;
        assert_eq!(
            match_tag(&event, &device_candidates(&p), later).unwrap_err(),
            Error::NotOurs
        );
    }

    /// A wrap tagged right but sealed by another key than the expected
    /// sender is refused.
    #[test]
    fn the_seal_must_come_from_the_expected_sender() {
        let p = pair();
        let mallory = Keys::generate();
        let key = TagKey::for_peer(&p.device, &p.gateway.public_key().to_bytes()).unwrap();
        let event = wrap(
            &mallory,
            &p.gateway.public_key().to_bytes(),
            &key,
            kind::DECISION,
            "{}",
            NOW,
        )
        .unwrap();
        assert!(match_tag(&event, &device_candidates(&p), NOW).is_ok());
        assert!(open(
            &p.gateway,
            &event,
            &device_candidates(&p),
            &mut SeenWraps::default(),
            NOW
        )
        .is_err());
        // With no expected sender (pairing), the sender is reported.
        let secret = [5u8; 32];
        let pairing = vec![Candidate {
            id: "pairing",
            tag_key: TagKey::for_pairing(&secret),
            sender: None,
        }];
        let event = wrap(
            &mallory,
            &p.gateway.public_key().to_bytes(),
            &TagKey::for_pairing(&secret),
            kind::PAIRING,
            "{}",
            NOW,
        )
        .unwrap();
        assert_eq!(
            open(&p.gateway, &event, &pairing, &mut SeenWraps::default(), NOW)
                .unwrap()
                .sender,
            mallory.public_key().to_bytes()
        );
    }

    #[test]
    fn size_and_kind_limits() {
        let p = pair();
        let key = TagKey::for_peer(&p.device, &p.gateway.public_key().to_bytes()).unwrap();
        let big = "x".repeat(MAX_RUMOR_BYTES);
        assert!(matches!(
            wrap(
                &p.device,
                &p.gateway.public_key().to_bytes(),
                &key,
                kind::DECISION,
                &big,
                NOW
            ),
            Err(Error::TooLarge(_))
        ));
        assert!(wrap(
            &p.device,
            &p.gateway.public_key().to_bytes(),
            &key,
            1,
            "{}",
            NOW
        )
        .is_err());
        // A rumor just under the limit wraps to under 64 KiB, the smallest
        // event limit common relays set.
        let fits = "x".repeat(MAX_RUMOR_BYTES - 400);
        let event = wrap(
            &p.device,
            &p.gateway.public_key().to_bytes(),
            &key,
            kind::REQUEST,
            &fits,
            NOW,
        )
        .unwrap();
        assert!(
            event.as_json().len() < 64 * 1024,
            "{}",
            event.as_json().len()
        );
        assert!(open(
            &p.gateway,
            &event,
            &device_candidates(&p),
            &mut SeenWraps::default(),
            NOW
        )
        .is_ok());
    }

    /// A wrap built by hand around any seal and rumor, tagged right, so each
    /// check after the tag can be tested on its own.
    fn raw_wrap(
        p: &Pair,
        seal_kind: Kind,
        seal_signer: &Keys,
        rumor_json: &str,
        content_override: Option<&str>,
        seal_tags: Vec<Tag>,
    ) -> Event {
        let receiver = p.gateway.public_key();
        let sealed = nip44::encrypt(
            seal_signer.secret_key(),
            &receiver,
            rumor_json,
            nip44::Version::V2,
        )
        .unwrap();
        let seal = EventBuilder::new(seal_kind, sealed)
            .tags(seal_tags)
            .sign_with_keys(seal_signer)
            .unwrap();
        let ephemeral = Keys::generate();
        let wrapped = content_override.map(str::to_string).unwrap_or_else(|| {
            nip44::encrypt(
                ephemeral.secret_key(),
                &receiver,
                seal.as_json(),
                nip44::Version::V2,
            )
            .unwrap()
        });
        let key = TagKey::for_peer(&p.device, &receiver.to_bytes()).unwrap();
        let tag = key.tag(&ephemeral.public_key().to_bytes(), &wrapped);
        EventBuilder::new(Kind::GiftWrap, wrapped)
            .tags([
                Tag::public_key(receiver),
                Tag::custom(TagKind::custom(TAG_NAME), [hex::encode(tag)]),
            ])
            .custom_created_at(Timestamp::from_secs(NOW))
            .sign_with_keys(&ephemeral)
            .unwrap()
    }

    fn rumor(author: &Keys, kind: u16, tags: Vec<Tag>, content: &str) -> UnsignedEvent {
        let mut r = EventBuilder::new(Kind::from(kind), content)
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(NOW))
            .build(author.public_key());
        r.ensure_id();
        r
    }

    /// Every check after the tag, broken on its own, refuses the wrap.
    #[test]
    fn each_check_inside_the_wrap_refuses() {
        let p = pair();
        let candidates = device_candidates(&p);
        let good = rumor(&p.device, kind::DECISION, vec![], "{}");
        let ok = raw_wrap(&p, Kind::Seal, &p.device, &good.as_json(), None, vec![]);
        assert!(open(&p.gateway, &ok, &candidates, &mut SeenWraps::default(), NOW).is_ok());

        // The wrap's own signature.
        let mut forged = ok.clone();
        forged.sig =
            Keys::generate().sign_schnorr(&nostr::secp256k1::Message::from_digest([1; 32]));
        assert!(
            open(
                &p.gateway,
                &forged,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "wrap signature"
        );
        // The seal's kind.
        let wrong_kind = raw_wrap(&p, Kind::TextNote, &p.device, &good.as_json(), None, vec![]);
        assert!(
            open(
                &p.gateway,
                &wrong_kind,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "seal kind"
        );
        // A rumor authored by another key than the seal's signer.
        let other = rumor(&Keys::generate(), kind::DECISION, vec![], "{}");
        let impostor = raw_wrap(&p, Kind::Seal, &p.device, &other.as_json(), None, vec![]);
        assert!(
            open(
                &p.gateway,
                &impostor,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "rumor author"
        );
        // A rumor whose id does not match.
        let mut bad_id = good.clone();
        bad_id.content = "{\"x\":1}".into();
        let bad_id = raw_wrap(&p, Kind::Seal, &p.device, &bad_id.as_json(), None, vec![]);
        assert!(
            open(
                &p.gateway,
                &bad_id,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "rumor id"
        );
        // A rumor of another kind, or with tags.
        let not_ours = rumor(&p.device, 1, vec![], "{}");
        let not_ours = raw_wrap(&p, Kind::Seal, &p.device, &not_ours.as_json(), None, vec![]);
        assert!(
            open(
                &p.gateway,
                &not_ours,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "rumor kind"
        );
        let tagged = rumor(
            &p.device,
            kind::DECISION,
            vec![Tag::public_key(p.gateway.public_key())],
            "{}",
        );
        let tagged = raw_wrap(&p, Kind::Seal, &p.device, &tagged.as_json(), None, vec![]);
        assert!(
            open(
                &p.gateway,
                &tagged,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "rumor tags"
        );
        // A seal with tags.
        let tagged_seal = raw_wrap(
            &p,
            Kind::Seal,
            &p.device,
            &good.as_json(),
            None,
            vec![Tag::public_key(p.gateway.public_key())],
        );
        assert!(
            open(
                &p.gateway,
                &tagged_seal,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "seal tags"
        );
        // A rumor over the size limit.
        let big = rumor(
            &p.device,
            kind::DECISION,
            vec![],
            &"x".repeat(MAX_RUMOR_BYTES),
        );
        let big = raw_wrap(&p, Kind::Seal, &p.device, &big.as_json(), None, vec![]);
        assert!(
            open(
                &p.gateway,
                &big,
                &candidates,
                &mut SeenWraps::default(),
                NOW
            )
            .is_err(),
            "rumor size"
        );
        // Wrap content over the limit is dropped before anything else.
        let huge = raw_wrap(
            &p,
            Kind::Seal,
            &p.device,
            &good.as_json(),
            Some(&"A".repeat(MAX_WRAP_CONTENT + 1)),
            vec![],
        );
        assert_eq!(
            match_tag(&huge, &candidates, NOW).unwrap_err(),
            Error::NotOurs
        );
    }

    /// A wrap of another kind, or with the tag twice, is not matched, even
    /// with a tag that is otherwise right.
    #[test]
    fn only_tagged_gift_wraps_are_matched() {
        let p = pair();
        let candidates = device_candidates(&p);
        let build = |kind: Kind, copies: usize| {
            let ephemeral = Keys::generate();
            let content = "AAAA".to_string();
            let key = TagKey::for_peer(&p.device, &p.gateway.public_key().to_bytes()).unwrap();
            let tag = Tag::custom(
                TagKind::custom(TAG_NAME),
                [hex::encode(
                    key.tag(&ephemeral.public_key().to_bytes(), &content),
                )],
            );
            let mut tags = vec![Tag::public_key(p.gateway.public_key())];
            tags.extend(std::iter::repeat_n(tag, copies));
            EventBuilder::new(kind, content)
                .tags(tags)
                .custom_created_at(Timestamp::from_secs(NOW))
                .sign_with_keys(&ephemeral)
                .unwrap()
        };
        assert!(match_tag(&build(Kind::GiftWrap, 1), &candidates, NOW).is_ok());
        assert_eq!(
            match_tag(&build(Kind::Custom(1060), 1), &candidates, NOW).unwrap_err(),
            Error::NotOurs
        );
        assert_eq!(
            match_tag(&build(Kind::GiftWrap, 0), &candidates, NOW).unwrap_err(),
            Error::NotOurs
        );
        let twice = build(Kind::GiftWrap, 2);
        let copies = twice
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::custom(TAG_NAME));
        assert_eq!(copies.count(), 2);
        assert_eq!(
            match_tag(&twice, &candidates, NOW).unwrap_err(),
            Error::NotOurs
        );
    }

    /// A wrap opened once is dropped unopened when it comes again, before
    /// any decryption: even one whose decryption would fail.
    #[test]
    fn a_replayed_wrap_is_dropped_before_decrypting() {
        let p = pair();
        let candidates = device_candidates(&p);
        let event = from_device(&p, "{}");
        let mut seen = SeenWraps::default();
        assert!(open(&p.gateway, &event, &candidates, &mut seen, NOW).is_ok());
        assert_eq!(
            open(&p.gateway, &event, &candidates, &mut seen, NOW).unwrap_err(),
            Error::NotOurs
        );
        // Tagged and signed but undecryptable: the first try fails at the
        // wrap's decryption, the replay before it.
        let garbage = raw_wrap(&p, Kind::Seal, &p.device, "{}", Some("AAAA"), vec![]);
        let mut seen = SeenWraps::default();
        assert!(matches!(
            open(&p.gateway, &garbage, &candidates, &mut seen, NOW),
            Err(Error::Invalid(_))
        ));
        assert_eq!(
            open(&p.gateway, &garbage, &candidates, &mut seen, NOW).unwrap_err(),
            Error::NotOurs
        );
        // A wrap with a forged signature is not recorded, so it cannot keep
        // the real one out.
        let mut forged = event.clone();
        forged.sig =
            Keys::generate().sign_schnorr(&nostr::secp256k1::Message::from_digest([1; 32]));
        let mut seen = SeenWraps::default();
        assert!(open(&p.gateway, &forged, &candidates, &mut seen, NOW).is_err());
        assert!(open(&p.gateway, &event, &candidates, &mut seen, NOW).is_ok());
    }

    /// A pairing session, whose sender is not known yet, opens only `pair`.
    #[test]
    fn a_pairing_session_opens_only_pair() {
        let p = pair();
        let secret = [5u8; 32];
        let pairing = vec![Candidate {
            id: "pairing",
            tag_key: TagKey::for_pairing(&secret),
            sender: None,
        }];
        for (kind, ok) in [
            (kind::PAIRING, true),
            (kind::DECISION, false),
            (kind::FREEZE, false),
            (kind::REQUEST, false),
        ] {
            let event = wrap(
                &p.device,
                &p.gateway.public_key().to_bytes(),
                &TagKey::for_pairing(&secret),
                kind,
                "{}",
                NOW,
            )
            .unwrap();
            let opened = open(&p.gateway, &event, &pairing, &mut SeenWraps::default(), NOW);
            assert_eq!(opened.is_ok(), ok, "{kind}");
        }
    }

    #[test]
    fn opened_debug_leaves_out_the_content() {
        let p = pair();
        let event = from_device(&p, "{\"secret\":\"hunter2\"}");
        let opened = open(
            &p.gateway,
            &event,
            &device_candidates(&p),
            &mut SeenWraps::default(),
            NOW,
        )
        .unwrap();
        let shown = format!("{opened:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("content_len"));
    }

    #[test]
    fn seen_wraps_drop_replays_and_prune_by_the_window() {
        let mut seen = SeenWraps::default();
        assert!(seen.first_time([1; 32], NOW, NOW));
        assert!(!seen.first_time([1; 32], NOW, NOW));
        assert!(!seen.first_time([2; 32], NOW - WINDOW_PAST_SECS - 1, NOW));
        assert_eq!(seen.len(), 1);
        assert!(seen.first_time([3; 32], NOW + 1, NOW + WINDOW_PAST_SECS + 1));
        assert_eq!(seen.len(), 1);
    }
}

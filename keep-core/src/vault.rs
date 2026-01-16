#![forbid(unsafe_code)]

use std::cell::Cell;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A time-limited and read-limited vault for sensitive data.
///
/// `EphemeralVault` provides automatic expiration and read counting for secrets.
/// The inner value is zeroized when the vault is dropped.
///
/// # Security Note
///
/// The secret remains in memory until the vault is dropped, even after TTL expires
/// or reads are exhausted. Use [`revoke`](Self::revoke) to explicitly zeroize early.
pub struct EphemeralVault<T: Zeroize> {
    inner: Option<T>,
    expires_at: Instant,
    remaining_reads: Cell<usize>,
}

impl<T: Zeroize> EphemeralVault<T> {
    /// Create a new vault with the given TTL and maximum read count.
    pub fn new(inner: T, ttl: Duration, max_reads: usize) -> Self {
        Self {
            inner: Some(inner),
            expires_at: Instant::now() + ttl,
            remaining_reads: Cell::new(max_reads),
        }
    }

    /// Access the secret if still valid (not expired, not exhausted, not revoked).
    /// Each successful call decrements the remaining read count.
    #[must_use]
    pub fn get(&self) -> Option<&T> {
        if Instant::now() >= self.expires_at {
            return None;
        }

        let remaining = self.remaining_reads.get();
        if remaining == 0 {
            return None;
        }

        self.remaining_reads.set(remaining - 1);
        self.inner.as_ref()
    }

    /// Remaining reads before exhaustion.
    pub fn remaining_reads(&self) -> usize {
        self.remaining_reads.get()
    }

    /// Returns true if TTL has elapsed.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns `true` if the secret has been revoked (zeroized early).
    pub fn is_revoked(&self) -> bool {
        self.inner.is_none()
    }

    /// Time remaining until expiration.
    pub fn time_remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// Zeroize and remove the secret early. After this, `get` returns `None`.
    pub fn revoke(&mut self) {
        if let Some(ref mut inner) = self.inner {
            inner.zeroize();
        }
        self.inner = None;
        self.remaining_reads.set(0);
    }
}

impl<T: Zeroize> Drop for EphemeralVault<T> {
    fn drop(&mut self) {
        if let Some(ref mut inner) = self.inner {
            inner.zeroize();
        }
    }
}

impl<T: Zeroize> ZeroizeOnDrop for EphemeralVault<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_vault_read_limit() {
        let secret: [u8; 32] = [0xAB; 32];
        let vault = EphemeralVault::new(secret, Duration::from_secs(60), 3);

        assert_eq!(vault.remaining_reads(), 3);
        assert!(vault.get().is_some());
        assert_eq!(vault.remaining_reads(), 2);
        assert!(vault.get().is_some());
        assert_eq!(vault.remaining_reads(), 1);
        assert!(vault.get().is_some());
        assert_eq!(vault.remaining_reads(), 0);
        assert!(vault.get().is_none());
    }

    #[test]
    fn test_vault_ttl_expiry() {
        let secret: [u8; 32] = [0xCD; 32];
        let vault = EphemeralVault::new(secret, Duration::from_millis(50), 100);

        assert!(!vault.is_expired());
        assert!(vault.get().is_some());

        sleep(Duration::from_millis(60));

        assert!(vault.is_expired());
        assert!(vault.get().is_none());
    }

    #[test]
    fn test_vault_zero_reads() {
        let secret: [u8; 32] = [0xEF; 32];
        let vault = EphemeralVault::new(secret, Duration::from_secs(60), 0);

        assert!(vault.get().is_none());
    }

    #[test]
    fn test_vault_time_remaining() {
        let secret: [u8; 32] = [0x12; 32];
        let vault = EphemeralVault::new(secret, Duration::from_secs(10), 5);

        let remaining = vault.time_remaining();
        assert!(remaining <= Duration::from_secs(10));
        assert!(remaining > Duration::from_secs(9));
    }

    #[test]
    fn test_vault_revoke() {
        let secret: [u8; 32] = [0x34; 32];
        let mut vault = EphemeralVault::new(secret, Duration::from_secs(60), 10);

        assert!(!vault.is_revoked());
        assert!(vault.get().is_some());
        assert_eq!(vault.remaining_reads(), 9);

        vault.revoke();

        assert!(vault.is_revoked());
        assert!(vault.get().is_none());
        assert_eq!(vault.remaining_reads(), 0);
    }
}

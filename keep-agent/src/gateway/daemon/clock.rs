// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The gateway's clock: Unix seconds that only advance with elapsed time.
//!
//! While running, the clock is a start time plus `CLOCK_BOOTTIME`, which keeps
//! counting through suspend and ignores the wall clock, so stepping the wall
//! clock can neither age spends out of a budget early nor hold them in.
//!
//! The clock is persisted as a heartbeat (the boot it was taken in, the boot
//! time and the clock). A restart within the same boot continues from the
//! heartbeat by elapsed boot time alone. After a reboot the wall clock is the
//! only source, so it is trusted only within bounds: never earlier than any
//! time the vault has seen, and never further ahead of it than
//! [`MAX_UNCONFIRMED_GAP_SECS`] (a budget window) unless the owner confirms
//! the jump, so a wall clock wrongly far ahead cannot reset every budget or
//! pin the ledgers in the future. A gateway down for longer than a day needs
//! that confirmation to start.

use serde::{Deserialize, Serialize};

use crate::error::{AgentError, Result};

/// The ledger key the heartbeat is stored under. Never 16 bytes long, so it
/// cannot be a credential's ledger.
pub const HEARTBEAT_KEY: &[u8] = b"gateway-clock";

/// How far past the latest time the vault has seen the wall clock may read
/// after a reboot before the owner must confirm it: one budget window, so a
/// clock that jumped forward while the gateway was down can at most age out
/// what real time would have, never reset a budget outright.
pub const MAX_UNCONFIRMED_GAP_SECS: u64 = crate::policy::BUDGET_WINDOW_SECS;

/// The persisted clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    /// The kernel's boot id when the heartbeat was taken.
    pub boot_id: String,
    /// `CLOCK_BOOTTIME` seconds when it was taken.
    pub boottime: u64,
    /// The gateway's clock when it was taken.
    pub clock: u64,
}

impl Heartbeat {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| AgentError::Serialization(format!("gateway clock heartbeat: {e}")))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AgentError::Serialization(e.to_string()))
    }
}

/// What the clock is started from.
#[derive(Debug, Clone)]
pub struct Seed<'a> {
    /// The stored heartbeat, if any.
    pub heartbeat: Option<&'a Heartbeat>,
    /// The latest time the vault has seen: the heartbeat, every ledger and
    /// every credential's issue time.
    pub floor: u64,
    /// The wall clock now, in Unix seconds.
    pub wall: u64,
    /// The kernel's boot id now.
    pub boot_id: &'a str,
    /// `CLOCK_BOOTTIME` seconds now.
    pub boottime: u64,
    /// The owner confirmed a wall clock far ahead of the floor.
    pub accept_jump: bool,
}

/// The clock reading to start from, or why the gateway must not start.
pub fn start_time(seed: &Seed<'_>) -> Result<u64> {
    if let Some(hb) = seed.heartbeat {
        if hb.boot_id == seed.boot_id && seed.boottime >= hb.boottime {
            let elapsed = seed.boottime - hb.boottime;
            return Ok(hb.clock.saturating_add(elapsed).max(seed.floor));
        }
    }
    if seed.wall < seed.floor {
        tracing::warn!(
            wall = seed.wall,
            floor = seed.floor,
            "the wall clock reads before the latest time the vault has seen; starting from that time"
        );
        return Ok(seed.floor);
    }
    if seed.floor > 0 && seed.wall - seed.floor > MAX_UNCONFIRMED_GAP_SECS && !seed.accept_jump {
        return Err(AgentError::Other(format!(
            "the wall clock ({}) is {} seconds past the latest time the vault has seen ({}), \
             more than {MAX_UNCONFIRMED_GAP_SECS}; fix the clock, or if it is right, start once \
             with --accept-clock-jump",
            seed.wall,
            seed.wall - seed.floor,
            seed.floor
        )));
    }
    Ok(seed.wall)
}

/// Reads the kernel's clocks.
pub trait TimeSource: Send + Sync {
    /// `CLOCK_BOOTTIME` in whole seconds.
    fn boottime(&self) -> u64;
}

/// The running kernel.
pub struct Kernel;

impl TimeSource for Kernel {
    fn boottime(&self) -> u64 {
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        u64::try_from(ts.tv_sec).unwrap_or(0)
    }
}

/// The kernel's boot id, which changes on every boot.
pub fn boot_id() -> Result<String> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| AgentError::Other(format!("read the boot id: {e}")))?;
    let id = id.trim();
    if id.len() != 36 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(AgentError::Other(format!("unexpected boot id {id:?}")));
    }
    Ok(id.to_string())
}

/// The wall clock in Unix seconds.
pub fn wall_clock() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AgentError::Other("the wall clock reads before 1970".into()))
}

/// The gateway's clock: the start time plus boot time elapsed since start.
pub struct Clock {
    start: u64,
    boottime_at_start: u64,
    boot_id: String,
    source: Box<dyn TimeSource>,
}

impl Clock {
    pub fn new(start: u64, boot_id: String, source: Box<dyn TimeSource>) -> Self {
        Self {
            start,
            boottime_at_start: source.boottime(),
            boot_id,
            source,
        }
    }

    /// Unix seconds now. Never goes back: boot time only advances.
    pub fn now(&self) -> u64 {
        let elapsed = self
            .source
            .boottime()
            .saturating_sub(self.boottime_at_start);
        self.start.saturating_add(elapsed)
    }

    /// The heartbeat to persist for the clock now.
    pub fn heartbeat(&self) -> Heartbeat {
        let boottime = self.source.boottime();
        Heartbeat {
            boot_id: self.boot_id.clone(),
            boottime,
            clock: self
                .start
                .saturating_add(boottime.saturating_sub(self.boottime_at_start)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const T: u64 = 1_800_000_000;
    const BOOT: &str = "0f0e8c49-7d0d-4d47-a4b1-ad1b6c1b0a51";
    const OTHER_BOOT: &str = "1f0e8c49-7d0d-4d47-a4b1-ad1b6c1b0a51";

    /// A boot time the test sets.
    #[derive(Clone, Default)]
    pub(crate) struct FakeBoot(pub Arc<AtomicU64>);

    impl FakeBoot {
        pub(crate) fn advance(&self, secs: u64) {
            self.0.fetch_add(secs, Ordering::SeqCst);
        }
    }

    impl TimeSource for FakeBoot {
        fn boottime(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn seed<'a>(hb: Option<&'a Heartbeat>, floor: u64, wall: u64, boot: &'a str) -> Seed<'a> {
        Seed {
            heartbeat: hb,
            floor,
            wall,
            boot_id: boot,
            boottime: 500,
            accept_jump: false,
        }
    }

    #[test]
    fn a_restart_in_the_same_boot_ignores_the_wall_clock() {
        let hb = Heartbeat {
            boot_id: BOOT.into(),
            boottime: 400,
            clock: T,
        };
        for wall in [0, T - 86_400, T + 100, T + 10 * MAX_UNCONFIRMED_GAP_SECS] {
            assert_eq!(
                start_time(&seed(Some(&hb), T, wall, BOOT)).unwrap(),
                T + 100
            );
        }
        assert_eq!(
            start_time(&seed(Some(&hb), T + 1_000, 0, BOOT)).unwrap(),
            T + 1_000,
            "never before the floor"
        );
    }

    #[test]
    fn a_confirmation_is_needed_past_one_budget_window() {
        assert_eq!(MAX_UNCONFIRMED_GAP_SECS, 24 * 60 * 60);
        assert_eq!(MAX_UNCONFIRMED_GAP_SECS, crate::policy::BUDGET_WINDOW_SECS);
    }

    #[test]
    fn after_a_reboot_the_wall_clock_is_bounded_by_the_floor() {
        let hb = Heartbeat {
            boot_id: BOOT.into(),
            boottime: 400,
            clock: T,
        };
        let s = |wall| start_time(&seed(Some(&hb), T, wall, OTHER_BOOT));
        assert_eq!(s(T - 5).unwrap(), T, "a clock behind starts at the floor");
        assert_eq!(s(T + 3_600).unwrap(), T + 3_600);
        assert_eq!(
            s(T + MAX_UNCONFIRMED_GAP_SECS).unwrap(),
            T + MAX_UNCONFIRMED_GAP_SECS
        );
        let err = s(T + MAX_UNCONFIRMED_GAP_SECS + 1).unwrap_err();
        assert!(err.to_string().contains("--accept-clock-jump"), "{err}");
        let mut confirmed = seed(Some(&hb), T, T + 10 * MAX_UNCONFIRMED_GAP_SECS, OTHER_BOOT);
        confirmed.accept_jump = true;
        assert_eq!(
            start_time(&confirmed).unwrap(),
            T + 10 * MAX_UNCONFIRMED_GAP_SECS
        );
        // A boot time behind the heartbeat's cannot be the same boot.
        let mut behind = seed(Some(&hb), T, T + 7, BOOT);
        behind.boottime = 399;
        assert_eq!(start_time(&behind).unwrap(), T + 7);
    }

    #[test]
    fn without_a_heartbeat_the_floor_still_bounds_the_wall_clock() {
        assert_eq!(start_time(&seed(None, 0, T, BOOT)).unwrap(), T);
        assert_eq!(start_time(&seed(None, T, T - 1, BOOT)).unwrap(), T);
        assert!(start_time(&seed(None, T, T + MAX_UNCONFIRMED_GAP_SECS + 1, BOOT)).is_err());
    }

    #[test]
    fn the_clock_follows_boot_time_and_its_heartbeat_continues_it() {
        let boot = FakeBoot::default();
        boot.advance(1_000);
        let clock = Clock::new(T, BOOT.into(), Box::new(boot.clone()));
        assert_eq!(clock.now(), T);
        boot.advance(90);
        assert_eq!(clock.now(), T + 90);
        let hb = clock.heartbeat();
        assert_eq!(
            hb,
            Heartbeat {
                boot_id: BOOT.into(),
                boottime: 1_090,
                clock: T + 90
            }
        );
        assert_eq!(Heartbeat::decode(&hb.encode().unwrap()).unwrap(), hb);
        assert!(
            Heartbeat::decode(b"{\"boot_id\":\"x\",\"boottime\":1,\"clock\":1,\"x\":1}").is_err()
        );
        let mut later = seed(Some(&hb), 0, 0, BOOT);
        later.boottime = 1_100;
        assert_eq!(start_time(&later).unwrap(), T + 100);
    }

    #[test]
    fn the_kernel_clocks_read() {
        let id = boot_id().unwrap();
        assert_eq!(id, boot_id().unwrap());
        let a = Kernel.boottime();
        assert!(a > 0);
        assert!(Kernel.boottime() >= a);
        assert!(wall_clock().unwrap() > 1_700_000_000);
    }
}

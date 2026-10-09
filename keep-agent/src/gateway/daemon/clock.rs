// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The gateway's clocks.
//!
//! The budget clock decides spend windows, rate limits and audit budgets. It
//! is a start time plus `CLOCK_BOOTTIME`, which keeps counting through suspend
//! and ignores the wall clock, so stepping the wall clock can neither age
//! spends out of a budget early nor hold them in. It is persisted as a
//! heartbeat (the boot it was taken in, the boot time and the clock): a restart
//! within the same boot continues it by elapsed boot time, and after a reboot
//! it resumes from the latest time the vault has seen. Time the gateway was
//! down is never counted, so no clock, however wrong, can age out a spend: a
//! budget is held for longer, never released early.
//!
//! The calendar clock decides when credentials expire: the wall clock, but
//! never behind the budget clock. A wall clock that runs ahead only expires
//! credentials early.

use serde::{Deserialize, Serialize};

use crate::error::{AgentError, Result};

/// The ledger key the heartbeat is stored under. Never 16 bytes long, so it
/// cannot be a credential's ledger.
pub const HEARTBEAT_KEY: &[u8] = b"gateway-clock";

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

/// What the budget clock is started from.
#[derive(Debug, Clone)]
pub struct Seed<'a> {
    /// The stored heartbeat, if any.
    pub heartbeat: Option<&'a Heartbeat>,
    /// The latest budget time the vault has seen: the heartbeat and every
    /// ledger.
    pub floor: u64,
    /// The wall clock now, in Unix seconds.
    pub wall: u64,
    /// The kernel's boot id now.
    pub boot_id: &'a str,
    /// `CLOCK_BOOTTIME` seconds now.
    pub boottime: u64,
}

/// The budget clock reading to start from. The wall clock is used only by a
/// vault that has never seen any time.
pub fn start_time(seed: &Seed<'_>) -> u64 {
    if let Some(hb) = seed.heartbeat {
        if hb.boot_id == seed.boot_id && seed.boottime >= hb.boottime {
            let elapsed = seed.boottime - hb.boottime;
            return hb.clock.saturating_add(elapsed).max(seed.floor);
        }
    }
    if seed.floor == 0 {
        seed.wall
    } else {
        seed.floor
    }
}

/// Reads the kernel's clocks.
pub trait TimeSource: Send + Sync {
    /// `CLOCK_BOOTTIME` in whole seconds.
    fn boottime(&self) -> u64;
    /// The wall clock in Unix seconds, or 0 when it reads before 1970.
    fn wall(&self) -> u64;
}

/// The running kernel.
pub struct Kernel;

impl TimeSource for Kernel {
    fn boottime(&self) -> u64 {
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        u64::try_from(ts.tv_sec).unwrap_or(0)
    }

    fn wall(&self) -> u64 {
        wall_clock().unwrap_or(0)
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

/// The gateway's clocks: the budget clock is the start time plus boot time
/// elapsed since start; the calendar clock is the wall clock, never behind it.
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

    /// The calendar time now, for credential expiry: the wall clock, never
    /// behind the budget clock.
    pub fn calendar(&self) -> u64 {
        self.now().max(self.source.wall())
    }

    /// The budget clock now. Never goes back: boot time only advances.
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

    /// A boot time and a wall clock the test sets.
    #[derive(Clone, Default)]
    pub(crate) struct FakeBoot(pub Arc<AtomicU64>, pub Arc<AtomicU64>);

    impl FakeBoot {
        pub(crate) fn advance(&self, secs: u64) {
            self.0.fetch_add(secs, Ordering::SeqCst);
        }

        pub(crate) fn set_wall(&self, wall: u64) {
            self.1.store(wall, Ordering::SeqCst);
        }
    }

    impl TimeSource for FakeBoot {
        fn boottime(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }

        fn wall(&self) -> u64 {
            self.1.load(Ordering::SeqCst)
        }
    }

    fn seed<'a>(hb: Option<&'a Heartbeat>, floor: u64, wall: u64, boot: &'a str) -> Seed<'a> {
        Seed {
            heartbeat: hb,
            floor,
            wall,
            boot_id: boot,
            boottime: 500,
        }
    }

    #[test]
    fn a_restart_in_the_same_boot_continues_by_boot_time_alone() {
        let hb = Heartbeat {
            boot_id: BOOT.into(),
            boottime: 400,
            clock: T,
        };
        for wall in [0, T - 86_400, T + 100, T + 1_000 * 86_400] {
            assert_eq!(start_time(&seed(Some(&hb), T, wall, BOOT)), T + 100);
        }
        assert_eq!(
            start_time(&seed(Some(&hb), T + 1_000, 0, BOOT)),
            T + 1_000,
            "never before the floor"
        );
    }

    #[test]
    fn after_a_reboot_the_clock_resumes_where_the_vault_left_it() {
        let hb = Heartbeat {
            boot_id: BOOT.into(),
            boottime: 400,
            clock: T,
        };
        // Whatever the wall clock says, downtime is not counted.
        for wall in [0, T - 5, T + 3_600, T + 86_400, T + 1_000 * 86_400] {
            assert_eq!(
                start_time(&seed(Some(&hb), T, wall, OTHER_BOOT)),
                T,
                "{wall}"
            );
        }
        // A boot time behind the heartbeat's cannot be the same boot.
        let mut behind = seed(Some(&hb), T, T + 7, BOOT);
        behind.boottime = 399;
        assert_eq!(start_time(&behind), T);
        // Without a heartbeat, the ledgers' times hold it.
        assert_eq!(start_time(&seed(None, T, T + 86_400, OTHER_BOOT)), T);
    }

    #[test]
    fn a_vault_that_has_seen_no_time_starts_from_the_wall_clock() {
        assert_eq!(start_time(&seed(None, 0, T, BOOT)), T);
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
        assert_eq!(start_time(&later), T + 100);
    }

    #[test]
    fn the_calendar_is_the_wall_clock_never_behind_the_budget_clock() {
        let boot = FakeBoot::default();
        let clock = Clock::new(T, BOOT.into(), Box::new(boot.clone()));
        assert_eq!(clock.calendar(), T, "a wall clock behind does not count");
        boot.set_wall(T + 86_400);
        assert_eq!(clock.calendar(), T + 86_400);
        assert_eq!(clock.now(), T, "the budget clock ignores it");
    }

    #[test]
    fn the_kernel_clocks_read() {
        let id = boot_id().unwrap();
        assert_eq!(id, boot_id().unwrap());
        let a = Kernel.boottime();
        assert!(a > 0);
        assert!(Kernel.boottime() >= a);
        assert!(wall_clock().unwrap() > 1_700_000_000);
        assert!(Kernel.wall() > 1_700_000_000);
    }
}

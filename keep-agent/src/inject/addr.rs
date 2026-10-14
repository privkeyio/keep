// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Which resolved addresses an injected request may connect to: only globally
//! reachable unicast, so a DNS answer cannot point a secret at a service on
//! the gateway's host or network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `addr` is globally reachable unicast. Stricter than the IANA
/// special-purpose registry where a block holds little but special uses:
/// all of `2001::/23`, 6to4 and `192.0.0.0/24` are refused outright.
pub fn is_global(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn in_v4(addr: Ipv4Addr, net: [u8; 4], len: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
    u32::from(addr) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn is_global_v4(addr: Ipv4Addr) -> bool {
    const REFUSED: [([u8; 4], u32); 16] = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
        ([255, 255, 255, 255], 32),
    ];
    !REFUSED.iter().any(|&(net, len)| in_v4(addr, net, len))
}

fn in_v6(addr: Ipv6Addr, net: [u16; 8], len: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
    u128::from(addr) & mask == u128::from(Ipv6Addr::from(net)) & mask
}

fn is_global_v6(addr: Ipv6Addr) -> bool {
    // NAT64's well-known prefix carries an IPv4 address in its last 32 bits;
    // it is as reachable as that address.
    if in_v6(addr, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        let [.., a, b, c, d] = addr.octets();
        return is_global_v4(Ipv4Addr::new(a, b, c, d));
    }
    const REFUSED: [([u16; 8], u32); 4] = [
        ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
        ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
        ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    ];
    in_v6(addr, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3)
        && !REFUSED.iter().any(|&(net, len)| in_v6(addr, net, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global(s: &str) -> bool {
        is_global(s.parse().unwrap())
    }

    #[test]
    fn public_addresses_are_global() {
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.0",
            "192.0.3.0",
            "192.88.98.255",
            "192.88.100.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2001:200::1",
            "2003::1",
            "3ffe:ffff::1",
            "3fff:1000::1",
            "64:ff9b::808:808",
        ] {
            assert!(global(a), "{a} should be global");
        }
    }

    #[test]
    fn special_addresses_are_refused() {
        for a in [
            "0.0.0.0",
            "0.255.255.255",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "::8.8.8.8",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b:1::808:808",
            "64:ff9b:0:0:0:1:808:808",
            "100::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:0:4136:e378::1",
            "2001:1::1",
            "2001:1ff::1",
            "2001:db8::1",
            "2002:808:808::1",
            "3fff::1",
            "3fff:fff::1",
            "5f00::1",
            "5eff::1",
            "4000::1",
            "1fff:ffff::1",
        ] {
            assert!(!global(a), "{a} should be refused");
        }
    }
}

//! IPv4/IPv6 addresses, CIDR blocks and inclusive address ranges.
//!
//! Both families use `u128` (IPv4 occupies the low 32 bits). Range arithmetic (merge, subtract,
//! aggregate) is done per family; ranges of different families are never mixed.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type Range = (u128, u128);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    pub fn bits(self) -> u8 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }

    /// Key used in the state file and the configuration (`ipv4`, `ipv6`).
    pub fn key(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }

    /// The `ip` utility flag.
    pub fn ip_flag(self) -> &'static str {
        match self {
            Family::V4 => "-4",
            Family::V6 => "-6",
        }
    }

    pub fn of(ip: &IpAddr) -> Family {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cidr {
    pub fam: Family,
    pub addr: u128,
    pub len: u8,
}

pub fn ip_to_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u32::from(*a) as u128,
        IpAddr::V6(a) => u128::from(*a),
    }
}

pub fn u128_to_ip(fam: Family, v: u128) -> IpAddr {
    match fam {
        Family::V4 => IpAddr::V4(Ipv4Addr::from(v as u32)),
        Family::V6 => IpAddr::V6(Ipv6Addr::from(v)),
    }
}

fn full(fam: Family) -> u128 {
    match fam {
        Family::V4 => u32::MAX as u128,
        Family::V6 => u128::MAX,
    }
}

fn mask(fam: Family, len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        let host = fam.bits() - len;
        (full(fam) >> host) << host
    }
}

impl Cidr {
    /// Accepts `addr/len` and a bare address (a host route). Host bits are cleared.
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, len) = match s.split_once('/') {
            Some((ip, l)) => (ip, Some(l.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let ip: IpAddr = ip.parse().ok()?;
        let fam = Family::of(&ip);
        let len = len.unwrap_or(fam.bits());
        (len <= fam.bits()).then(|| Cidr { fam, addr: ip_to_u128(&ip) & mask(fam, len), len })
    }

    pub fn first(&self) -> u128 {
        self.addr
    }

    pub fn last(&self) -> u128 {
        self.addr | (!mask(self.fam, self.len) & full(self.fam))
    }

    pub fn range(&self) -> Range {
        (self.first(), self.last())
    }

    #[cfg(test)]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        Family::of(ip) == self.fam && ip_to_u128(ip) & mask(self.fam, self.len) == self.addr
    }

    /// An address inside the block that is not its first one (so not a network address), when there is one.
    pub fn probe(&self) -> IpAddr {
        let a = if self.len >= self.fam.bits() - 1 { self.first() } else { self.first() + 1 };
        u128_to_ip(self.fam, a)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", u128_to_ip(self.fam, self.addr), self.len)
    }
}

/// Smallest list of CIDR blocks covering exactly `start..=end`.
pub fn range_to_cidrs(fam: Family, start: u128, end: u128) -> Vec<Cidr> {
    let bits = fam.bits() as u32;
    let mut out = Vec::new();
    let mut cur = start;
    while cur <= end {
        let align = if cur == 0 { bits } else { cur.trailing_zeros().min(bits) };
        let remaining = end - cur; // size - 1, which cannot overflow
        let fit = if remaining == u128::MAX { 128 } else { 127 - (remaining + 1).leading_zeros() };
        let host_bits = align.min(fit);
        out.push(Cidr { fam, addr: cur, len: (bits - host_bits) as u8 });
        let last = cur + if host_bits == 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
        if last >= end {
            break;
        }
        cur = last + 1;
    }
    out
}

/// Sort and merge overlapping or touching ranges.
pub fn merge(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_unstable();
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        match out.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// `ranges` minus `holes`. Both inputs are merged first.
pub fn subtract(ranges: Vec<Range>, holes: Vec<Range>) -> Vec<Range> {
    let ranges = merge(ranges);
    let holes = merge(holes);
    let mut out = Vec::with_capacity(ranges.len());
    let mut first_hole = 0;
    for (s, e) in ranges {
        while first_hole < holes.len() && holes[first_hole].1 < s {
            first_hole += 1;
        }
        let mut cur = s;
        let mut i = first_hole;
        loop {
            match holes.get(i) {
                Some(&(hs, he)) if hs <= e => {
                    if hs > cur {
                        out.push((cur, hs - 1));
                    }
                    if he >= e {
                        break;
                    }
                    cur = he + 1;
                    i += 1;
                }
                _ => {
                    out.push((cur, e));
                    break;
                }
            }
        }
    }
    out
}

/// Merge ranges and express the result as the fewest CIDR blocks.
pub fn aggregate(fam: Family, ranges: Vec<Range>) -> Vec<Cidr> {
    merge(ranges).into_iter().flat_map(|(s, e)| range_to_cidrs(fam, s, e)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_parse_masks_host_bits_and_validates_length() {
        assert_eq!(c("10.1.2.3/24").to_string(), "10.1.2.0/24");
        assert_eq!(c("8.8.8.8").to_string(), "8.8.8.8/32");
        assert_eq!(c("0.0.0.0/0").last(), u32::MAX as u128);
        assert_eq!(c("2a00:1450:4001::1/32").to_string(), "2a00:1450::/32");
        assert_eq!(c("2001:db8::1").to_string(), "2001:db8::1/128");
        assert_eq!(c("::/0").last(), u128::MAX);
        for bad in ["1.2.3.0/33", "1.2.3.0/x", "::/129", "1.2.3", "1.2.3.256", "", "abc", "1.2.3.4.5", "gggg::"] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn families_are_kept_apart() {
        assert_eq!(c("1.2.3.0/24").fam, Family::V4);
        assert_eq!(c("2001:db8::/32").fam, Family::V6);
        assert!(c("0.0.0.0/0").contains(&ip("8.8.8.8")));
        assert!(!c("0.0.0.0/0").contains(&ip("2001:db8::1")));
        assert!(c("::/0").contains(&ip("2001:db8::1")));
        assert!(!c("::/0").contains(&ip("8.8.8.8")));
    }

    #[test]
    fn cidr_contains_and_probe() {
        let n = c("213.59.0.0/16");
        assert!(n.contains(&ip("213.59.200.1")));
        assert!(!n.contains(&ip("213.60.0.0")));
        assert_eq!(n.probe(), ip("213.59.0.1"));
        assert_eq!(c("1.2.3.4/32").probe(), ip("1.2.3.4"));
        assert_eq!(c("2a00:1450::/32").probe(), ip("2a00:1450::1"));
        assert!(c("2a00:1450::/32").contains(&c("2a00:1450::/32").probe()));
    }

    #[test]
    fn range_to_cidrs_matches_the_known_cases() {
        let v4 = |s: &str, n: u128| {
            let a = ip_to_u128(&ip(s));
            range_to_cidrs(Family::V4, a, a + n - 1).iter().map(|c| c.to_string()).collect::<Vec<_>>()
        };
        assert_eq!(v4("10.0.0.0", 6), ["10.0.0.0/30", "10.0.0.4/31"]);
        assert_eq!(v4("213.59.0.0", 65536), ["213.59.0.0/16"]);
        assert_eq!(v4("37.9.96.0", 8192), ["37.9.96.0/19"]);
        assert_eq!(v4("10.0.0.1", 1), ["10.0.0.1/32"]);
        assert_eq!(v4("0.0.0.0", 1u128 << 32), ["0.0.0.0/0"]);
        assert_eq!(v4("255.255.255.254", 2), ["255.255.255.254/31"]);
    }

    #[test]
    fn range_to_cidrs_handles_v6_including_the_whole_space() {
        let a = ip_to_u128(&ip("2a00:1450::"));
        assert_eq!(range_to_cidrs(Family::V6, a, a | ((1u128 << 96) - 1))[0].to_string(), "2a00:1450::/32");
        assert_eq!(range_to_cidrs(Family::V6, 0, u128::MAX), [c("::/0")]);
        assert_eq!(range_to_cidrs(Family::V6, u128::MAX, u128::MAX), [c("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")]);
        let odd = range_to_cidrs(Family::V6, a + 1, a + 5);
        let total: u128 = odd.iter().map(|b| b.last() - b.first() + 1).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn range_to_cidrs_covers_exactly_the_range() {
        let (s, e) = (ip_to_u128(&ip("10.0.0.3")), ip_to_u128(&ip("10.0.3.200")));
        let blocks = range_to_cidrs(Family::V4, s, e);
        let total: u128 = blocks.iter().map(|b| b.last() - b.first() + 1).sum();
        assert_eq!(total, e - s + 1);
        assert_eq!(blocks.first().unwrap().first(), s);
        assert_eq!(blocks.last().unwrap().last(), e);
    }

    #[test]
    fn merge_joins_overlapping_and_touching() {
        assert_eq!(merge(vec![(10, 20), (21, 30), (5, 12), (40, 50)]), [(5, 30), (40, 50)]);
        assert_eq!(merge(vec![(0, u128::MAX), (5, 6)]), [(0, u128::MAX)]);
        assert_eq!(merge(vec![(u128::MAX - 1, u128::MAX), (0, 0)]), [(0, 0), (u128::MAX - 1, u128::MAX)]);
    }

    #[test]
    fn subtract_cuts_holes() {
        assert_eq!(subtract(vec![(0, 100)], vec![(10, 20), (50, 60)]), [(0, 9), (21, 49), (61, 100)]);
        assert_eq!(subtract(vec![(0, 100)], vec![(0, 100)]), []);
        assert_eq!(subtract(vec![(0, 100)], vec![(0, 10)]), [(11, 100)]);
        assert_eq!(subtract(vec![(0, 100)], vec![(90, 200)]), [(0, 89)]);
        assert_eq!(subtract(vec![(0, 10), (20, 30)], vec![(5, 25)]), [(0, 4), (26, 30)]);
        assert_eq!(subtract(vec![(0, u128::MAX)], vec![(0, 0), (u128::MAX, u128::MAX)]), [(1, u128::MAX - 1)]);
        assert_eq!(subtract(vec![(5, 9)], vec![]), [(5, 9)]);
    }

    #[test]
    fn aggregate_collapses_adjacent_blocks() {
        let ranges = vec![c("10.0.0.0/25").range(), c("10.0.0.128/25").range(), c("10.0.1.0/24").range()];
        let out: Vec<String> = aggregate(Family::V4, ranges).iter().map(|c| c.to_string()).collect();
        assert_eq!(out, ["10.0.0.0/23"]);
        let v6 = aggregate(Family::V6, vec![c("2001:db8::/33").range(), c("2001:db8:8000::/33").range()]);
        assert_eq!(v6, [c("2001:db8::/32")]);
    }

    #[test]
    fn carving_a_slice_out_of_a_block_leaves_the_rest_routable() {
        for (whole, hole, inside_hole, before, after) in [
            ("198.0.0.0/16", "198.0.41.0/24", "198.0.41.7", "198.0.40.255", "198.0.42.0"),
            ("2a00:1450::/32", "2a00:1450:4001::/48", "2a00:1450:4001::7", "2a00:1450:4000:ffff::1", "2a00:1450:4002::"),
        ] {
            let fam = c(whole).fam;
            let blocks = aggregate(fam, subtract(vec![c(whole).range()], vec![c(hole).range()]));
            assert!(blocks.iter().all(|b| !b.contains(&ip(inside_hole))));
            assert!(blocks.iter().any(|b| b.contains(&ip(before))));
            assert!(blocks.iter().any(|b| b.contains(&ip(after))));
        }
    }
}

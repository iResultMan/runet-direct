//! IPv4 addresses, CIDR blocks and inclusive address ranges.
//!
//! All set arithmetic (merge, subtract, aggregate) works on `(start, end)` ranges
//! held as `u32`; widening to `u64` is used wherever `end + 1` could overflow.

use std::fmt;

pub type Range = (u32, u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cidr {
    pub addr: u32,
    pub len: u8,
}

pub fn parse_ipv4(s: &str) -> Option<u32> {
    let mut parts = s.split('.');
    let mut out: u32 = 0;
    for _ in 0..4 {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out = (out << 8) | p.parse::<u8>().ok()? as u32;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

pub fn fmt_ipv4(a: u32) -> String {
    format!("{}.{}.{}.{}", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255)
}

fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    }
}

impl Cidr {
    /// Accepts `a.b.c.d/n` and a bare `a.b.c.d` (a /32). Host bits are cleared.
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, len) = match s.split_once('/') {
            Some((ip, l)) => (ip, l.parse::<u8>().ok().filter(|l| *l <= 32)?),
            None => (s, 32),
        };
        Some(Cidr { addr: parse_ipv4(ip)? & mask(len), len })
    }

    pub fn first(&self) -> u32 {
        self.addr
    }

    pub fn last(&self) -> u32 {
        self.addr | !mask(self.len)
    }

    pub fn range(&self) -> Range {
        (self.first(), self.last())
    }

    #[cfg(test)]
    pub fn contains(&self, ip: u32) -> bool {
        ip & mask(self.len) == self.addr
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", fmt_ipv4(self.addr), self.len)
    }
}

/// Smallest list of CIDR blocks covering exactly `start..=end`.
pub fn range_to_cidrs(start: u32, end: u32) -> Vec<Cidr> {
    let mut out = Vec::new();
    let mut cur = start as u64;
    let end = end as u64;
    while cur <= end {
        let align = if cur == 0 { 32 } else { (cur as u32).trailing_zeros() };
        let fit = 63 - (end - cur + 1).leading_zeros(); // floor(log2(remaining))
        let host_bits = align.min(fit);
        out.push(Cidr { addr: cur as u32, len: (32 - host_bits) as u8 });
        cur += 1u64 << host_bits;
    }
    out
}

/// Sort and merge overlapping or touching ranges.
pub fn merge(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_unstable();
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        match out.last_mut() {
            Some(last) if (s as u64) <= last.1 as u64 + 1 => last.1 = last.1.max(e),
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
    let mut h = 0;
    for (s, e) in ranges {
        let mut cur = s as u64;
        let e = e as u64;
        while h < holes.len() && (holes[h].1 as u64) < cur {
            h += 1;
        }
        let mut i = h;
        while cur <= e {
            match holes.get(i) {
                Some(&(hs, he)) if (hs as u64) <= e => {
                    if (hs as u64) > cur {
                        out.push((cur as u32, hs - 1));
                    }
                    cur = he as u64 + 1;
                    i += 1;
                }
                _ => {
                    out.push((cur as u32, e as u32));
                    break;
                }
            }
        }
    }
    out
}

/// Merge ranges and express the result as the fewest CIDR blocks.
pub fn aggregate(ranges: Vec<Range>) -> Vec<Cidr> {
    merge(ranges).into_iter().flat_map(|(s, e)| range_to_cidrs(s, e)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn ipv4_round_trip_including_high_octets() {
        for ip in ["0.0.0.0", "255.255.255.255", "10.0.0.1", "213.59.0.0", "192.168.1.76", "2.63.246.71"] {
            assert_eq!(fmt_ipv4(parse_ipv4(ip).unwrap()), ip);
        }
        assert_eq!(parse_ipv4("255.255.255.255"), Some(u32::MAX));
    }

    #[test]
    fn ipv4_rejects_garbage() {
        for bad in ["", "abc", "1.2.3", "1.2.3.256", "1.2.3.4.5", "1..3.4", "1.2.3.-4", "01234.1.1.1"] {
            assert_eq!(parse_ipv4(bad), None, "{bad}");
        }
    }

    #[test]
    fn cidr_parse_masks_host_bits_and_validates_length() {
        assert_eq!(c("10.1.2.3/24").to_string(), "10.1.2.0/24");
        assert_eq!(c("8.8.8.8").to_string(), "8.8.8.8/32");
        assert_eq!(c("0.0.0.0/0").last(), u32::MAX);
        assert!(Cidr::parse("1.2.3.0/33").is_none());
        assert!(Cidr::parse("1.2.3.0/x").is_none());
    }

    #[test]
    fn cidr_contains() {
        let n = c("213.59.0.0/16");
        assert!(n.contains(parse_ipv4("213.59.200.1").unwrap()));
        assert!(!n.contains(parse_ipv4("213.60.0.0").unwrap()));
        assert!(c("0.0.0.0/0").contains(parse_ipv4("8.8.8.8").unwrap()));
    }

    #[test]
    fn range_to_cidrs_matches_the_known_cases() {
        let r = |s: &str, n: u64| {
            let a = parse_ipv4(s).unwrap();
            range_to_cidrs(a, (a as u64 + n - 1) as u32).iter().map(|c| c.to_string()).collect::<Vec<_>>()
        };
        assert_eq!(r("10.0.0.0", 6), ["10.0.0.0/30", "10.0.0.4/31"]);
        assert_eq!(r("213.59.0.0", 65536), ["213.59.0.0/16"]);
        assert_eq!(r("37.9.96.0", 8192), ["37.9.96.0/19"]);
        assert_eq!(r("10.0.0.1", 1), ["10.0.0.1/32"]);
        assert_eq!(r("0.0.0.0", 1u64 << 32), ["0.0.0.0/0"]);
        assert_eq!(r("255.255.255.254", 2), ["255.255.255.254/31"]);
    }

    #[test]
    fn range_to_cidrs_covers_exactly_the_range() {
        let (s, e) = (parse_ipv4("10.0.0.3").unwrap(), parse_ipv4("10.0.3.200").unwrap());
        let blocks = range_to_cidrs(s, e);
        let total: u64 = blocks.iter().map(|b| b.last() as u64 - b.first() as u64 + 1).sum();
        assert_eq!(total, e as u64 - s as u64 + 1);
        assert_eq!(blocks.first().unwrap().first(), s);
        assert_eq!(blocks.last().unwrap().last(), e);
    }

    #[test]
    fn merge_joins_overlapping_and_touching() {
        assert_eq!(merge(vec![(10, 20), (21, 30), (5, 12), (40, 50)]), [(5, 30), (40, 50)]);
        assert_eq!(merge(vec![(0, u32::MAX), (5, 6)]), [(0, u32::MAX)]);
        assert_eq!(merge(vec![(u32::MAX - 1, u32::MAX), (0, 0)]), [(0, 0), (u32::MAX - 1, u32::MAX)]);
    }

    #[test]
    fn subtract_cuts_holes() {
        assert_eq!(subtract(vec![(0, 100)], vec![(10, 20), (50, 60)]), [(0, 9), (21, 49), (61, 100)]);
        assert_eq!(subtract(vec![(0, 100)], vec![(0, 100)]), []);
        assert_eq!(subtract(vec![(0, 100)], vec![(0, 10)]), [(11, 100)]);
        assert_eq!(subtract(vec![(0, 100)], vec![(90, 200)]), [(0, 89)]);
        assert_eq!(subtract(vec![(0, 10), (20, 30)], vec![(5, 25)]), [(0, 4), (26, 30)]);
        assert_eq!(subtract(vec![(0, u32::MAX)], vec![(0, 0), (u32::MAX, u32::MAX)]), [(1, u32::MAX - 1)]);
        assert_eq!(subtract(vec![(5, 9)], vec![]), [(5, 9)]);
    }

    #[test]
    fn aggregate_collapses_adjacent_blocks() {
        let ranges = vec![c("10.0.0.0/25").range(), c("10.0.0.128/25").range(), c("10.0.1.0/24").range()];
        let out: Vec<String> = aggregate(ranges).iter().map(|c| c.to_string()).collect();
        assert_eq!(out, ["10.0.0.0/23"]);
    }

    #[test]
    fn carving_a_slice_out_of_a_block_leaves_the_rest_routable() {
        let rest = subtract(vec![c("198.0.0.0/16").range()], vec![c("198.0.41.0/24").range()]);
        let blocks = aggregate(rest);
        assert!(blocks.iter().all(|b| !b.contains(parse_ipv4("198.0.41.7").unwrap())));
        assert!(blocks.iter().any(|b| b.contains(parse_ipv4("198.0.40.255").unwrap())));
        assert!(blocks.iter().any(|b| b.contains(parse_ipv4("198.0.42.0").unwrap())));
    }
}

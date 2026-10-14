//! Where the list of direct destinations comes from: the RIPE delegation file for a
//! country and the hand-maintained `manual.list`.

use crate::cidr::{self, Cidr, Range};
use std::io::{self, BufRead};

// ---------------------------------------------------------------------------
// RIPE "delegated-extended" statistics (RIR Statistics Exchange Format).
//
//   registry|cc|type|start|value|date|status[|opaque-id]
//   ripencc|RU|ipv4|213.59.0.0|65536|20090310|allocated|...
//
// For ipv4 `value` is the NUMBER OF ADDRESSES in the block, not a prefix length.
// The first line is a version header, summary lines have `*` as country.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
pub struct RipeList {
    pub ranges: Vec<Range>,
    /// Snapshot date (`YYYY-MM-DD`) taken from the file header.
    pub snapshot: Option<String>,
}

pub fn parse_ripe<R: BufRead>(reader: R, country: &str, statuses: &[&str]) -> io::Result<RipeList> {
    let mut out = RipeList::default();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        if out.snapshot.is_none() && f.len() >= 6 && f[0].bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            // Version header: version|registry|serial|records|startdate|enddate|UTCoffset.
            // `serial` is not a date; `enddate` is (fall back to `startdate`).
            out.snapshot = [f[5], f[4]]
                .iter()
                .find(|d| d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit()))
                .map(|d| format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..8]));
            continue;
        }
        if f.len() < 6 || f[1] != country || f[2] != "ipv4" || f[5] == "summary" {
            continue;
        }
        if let Some(status) = f.get(6) {
            if !status.is_empty() && !statuses.contains(status) {
                continue;
            }
        }
        let (Some(start), Ok(count)) = (cidr::parse_ipv4(f[3]), f[4].parse::<u64>()) else { continue };
        if count == 0 || start as u64 + count - 1 > u32::MAX as u64 {
            continue;
        }
        out.ranges.push((start, (start as u64 + count - 1) as u32));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// manual.list
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Direct,
    Vpn,
}

impl Verdict {
    pub fn word(self) -> &'static str {
        match self {
            Verdict::Direct => "direct",
            Verdict::Vpn => "vpn",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Net(Cidr),
    Host(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Net(c) => write!(f, "{c}"),
            Target::Host(h) => write!(f, "{h}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub verdict: Verdict,
    pub target: Target,
    /// Unix time after which the entry no longer applies; `None` = permanent.
    pub until: Option<u64>,
}

impl Entry {
    pub fn active(&self, now: u64) -> bool {
        self.until.is_none_or(|u| u > now)
    }
}

pub fn parse_target(s: &str) -> Result<Target, String> {
    if let Some(c) = Cidr::parse(s) {
        return Ok(Target::Net(c));
    }
    let looks_numeric = s.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b'/');
    let host = s.trim_end_matches('.').to_ascii_lowercase();
    let valid_chars = host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    if looks_numeric || !valid_chars || host.len() > 253 || !host.contains('.') || host.starts_with('.') || host.contains("..") {
        return Err(format!("`{s}` is neither an IPv4 address/CIDR nor a domain name"));
    }
    Ok(Target::Host(host))
}

/// `[direct|vpn] <target> [until=<ISO time | unix seconds>]  # comment`. `None` for blank/comment lines.
fn parse_line(raw: &str) -> Option<Result<Entry, String>> {
    let line = raw.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return None;
    }
    let mut words = line.split_whitespace().peekable();
    let verdict = match words.peek() {
        Some(&"direct") => {
            words.next();
            Verdict::Direct
        }
        Some(&"vpn") => {
            words.next();
            Verdict::Vpn
        }
        _ => Verdict::Direct,
    };
    let Some(target) = words.next() else { return Some(Err(format!("expected a target after the keyword in `{line}`"))) };
    let mut until = None;
    for extra in words {
        match extra.strip_prefix("until=").map(|v| (v, crate::log::parse_iso(v))) {
            Some((_, Some(t))) => until = Some(t),
            Some((v, None)) => return Some(Err(format!("bad time `{v}` (use 2026-10-14T18:00:00Z or unix seconds)"))),
            None => return Some(Err(format!("unexpected `{extra}` in `{line}`"))),
        }
    }
    Some(parse_target(target).map(|target| Entry { verdict, target, until }))
}

/// Parse the file; invalid lines are reported, not fatal. Expired entries are still returned.
pub fn parse_manual(text: &str) -> (Vec<Entry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        match parse_line(raw) {
            Some(Ok(e)) => entries.push(e),
            Some(Err(e)) => errors.push(format!("line {}: {e}", i + 1)),
            None => {}
        }
    }
    (entries, errors)
}

fn line_target(raw: &str) -> Option<Target> {
    parse_line(raw)?.ok().map(|e| e.target)
}

fn join_lines(lines: &[&str]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    }
}

/// Remove every line whose target equals `target`; returns the new text and how many lines went.
pub fn remove_target(text: &str, target: &Target) -> (String, usize) {
    let mut removed = 0;
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| {
            let hit = line_target(l).as_ref() == Some(target);
            removed += usize::from(hit);
            !hit
        })
        .collect();
    (join_lines(&kept), removed)
}

/// Set the verdict for `target` (optionally only until a time), replacing any previous line for it.
pub fn set_target(text: &str, verdict: Verdict, target: &Target, until: Option<u64>) -> String {
    let (mut out, _) = remove_target(text, target);
    out.push_str(&format!("{} {}", verdict.word(), target));
    if let Some(u) = until {
        out.push_str(&format!(" until={}", crate::log::iso(u)));
    }
    out.push('\n');
    out
}

/// Drop lines whose time has passed; returns the new text and the targets that expired.
pub fn drop_expired(text: &str, now: u64) -> (String, Vec<String>) {
    let mut expired = Vec::new();
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| match parse_line(l) {
            Some(Ok(e)) if !e.active(now) => {
                expired.push(e.target.to_string());
                false
            }
            _ => true,
        })
        .collect();
    (join_lines(&kept), expired)
}

/// Lines of a bulk file: one target per line, `#` comments allowed.
pub fn parse_target_list(text: &str) -> Result<Vec<Target>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if !line.is_empty() {
            out.push(parse_target(line).map_err(|e| format!("line {}: {e}", i + 1))?);
        }
    }
    Ok(out)
}

/// Final route set: (country ranges ∪ manual direct) − manual vpn, fully aggregated.
pub fn compose(country: Vec<Range>, direct: Vec<Range>, vpn: Vec<Range>) -> Vec<Cidr> {
    let mut all = country;
    all.extend(direct);
    cidr::aggregate(cidr::subtract(all, vpn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ripe(text: &str) -> RipeList {
        parse_ripe(Cursor::new(text), "RU", &["allocated", "assigned"]).unwrap()
    }

    #[test]
    fn ripe_keeps_only_country_ipv4_allocated_or_assigned() {
        let r = ripe(
            "2|ripencc|20261002|273655|19821001|20261001|+0000\n\
             # comment\n\
             ripencc|RU|ipv4|213.59.0.0|65536|20090310|allocated|a1b2c3\n\
             ripencc|RU|ipv4|5.228.0.0|65536|20110101|assigned|d4e5f6\n\
             ripencc|DE|ipv4|85.214.0.0|65536|20050101|allocated|zzzz\n\
             ripencc|RU|ipv6|2a02:6b8::|32|20090310|allocated|a1b2c3\n\
             ripencc|RU|asn|12345|1|20090310|allocated\n\
             ripencc|RU|ipv4|37.9.96.0|8192|20100101|available|aaaaaa\n\
             ripencc|*|ipv4|*|112500224|summary\n\
             garbage line\n\
             \n",
        );
        let blocks: Vec<String> = cidr::aggregate(r.ranges).iter().map(|c| c.to_string()).collect();
        assert_eq!(blocks, ["5.228.0.0/16", "213.59.0.0/16"]);
        assert_eq!(r.snapshot.as_deref(), Some("2026-10-01"));
    }

    #[test]
    fn ripe_status_filter_is_configurable() {
        let l = parse_ripe(Cursor::new("ripencc|RU|ipv4|37.9.96.0|8192|20100101|available|aaaaaa"), "RU", &["available"]).unwrap();
        assert_eq!(cidr::aggregate(l.ranges)[0].to_string(), "37.9.96.0/19");
    }

    #[test]
    fn ripe_ignores_blocks_that_overflow_the_address_space() {
        assert!(ripe("ripencc|RU|ipv4|255.255.255.0|512|20100101|allocated").ranges.is_empty());
        assert!(ripe("ripencc|RU|ipv4|10.0.0.0|0|20100101|allocated").ranges.is_empty());
    }

    #[test]
    fn manual_list_parses_verdicts_comments_and_reports_bad_lines() {
        let (e, errs) = parse_manual(
            "# header\n\
             1.2.3.0/24\n\
             direct Sberbank.ru   # bank\n\
             vpn 8.8.8.8\n\
             maybe example.com\n\
             1.2.3\n\
             \n",
        );
        assert_eq!(
            e,
            vec![
                Entry { verdict: Verdict::Direct, target: Target::Net(Cidr::parse("1.2.3.0/24").unwrap()), until: None },
                Entry { verdict: Verdict::Direct, target: Target::Host("sberbank.ru".into()), until: None },
                Entry { verdict: Verdict::Vpn, target: Target::Net(Cidr::parse("8.8.8.8").unwrap()), until: None },
            ]
        );
        assert_eq!(errs.len(), 2);
        assert!(errs[0].starts_with("line 5"));
        assert!(errs[1].starts_with("line 6"));
    }

    #[test]
    fn targets_reject_nonsense() {
        for bad in ["localhost", "a b", "-", "1.2.3.4.5", "ex ample.com", "..", "exa$mple.com"] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_target("Example.COM.").unwrap(), Target::Host("example.com".into()));
    }

    #[test]
    fn editing_the_list_keeps_comments_and_replaces_duplicates() {
        let text = "# keep me\ndirect sber.ru # note\n10.0.0.0/8\n";
        let sber = Target::Host("sber.ru".into());
        let edited = set_target(text, Verdict::Vpn, &sber, None);
        assert_eq!(edited, "# keep me\n10.0.0.0/8\nvpn sber.ru\n");
        let (after, n) = remove_target(&edited, &sber);
        assert_eq!((after.as_str(), n), ("# keep me\n10.0.0.0/8\n", 1));
        let (_, none) = remove_target(&after, &sber);
        assert_eq!(none, 0);
    }

    #[test]
    fn temporary_entries_carry_a_time_and_expire() {
        let (e, errs) =
            parse_manual("vpn 1.2.3.0/24 until=2026-10-14T18:00:00Z\nvpn 5.5.5.5 until=1000\nvpn 6.6.6.6 until=soon\nvpn 7.7.7.7 extra\n");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].until, crate::log::parse_iso("2026-10-14T18:00:00Z"));
        assert!(e[1].active(999) && !e[1].active(1000));
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn set_target_writes_a_readable_time_and_replaces_the_old_line() {
        let t = Target::Net(Cidr::parse("1.2.3.0/24").unwrap());
        let text = set_target("direct 1.2.3.0/24\n", Verdict::Vpn, &t, Some(1_791_981_000));
        assert_eq!(text, "vpn 1.2.3.0/24 until=2026-10-14T12:30:00Z\n");
        let (again, n) = remove_target(&text, &t);
        assert_eq!((again.as_str(), n), ("", 1), "a line with a time is found by its target");
    }

    #[test]
    fn expired_lines_are_dropped_and_reported() {
        let text = "# keep\nvpn 1.2.3.0/24 until=100\nvpn 5.5.5.5 until=300\ndirect sber.ru\n";
        let (out, gone) = drop_expired(text, 200);
        assert_eq!(
            out,
            "# keep\nvpn 5.5.5.5 until=1970-01-01T00:05:00Z\ndirect sber.ru\n".replace("until=1970-01-01T00:05:00Z", "until=300")
        );
        assert_eq!(gone, ["1.2.3.0/24"]);
    }

    #[test]
    fn bulk_lists_take_one_target_per_line() {
        let t = parse_target_list("# c\n1.2.3.0/24\n\nexample.com # x\n").unwrap();
        assert_eq!(t.len(), 2);
        assert!(parse_target_list("1.2.3.0/24\nnonsense\n").unwrap_err().starts_with("line 2"));
    }

    #[test]
    fn vpn_entries_cut_holes_in_the_country_list() {
        let country = vec![Cidr::parse("5.228.0.0/16").unwrap().range()];
        let direct = vec![Cidr::parse("1.1.1.1").unwrap().range()];
        let vpn = vec![Cidr::parse("5.228.1.0/24").unwrap().range(), Cidr::parse("1.1.1.1").unwrap().range()];
        let blocks = compose(country, direct, vpn);
        let ip = |s| cidr::parse_ipv4(s).unwrap();
        assert!(!blocks.iter().any(|b| b.contains(ip("5.228.1.9")) || b.contains(ip("1.1.1.1"))));
        assert!(blocks.iter().any(|b| b.contains(ip("5.228.0.255"))));
        assert!(blocks.iter().any(|b| b.contains(ip("5.228.2.0"))));
    }
}

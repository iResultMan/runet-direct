//! Minimal timestamped logging to stderr and, optionally, a size-capped file.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

static SINK: Mutex<Option<File>> = Mutex::new(None);

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `2026-10-14T12:30:00Z` for a unix timestamp.
pub fn iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Inverse of [`iso`]: `2026-10-14T12:30:00Z` -> unix seconds. A plain integer is taken as unix seconds.
pub fn parse_iso(s: &str) -> Option<u64> {
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    // Days-from-civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

/// Also write log lines to `path`; the previous file is kept once as `<path>.1`.
pub fn init_file(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if fs::metadata(path).map(|m| m.len() > MAX_LOG_BYTES).unwrap_or(false) {
        let _ = fs::rename(path, path.with_extension("log.1"));
    }
    if let Ok(f) = OpenOptions::new().create(true).append(true).open(path) {
        *SINK.lock().unwrap() = Some(f);
    }
}

fn emit(level: &str, msg: &str) {
    let line = format!("{} {level} {msg}", iso(now()));
    eprintln!("{line}");
    if let Some(f) = SINK.lock().unwrap().as_mut() {
        let _ = writeln!(f, "{line}");
    }
}

pub fn info(msg: impl AsRef<str>) {
    emit("INFO ", msg.as_ref());
}

pub fn warn(msg: impl AsRef<str>) {
    emit("WARN ", msg.as_ref());
}

pub fn error(msg: impl AsRef<str>) {
    emit("ERROR", msg.as_ref());
}

#[cfg(test)]
mod tests {
    use super::iso;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso(1_791_981_000), "2026-10-14T12:30:00Z");
    }

    #[test]
    fn parses_what_it_prints() {
        for t in [0, 951_782_400, 1_791_981_000, 4_102_444_799] {
            assert_eq!(super::parse_iso(&iso(t)), Some(t));
        }
        assert_eq!(super::parse_iso("1791981000"), Some(1_791_981_000));
        for bad in ["", "tomorrow", "2026-13-01T00:00:00Z", "2026-10-14 12:30:00", "2026-10-14T25:00:00Z"] {
            assert_eq!(super::parse_iso(bad), None, "{bad}");
        }
    }
}

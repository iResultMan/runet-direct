//! Orchestration: build the wanted route set, compare it with the kernel, repair the
//! difference, and run that in a loop as the daemon.

use crate::cidr::{self, Cidr, Family, Range};
use crate::config::{Config, Paths};
use crate::net::{make_plan, Installed, Net, Plan, Uplink};
use crate::sources::{self, Target, Verdict};
use crate::state::{Applied, Lock, Resolved, RuMeta, State};
use crate::{fetch, log};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::BufReader;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const HOST_TTL_SECS: u64 = 6 * 3600;
const LOCK_WAIT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Wanted route set
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Desired {
    pub v4: Vec<Cidr>,
    pub v6: Vec<Cidr>,
    /// Per family: the country list is on disk (or switched off), so absent routes may be pruned safely.
    pub prune_v4: bool,
    pub prune_v6: bool,
    pub warnings: Vec<String>,
}

impl Desired {
    pub fn routes(&self, fam: Family) -> &[Cidr] {
        match fam {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }

    pub fn prune_ok(&self, fam: Family) -> bool {
        match fam {
            Family::V4 => self.prune_v4,
            Family::V6 => self.prune_v6,
        }
    }
}

/// Country blocks from the cached list, split by family.
fn read_country(paths: &Paths) -> (Vec<Range>, Vec<Range>) {
    let Ok(text) = fs::read_to_string(paths.ru_file()) else { return (Vec::new(), Vec::new()) };
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for c in text.lines().filter_map(|l| Cidr::parse(l.trim())) {
        match c.fam {
            Family::V4 => v4.push(c.range()),
            Family::V6 => v6.push(c.range()),
        }
    }
    (v4, v6)
}

fn read_manual(paths: &Paths) -> (Vec<sources::Entry>, Vec<String>) {
    match fs::read_to_string(paths.manual_file()) {
        Ok(text) => sources::parse_manual(&text),
        Err(_) => (Vec::new(), Vec::new()),
    }
}

pub fn load_desired(paths: &Paths, cfg: &Config, state: &State, now: u64) -> Desired {
    let mut d = Desired::default();
    let (country4, country6) = if cfg.ru.enabled {
        let (c4, c6) = read_country(paths);
        d.prune_v4 = !c4.is_empty();
        d.prune_v6 = !c6.is_empty();
        if c4.is_empty() {
            d.warnings.push("country list not downloaded yet".into());
        }
        (c4, c6)
    } else {
        d.prune_v4 = true;
        d.prune_v6 = true;
        (Vec::new(), Vec::new())
    };

    let (entries, errors) = read_manual(paths);
    d.warnings.extend(errors);
    let mut direct: [Vec<Range>; 2] = [Vec::new(), Vec::new()];
    let mut vpn: [Vec<Range>; 2] = [Vec::new(), Vec::new()];
    let slot = |f: Family| usize::from(f == Family::V6);
    for e in entries.iter().filter(|e| e.active(now)) {
        let ranges: Vec<(Family, Range)> = match &e.target {
            Target::Net(c) => vec![(c.fam, c.range())],
            Target::Host(h) => state
                .resolved
                .get(h)
                .map(|r| {
                    r.ips.iter().filter_map(|ip| ip.parse::<IpAddr>().ok()).map(|ip| (Family::of(&ip), sources::host_range(&ip))).collect()
                })
                .unwrap_or_default(),
        };
        for (fam, range) in ranges {
            match e.verdict {
                Verdict::Direct => direct[slot(fam)].push(range),
                Verdict::Vpn => vpn[slot(fam)].push(range),
            }
        }
    }
    let [direct4, direct6] = direct;
    let [vpn4, vpn6] = vpn;
    d.v4 = sources::compose(Family::V4, country4, direct4, vpn4);
    d.v6 = sources::compose(Family::V6, country6, direct6, vpn6);
    d
}

/// Remove entries of manual.list whose time has passed (the lock is held by the caller).
fn expire_manual(paths: &Paths, now: u64) {
    let Ok(text) = fs::read_to_string(paths.manual_file()) else { return };
    let (cleaned, gone) = sources::drop_expired(&text, now);
    if !gone.is_empty() && crate::util::write_atomic(&paths.manual_file(), cleaned).is_ok() {
        log::info(format!("temporary entries expired: {}", gone.join(", ")));
    }
}

/// Seconds until the next temporary entry expires, so the daemon wakes up exactly then.
fn next_expiry(paths: &Paths, now: u64) -> Option<u64> {
    let (entries, _) = read_manual(paths);
    entries.iter().filter_map(|e| e.until).filter(|u| *u > now).min().map(|u| u - now)
}

/// Is everything currently sent through the VPN on purpose (`pause`)? `Some(None)` = until resumed.
pub fn paused(paths: &Paths, now: u64) -> Option<Option<u64>> {
    let (entries, _) = read_manual(paths);
    entries
        .iter()
        .find(|e| e.verdict == Verdict::Vpn && e.active(now) && matches!(&e.target, Target::Net(c) if c.len == 0))
        .map(|e| e.until)
}

fn resolve_host(host: &str) -> Vec<String> {
    let mut ips: Vec<String> = (host, 0u16).to_socket_addrs().map(|it| it.map(|a| a.ip().to_string()).collect()).unwrap_or_default();
    ips.sort();
    ips.dedup();
    ips
}

fn refresh_hosts(paths: &Paths, state: &mut State, now: u64, force: bool) {
    let (entries, _) = read_manual(paths);
    let hosts: HashSet<String> =
        entries.iter().filter_map(|e| if let Target::Host(h) = &e.target { Some(h.clone()) } else { None }).collect();
    state.resolved.retain(|h, _| hosts.contains(h));
    for h in hosts {
        let fresh = state.resolved.get(&h).is_some_and(|r| now.saturating_sub(r.at) < HOST_TTL_SECS && !r.ips.is_empty());
        if fresh && !force {
            continue;
        }
        let ips = resolve_host(&h);
        if ips.is_empty() {
            log::warn(format!("{h}: no addresses (keeping previous ones)"));
            if let Some(r) = state.resolved.get_mut(&h) {
                r.at = now.saturating_sub(HOST_TTL_SECS) + 600; // retry in ~10 minutes
            }
        } else {
            state.resolved.insert(h, Resolved { at: now, ips });
        }
    }
}

// ---------------------------------------------------------------------------
// Country list download
// ---------------------------------------------------------------------------

pub struct Fetched {
    pub v4: Vec<Cidr>,
    pub v6: Vec<Cidr>,
    pub snapshot: Option<String>,
}

pub fn fetch_country(cfg: &Config, paths: &Paths, bind_iface: Option<&str>) -> Result<Fetched, String> {
    // One file per process: a daemon and a one-shot command can never write into the same download.
    let tmp = paths.state_dir.join(format!("download.{}.tmp", std::process::id()));
    let _ = paths.ensure_dirs();
    log::info(format!("downloading {}", cfg.ru.source_url));
    let result = fetch::download(&cfg.ru.source_url, &tmp, bind_iface).and_then(|()| {
        let file = fs::File::open(&tmp).map_err(|e| e.to_string())?;
        let list = sources::parse_ripe(BufReader::new(file), &cfg.ru.country, &["allocated", "assigned"]).map_err(|e| e.to_string())?;
        let (v4, v6) = (cidr::aggregate(Family::V4, list.v4), cidr::aggregate(Family::V6, list.v6));
        if v4.len() < cfg.ru.min_prefixes {
            return Err(format!(
                "got {} IPv4 blocks for {} (minimum {}); looks like a truncated or wrong file",
                v4.len(),
                cfg.ru.country,
                cfg.ru.min_prefixes
            ));
        }
        if cfg.ipv6.enabled && v6.len() < cfg.ru.min_prefixes / 10 {
            return Err(format!(
                "got {} IPv6 blocks for {} (minimum {}); looks like a truncated or wrong file",
                v6.len(),
                cfg.ru.country,
                cfg.ru.min_prefixes / 10
            ));
        }
        Ok(Fetched { v4, v6, snapshot: list.snapshot })
    });
    let _ = fs::remove_file(&tmp);
    result
}

fn store_country(paths: &Paths, state: &mut State, f: &Fetched, now: u64) -> std::io::Result<()> {
    let mut text = String::with_capacity((f.v4.len() + f.v6.len()) * 20);
    for b in f.v4.iter().chain(&f.v6) {
        text.push_str(&b.to_string());
        text.push('\n');
    }
    let tmp = paths.ru_file().with_extension("txt.tmp");
    fs::write(&tmp, text)?;
    fs::rename(tmp, paths.ru_file())?;
    state.ru = Some(RuMeta { fetched_at: now, snapshot: f.snapshot.clone(), count: f.v4.len(), count_v6: f.v6.len() });
    state.last_refresh_error = None;
    Ok(())
}

fn needs_refresh(cfg: &Config, state: &State, now: u64) -> bool {
    if !cfg.ru.enabled {
        return false;
    }
    let since_attempt = now.saturating_sub(state.last_refresh_attempt);
    match &state.ru {
        None => since_attempt >= 120,
        Some(m) => now.saturating_sub(m.fetched_at) >= cfg.ru.refresh_days * 86_400 && since_attempt >= 3600,
    }
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize)]
pub struct FamilyReport {
    pub family: &'static str,
    pub uplink: Option<String>,
    pub wanted: usize,
    pub added: usize,
    pub removed: usize,
    pub kept: usize,
    /// What was done to the routing rule, if anything (restored, or moved above a VPN rule).
    pub rule_change: Option<String>,
    pub skipped: Option<String>,
}

impl FamilyReport {
    pub fn changed(&self) -> bool {
        self.added + self.removed > 0 || self.rule_change.is_some()
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub families: Vec<FamilyReport>,
}

impl Report {
    pub fn changed(&self) -> bool {
        self.families.iter().any(FamilyReport::changed)
    }

    fn sum(&self, f: impl Fn(&FamilyReport) -> usize) -> usize {
        self.families.iter().map(f).sum()
    }
}

fn key_of(fam: Family) -> String {
    fam.key().to_string()
}

/// Bring one family's routes (and, on Linux, rule) to the wanted state.
fn reconcile_family(cfg: &Config, net: &dyn Net, state: &mut State, desired: &Desired, fam: Family) -> Result<FamilyReport, String> {
    let wanted = desired.routes(fam);
    let mut report = FamilyReport { family: fam.label(), wanted: wanted.len(), ..FamilyReport::default() };
    let was_active = state.active.contains(&key_of(fam));

    // A machine without IPv6 must not turn into a permanent error: treat "cannot tell" as "none".
    let uplink = match net.uplink(cfg, fam) {
        Ok(u) => u,
        Err(e) if fam == Family::V6 => {
            report.skipped = Some(format!("IPv6 is not usable here ({e}); leaving it alone"));
            None
        }
        Err(e) => return Err(e),
    };
    // IPv4 always gets its rule restored (even while the link is briefly gone); IPv6 only once it is in use.
    if fam == Family::V4 || uplink.is_some() || was_active {
        report.rule_change = net.ensure_rule(cfg, fam, None)?;
    }
    let Some(uplink) = uplink else {
        report.skipped.get_or_insert_with(|| format!("no physical {} uplink found; leaving routes as they are", fam.label()));
        return Ok(report);
    };
    report.uplink = Some(uplink.describe());

    let mut ours: Vec<Uplink> = vec![uplink.clone()];
    ours.extend(state.uplinks.get(fam.key()).cloned());
    let mut candidates: HashSet<Cidr> = wanted.iter().copied().collect();
    candidates.extend(state.installed.iter().filter_map(|s| Cidr::parse(s)).filter(|c| c.fam == fam));

    let installed: Vec<Installed> = net.installed(cfg, fam, &candidates, &ours)?;
    let plan: Plan = make_plan(wanted, &installed, &uplink, desired.prune_ok(fam));
    report.kept = plan.keep;
    report.added = plan.add.len();
    report.removed = plan.remove.len();

    if !plan.is_empty() {
        net.apply(cfg, fam, &uplink, &plan)?;
    }
    if net.tracks_ownership() {
        state.installed.retain(|s| Cidr::parse(s).is_some_and(|c| c.fam != fam));
        state.installed.extend(wanted.iter().map(|c| c.to_string()));
    }
    state.uplinks.insert(key_of(fam), uplink);
    if !was_active {
        state.active.push(key_of(fam));
    }

    // With the routes in place, judge the rule by its effect: does a destination that must be direct
    // really leave through the physical link? If a VPN put its own rule in front, move ours above it.
    if let Some(moved) = net.ensure_rule(cfg, fam, wanted.first().map(Cidr::probe))? {
        report.rule_change = Some(match report.rule_change.take() {
            Some(first) => format!("{first}; {moved}"),
            None => moved,
        });
    }
    Ok(report)
}

/// Remove what we installed for a family that is no longer managed.
fn clear_family(cfg: &Config, net: &dyn Net, state: &mut State, fam: Family) -> Result<usize, String> {
    let candidates: HashSet<Cidr> = state.installed.iter().filter_map(|s| Cidr::parse(s)).filter(|c| c.fam == fam).collect();
    let ours: Vec<Uplink> = state.uplinks.get(fam.key()).cloned().into_iter().chain(net.uplink(cfg, fam).ok().flatten()).collect();
    let removed = net.clear(cfg, fam, &candidates, &ours)?;
    state.installed.retain(|s| Cidr::parse(s).is_some_and(|c| c.fam != fam));
    state.uplinks.remove(fam.key());
    state.active.retain(|a| a != fam.key());
    Ok(removed)
}

pub fn reconcile(cfg: &Config, net: &dyn Net, state: &mut State, desired: &Desired) -> Result<Report, String> {
    let mut report = Report::default();
    let mut errors = Vec::new();
    for fam in cfg.families() {
        match reconcile_family(cfg, net, state, desired, fam) {
            Ok(r) => report.families.push(r),
            Err(e) => errors.push(format!("{}: {e}", fam.label())),
        }
    }
    if report.sum(|f| f.added + f.removed) > 0 {
        let uplinks: Vec<String> = report.families.iter().filter_map(|f| f.uplink.as_ref().map(|u| format!("{}: {u}", f.family))).collect();
        state.last_apply = Some(Applied {
            at: log::now(),
            added: report.sum(|f| f.added),
            removed: report.sum(|f| f.removed),
            total: report.families.iter().filter(|f| f.uplink.is_some()).map(|f| f.wanted).sum(),
            uplink: uplinks.join("; "),
        });
    }
    if errors.is_empty() {
        Ok(report)
    } else {
        Err(errors.join("; "))
    }
}

#[derive(Default)]
pub struct CycleOpts {
    /// Download now, whatever the schedule says.
    pub force_refresh: bool,
    /// Download when the schedule says it is due. Only the daemon and explicit refreshes may: a quick
    /// command such as `add` must never hang on an 18 MB download.
    pub allow_fetch: bool,
}

pub struct Cycle {
    pub report: Report,
    pub desired: Desired,
}

/// One full pass: refresh data when due, then reconcile. Safe to call from the daemon and from CLI commands.
pub fn cycle(paths: &Paths, cfg: &Config, net: &dyn Net, opts: &CycleOpts) -> Result<Cycle, String> {
    let now = log::now();
    let pre = State::load(paths);
    let want_fetch = cfg.ru.enabled && (opts.force_refresh || (opts.allow_fetch && needs_refresh(cfg, &pre, now)));
    let fetched = if want_fetch {
        let dev = cfg.families().into_iter().find_map(|f| net.uplink(cfg, f).ok().flatten()).map(|u| u.dev);
        let dev = dev.filter(|d| d.parse::<u32>().is_err()); // Windows reports an index, not a name
        Some(fetch_country(cfg, paths, dev.as_deref()))
    } else {
        None
    };

    let _lock = Lock::acquire(paths, LOCK_WAIT)?;
    let mut state = State::load(paths);
    if let Some(result) = fetched {
        state.last_refresh_attempt = now;
        match result {
            Ok(f) => {
                store_country(paths, &mut state, &f, now).map_err(|e| format!("cannot store the country list: {e}"))?;
                log::info(format!(
                    "country list updated: {} IPv4 + {} IPv6 blocks (RIPE snapshot {})",
                    f.v4.len(),
                    f.v6.len(),
                    f.snapshot.as_deref().unwrap_or("unknown")
                ));
            }
            Err(e) => {
                log::warn(format!("country list download failed: {e}"));
                state.last_refresh_error = Some(e);
            }
        }
    }
    for fam in Family::ALL {
        if !cfg.enabled(fam) && state.active.contains(&key_of(fam)) {
            match clear_family(cfg, net, &mut state, fam) {
                Ok(n) => log::info(format!("{} is disabled: removed {n} routes", fam.label())),
                Err(e) => log::warn(format!("{} is disabled but cleaning up failed: {e}", fam.label())),
            }
        }
    }
    expire_manual(paths, now);
    refresh_hosts(paths, &mut state, now, opts.force_refresh);
    let desired = load_desired(paths, cfg, &state, now);
    let result = reconcile(cfg, net, &mut state, &desired);
    state.last_error = result.as_ref().err().cloned();
    let _ = state.save(paths);
    result.map(|report| Cycle { report, desired })
}

/// Remove everything we installed, for both families whether or not they are enabled.
pub fn clear(paths: &Paths, cfg: &Config, net: &dyn Net) -> Result<usize, String> {
    let _lock = Lock::acquire(paths, LOCK_WAIT)?;
    let mut state = State::load(paths);
    let mut total = 0;
    let mut errors = Vec::new();
    for fam in Family::ALL {
        match clear_family(cfg, net, &mut state, fam) {
            Ok(n) => total += n,
            Err(_) if fam == Family::V6 => {} // no IPv6 support on this machine: nothing to remove
            Err(e) => errors.push(format!("{}: {e}", fam.label())),
        }
    }
    let _ = state.save(paths);
    if errors.is_empty() {
        Ok(total)
    } else {
        Err(errors.join("; "))
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Sample {
    pub ip: String,
    pub dev: String,
    pub via: Option<String>,
    pub tunnel: bool,
}

#[derive(Debug, Serialize)]
pub struct FamilyHealth {
    pub family: &'static str,
    pub uplink: Option<String>,
    pub rule_present: bool,
    /// Linux: the priority of our `ip rule` right now (other tools should use a smaller number to be evaluated first).
    pub rule_priority: Option<u32>,
    pub wanted: usize,
    pub installed: usize,
    pub missing: usize,
    pub stale: usize,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Serialize)]
pub struct Health {
    pub healthy: bool,
    pub problems: Vec<String>,
    pub tunnels: Vec<String>,
    pub families: Vec<FamilyHealth>,
    pub country_blocks: Option<usize>,
    pub country_blocks_v6: Option<usize>,
    pub country_snapshot: Option<String>,
    pub country_age_days: Option<u64>,
    /// Everything is routed through the VPN on purpose; `Some(None)` means until `resume`.
    pub paused: Option<Option<u64>>,
}

fn family_health(cfg: &Config, net: &dyn Net, state: &State, desired: &Desired, fam: Family, problems: &mut Vec<String>) -> FamilyHealth {
    let tag = |m: String| if cfg.families().len() > 1 { format!("{}: {m}", fam.label()) } else { m };
    let wanted = desired.routes(fam);
    let mut h = FamilyHealth {
        family: fam.label(),
        uplink: None,
        rule_present: true,
        rule_priority: None,
        wanted: wanted.len(),
        installed: 0,
        missing: wanted.len(),
        stale: 0,
        samples: Vec::new(),
    };
    let was_active = state.active.contains(&key_of(fam));

    let uplink = net.uplink(cfg, fam).unwrap_or_else(|e| {
        if fam == Family::V4 || was_active {
            problems.push(tag(format!("cannot detect the uplink: {e}")));
        }
        None
    });
    let Some(up) = uplink else {
        // A machine may simply have no IPv6; that is a problem only if we were using it.
        if fam == Family::V4 || was_active {
            problems.push(tag("no physical uplink found".into()));
        } else {
            h.missing = 0;
        }
        return h;
    };
    h.uplink = Some(up.describe());

    h.rule_present = net.rule_present(cfg, fam).unwrap_or_else(|e| {
        problems.push(tag(format!("cannot read ip rules: {e}")));
        false
    });
    h.rule_priority = net.rule_priority(cfg, fam).unwrap_or(None);
    if !h.rule_present && net.name() == "linux" {
        problems.push(tag(format!("rule `from all lookup {}` (priority {}) is missing", cfg.routing.table, cfg.routing.priority)));
    }

    let mut candidates: HashSet<Cidr> = wanted.iter().copied().collect();
    candidates.extend(state.installed.iter().filter_map(|s| Cidr::parse(s)).filter(|c| c.fam == fam));
    let mut ours = vec![up.clone()];
    ours.extend(state.uplinks.get(fam.key()).cloned());
    match net.installed(cfg, fam, &candidates, &ours) {
        Ok(inst) => {
            let plan = make_plan(wanted, &inst, &up, true);
            h.installed = plan.keep;
            h.missing = plan.add.len();
            h.stale = plan.remove.len();
        }
        Err(e) => problems.push(tag(format!("cannot read the routing table: {e}"))),
    }
    if h.missing > 0 {
        problems.push(tag(format!("{} wanted routes are missing", h.missing)));
    }
    if h.stale > 0 {
        problems.push(tag(format!("{} routes do not match the wanted set", h.stale)));
    }

    let n = wanted.len();
    if n > 0 {
        let mut idx: Vec<usize> = (0..6).map(|i| i * (n - 1) / 5).collect();
        idx.dedup();
        for i in idx {
            let ip = wanted[i].probe();
            match net.lookup(cfg, ip) {
                Ok(l) => {
                    if l.tunnel {
                        problems.push(tag(format!("{ip} would leave through the tunnel {}", l.dev)));
                    }
                    h.samples.push(Sample { ip: ip.to_string(), dev: l.dev, via: l.via, tunnel: l.tunnel });
                }
                Err(e) => problems.push(tag(format!("route lookup for {ip} failed: {e}"))),
            }
        }
    }
    h
}

pub fn health(paths: &Paths, cfg: &Config, net: &dyn Net) -> Health {
    let now = log::now();
    let state = State::load(paths);
    let desired = load_desired(paths, cfg, &state, now);
    let mut problems = Vec::new();

    let families: Vec<FamilyHealth> =
        cfg.families().into_iter().map(|f| family_health(cfg, net, &state, &desired, f, &mut problems)).collect();

    let age = state.ru.as_ref().map(|m| now.saturating_sub(m.fetched_at) / 86_400);
    if cfg.ru.enabled {
        match (&state.ru, age) {
            (None, _) => problems.push(match &state.last_refresh_error {
                Some(e) => format!("country list not downloaded: {e}"),
                None => "country list not downloaded yet".into(),
            }),
            (Some(_), Some(a)) if a > cfg.ru.refresh_days * 2 => problems.push(format!(
                "country list is {a} days old (refresh failing: {})",
                state.last_refresh_error.as_deref().unwrap_or("unknown")
            )),
            _ => {}
        }
    }
    problems.extend(desired.warnings.iter().filter(|w| !w.starts_with("country list not downloaded")).cloned());

    Health {
        healthy: problems.is_empty(),
        problems,
        tunnels: net.tunnels(),
        families,
        country_blocks: state.ru.as_ref().map(|m| m.count),
        country_blocks_v6: state.ru.as_ref().map(|m| m.count_v6),
        country_snapshot: state.ru.as_ref().and_then(|m| m.snapshot.clone()),
        country_age_days: age,
        paused: paused(paths, now),
    }
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

fn spawn_watcher(cmd: Vec<String>, ignore: Vec<String>) -> Receiver<()> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || loop {
        use std::io::BufRead;
        let child = Command::new(&cmd[0]).args(&cmd[1..]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
        match child {
            Ok(mut child) => {
                if let Some(out) = child.stdout.take() {
                    for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                        if !ignore.iter().any(|i| line.contains(i.as_str())) {
                            let _ = tx.send(());
                        }
                    }
                }
                let _ = child.wait();
            }
            Err(e) => log::warn(format!("cannot start `{}` for change notifications: {e}", cmd[0])),
        }
        std::thread::sleep(Duration::from_secs(5));
    });
    rx
}

/// Wait until the event stream is quiet (our own changes echo through it). Returns whether anything
/// arrived, because that may include a real change that must not be lost: the caller runs another
/// pass, which is a no-op when it was only the echo.
fn settle(rx: &Receiver<()>) -> bool {
    let start = Instant::now();
    let mut seen = false;
    while start.elapsed() < Duration::from_secs(20) && rx.recv_timeout(Duration::from_millis(1500)).is_ok() {
        seen = true;
    }
    seen
}

pub fn run_daemon(paths: &Paths, net: &dyn Net) -> ! {
    log::info(format!("runet-direct {} started ({})", env!("CARGO_PKG_VERSION"), net.name()));
    let mut cfg = Config::default();
    if let Ok(c) = Config::load(&paths.config_file()) {
        cfg = c;
    }
    let events = net.watch_command().map(|cmd| spawn_watcher(cmd, net.echo_filters(&cfg)));
    let mut last_err = String::new();
    let mut last_uplinks: BTreeMap<&'static str, Option<String>> = BTreeMap::new();
    let mut last_skipped: BTreeMap<&'static str, Option<String>> = BTreeMap::new();
    let mut rerun = false;

    loop {
        match Config::load(&paths.config_file()) {
            Ok(c) => cfg = c,
            Err(e) => {
                if e != last_err {
                    log::error(format!("config error (keeping previous settings): {e}"));
                    last_err = e;
                }
            }
        }
        match cycle(paths, &cfg, net, &CycleOpts { allow_fetch: true, ..CycleOpts::default() }) {
            Ok(c) => {
                last_err.clear();
                for f in &c.report.families {
                    if last_uplinks.get(f.family) != Some(&f.uplink) {
                        log::info(format!("{} uplink: {}", f.family, f.uplink.as_deref().unwrap_or("none")));
                        last_uplinks.insert(f.family, f.uplink.clone());
                    }
                    if last_skipped.get(f.family) != Some(&f.skipped) {
                        if let Some(s) = &f.skipped {
                            // Having no IPv6 at all is normal; having no IPv4 uplink is worth a warning.
                            if f.family == "IPv6" {
                                log::info(s);
                            } else {
                                log::warn(s);
                            }
                        }
                        last_skipped.insert(f.family, f.skipped.clone());
                    }
                }
                if c.report.changed() {
                    let parts: Vec<String> = c
                        .report
                        .families
                        .iter()
                        .filter(|f| f.changed())
                        .map(|f| {
                            let rule = f.rule_change.as_deref().map(|r| format!("; {r}")).unwrap_or_default();
                            format!("{}: +{} -{} (total {}){rule}", f.family, f.added, f.removed, f.wanted)
                        })
                        .collect();
                    log::info(format!("synced: {}", parts.join(" | ")));
                    // Our own changes echo through the watcher; wait until it is quiet again.
                    if let Some(rx) = &events {
                        rerun = settle(rx);
                    }
                }
            }
            Err(e) => {
                if e != last_err {
                    log::error(&e);
                    last_err = e;
                }
            }
        }
        if std::mem::take(&mut rerun) {
            // A flapping link must not turn into a tight loop of `ip` commands.
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let mut wait = Duration::from_secs(cfg.daemon.interval_seconds.max(5));
        if let Some(secs) = next_expiry(paths, log::now()) {
            wait = wait.min(Duration::from_secs(secs + 1));
        }
        match &events {
            Some(rx) => match rx.recv_timeout(wait) {
                Ok(()) => {
                    std::thread::sleep(Duration::from_millis(500));
                    settle(rx);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(wait),
            },
            None => std::thread::sleep(wait),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Lookup;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeNet {
        uplinks: RefCell<BTreeMap<Family, Uplink>>,
        table: RefCell<Vec<Installed>>,
        rules: RefCell<HashSet<Family>>,
        applied: RefCell<usize>,
    }

    impl FakeNet {
        fn with(v4: Option<Uplink>, v6: Option<Uplink>) -> FakeNet {
            let n = FakeNet::default();
            n.set(Family::V4, v4);
            n.set(Family::V6, v6);
            n
        }
        fn set(&self, fam: Family, u: Option<Uplink>) {
            match u {
                Some(u) => self.uplinks.borrow_mut().insert(fam, u),
                None => self.uplinks.borrow_mut().remove(&fam),
            };
        }
        fn count(&self, fam: Family) -> usize {
            self.table.borrow().iter().filter(|i| i.prefix.fam == fam).count()
        }
    }

    impl Net for FakeNet {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn require_admin(&self) -> Result<(), String> {
            Ok(())
        }
        fn uplink(&self, _: &Config, fam: Family) -> Result<Option<Uplink>, String> {
            Ok(self.uplinks.borrow().get(&fam).cloned())
        }
        fn tunnels(&self) -> Vec<String> {
            vec![]
        }
        fn ensure_rule(&self, _: &Config, fam: Family, _: Option<IpAddr>) -> Result<Option<String>, String> {
            Ok(self.rules.borrow_mut().insert(fam).then(|| "rule restored".to_string()))
        }
        fn rule_present(&self, _: &Config, fam: Family) -> Result<bool, String> {
            Ok(self.rules.borrow().contains(&fam))
        }
        fn installed(&self, _: &Config, fam: Family, _: &HashSet<Cidr>, _: &[Uplink]) -> Result<Vec<Installed>, String> {
            Ok(self.table.borrow().iter().filter(|i| i.prefix.fam == fam).cloned().collect())
        }
        fn apply(&self, _: &Config, _: Family, up: &Uplink, plan: &Plan) -> Result<(), String> {
            *self.applied.borrow_mut() += 1;
            let mut t = self.table.borrow_mut();
            t.retain(|i| !plan.remove.contains(i));
            for p in &plan.add {
                t.push(Installed { prefix: *p, via: up.via.clone(), dev: up.dev.clone() });
            }
            Ok(())
        }
        fn clear(&self, _: &Config, fam: Family, _: &HashSet<Cidr>, _: &[Uplink]) -> Result<usize, String> {
            let before = self.count(fam);
            self.table.borrow_mut().retain(|i| i.prefix.fam != fam);
            self.rules.borrow_mut().remove(&fam);
            Ok(before)
        }
        fn lookup(&self, _: &Config, _: IpAddr) -> Result<Lookup, String> {
            unimplemented!()
        }
        fn watch_command(&self) -> Option<Vec<String>> {
            None
        }
        fn tracks_ownership(&self) -> bool {
            false
        }
    }

    fn up(via: &str) -> Uplink {
        Uplink { dev: "eth0".into(), via: Some(via.into()) }
    }

    fn v4only() -> Config {
        let mut c = Config::default();
        c.ipv6.enabled = false;
        c
    }

    fn desired(v4: &[&str], v6: &[&str], prune_ok: bool) -> Desired {
        let parse = |l: &[&str]| l.iter().map(|b| Cidr::parse(b).unwrap()).collect();
        Desired { v4: parse(v4), v6: parse(v6), prune_v4: prune_ok, prune_v6: prune_ok, ..Desired::default() }
    }

    #[test]
    fn first_pass_installs_rule_and_routes_and_second_pass_is_quiet() {
        let net = FakeNet::with(Some(up("10.0.0.1")), None);
        let (cfg, mut st) = (v4only(), State::default());
        let d = desired(&["5.0.0.0/8", "6.0.0.0/8"], &[], true);
        let r1 = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert_eq!((r1.sum(|f| f.added), r1.sum(|f| f.removed), r1.changed()), (2, 0, true));
        assert!(r1.families[0].rule_change.is_some());
        let r2 = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert!(!r2.changed());
        assert_eq!(*net.applied.borrow(), 1);
    }

    #[test]
    fn a_vanished_rule_is_restored_even_without_route_changes() {
        let net = FakeNet::with(Some(up("10.0.0.1")), None);
        let (cfg, mut st) = (v4only(), State::default());
        let d = desired(&["5.0.0.0/8"], &[], true);
        reconcile(&cfg, &net, &mut st, &d).unwrap();
        net.rules.borrow_mut().clear(); // tethering removed the rule
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert!(r.families[0].rule_change.is_some() && r.sum(|f| f.added) == 0);
    }

    #[test]
    fn a_new_gateway_repoints_every_route() {
        let net = FakeNet::with(Some(up("10.0.0.1")), None);
        let (cfg, mut st) = (v4only(), State::default());
        let d = desired(&["5.0.0.0/8", "6.0.0.0/8"], &[], true);
        reconcile(&cfg, &net, &mut st, &d).unwrap();
        net.set(Family::V4, Some(up("192.168.1.1")));
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert_eq!((r.sum(|f| f.added), r.sum(|f| f.removed)), (2, 2));
        assert!(net.table.borrow().iter().all(|i| i.via.as_deref() == Some("192.168.1.1")));
    }

    #[test]
    fn without_an_uplink_nothing_is_touched_but_the_rule_is_kept() {
        let net = FakeNet::with(Some(up("10.0.0.1")), None);
        let (cfg, mut st) = (v4only(), State::default());
        let d = desired(&["5.0.0.0/8"], &[], true);
        reconcile(&cfg, &net, &mut st, &d).unwrap();
        net.set(Family::V4, None);
        net.rules.borrow_mut().clear();
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert!(r.families[0].skipped.is_some() && r.families[0].rule_change.is_some());
        assert_eq!(net.table.borrow().len(), 1, "routes must survive a lost uplink");
    }

    #[test]
    fn a_missing_country_list_never_wipes_the_table() {
        let net = FakeNet::with(Some(up("10.0.0.1")), None);
        let (cfg, mut st) = (v4only(), State::default());
        reconcile(&cfg, &net, &mut st, &desired(&["5.0.0.0/8", "6.0.0.0/8"], &[], true)).unwrap();
        let r = reconcile(&cfg, &net, &mut st, &desired(&["7.0.0.0/8"], &[], false)).unwrap();
        assert_eq!((r.sum(|f| f.added), r.sum(|f| f.removed)), (1, 0));
        assert_eq!(net.table.borrow().len(), 3);
    }

    #[test]
    fn removing_a_target_removes_its_route() {
        let net = FakeNet::with(Some(up("10.0.0.1")), None);
        let (cfg, mut st) = (v4only(), State::default());
        reconcile(&cfg, &net, &mut st, &desired(&["5.0.0.0/8", "6.0.0.0/8"], &[], true)).unwrap();
        let r = reconcile(&cfg, &net, &mut st, &desired(&["5.0.0.0/8"], &[], true)).unwrap();
        assert_eq!((r.sum(|f| f.added), r.sum(|f| f.removed)), (0, 1));
    }

    #[test]
    fn both_families_are_reconciled_independently() {
        let net = FakeNet::with(Some(up("10.0.0.1")), Some(up("fe80::1")));
        let (cfg, mut st) = (Config::default(), State::default());
        let d = desired(&["5.0.0.0/8"], &["2a00:1450::/32", "2a02:6b8::/32"], true);
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert_eq!((net.count(Family::V4), net.count(Family::V6)), (1, 2));
        assert_eq!(r.families.len(), 2);
        assert!(st.active.contains(&"ipv4".to_string()) && st.active.contains(&"ipv6".to_string()));
        // The IPv6 gateway changes; IPv4 must not be touched.
        net.set(Family::V6, Some(up("fe80::2")));
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert_eq!((r.families[0].changed(), r.families[1].added, r.families[1].removed), (false, 2, 2));
    }

    #[test]
    fn a_machine_without_ipv6_stays_quiet() {
        let net = FakeNet::with(Some(up("10.0.0.1")), None);
        let (cfg, mut st) = (Config::default(), State::default());
        let r = reconcile(&cfg, &net, &mut st, &desired(&["5.0.0.0/8"], &["2a00:1450::/32"], true)).unwrap();
        assert_eq!(net.count(Family::V6), 0);
        assert!(!net.rules.borrow().contains(&Family::V6), "no IPv6 rule is created without an IPv6 uplink");
        assert!(!st.active.contains(&"ipv6".to_string()));
        assert!(r.families[1].skipped.is_some());
    }

    #[test]
    fn a_disabled_family_is_cleaned_up_once_and_then_left_alone() {
        let net = FakeNet::with(Some(up("10.0.0.1")), Some(up("fe80::1")));
        let (cfg, mut st) = (Config::default(), State::default());
        let d = desired(&["5.0.0.0/8"], &["2a00:1450::/32"], true);
        reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert_eq!(net.count(Family::V6), 1);

        let off = v4only();
        assert!(st.active.contains(&"ipv6".to_string()));
        assert_eq!(clear_family(&off, &net, &mut st, Family::V6).unwrap(), 1);
        assert_eq!(net.count(Family::V6), 0);
        assert!(!st.active.contains(&"ipv6".to_string()));
        let r = reconcile(&off, &net, &mut st, &d).unwrap();
        assert_eq!(r.families.len(), 1, "a disabled family is not reconciled");
        assert_eq!(net.count(Family::V4), 1, "the other family is untouched");
    }

    #[test]
    fn refresh_schedule() {
        let cfg = Config::default();
        let mut st = State::default();
        assert!(needs_refresh(&cfg, &st, 100_000_000), "no list yet -> fetch");
        st.last_refresh_attempt = 99_999_950;
        assert!(!needs_refresh(&cfg, &st, 100_000_000), "just failed -> back off");
        st.ru = Some(RuMeta { fetched_at: 100_000_000 - 3 * 86_400, snapshot: None, count: 1, count_v6: 0 });
        st.last_refresh_attempt = 0;
        assert!(!needs_refresh(&cfg, &st, 100_000_000), "fresh list");
        st.ru = Some(RuMeta { fetched_at: 100_000_000 - 31 * 86_400, snapshot: None, count: 1, count_v6: 0 });
        assert!(needs_refresh(&cfg, &st, 100_000_000), "stale list");
        let mut off = Config::default();
        off.ru.enabled = false;
        assert!(!needs_refresh(&off, &st, 100_000_000));
    }
}

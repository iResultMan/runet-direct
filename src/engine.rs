//! Orchestration: build the wanted route set, compare it with the kernel, repair the
//! difference, and run that in a loop as the daemon.

use crate::cidr::{self, Cidr, Range};
use crate::config::{Config, Paths};
use crate::net::{make_plan, Installed, Net, Plan, Uplink};
use crate::sources::{self, Target, Verdict};
use crate::state::{Applied, Lock, Resolved, RuMeta, State};
use crate::{fetch, log};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::BufReader;
use std::net::ToSocketAddrs;
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
    pub routes: Vec<Cidr>,
    /// The country list is on disk (or switched off), so absent routes may be pruned safely.
    pub prune_ok: bool,
    pub country_blocks: usize,
    pub manual_direct: usize,
    pub manual_vpn: usize,
    pub warnings: Vec<String>,
}

fn read_country(paths: &Paths) -> Option<Vec<Range>> {
    let text = fs::read_to_string(paths.ru_file()).ok()?;
    let ranges: Vec<Range> = text.lines().filter_map(|l| Cidr::parse(l.trim())).map(|c| c.range()).collect();
    (!ranges.is_empty()).then_some(ranges)
}

fn read_manual(paths: &Paths) -> (Vec<sources::Entry>, Vec<String>) {
    match fs::read_to_string(paths.manual_file()) {
        Ok(text) => sources::parse_manual(&text),
        Err(_) => (Vec::new(), Vec::new()),
    }
}

pub fn load_desired(paths: &Paths, cfg: &Config, state: &State, now: u64) -> Desired {
    let mut d = Desired::default();
    let country = if cfg.ru.enabled {
        match read_country(paths) {
            Some(r) => {
                d.prune_ok = true;
                r
            }
            None => {
                d.warnings.push("country list not downloaded yet".into());
                Vec::new()
            }
        }
    } else {
        d.prune_ok = true;
        Vec::new()
    };
    d.country_blocks = country.len();

    let (entries, errors) = read_manual(paths);
    d.warnings.extend(errors);
    let (mut direct, mut vpn): (Vec<Range>, Vec<Range>) = (Vec::new(), Vec::new());
    for e in entries.iter().filter(|e| e.active(now)) {
        let ranges: Vec<Range> = match &e.target {
            Target::Net(c) => vec![c.range()],
            Target::Host(h) => state
                .resolved
                .get(h)
                .map(|r| r.ips.iter().filter_map(|ip| cidr::parse_ipv4(ip)).map(|a| (a, a)).collect())
                .unwrap_or_default(),
        };
        match e.verdict {
            Verdict::Direct => {
                d.manual_direct += 1;
                direct.extend(ranges)
            }
            Verdict::Vpn => {
                d.manual_vpn += 1;
                vpn.extend(ranges)
            }
        }
    }
    d.routes = sources::compose(country, direct, vpn);
    d
}

/// Remove entries of manual.list whose time has passed (the lock is held by the caller).
fn expire_manual(paths: &Paths, now: u64) {
    let Ok(text) = fs::read_to_string(paths.manual_file()) else { return };
    let (cleaned, gone) = sources::drop_expired(&text, now);
    if !gone.is_empty() && fs::write(paths.manual_file(), cleaned).is_ok() {
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
    let all = Target::Net(Cidr { addr: 0, len: 0 });
    entries.iter().find(|e| e.verdict == Verdict::Vpn && e.target == all && e.active(now)).map(|e| e.until)
}

fn resolve_host(host: &str) -> Vec<String> {
    let mut ips: Vec<String> = (host, 0u16)
        .to_socket_addrs()
        .map(|it| it.filter_map(|a| if let std::net::SocketAddr::V4(v) = a { Some(v.ip().to_string()) } else { None }).collect())
        .unwrap_or_default();
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
            log::warn(format!("{h}: no IPv4 addresses (keeping previous ones)"));
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
    pub blocks: Vec<Cidr>,
    pub snapshot: Option<String>,
}

pub fn fetch_country(cfg: &Config, paths: &Paths, bind_iface: Option<&str>) -> Result<Fetched, String> {
    let tmp = paths.state_dir.join("download.tmp");
    let _ = paths.ensure_dirs();
    log::info(format!("downloading {}", cfg.ru.source_url));
    let result = fetch::download(&cfg.ru.source_url, &tmp, bind_iface).and_then(|()| {
        let file = fs::File::open(&tmp).map_err(|e| e.to_string())?;
        let list = sources::parse_ripe(BufReader::new(file), &cfg.ru.country, &["allocated", "assigned"]).map_err(|e| e.to_string())?;
        let blocks = cidr::aggregate(list.ranges);
        if blocks.len() < cfg.ru.min_prefixes {
            return Err(format!(
                "got {} blocks for {} (minimum {}); looks like a truncated or wrong file",
                blocks.len(),
                cfg.ru.country,
                cfg.ru.min_prefixes
            ));
        }
        Ok(Fetched { blocks, snapshot: list.snapshot })
    });
    let _ = fs::remove_file(&tmp);
    result
}

fn store_country(paths: &Paths, state: &mut State, f: &Fetched, now: u64) -> std::io::Result<()> {
    let mut text = String::with_capacity(f.blocks.len() * 18);
    for b in &f.blocks {
        text.push_str(&b.to_string());
        text.push('\n');
    }
    let tmp = paths.ru_file().with_extension("txt.tmp");
    fs::write(&tmp, text)?;
    fs::rename(tmp, paths.ru_file())?;
    state.ru = Some(RuMeta { fetched_at: now, snapshot: f.snapshot.clone(), count: f.blocks.len() });
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
pub struct Report {
    pub uplink: Option<String>,
    pub wanted: usize,
    pub added: usize,
    pub removed: usize,
    pub kept: usize,
    /// What was done to the routing rule, if anything (restored, or moved above a VPN rule).
    pub rule_change: Option<String>,
    pub skipped: Option<String>,
}

impl Report {
    pub fn changed(&self) -> bool {
        self.added + self.removed > 0 || self.rule_change.is_some()
    }
}

pub fn reconcile(cfg: &Config, net: &dyn Net, state: &mut State, desired: &Desired) -> Result<Report, String> {
    let mut report = Report { wanted: desired.routes.len(), ..Report::default() };
    report.rule_change = net.ensure_rule(cfg, None)?;

    let Some(uplink) = net.uplink(cfg)? else {
        report.skipped = Some("no physical uplink found; leaving routes as they are".into());
        return Ok(report);
    };
    report.uplink = Some(uplink.describe());

    let mut ours: Vec<Uplink> = vec![uplink.clone()];
    ours.extend(state.installed_uplink.clone());
    let mut candidates: HashSet<Cidr> = desired.routes.iter().copied().collect();
    candidates.extend(state.installed.iter().filter_map(|s| Cidr::parse(s)));

    let installed: Vec<Installed> = net.installed(cfg, &candidates, &ours)?;
    let plan: Plan = make_plan(&desired.routes, &installed, &uplink, desired.prune_ok);
    report.kept = plan.keep;
    report.added = plan.add.len();
    report.removed = plan.remove.len();

    if !plan.is_empty() {
        net.apply(cfg, &uplink, &plan)?;
        state.last_apply =
            Some(Applied { at: log::now(), added: report.added, removed: report.removed, total: report.wanted, uplink: uplink.describe() });
    }
    if net.tracks_ownership() {
        state.installed = desired.routes.iter().map(|c| c.to_string()).collect();
    }
    state.installed_uplink = Some(uplink);

    // With the routes in place, judge the rule by its effect: does a destination that must be direct
    // really leave through the physical link? If a VPN put its own rule in front, move ours above it.
    let probe = desired.routes.first().map(probe_address);
    if let Some(moved) = net.ensure_rule(cfg, probe)? {
        report.rule_change = Some(match report.rule_change.take() {
            Some(first) => format!("{first}; {moved}"),
            None => moved,
        });
    }
    Ok(report)
}

/// An address inside `block` that is neither its network nor broadcast address.
fn probe_address(block: &Cidr) -> u32 {
    if block.len >= 31 {
        block.first()
    } else {
        block.first() + 1
    }
}

#[derive(Default)]
pub struct CycleOpts {
    pub force_refresh: bool,
}

pub struct Cycle {
    pub report: Report,
    pub desired: Desired,
}

/// One full pass: refresh data when due, then reconcile. Safe to call from the daemon and from CLI commands.
pub fn cycle(paths: &Paths, cfg: &Config, net: &dyn Net, opts: &CycleOpts) -> Result<Cycle, String> {
    let now = log::now();
    let pre = State::load(paths);
    let want_fetch = cfg.ru.enabled && (opts.force_refresh || needs_refresh(cfg, &pre, now));
    let fetched = if want_fetch {
        let dev = net.uplink(cfg).ok().flatten().map(|u| u.dev);
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
                    "country list updated: {} blocks (RIPE snapshot {})",
                    f.blocks.len(),
                    f.snapshot.as_deref().unwrap_or("unknown")
                ));
            }
            Err(e) => {
                log::warn(format!("country list download failed: {e}"));
                state.last_refresh_error = Some(e);
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

/// Remove everything we installed.
pub fn clear(paths: &Paths, cfg: &Config, net: &dyn Net) -> Result<usize, String> {
    let _lock = Lock::acquire(paths, LOCK_WAIT)?;
    let mut state = State::load(paths);
    let desired = load_desired(paths, cfg, &state, log::now());
    let mut candidates: HashSet<Cidr> = desired.routes.iter().copied().collect();
    candidates.extend(state.installed.iter().filter_map(|s| Cidr::parse(s)));
    let mut ours: Vec<Uplink> = state.installed_uplink.clone().into_iter().collect();
    ours.extend(net.uplink(cfg).ok().flatten());
    let removed = net.clear(cfg, &candidates, &ours)?;
    state.installed.clear();
    state.installed_uplink = None;
    let _ = state.save(paths);
    Ok(removed)
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
pub struct Health {
    pub healthy: bool,
    pub problems: Vec<String>,
    pub uplink: Option<String>,
    pub tunnels: Vec<String>,
    pub rule_present: bool,
    pub wanted: usize,
    pub installed: usize,
    pub missing: usize,
    pub stale: usize,
    pub country_blocks: Option<usize>,
    pub country_snapshot: Option<String>,
    pub country_age_days: Option<u64>,
    pub samples: Vec<Sample>,
    /// Everything is routed through the VPN on purpose; `Some(None)` means until `resume`.
    pub paused: Option<Option<u64>>,
}

pub fn health(paths: &Paths, cfg: &Config, net: &dyn Net) -> Health {
    let now = log::now();
    let state = State::load(paths);
    let desired = load_desired(paths, cfg, &state, now);
    let mut problems = Vec::new();

    let rule_present = net.rule_present(cfg).unwrap_or_else(|e| {
        problems.push(format!("cannot read ip rules: {e}"));
        false
    });
    if !rule_present && net.name() == "linux" {
        problems.push(format!("rule `from all lookup {}` (priority {}) is missing", cfg.routing.table, cfg.routing.priority));
    }

    let uplink = net.uplink(cfg).unwrap_or_else(|e| {
        problems.push(format!("cannot detect the uplink: {e}"));
        None
    });
    if uplink.is_none() {
        problems.push("no physical uplink found".into());
    }

    let (mut installed_ok, mut missing, mut stale) = (0, desired.routes.len(), 0);
    if let Some(up) = &uplink {
        let mut candidates: HashSet<Cidr> = desired.routes.iter().copied().collect();
        candidates.extend(state.installed.iter().filter_map(|s| Cidr::parse(s)));
        let mut ours = vec![up.clone()];
        ours.extend(state.installed_uplink.clone());
        match net.installed(cfg, &candidates, &ours) {
            Ok(inst) => {
                let plan = make_plan(&desired.routes, &inst, up, true);
                installed_ok = plan.keep;
                missing = plan.add.len();
                stale = plan.remove.len();
            }
            Err(e) => problems.push(format!("cannot read the routing table: {e}")),
        }
    }
    if missing > 0 {
        problems.push(format!("{missing} wanted routes are missing"));
    }
    if stale > 0 {
        problems.push(format!("{stale} routes do not match the wanted set"));
    }

    let mut samples = Vec::new();
    let n = desired.routes.len();
    if n > 0 {
        let mut idx: Vec<usize> = (0..6).map(|i| i * (n - 1) / 5).collect();
        idx.dedup();
        for i in idx {
            let ip = probe_address(&desired.routes[i]);
            match net.lookup(cfg, ip) {
                Ok(l) => {
                    if l.tunnel {
                        problems.push(format!("{} would leave through the tunnel {}", cidr::fmt_ipv4(ip), l.dev));
                    }
                    samples.push(Sample { ip: cidr::fmt_ipv4(ip), dev: l.dev, via: l.via, tunnel: l.tunnel });
                }
                Err(e) => problems.push(format!("route lookup for {} failed: {e}", cidr::fmt_ipv4(ip))),
            }
        }
    }

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
        uplink: uplink.map(|u| u.describe()),
        tunnels: net.tunnels(),
        rule_present,
        wanted: desired.routes.len(),
        installed: installed_ok,
        missing,
        stale,
        country_blocks: state.ru.as_ref().map(|m| m.count),
        country_snapshot: state.ru.as_ref().and_then(|m| m.snapshot.clone()),
        country_age_days: age,
        samples,
        paused: paused(paths, now),
    }
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

fn spawn_watcher(cmd: Vec<String>, ignore: String) -> Receiver<()> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || loop {
        use std::io::BufRead;
        let child = Command::new(&cmd[0]).args(&cmd[1..]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
        match child {
            Ok(mut child) => {
                if let Some(out) = child.stdout.take() {
                    for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                        if ignore.is_empty() || !line.contains(&ignore) {
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

fn run_hook(cmd: &str, changed: bool) {
    if cmd.trim().is_empty() {
        return;
    }
    let mut c = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", cmd]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", cmd]);
        c
    };
    c.env("RUNET_DIRECT_CHANGED", if changed { "1" } else { "0" }).stdin(Stdio::null());
    match c.spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => {
                        if !st.success() {
                            log::warn(format!("hook exited with {st}"));
                        }
                        break;
                    }
                    Ok(None) if start.elapsed() > Duration::from_secs(120) => {
                        let _ = child.kill();
                        log::warn("hook killed after 120 s");
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(200)),
                    Err(_) => break,
                }
            }
        }
        Err(e) => log::warn(format!("cannot run hook: {e}")),
    }
}

pub fn run_daemon(paths: &Paths, net: &dyn Net) -> ! {
    log::info(format!("runet-direct {} started ({})", env!("CARGO_PKG_VERSION"), net.name()));
    let mut cfg = Config::default();
    if let Ok(c) = Config::load(&paths.config_file()) {
        cfg = c;
    }
    let events = net.watch_command().map(|cmd| spawn_watcher(cmd, format!(" table {}", cfg.routing.table)));
    let mut last_err = String::new();
    let mut last_uplink: Option<String> = None;
    let mut triggered = true;
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
        match cycle(paths, &cfg, net, &CycleOpts::default()) {
            Ok(c) => {
                last_err.clear();
                let r = &c.report;
                if r.uplink != last_uplink {
                    log::info(format!("uplink: {}", r.uplink.as_deref().unwrap_or("none")));
                    last_uplink = r.uplink.clone();
                }
                if r.changed() {
                    log::info(format!(
                        "synced: +{} -{} (total {}){}",
                        r.added,
                        r.removed,
                        r.wanted,
                        r.rule_change.as_deref().map(|c| format!("; {c}")).unwrap_or_default()
                    ));
                    // Our own changes echo through the watcher; wait until it is quiet again.
                    if let Some(rx) = &events {
                        rerun = settle(rx);
                    }
                }
                if let Some(s) = &r.skipped {
                    if last_err != *s {
                        log::warn(s);
                        last_err = s.clone();
                    }
                }
                if triggered || r.changed() {
                    run_hook(&cfg.daemon.hook, r.changed());
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
            triggered = true;
            continue;
        }
        let mut wait = Duration::from_secs(cfg.daemon.interval_seconds.max(5));
        if let Some(secs) = next_expiry(paths, log::now()) {
            wait = wait.min(Duration::from_secs(secs + 1));
        }
        triggered = match &events {
            Some(rx) => match rx.recv_timeout(wait) {
                Ok(()) => {
                    std::thread::sleep(Duration::from_millis(500));
                    settle(rx);
                    true
                }
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(wait);
                    false
                }
            },
            None => {
                std::thread::sleep(wait);
                false
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Lookup;
    use std::cell::RefCell;

    struct FakeNet {
        uplink: RefCell<Option<Uplink>>,
        table: RefCell<Vec<Installed>>,
        rule: RefCell<bool>,
        applied: RefCell<usize>,
    }

    impl FakeNet {
        fn new(up: Option<Uplink>) -> FakeNet {
            FakeNet { uplink: RefCell::new(up), table: RefCell::default(), rule: RefCell::new(false), applied: RefCell::new(0) }
        }
    }

    impl Net for FakeNet {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn require_admin(&self) -> Result<(), String> {
            Ok(())
        }
        fn uplink(&self, _: &Config) -> Result<Option<Uplink>, String> {
            Ok(self.uplink.borrow().clone())
        }
        fn tunnels(&self) -> Vec<String> {
            vec![]
        }
        fn ensure_rule(&self, _: &Config, _: Option<u32>) -> Result<Option<String>, String> {
            Ok((!self.rule.replace(true)).then(|| "rule restored".to_string()))
        }
        fn rule_present(&self, _: &Config) -> Result<bool, String> {
            Ok(*self.rule.borrow())
        }
        fn installed(&self, _: &Config, _: &HashSet<Cidr>, _: &[Uplink]) -> Result<Vec<Installed>, String> {
            Ok(self.table.borrow().clone())
        }
        fn apply(&self, _: &Config, up: &Uplink, plan: &Plan) -> Result<(), String> {
            *self.applied.borrow_mut() += 1;
            let mut t = self.table.borrow_mut();
            t.retain(|i| !plan.remove.contains(i));
            for p in &plan.add {
                t.push(Installed { prefix: *p, via: up.via.clone(), dev: up.dev.clone() });
            }
            Ok(())
        }
        fn clear(&self, _: &Config, _: &HashSet<Cidr>, _: &[Uplink]) -> Result<usize, String> {
            Ok(0)
        }
        fn lookup(&self, _: &Config, _: u32) -> Result<Lookup, String> {
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

    fn desired(blocks: &[&str], prune_ok: bool) -> Desired {
        Desired { routes: blocks.iter().map(|b| Cidr::parse(b).unwrap()).collect(), prune_ok, ..Desired::default() }
    }

    #[test]
    fn first_pass_installs_rule_and_routes_and_second_pass_is_quiet() {
        let net = FakeNet::new(Some(up("10.0.0.1")));
        let (cfg, mut st) = (Config::default(), State::default());
        let d = desired(&["5.0.0.0/8", "6.0.0.0/8"], true);
        let r1 = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert_eq!((r1.added, r1.removed, r1.rule_change.is_some()), (2, 0, true));
        let r2 = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert!(!r2.changed());
        assert_eq!(*net.applied.borrow(), 1);
    }

    #[test]
    fn a_vanished_rule_is_restored_even_without_route_changes() {
        let net = FakeNet::new(Some(up("10.0.0.1")));
        let (cfg, mut st) = (Config::default(), State::default());
        let d = desired(&["5.0.0.0/8"], true);
        reconcile(&cfg, &net, &mut st, &d).unwrap();
        *net.rule.borrow_mut() = false; // tethering removed the rule
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert!(r.rule_change.is_some() && r.added == 0);
    }

    #[test]
    fn a_new_gateway_repoints_every_route() {
        let net = FakeNet::new(Some(up("10.0.0.1")));
        let (cfg, mut st) = (Config::default(), State::default());
        let d = desired(&["5.0.0.0/8", "6.0.0.0/8"], true);
        reconcile(&cfg, &net, &mut st, &d).unwrap();
        *net.uplink.borrow_mut() = Some(up("192.168.1.1"));
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert_eq!((r.added, r.removed), (2, 2));
        assert!(net.table.borrow().iter().all(|i| i.via.as_deref() == Some("192.168.1.1")));
    }

    #[test]
    fn without_an_uplink_nothing_is_touched_but_the_rule_is_kept() {
        let net = FakeNet::new(Some(up("10.0.0.1")));
        let (cfg, mut st) = (Config::default(), State::default());
        let d = desired(&["5.0.0.0/8"], true);
        reconcile(&cfg, &net, &mut st, &d).unwrap();
        *net.uplink.borrow_mut() = None;
        *net.rule.borrow_mut() = false;
        let r = reconcile(&cfg, &net, &mut st, &d).unwrap();
        assert!(r.skipped.is_some() && r.rule_change.is_some());
        assert_eq!(net.table.borrow().len(), 1, "routes must survive a lost uplink");
    }

    #[test]
    fn a_missing_country_list_never_wipes_the_table() {
        let net = FakeNet::new(Some(up("10.0.0.1")));
        let (cfg, mut st) = (Config::default(), State::default());
        reconcile(&cfg, &net, &mut st, &desired(&["5.0.0.0/8", "6.0.0.0/8"], true)).unwrap();
        let r = reconcile(&cfg, &net, &mut st, &desired(&["7.0.0.0/8"], false)).unwrap();
        assert_eq!((r.added, r.removed), (1, 0));
        assert_eq!(net.table.borrow().len(), 3);
    }

    #[test]
    fn removing_a_target_removes_its_route() {
        let net = FakeNet::new(Some(up("10.0.0.1")));
        let (cfg, mut st) = (Config::default(), State::default());
        reconcile(&cfg, &net, &mut st, &desired(&["5.0.0.0/8", "6.0.0.0/8"], true)).unwrap();
        let r = reconcile(&cfg, &net, &mut st, &desired(&["5.0.0.0/8"], true)).unwrap();
        assert_eq!((r.added, r.removed), (0, 1));
    }

    #[test]
    fn refresh_schedule() {
        let cfg = Config::default();
        let mut st = State::default();
        assert!(needs_refresh(&cfg, &st, 100_000_000), "no list yet -> fetch");
        st.last_refresh_attempt = 99_999_950;
        assert!(!needs_refresh(&cfg, &st, 100_000_000), "just failed -> back off");
        st.ru = Some(RuMeta { fetched_at: 100_000_000 - 3 * 86_400, snapshot: None, count: 1 });
        st.last_refresh_attempt = 0;
        assert!(!needs_refresh(&cfg, &st, 100_000_000), "fresh list");
        st.ru = Some(RuMeta { fetched_at: 100_000_000 - 31 * 86_400, snapshot: None, count: 1 });
        assert!(needs_refresh(&cfg, &st, 100_000_000), "stale list");
        let mut off = Config::default();
        off.ru.enabled = false;
        assert!(!needs_refresh(&off, &st, 100_000_000));
    }
}

mod cidr;
mod config;
mod engine;
mod fetch;
mod log;
mod net;
mod platform;
mod service;
mod sources;
mod state;
mod util;

use clap::{Parser, Subcommand};
use config::{Config, Paths};
use net::Net;
use serde_json::json;
use sources::{Target, Verdict};
use state::State;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant};

/// Keeps Russian-internet traffic off your VPN. Runs as a background service; every command
/// below is also meant to be called by other programs (see `--json` and the exit codes).
#[derive(Parser)]
#[command(name = "runet-direct", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install the service, enable it at boot and start it (needs root/Administrator; safe to re-run to upgrade)
    Install {
        /// Register the service but do not start it
        #[arg(long)]
        no_start: bool,
    },
    /// Stop and remove the service and all routes it installed
    Uninstall {
        /// Also delete configuration, manual list and downloaded data
        #[arg(long)]
        purge: bool,
    },
    /// Start the service
    Start,
    /// Stop the service (routes stay in place; use `clear` to remove them)
    Stop,
    /// Restart the service
    Restart,
    /// Start the service automatically at boot
    Enable,
    /// Do not start the service at boot
    Disable,
    /// Service and routing state. Exit code: 0 healthy, 1 running but unhealthy, 3 installed but not running, 4 not installed
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Verify the real routing state, or where TARGET (IP, CIDR or domain) would go. Exit code: 0 ok / direct, 1 problem / goes through a tunnel
    Check {
        target: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Bring the routing table to the wanted state once, without the daemon
    Apply,
    /// Download the country address list now, then apply
    Refresh,
    /// Remove every route and rule installed by this program
    Clear,
    /// Always send these destinations (IP, a.b.c.d/n or domain) directly
    Add {
        #[command(flatten)]
        targets: Targets,
        #[command(flatten)]
        when: Timing,
    },
    /// Never send these destinations directly, even if the country list contains them
    Exclude {
        #[command(flatten)]
        targets: Targets,
        #[command(flatten)]
        when: Timing,
    },
    /// Forget these destinations from the manual list
    Remove {
        #[command(flatten)]
        targets: Targets,
    },
    /// Send EVERYTHING through the VPN for a while (or until `resume`), e.g. to test from a foreign address
    Pause {
        #[command(flatten)]
        when: Timing,
    },
    /// End a pause
    Resume,
    /// Show the manual list
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show or change settings: `config`, `config path`, `config get ipv6.enabled`, `config set ipv6.enabled false`
    Config {
        #[command(subcommand)]
        action: Option<ConfigCmd>,
    },
    /// Run the daemon in the foreground (this is what the service executes)
    Run {
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print where the configuration files live
    Path,
    /// Print one setting, e.g. `ipv6.enabled`
    Get { key: String },
    /// Change one setting (comments in the file are kept) and apply it right away
    Set { key: String, value: String },
}

#[derive(clap::Args)]
struct Targets {
    /// IP addresses, a.b.c.d/n networks or domain names
    #[arg(required_unless_present = "file")]
    targets: Vec<String>,
    /// Also read targets from FILE, one per line ("-" = standard input)
    #[arg(long)]
    file: Option<PathBuf>,
}

#[derive(clap::Args)]
struct Timing {
    /// Only for this long, then revert automatically: 90s, 30m, 2h, 1d, 1w
    #[arg(long = "for", conflicts_with = "until")]
    duration: Option<String>,
    /// Only until this time: 2026-10-14T18:00:00Z or unix seconds
    #[arg(long)]
    until: Option<String>,
}

fn parse_duration(s: &str) -> Result<u64, String> {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("bad duration `{s}` (examples: 90s, 30m, 2h, 1d)"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return Err(format!("bad duration `{s}` (examples: 90s, 30m, 2h, 1d)")),
    };
    Ok(n * mult)
}

impl Timing {
    fn until(&self) -> Option<u64> {
        if let Some(d) = &self.duration {
            return Some(log::now() + parse_duration(d).unwrap_or_else(|e| die(e)));
        }
        self.until
            .as_deref()
            .map(|u| log::parse_iso(u).unwrap_or_else(|| die(format!("bad time `{u}` (use 2026-10-14T18:00:00Z or unix seconds)"))))
    }
}

impl Targets {
    fn resolve(&self) -> Vec<Target> {
        let mut out: Vec<Target> = self.targets.iter().map(|t| sources::parse_target(t).unwrap_or_else(|e| die(e))).collect();
        if let Some(f) = &self.file {
            let text = if f.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin()).unwrap_or_else(|e| die(format!("stdin: {e}")))
            } else {
                std::fs::read_to_string(f).unwrap_or_else(|e| die(format!("{}: {e}", f.display())))
            };
            out.extend(sources::parse_target_list(&text).unwrap_or_else(|e| die(format!("{}: {e}", f.display()))));
        }
        if out.is_empty() {
            die("no targets given");
        }
        out
    }
}

/// `0.0.0.0/0` and `::/0`: pausing covers both families.
fn everything() -> [Target; 2] {
    [Target::Net(cidr::Cidr { fam: cidr::Family::V4, addr: 0, len: 0 }), Target::Net(cidr::Cidr { fam: cidr::Family::V6, addr: 0, len: 0 })]
}

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("error: {}", msg.as_ref());
    exit(2)
}

fn load_config(paths: &Paths) -> Config {
    Config::load(&paths.config_file()).unwrap_or_else(|e| die(format!("bad configuration: {e}")))
}

fn need_admin(net: &dyn Net) {
    if let Err(e) = net.require_admin() {
        die(e);
    }
}

fn print_json(v: &impl serde::Serialize) {
    println!("{}", serde_json::to_string_pretty(v).expect("serializable"));
}

fn main() {
    let cli = Cli::parse();
    let paths = Paths::detect();
    let net = platform::current();
    let mgr = service::current();

    match cli.cmd {
        Cmd::Install { no_start } => install(&paths, net.as_ref(), mgr.as_ref(), no_start),
        Cmd::Uninstall { purge } => uninstall(&paths, net.as_ref(), mgr.as_ref(), purge),
        Cmd::Start => service_op(net.as_ref(), || mgr.start(), "started"),
        Cmd::Stop => service_op(net.as_ref(), || mgr.stop(), "stopped (routes stay in place; `runet-direct clear` removes them)"),
        Cmd::Restart => service_op(net.as_ref(), || mgr.restart(), "restarted"),
        Cmd::Enable => service_op(net.as_ref(), || mgr.enable(), "will start at boot"),
        Cmd::Disable => service_op(net.as_ref(), || mgr.disable(), "will not start at boot"),
        Cmd::Status { json } => status(&paths, net.as_ref(), mgr.as_ref(), json),
        Cmd::Check { target, json } => check(&paths, net.as_ref(), target, json),
        Cmd::Apply => apply(&paths, net.as_ref(), false),
        Cmd::Refresh => apply(&paths, net.as_ref(), true),
        Cmd::Clear => {
            need_admin(net.as_ref());
            match engine::clear(&paths, &load_config(&paths), net.as_ref()) {
                Ok(n) => println!("removed {n} routes and the routing rule"),
                Err(e) => die(e),
            }
        }
        Cmd::Add { targets, when } => edit_manual(&paths, net.as_ref(), &targets.resolve(), Some(Verdict::Direct), when.until()),
        Cmd::Exclude { targets, when } => edit_manual(&paths, net.as_ref(), &targets.resolve(), Some(Verdict::Vpn), when.until()),
        Cmd::Remove { targets } => edit_manual(&paths, net.as_ref(), &targets.resolve(), None, None),
        Cmd::Pause { when } => edit_manual(&paths, net.as_ref(), &everything(), Some(Verdict::Vpn), when.until()),
        Cmd::Resume => edit_manual(&paths, net.as_ref(), &everything(), None, None),
        Cmd::List { json } => list(&paths, json),
        Cmd::Config { action } => config_cmd(&paths, net.as_ref(), action),
        Cmd::Run { log_file } => {
            if let Some(f) = log_file {
                log::init_file(&f);
            }
            need_admin(net.as_ref());
            let _ = paths.write_defaults();
            engine::run_daemon(&paths, net.as_ref());
        }
    }
}

fn service_op(net: &dyn Net, op: impl FnOnce() -> Result<(), String>, done: &str) {
    need_admin(net);
    match op() {
        Ok(()) => println!("{done}"),
        Err(e) => die(e),
    }
}

// ---------------------------------------------------------------------------
// install / uninstall
// ---------------------------------------------------------------------------

fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

fn copy_binary(src: &Path, dst: &Path) -> Result<(), String> {
    if same_file(src, dst) {
        return Ok(());
    }
    if let Some(dir) = dst.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = dst.with_extension("new");
    std::fs::copy(src, &tmp).map_err(|e| format!("copy to {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, dst).map_err(|e| format!("replace {}: {e}", dst.display()))
}

fn install(paths: &Paths, net: &dyn Net, mgr: &dyn service::Manager, no_start: bool) {
    need_admin(net);
    let exe = std::env::current_exe().unwrap_or_else(|e| die(format!("cannot locate this executable: {e}")));
    if mgr.status().running {
        let _ = mgr.stop(); // an upgrade must be able to replace the binary
    }
    paths.write_defaults().unwrap_or_else(|e| die(format!("cannot create {}: {e}", paths.config_dir.display())));
    copy_binary(&exe, &paths.install_bin).unwrap_or_else(|e| die(e));
    mgr.install(&paths.install_bin, paths).unwrap_or_else(|e| die(e));
    println!("installed: {} (managed by {})", paths.install_bin.display(), mgr.name());
    println!("configuration: {}", paths.config_dir.display());
    if no_start {
        println!("not started; run `runet-direct start`");
        return;
    }
    mgr.start().unwrap_or_else(|e| die(e));
    println!("started; waiting for the first sync (downloads the country address list, ~10 MB)...");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(150) {
        let s = State::load(paths);
        if s.ru.is_some() && !s.uplinks.is_empty() {
            let n = s.last_apply.map(|a| a.total).unwrap_or(0);
            println!("done: {n} routes installed. Check anytime with `runet-direct status`.");
            return;
        }
        if let Some(e) = s.last_refresh_error {
            println!("the first download failed ({e}); the service keeps retrying in the background. See `runet-direct status`.");
            return;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    println!("still working in the background; see `runet-direct status`.");
}

fn uninstall(paths: &Paths, net: &dyn Net, mgr: &dyn service::Manager, purge: bool) {
    need_admin(net);
    let cfg = load_config(paths);
    let _ = mgr.stop();
    match engine::clear(paths, &cfg, net) {
        Ok(n) => println!("removed {n} routes and the routing rule"),
        Err(e) => eprintln!("warning: could not remove routes: {e}"),
    }
    if let Err(e) = mgr.uninstall() {
        eprintln!("warning: {e}");
    }
    let exe = std::env::current_exe().ok();
    if exe.as_deref().map(|e| !same_file(e, &paths.install_bin)).unwrap_or(true) {
        let _ = std::fs::remove_file(&paths.install_bin);
    } else if !cfg!(windows) {
        let _ = std::fs::remove_file(&paths.install_bin); // unlinking a running binary is fine on Unix
    } else {
        println!("note: delete {} manually (a running program cannot remove itself on Windows)", paths.install_bin.display());
    }
    if purge {
        let _ = std::fs::remove_dir_all(&paths.state_dir);
        let _ = std::fs::remove_dir_all(&paths.config_dir);
    }
    println!("uninstalled{}", if purge { " (configuration and data deleted)" } else { "" });
}

// ---------------------------------------------------------------------------
// status / check
// ---------------------------------------------------------------------------

fn status(paths: &Paths, net: &dyn Net, mgr: &dyn service::Manager, as_json: bool) {
    let cfg = load_config(paths);
    let svc = mgr.status();
    let h = engine::health(paths, &cfg, net);
    let state = State::load(paths);
    let code = if !svc.installed {
        4
    } else if !svc.running {
        3
    } else if !h.healthy {
        1
    } else {
        0
    };
    if as_json {
        print_json(&json!({
            "service": svc,
            "health": h,
            "last_apply": state.last_apply,
            "last_error": state.last_error,
            "last_refresh_error": state.last_refresh_error,
            "exit_code": code,
        }));
        exit(code);
    }
    let yes = |b: bool, t: &str, f: &str| if b { t.to_string() } else { f.to_string() };
    println!(
        "Service:  {} ({}), {}",
        yes(svc.running, "running", if svc.installed { "not running" } else { "not installed" }),
        svc.manager,
        yes(svc.enabled, "starts at boot", "does not start at boot")
    );
    if let Some(until) = h.paused {
        match until {
            Some(u) => println!("PAUSED:   everything goes through the VPN until {} (`runet-direct resume` ends it)", log::iso(u)),
            None => println!("PAUSED:   everything goes through the VPN until `runet-direct resume`"),
        }
    }
    if !h.tunnels.is_empty() {
        println!("Tunnels:  {} (left alone)", h.tunnels.join(", "));
    }
    for f in &h.families {
        let up = f.uplink.as_deref().unwrap_or(if f.family == "IPv6" { "none (no IPv6 here)" } else { "none found" });
        println!("{} uplink: {up}", f.family);
        if f.uplink.is_some() {
            println!(
                "{} routes: {} of {} in place{}{}",
                f.family,
                f.installed,
                f.wanted,
                yes(f.missing + f.stale > 0, &format!(" ({} missing, {} stale)", f.missing, f.stale), ""),
                match (net.name() == "linux", f.rule_present, f.rule_priority) {
                    (true, false, _) => "   [RULE MISSING]".to_string(),
                    (true, true, Some(p)) => format!("   (rule priority {p})"),
                    _ => String::new(),
                }
            );
        }
    }
    match (h.country_blocks, &h.country_snapshot, h.country_age_days) {
        (Some(n), snap, age) => println!(
            "Country:  {n} IPv4 + {} IPv6 blocks, RIPE snapshot {}, fetched {} days ago",
            h.country_blocks_v6.unwrap_or(0),
            snap.as_deref().unwrap_or("unknown"),
            age.unwrap_or(0)
        ),
        _ => println!("Country:  not downloaded yet"),
    }
    if let Some(a) = &state.last_apply {
        println!("Last change: {} (+{} -{})", log::iso(a.at), a.added, a.removed);
    }
    for f in &h.families {
        for s in &f.samples {
            println!("  probe {:>25} -> {}{}", s.ip, s.dev, if s.tunnel { "  [TUNNEL]" } else { "" });
        }
    }
    if h.healthy {
        println!("Health:   OK");
    } else {
        println!("Health:   PROBLEMS");
        for p in &h.problems {
            println!("  - {p}");
        }
    }
    exit(code);
}

fn check(paths: &Paths, net: &dyn Net, target: Option<String>, as_json: bool) {
    let cfg = load_config(paths);
    let Some(target) = target else {
        let h = engine::health(paths, &cfg, net);
        if as_json {
            print_json(&h);
        } else if h.healthy {
            let routes: usize = h.families.iter().map(|f| f.installed).sum();
            let probes: usize = h.families.iter().map(|f| f.samples.len()).sum();
            println!("OK: {routes} routes in place, {probes} probes leave through the physical uplink");
        } else {
            for p in &h.problems {
                println!("problem: {p}");
            }
        }
        exit(if h.healthy { 0 } else { 1 });
    };
    let ips: Vec<std::net::IpAddr> = match sources::parse_target(&target).unwrap_or_else(|e| die(e)) {
        Target::Net(c) => vec![c.probe()],
        Target::Host(h) => {
            use std::net::ToSocketAddrs;
            let v: Vec<std::net::IpAddr> = (h.as_str(), 0u16).to_socket_addrs().map(|it| it.map(|a| a.ip()).collect()).unwrap_or_default();
            if v.is_empty() {
                die(format!("{h} has no address"));
            }
            v
        }
    };
    let mut leaks = false;
    let mut out = Vec::new();
    for ip in ips {
        match net.lookup(&cfg, ip) {
            Ok(l) => {
                leaks |= l.tunnel;
                if !as_json {
                    println!("{:>25} -> {}{}", ip, if l.tunnel { "TUNNEL " } else { "direct via " }, l.dev);
                }
                out.push(json!({"ip": ip.to_string(), "interface": l.dev, "via": l.via, "tunnel": l.tunnel}));
            }
            Err(e) => die(e),
        }
    }
    if as_json {
        print_json(&json!({"target": target, "direct": !leaks, "results": out}));
    }
    exit(i32::from(leaks));
}

// ---------------------------------------------------------------------------
// apply / manual list
// ---------------------------------------------------------------------------

fn apply(paths: &Paths, net: &dyn Net, force_refresh: bool) {
    need_admin(net);
    let cfg = load_config(paths);
    let _ = paths.write_defaults();
    match engine::cycle(paths, &cfg, net, &engine::CycleOpts { force_refresh }) {
        Ok(c) => {
            for r in &c.report.families {
                if let Some(msg) = &r.skipped {
                    println!("{}: {msg}", r.family);
                }
                println!(
                    "{}: uplink {}; routes wanted {}, added {}, removed {}, unchanged {}{}",
                    r.family,
                    r.uplink.as_deref().unwrap_or("none"),
                    r.wanted,
                    r.added,
                    r.removed,
                    r.kept,
                    r.rule_change.as_deref().map(|c| format!("; {c}")).unwrap_or_default()
                );
            }
            for w in c.desired.warnings {
                println!("warning: {w}");
            }
        }
        Err(e) => die(e),
    }
}

fn edit_manual(paths: &Paths, net: &dyn Net, targets: &[Target], verdict: Option<Verdict>, until: Option<u64>) {
    need_admin(net);
    {
        let _lock = state::Lock::acquire(paths, Duration::from_secs(60)).unwrap_or_else(|e| die(e));
        let _ = paths.write_defaults();
        let mut text = std::fs::read_to_string(paths.manual_file()).unwrap_or_default();
        for t in targets {
            match verdict {
                Some(v) => {
                    text = sources::set_target(&text, v, t, until);
                    match until {
                        Some(u) => println!("{} {} until {}", v.word(), t, log::iso(u)),
                        None => println!("{} {}", v.word(), t),
                    }
                }
                None => {
                    let (new, n) = sources::remove_target(&text, t);
                    text = new;
                    println!("{} {}", if n > 0 { "removed" } else { "not in the list:" }, t);
                }
            }
        }
        std::fs::write(paths.manual_file(), text).unwrap_or_else(|e| die(format!("{}: {e}", paths.manual_file().display())));
    }
    apply(paths, net, false);
}

fn list(paths: &Paths, as_json: bool) {
    let text = std::fs::read_to_string(paths.manual_file()).unwrap_or_default();
    let (entries, errors) = sources::parse_manual(&text);
    let state = State::load(paths);
    if as_json {
        let items: Vec<_> = entries
            .iter()
            .map(|e| {
                let ips = match &e.target {
                    Target::Host(h) => state.resolved.get(h).map(|r| r.ips.clone()),
                    Target::Net(_) => None,
                };
                json!({"verdict": e.verdict.word(), "target": e.target.to_string(), "until": e.until.map(log::iso), "resolved": ips})
            })
            .collect();
        print_json(&json!({"entries": items, "errors": errors}));
        return;
    }
    if entries.is_empty() {
        println!("(empty) add entries with `runet-direct add <ip|cidr|domain>`");
    }
    for e in &entries {
        let extra = match &e.target {
            Target::Host(h) => state.resolved.get(h).map(|r| format!("  -> {}", r.ips.join(", "))).unwrap_or_default(),
            Target::Net(_) => String::new(),
        };
        let until = e.until.map(|u| format!("  (until {})", log::iso(u))).unwrap_or_default();
        println!("{:<7}{}{}{}", e.verdict.word(), e.target, until, extra);
    }
    for e in errors {
        eprintln!("warning: {e}");
    }
}

fn config_cmd(paths: &Paths, net: &dyn Net, action: Option<ConfigCmd>) {
    match action {
        None => {
            println!("# file:   {}", paths.config_file().display());
            println!("# manual: {}", paths.manual_file().display());
            println!("# data:   {}", paths.state_dir.display());
            println!("# log:    {}", paths.log_file.display());
            println!("{}", toml::to_string_pretty(&load_config(paths)).expect("config serializes"));
        }
        Some(ConfigCmd::Path) => println!("{}", paths.config_file().display()),
        Some(ConfigCmd::Get { key }) => {
            let cfg = toml::Value::try_from(load_config(paths)).expect("config serializes");
            let (section, name) = key.split_once('.').unwrap_or_else(|| die("use section.key, e.g. ipv6.enabled"));
            match cfg.get(section).and_then(|s| s.get(name)) {
                Some(toml::Value::String(s)) => println!("{s}"),
                Some(v) => println!("{v}"),
                None => die(format!("no such setting: {key}")),
            }
        }
        Some(ConfigCmd::Set { key, value }) => {
            need_admin(net);
            let (section, name) = key.split_once('.').unwrap_or_else(|| die("use section.key, e.g. ipv6.enabled"));
            let _ = paths.write_defaults();
            let text = std::fs::read_to_string(paths.config_file()).unwrap_or_else(|_| config::DEFAULT_CONFIG.to_string());
            let mut doc: toml_edit::DocumentMut = text.parse().unwrap_or_else(|e| die(format!("{}: {e}", paths.config_file().display())));
            // `true`, `900`, `["a"]` are taken as TOML; anything else as a plain string.
            let parsed = value.parse::<toml_edit::Value>().unwrap_or_else(|_| toml_edit::Value::from(value.as_str()));
            let table = doc
                .entry(section)
                .or_insert_with(toml_edit::table)
                .as_table_mut()
                .unwrap_or_else(|| die(format!("`{section}` is not a section")));
            table.insert(name, toml_edit::Item::Value(parsed));
            let new_text = doc.to_string();
            if let Err(e) = toml::from_str::<Config>(&new_text) {
                die(format!("refused, the result would be invalid: {e}"));
            }
            std::fs::write(paths.config_file(), new_text).unwrap_or_else(|e| die(format!("{}: {e}", paths.config_file().display())));
            println!("{key} = {value}");
            apply(paths, net, false);
        }
    }
}

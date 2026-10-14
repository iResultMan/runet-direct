//! Linux: a private routing table plus one `ip rule` that sends everything to it first.
//!
//! The rule has a smaller priority number than any rule a VPN client installs, so a
//! destination found in the table leaves through the physical gateway, and every other
//! destination falls through to whatever the VPN set up. Nothing here names a VPN.

use crate::cidr::{Cidr, Family};
use crate::config::Config;
use crate::net::{Installed, Lookup, Net, Plan, Uplink};
use crate::util;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub struct Linux;

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct DefaultRoute {
    pub dev: String,
    pub via: Option<String>,
    pub metric: u32,
    pub table: Option<String>,
    pub linkdown: bool,
}

fn token_after<'a>(tokens: &[&'a str], key: &str) -> Option<&'a str> {
    tokens.iter().position(|t| *t == key).and_then(|i| tokens.get(i + 1)).copied()
}

pub fn parse_default_routes(text: &str) -> Vec<DefaultRoute> {
    text.lines()
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.first() != Some(&"default") {
                return None;
            }
            Some(DefaultRoute {
                dev: token_after(&t, "dev")?.to_string(),
                via: token_after(&t, "via").map(str::to_string),
                metric: token_after(&t, "metric").and_then(|m| m.parse().ok()).unwrap_or(0),
                table: token_after(&t, "table").map(str::to_string),
                linkdown: t.contains(&"linkdown"),
            })
        })
        .collect()
}

/// Best non-tunnel default route. Prefers the main table; other tables are only a fallback
/// for VPN clients that remove the original default route from main.
pub fn pick_uplink(routes: &[DefaultRoute], is_tunnel: &dyn Fn(&str) -> bool, cfg: &Config) -> Option<Uplink> {
    let own_table = cfg.routing.table.to_string();
    let forced = cfg.routing.interface.as_str();
    let usable = |r: &&DefaultRoute| {
        r.table.as_deref() != Some(own_table.as_str())
            && !cfg.routing.ignore_interfaces.iter().any(|i| i == &r.dev)
            && if forced.is_empty() { !is_tunnel(&r.dev) } else { r.dev == forced }
    };
    let is_main = |r: &&DefaultRoute| matches!(r.table.as_deref(), None | Some("main"));
    let best = |main: bool| {
        routes
            .iter()
            .filter(usable)
            .filter(|r| is_main(r) == main)
            .min_by_key(|r| (r.linkdown, r.metric))
            .map(|r| Uplink { dev: r.dev.clone(), via: r.via.clone() })
    };
    best(true).or_else(|| best(false))
}

pub fn parse_table(text: &str) -> Vec<Installed> {
    text.lines()
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            let prefix = Cidr::parse(t.first()?)?;
            Some(Installed { prefix, via: token_after(&t, "via").map(str::to_string), dev: token_after(&t, "dev")?.to_string() })
        })
        .collect()
}

/// `name -> id` from an iproute2 `rt_tables` file.
pub fn parse_rt_tables(text: &str) -> HashMap<String, u32> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?;
            let mut w = l.split_whitespace();
            let id = w.next()?.parse().ok()?;
            Some((w.next()?.to_string(), id))
        })
        .collect()
}

/// One line of `ip rule show`.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub priority: u32,
    /// Plain `from all lookup <table>`, with no other selector narrowing it down.
    pub catch_all: bool,
    pub table: Option<u32>,
}

fn table_id(token: &str, labels: &HashMap<String, u32>) -> Option<u32> {
    match token {
        "main" => Some(MAIN_TABLE),
        "local" => Some(255),
        "default" => Some(253),
        t => t.parse().ok().or_else(|| labels.get(t).copied()),
    }
}

const MAIN_TABLE: u32 = 254;

/// `lookup` prints a label instead of the number when `rt_tables` names the table; both are resolved.
pub fn parse_rules(text: &str, labels: &HashMap<String, u32>) -> Vec<Rule> {
    text.lines()
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            let priority = t.first()?.strip_suffix(':')?.parse().ok()?;
            Some(Rule {
                priority,
                catch_all: t.get(1) == Some(&"from") && t.get(2) == Some(&"all") && t.get(3) == Some(&"lookup"),
                table: token_after(&t, "lookup").and_then(|l| table_id(l, labels)),
            })
        })
        .collect()
}

/// What `ip route get` decided: interface, next hop and the table the answer came from.
#[derive(Debug, PartialEq)]
pub struct RouteGet {
    pub dev: String,
    pub via: Option<String>,
    pub table: u32,
}

pub fn parse_route_get(text: &str, labels: &HashMap<String, u32>) -> Option<RouteGet> {
    let t: Vec<&str> = text.lines().next()?.split_whitespace().collect();
    Some(RouteGet {
        dev: token_after(&t, "dev")?.to_string(),
        via: token_after(&t, "via").map(str::to_string),
        table: token_after(&t, "table").and_then(|l| table_id(l, labels)).unwrap_or(MAIN_TABLE),
    })
}

/// What to do with the rule, decided from facts only.
#[derive(Debug, PartialEq)]
pub enum RuleOp {
    Nothing,
    Add(u32),
    /// Our rule exists at `from`, but another rule at `shadow` is evaluated first and sends the
    /// probe into a tunnel: re-create ours at `to`, just above it.
    Move {
        from: u32,
        to: u32,
        shadow: u32,
    },
    /// A shadowing rule exists but there is no free priority above it.
    Stuck {
        shadow: u32,
    },
    /// Traffic that must be direct goes into a tunnel because of a rule that is not a plain
    /// `from all lookup` (fwmark, `not`, `to` ...). It cannot be moved above automatically, but it must
    /// not stay silent either.
    Leak {
        rule: u32,
        table: u32,
    },
}

/// `probe`: where the answer for a destination that must be direct came from, and whether that
/// answer leads into a tunnel. `None` when no probe was made.
pub fn plan_rule(rules: &[Rule], table: u32, preferred: u32, probe: Option<(u32, bool)>) -> RuleOp {
    let ours = rules.iter().filter(|r| r.catch_all && r.table == Some(table)).map(|r| r.priority).min();
    let Some(mine) = ours else { return RuleOp::Add(preferred) };
    let Some((answered_from, via_tunnel)) = probe else { return RuleOp::Nothing };
    if !via_tunnel || answered_from == table {
        return RuleOp::Nothing;
    }
    let shadow = rules.iter().filter(|r| r.catch_all && r.table == Some(answered_from) && r.priority < mine).map(|r| r.priority).min();
    match shadow {
        Some(s) if s > 1 => RuleOp::Move { from: mine, to: s - 1, shadow: s },
        Some(s) => RuleOp::Stuck { shadow: s },
        None => {
            match rules.iter().filter(|r| r.table == Some(answered_from) && r.priority < mine && r.priority > 0).map(|r| r.priority).min() {
                Some(rule) => RuleOp::Leak { rule, table: answered_from },
                // Nothing in front of ours points there: the route itself is missing, which the next pass repairs.
                None => RuleOp::Nothing,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tunnel detection
// ---------------------------------------------------------------------------

const TUNNEL_PREFIXES: &[&str] = &[
    "tun",
    "tap",
    "wg",
    "utun",
    "ppp",
    "tailscale",
    "zt",
    "nordlynx",
    "proton",
    "ipsec",
    "vti",
    "gre",
    "ipip",
    "sit",
    "wt",
    "mullvad",
    "warp",
    "vpn",
    "ovpn",
    "tinc",
    "cscotun",
    "gpd",
];

/// A tunnel has no hardware behind it. Hardware-backed interfaces are physical even when the
/// kernel reports an unusual link type (raw-IP modems), and tun/tap devices announce themselves.
pub fn is_tunnel(dev: &str) -> bool {
    let base = format!("/sys/class/net/{dev}");
    if Path::new(&format!("{base}/tun_flags")).exists() {
        return true;
    }
    if Path::new(&format!("{base}/device")).exists() {
        return false;
    }
    if TUNNEL_PREFIXES.iter().any(|p| dev.starts_with(p)) {
        return true;
    }
    let link_type: Option<u32> = fs::read_to_string(format!("{base}/type")).ok().and_then(|s| s.trim().parse().ok());
    matches!(link_type, Some(t) if t != 1)
}

/// `ip monitor` prints the table's label instead of its number when rt_tables names it, so both forms
/// mark the echo of our own work.
pub fn echo_filters_for(table: u32, labels: &HashMap<String, u32>) -> Vec<String> {
    let mut filters = vec![format!(" table {table}")];
    let mut names: Vec<&String> = labels.iter().filter(|(_, id)| **id == table).map(|(n, _)| n).collect();
    names.sort();
    filters.extend(names.into_iter().map(|n| format!(" table {n}")));
    filters
}

fn rt_labels() -> HashMap<String, u32> {
    let mut all = HashMap::new();
    for p in ["/usr/share/iproute2/rt_tables", "/etc/iproute2/rt_tables"] {
        if let Ok(t) = fs::read_to_string(p) {
            all.extend(parse_rt_tables(&t));
        }
    }
    all
}

// ---------------------------------------------------------------------------
// Net
// ---------------------------------------------------------------------------

fn ip(args: &[&str]) -> Result<String, String> {
    util::run("ip", args)
}

fn route_line(prefix: &Cidr, via: &Option<String>, dev: &str, table: u32, verb: &str) -> String {
    match via {
        Some(v) => format!("route {verb} {prefix} via {v} dev {dev} table {table}\n"),
        None => format!("route {verb} {prefix} dev {dev} table {table}\n"),
    }
}

impl Net for Linux {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn require_admin(&self) -> Result<(), String> {
        if util::is_root() {
            Ok(())
        } else {
            Err("this needs root: re-run with sudo".into())
        }
    }

    fn uplink(&self, cfg: &Config, fam: Family) -> Result<Option<Uplink>, String> {
        let f = fam.ip_flag();
        let main = parse_default_routes(&ip(&[f, "route", "show", "table", "main"])?);
        if let Some(u) = pick_uplink(&main, &is_tunnel, cfg) {
            return Ok(Some(u));
        }
        // A VPN may have removed the original default from main; look in the other tables.
        let all = parse_default_routes(&ip(&[f, "route", "show", "table", "all", "default"])?);
        Ok(pick_uplink(&all, &is_tunnel, cfg))
    }

    fn tunnels(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir("/sys/class/net") else { return Vec::new() };
        let mut v: Vec<String> =
            entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n != "lo" && is_tunnel(n)).collect();
        v.sort();
        v
    }

    fn rule_present(&self, cfg: &Config, fam: Family) -> Result<bool, String> {
        let rules = parse_rules(&ip(&[fam.ip_flag(), "rule", "show"])?, &rt_labels());
        Ok(rules.iter().any(|r| r.catch_all && r.table == Some(cfg.routing.table)))
    }

    fn rule_priority(&self, cfg: &Config, fam: Family) -> Result<Option<u32>, String> {
        let rules = parse_rules(&ip(&[fam.ip_flag(), "rule", "show"])?, &rt_labels());
        Ok(rules.iter().filter(|r| r.catch_all && r.table == Some(cfg.routing.table)).map(|r| r.priority).min())
    }

    fn ensure_rule(&self, cfg: &Config, fam: Family, probe: Option<IpAddr>) -> Result<Option<String>, String> {
        let labels = rt_labels();
        let f = fam.ip_flag();
        let table = cfg.routing.table;
        let rules = parse_rules(&ip(&[f, "rule", "show"])?, &labels);
        let answer = match probe {
            Some(addr) => {
                let text = ip(&[f, "route", "get", &addr.to_string()])?;
                parse_route_get(&text, &labels).map(|g| (g.table, is_tunnel(&g.dev)))
            }
            None => None,
        };
        let add = |prio: u32| ip(&[f, "rule", "add", "priority", &prio.to_string(), "from", "all", "lookup", &table.to_string()]);
        let prefix = if fam == Family::V6 { "IPv6 " } else { "" };
        match plan_rule(&rules, table, cfg.routing.priority, answer) {
            RuleOp::Nothing => Ok(None),
            RuleOp::Add(p) => {
                add(p)?;
                Ok(Some(format!("{prefix}rule restored (priority {p})")))
            }
            RuleOp::Move { from, to, shadow } => {
                add(to)?;
                let _ = ip(&[f, "rule", "del", "priority", &from.to_string(), "from", "all", "lookup", &table.to_string()]);
                Ok(Some(format!(
                    "{prefix}rule moved from priority {from} to {to}: another rule at {shadow} was sending Russian traffic into the VPN"
                )))
            }
            RuleOp::Leak { rule, table } => Err(format!(
                "Russian traffic still leaves through a tunnel: the rule at priority {rule} (lookup {table}) is evaluated first and is not a plain `from all` rule, so it cannot be moved above automatically"
            )),
            RuleOp::Stuck { shadow } => {
                Err(format!("a rule at priority {shadow} sends Russian traffic into the VPN and nothing can be placed above it"))
            }
        }
    }

    fn installed(&self, cfg: &Config, fam: Family, _: &HashSet<Cidr>, _: &[Uplink]) -> Result<Vec<Installed>, String> {
        match ip(&[fam.ip_flag(), "route", "show", "table", &cfg.routing.table.to_string()]) {
            Ok(text) => Ok(parse_table(&text).into_iter().filter(|i| i.prefix.fam == fam).collect()),
            // An empty, never-used table makes some iproute2 versions fail instead of printing nothing.
            Err(e) if e.contains("FIB table does not exist") => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn apply(&self, cfg: &Config, fam: Family, uplink: &Uplink, plan: &Plan) -> Result<(), String> {
        let table = cfg.routing.table;
        // `replace` swaps a route atomically, so only stale routes need deleting, and they go last.
        let (_, stale) = plan.split_removals();
        let mut script = String::new();
        for p in &plan.add {
            script.push_str(&route_line(p, &uplink.via, &uplink.dev, table, "replace"));
        }
        for r in stale {
            script.push_str(&route_line(&r.prefix, &r.via, &r.dev, table, "del"));
        }
        // -force keeps going after a failing line (e.g. deleting a route that is already gone).
        match util::run_stdin("ip", &[fam.ip_flag(), "-force", "-batch", "-"], &script) {
            Ok(_) => Ok(()),
            Err(e) if plan.add.is_empty() => {
                // Only deletions: "No such process" for an already-removed route is fine.
                crate::log::warn(format!("some deletions failed: {e}"));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn clear(&self, cfg: &Config, fam: Family, _: &HashSet<Cidr>, _: &[Uplink]) -> Result<usize, String> {
        let f = fam.ip_flag();
        let table = cfg.routing.table.to_string();
        let before = self.installed(cfg, fam, &HashSet::new(), &[])?.len();
        let _ = ip(&[f, "route", "flush", "table", &table]);
        // The rule may have been moved by the shadow guard, so remove it wherever it is.
        let rules = parse_rules(&ip(&[f, "rule", "show"])?, &rt_labels());
        for r in rules.iter().filter(|r| r.catch_all && r.table == Some(cfg.routing.table)) {
            let _ = ip(&[f, "rule", "del", "priority", &r.priority.to_string(), "from", "all", "lookup", &table]);
        }
        Ok(before)
    }

    fn lookup(&self, _: &Config, addr: IpAddr) -> Result<Lookup, String> {
        let text = ip(&[Family::of(&addr).ip_flag(), "route", "get", &addr.to_string()])?;
        let g = parse_route_get(&text, &rt_labels()).ok_or_else(|| format!("unexpected `ip route get` output: {}", text.trim()))?;
        Ok(Lookup { tunnel: is_tunnel(&g.dev), dev: g.dev, via: g.via })
    }

    fn echo_filters(&self, cfg: &Config) -> Vec<String> {
        echo_filters_for(cfg.routing.table, &rt_labels())
    }

    fn watch_command(&self) -> Option<Vec<String>> {
        Some(["ip", "monitor", "route", "rule", "link", "address"].iter().map(|s| s.to_string()).collect())
    }

    fn tracks_ownership(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_tunnels(d: &str) -> bool {
        d.starts_with("tun") || d.starts_with("wg") || d.starts_with("ppp")
    }

    #[test]
    fn default_routes_are_parsed_with_metric_table_and_flags() {
        let r = parse_default_routes(
            "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100 \n\
             default via 10.8.0.1 dev tun0 metric 50\n\
             default dev ppp0 scope link\n\
             default via 10.0.0.1 dev eth0 table 100 \n\
             default via 10.0.0.1 dev wlan0 metric 600 linkdown\n\
             0.0.0.0/1 via 10.8.0.1 dev tun0\n",
        );
        assert_eq!(r.len(), 5);
        assert_eq!((r[0].dev.as_str(), r[0].via.as_deref(), r[0].metric, r[0].table.clone()), ("eth0", Some("10.0.0.1"), 100, None));
        assert_eq!(r[2].via, None);
        assert_eq!(r[3].table.as_deref(), Some("100"));
        assert!(r[4].linkdown);
    }

    #[test]
    fn uplink_skips_tunnels_and_takes_the_lowest_metric() {
        let r = parse_default_routes("default via 10.8.0.1 dev tun0 metric 1\ndefault via 192.168.1.1 dev wlan0 metric 600\ndefault via 10.0.0.1 dev eth0 metric 100\n");
        let u = pick_uplink(&r, &no_tunnels, &Config::default()).unwrap();
        assert_eq!((u.dev.as_str(), u.via.as_deref()), ("eth0", Some("10.0.0.1")));
    }

    #[test]
    fn a_link_that_is_down_loses_to_a_working_one() {
        let r = parse_default_routes("default via 1.1.1.1 dev eth0 metric 10 linkdown\ndefault via 2.2.2.2 dev wlan0 metric 600\n");
        assert_eq!(pick_uplink(&r, &no_tunnels, &Config::default()).unwrap().dev, "wlan0");
    }

    #[test]
    fn main_table_wins_and_other_tables_are_a_fallback() {
        let r = parse_default_routes("default via 10.0.0.1 dev eth1 table 100\ndefault via 192.168.1.1 dev eth0 metric 900\n");
        assert_eq!(pick_uplink(&r, &no_tunnels, &Config::default()).unwrap().dev, "eth0");
        let only_tunnel_in_main = parse_default_routes("default dev tun0\ndefault via 10.0.0.1 dev eth1 table 100\n");
        assert_eq!(pick_uplink(&only_tunnel_in_main, &no_tunnels, &Config::default()).unwrap().dev, "eth1");
    }

    #[test]
    fn our_own_table_is_never_an_uplink_source() {
        let r = parse_default_routes("default via 10.0.0.1 dev eth1 table 900\n");
        assert_eq!(pick_uplink(&r, &no_tunnels, &Config::default()), None);
    }

    #[test]
    fn a_vpn_only_machine_has_no_uplink() {
        let r = parse_default_routes("default dev tun0 scope link\n");
        assert_eq!(pick_uplink(&r, &no_tunnels, &Config::default()), None);
    }

    #[test]
    fn config_can_force_or_exclude_interfaces() {
        let r =
            parse_default_routes("default via 1.1.1.1 dev eth0 metric 10\ndefault via 2.2.2.2 dev wlan0 metric 600\ndefault dev ppp0\n");
        let mut cfg = Config::default();
        cfg.routing.ignore_interfaces = vec!["eth0".into()];
        assert_eq!(pick_uplink(&r, &no_tunnels, &cfg).unwrap().dev, "wlan0");
        cfg.routing.interface = "ppp0".into();
        let u = pick_uplink(&r, &no_tunnels, &cfg).unwrap();
        assert_eq!((u.dev.as_str(), u.via), ("ppp0", None));
    }

    #[test]
    fn table_dump_is_parsed_including_host_routes_and_extras() {
        let t = parse_table("2.56.24.0/23 via 10.0.0.1 dev eth0 \n5.5.5.5 via 10.0.0.1 dev eth0 proto static\n9.9.9.0/24 dev ppp0 scope link\nblackhole 1.1.1.0/24\nweird\n");
        assert_eq!(t.len(), 3);
        assert_eq!(t[1].prefix.to_string(), "5.5.5.5/32");
        assert_eq!(t[2].via, None);
    }

    fn labels() -> HashMap<String, u32> {
        parse_rt_tables("# c\n255\tlocal\n900\trunet\n")
    }

    const RULES: &str = "0:\tfrom all lookup local\n1000:\tfrom all to 10.0.0.0/24 lookup main\n2400:\tfrom 10.0.0.5 lookup 100\n\
                         2500:\tfrom all lookup runet\n5210:\tfrom all fwmark 0x80000/0xff0000 lookup main\n30801:\tfrom all lookup 880\n32766:\tfrom all lookup main\n";

    #[test]
    fn rules_are_parsed_with_labels_and_selectors() {
        let r = parse_rules(RULES, &labels());
        assert_eq!(r.len(), 7);
        assert_eq!(r[3], Rule { priority: 2500, catch_all: true, table: Some(900) });
        assert!(!r[1].catch_all, "a rule limited by `to` is not a catch-all");
        assert!(!r[2].catch_all, "a rule limited by `from <addr>` is not a catch-all");
        assert!(!r[4].catch_all, "fwmark narrows it down");
        assert_eq!(r[6].table, Some(254));
    }

    #[test]
    fn route_get_output_is_parsed() {
        let out = "5.228.1.1 via 10.0.0.1 dev eth0 table runet src 10.0.0.5 uid 1000 \n    cache \n";
        assert_eq!(parse_route_get(out, &labels()), Some(RouteGet { dev: "eth0".into(), via: Some("10.0.0.1".into()), table: 900 }));
        let vpn = parse_route_get("8.8.8.8 dev tun0 table 880 src 172.16.0.2 uid 1000\n", &labels()).unwrap();
        assert_eq!((vpn.dev.as_str(), vpn.table, vpn.via), ("tun0", 880, None));
        assert_eq!(
            parse_route_get("8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.5\n", &labels()).unwrap().table,
            254,
            "no table token means main"
        );
        assert_eq!(parse_route_get("", &labels()), None);
    }

    #[test]
    fn a_missing_rule_is_added_at_the_preferred_priority() {
        let rules = parse_rules("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n", &labels());
        assert_eq!(plan_rule(&rules, 900, 2500, None), RuleOp::Add(2500));
        assert_eq!(plan_rule(&rules, 900, 2500, Some((880, true))), RuleOp::Add(2500));
    }

    #[test]
    fn a_healthy_rule_is_left_alone() {
        let rules = parse_rules(RULES, &labels());
        assert_eq!(plan_rule(&rules, 900, 2500, None), RuleOp::Nothing);
        assert_eq!(plan_rule(&rules, 900, 2500, Some((900, false))), RuleOp::Nothing, "answered from our table");
        assert_eq!(plan_rule(&rules, 900, 2400, Some((254, false))), RuleOp::Nothing, "main answered, but not into a tunnel");
    }

    #[test]
    fn a_vpn_rule_in_front_of_ours_is_leapfrogged() {
        // A VPN client inserted `1000: from all lookup 880` (default route into the tunnel).
        let rules = parse_rules(
            "0:\tfrom all lookup local\n1000:\tfrom all lookup 880\n2500:\tfrom all lookup runet\n32766:\tfrom all lookup main\n",
            &labels(),
        );
        assert_eq!(plan_rule(&rules, 900, 2500, Some((880, true))), RuleOp::Move { from: 2500, to: 999, shadow: 1000 });
    }

    #[test]
    fn the_lowest_numbered_shadow_wins_and_rules_below_ours_do_not_count() {
        let rules = parse_rules(
            "500:\tfrom all lookup 880\n1000:\tfrom all lookup 880\n2500:\tfrom all lookup runet\n30801:\tfrom all lookup 880\n",
            &labels(),
        );
        assert_eq!(plan_rule(&rules, 900, 2500, Some((880, true))), RuleOp::Move { from: 2500, to: 499, shadow: 500 });
        let behind = parse_rules("2500:\tfrom all lookup runet\n30801:\tfrom all lookup 880\n", &labels());
        assert_eq!(plan_rule(&behind, 900, 2500, Some((880, true))), RuleOp::Nothing, "a rule behind ours cannot shadow it");
    }

    #[test]
    fn the_echo_filter_knows_the_table_by_number_and_by_label() {
        assert_eq!(echo_filters_for(900, &labels()), [" table 900", " table runet"]);
        assert_eq!(echo_filters_for(901, &labels()), [" table 901"]);
    }

    #[test]
    fn a_non_plain_rule_in_front_is_reported_not_ignored() {
        let rules = parse_rules("1000:\tnot from all fwmark 0x1 lookup 880\n2500:\tfrom all lookup runet\n", &labels());
        assert_eq!(plan_rule(&rules, 900, 2500, Some((880, true))), RuleOp::Leak { rule: 1000, table: 880 });
        let to_net = parse_rules("900:\tfrom all to 8.0.0.0/8 lookup 880\n2500:\tfrom all lookup runet\n", &labels());
        assert!(matches!(plan_rule(&to_net, 900, 2500, Some((880, true))), RuleOp::Leak { rule: 900, .. }));
    }

    #[test]
    fn nothing_in_front_means_the_route_is_missing_not_a_shadow() {
        let rules = parse_rules("2500:\tfrom all lookup runet\n30801:\tfrom all lookup 880\n", &labels());
        assert_eq!(plan_rule(&rules, 900, 2500, Some((880, true))), RuleOp::Nothing);
    }

    #[test]
    fn a_shadow_at_priority_one_cannot_be_beaten() {
        let rules = parse_rules("1:\tfrom all lookup 880\n2500:\tfrom all lookup runet\n", &labels());
        assert_eq!(plan_rule(&rules, 900, 2500, Some((880, true))), RuleOp::Stuck { shadow: 1 });
    }

    #[test]
    fn ipv6_default_routes_and_tables_are_parsed() {
        let r = parse_default_routes(
            "default via fe80::1 dev eth0 proto ra metric 1024 expires 1790sec hoplimit 64 pref medium\n\
             default dev wg0 metric 1024 pref medium\n\
             default via fe80::2 dev eth1 proto ra metric 512 pref medium\n",
        );
        assert_eq!(r.len(), 3);
        let u = pick_uplink(&r, &no_tunnels, &Config::default()).unwrap();
        assert_eq!((u.dev.as_str(), u.via.as_deref()), ("eth1", Some("fe80::2")));
        let t =
            parse_table("2a00:1450::/32 via fe80::1 dev eth0 metric 1024 pref medium\n2a02:6b8::/32 dev ppp0 metric 1024 pref medium\n");
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].prefix.to_string(), "2a00:1450::/32");
        assert_eq!((t[0].via.as_deref(), t[1].via.clone()), (Some("fe80::1"), None));
    }

    #[test]
    fn ipv6_route_get_is_parsed() {
        let out = "2a00:1450::1 from :: via fe80::1 dev eth0 table runet proto static src 2001:db8::5 metric 1024 pref medium\n";
        let g = parse_route_get(out, &labels()).unwrap();
        assert_eq!((g.dev.as_str(), g.via.as_deref(), g.table), ("eth0", Some("fe80::1"), 900));
    }

    #[test]
    fn route_lines_use_replace_and_omit_via_for_point_to_point() {
        let c = Cidr::parse("5.0.0.0/8").unwrap();
        assert_eq!(
            route_line(&c, &Some("1.2.3.4".into()), "eth0", 900, "replace"),
            "route replace 5.0.0.0/8 via 1.2.3.4 dev eth0 table 900\n"
        );
        assert_eq!(route_line(&c, &None, "ppp0", 900, "del"), "route del 5.0.0.0/8 dev ppp0 table 900\n");
        let c6 = Cidr::parse("2a00:1450::/32").unwrap();
        assert_eq!(
            route_line(&c6, &Some("fe80::1".into()), "eth0", 900, "replace"),
            "route replace 2a00:1450::/32 via fe80::1 dev eth0 table 900\n"
        );
    }
}

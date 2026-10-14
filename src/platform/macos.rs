//! macOS: there is one routing table, so our routes sit next to everyone else's. Routing
//! picks the longest prefix, and our country blocks are far more specific than the `0/1` +
//! `128/1` pair (or the default route) a VPN installs, so they win without touching the VPN.
//! Ownership is tracked in the state file because the kernel table cannot tell us.

use crate::cidr::Cidr;
use crate::config::Config;
use crate::net::{Installed, Lookup, Net, Plan, Uplink};
use crate::util;
use std::collections::HashSet;

pub struct MacOs;

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub dest: String,
    pub gateway: String,
    pub flags: String,
    pub netif: String,
}

/// Rows of `netstat -rn -f inet`: `Destination Gateway Flags Netif [Expire]`.
pub fn parse_netstat(text: &str) -> Vec<Row> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() < 4 || t[0] == "Destination" {
                return None;
            }
            Some(Row { dest: t[0].into(), gateway: t[1].into(), flags: t[2].into(), netif: t[3].into() })
        })
        .collect()
}

/// netstat abbreviates destinations: `5.228/16` means `5.228.0.0/16`.
pub fn expand_dest(dest: &str, flags: &str) -> Option<Cidr> {
    if dest == "default" {
        return None;
    }
    let (addr, len) = match dest.split_once('/') {
        Some((a, l)) => (a, Some(l.parse::<u8>().ok()?)),
        None => (dest, None),
    };
    let octets: Vec<&str> = addr.split('.').collect();
    if octets.is_empty() || octets.len() > 4 || !octets.iter().all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let len = len.unwrap_or(if flags.contains('H') { 32 } else { 8 * octets.len() as u8 });
    let mut full = octets.clone();
    full.resize(4, "0");
    Cidr::parse(&format!("{}/{len}", full.join(".")))
}

pub fn is_tunnel(dev: &str) -> bool {
    ["utun", "ipsec", "ppp", "gif", "stf", "tun", "tap", "wg", "tailscale"].iter().any(|p| dev.starts_with(p))
}

pub fn pick_uplink(rows: &[Row], cfg: &Config) -> Option<Uplink> {
    let forced = cfg.routing.interface.as_str();
    let mut candidates: Vec<&Row> = rows
        .iter()
        .filter(|r| r.dest == "default")
        .filter(|r| !cfg.routing.ignore_interfaces.iter().any(|i| i == &r.netif))
        .filter(|r| if forced.is_empty() { !is_tunnel(&r.netif) } else { r.netif == forced })
        .collect();
    // Unscoped routes (no `I` flag) are the ones the system actually uses; scoped ones are a fallback.
    candidates.sort_by_key(|r| r.flags.contains('I'));
    let has_gateway = |r: &&&Row| crate::cidr::parse_ipv4(&r.gateway).is_some();
    // Unforced: need a real next hop (`link#N` gives nothing to point routes at). Forced: an
    // interface route is acceptable.
    let r = if forced.is_empty() { candidates.iter().find(has_gateway)? } else { candidates.first()? };
    let via = crate::cidr::parse_ipv4(&r.gateway).map(|_| r.gateway.clone());
    Some(Uplink { dev: r.netif.clone(), via })
}

pub fn installed_from(rows: &[Row], candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Vec<Installed> {
    rows.iter()
        .filter_map(|r| {
            let prefix = expand_dest(&r.dest, &r.flags)?;
            let via = crate::cidr::parse_ipv4(&r.gateway).map(|_| r.gateway.clone());
            (candidates.contains(&prefix) && ours.iter().any(|u| u.matches(&via, &r.netif))).then(|| Installed {
                prefix,
                via,
                dev: r.netif.clone(),
            })
        })
        .collect()
}

/// `route get` output: `gateway: x` / `interface: y`.
pub fn parse_route_get(text: &str) -> Option<(String, Option<String>)> {
    let field = |key: &str| text.lines().find_map(|l| l.trim().strip_prefix(key)).map(|v| v.trim().to_string());
    let dev = field("interface:")?;
    let via = field("gateway:").filter(|g| crate::cidr::parse_ipv4(g).is_some());
    Some((dev, via))
}

fn route_args(verb: &str, prefix: &Cidr, via: &Option<String>, dev: &str) -> Vec<String> {
    let mut a = vec!["-n".into(), "-q".into(), verb.to_string(), "-net".into(), prefix.to_string()];
    match via {
        Some(v) => a.push(v.clone()),
        None => {
            a.push("-interface".into());
            a.push(dev.to_string());
        }
    }
    a
}

fn run_routes(commands: Vec<Vec<String>>) -> Result<(), String> {
    const WORKERS: usize = 8;
    if commands.is_empty() {
        return Ok(());
    }
    let chunk = commands.len().div_ceil(WORKERS);
    let failures: Vec<String> = std::thread::scope(|s| {
        let handles: Vec<_> = commands
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    part.iter()
                        .filter_map(|args| {
                            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                            match util::run("/sbin/route", &refs) {
                                Err(e) if !e.contains("File exists") && !e.contains("not in table") => Some(e),
                                _ => None,
                            }
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    match failures.first() {
        None => Ok(()),
        Some(first) => Err(format!("{} route commands failed, first: {first}", failures.len())),
    }
}

impl Net for MacOs {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn require_admin(&self) -> Result<(), String> {
        if util::is_root() {
            Ok(())
        } else {
            Err("this needs root: re-run with sudo".into())
        }
    }

    fn uplink(&self, cfg: &Config) -> Result<Option<Uplink>, String> {
        Ok(pick_uplink(&parse_netstat(&util::run("netstat", &["-rn", "-f", "inet"])?), cfg))
    }

    fn tunnels(&self) -> Vec<String> {
        util::run("ifconfig", &["-l"])
            .map(|s| s.split_whitespace().filter(|n| is_tunnel(n)).map(String::from).collect())
            .unwrap_or_default()
    }

    fn ensure_rule(&self, _: &Config, _: Option<u32>) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn rule_present(&self, _: &Config) -> Result<bool, String> {
        Ok(true)
    }

    fn installed(&self, _: &Config, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<Vec<Installed>, String> {
        Ok(installed_from(&parse_netstat(&util::run("netstat", &["-rn", "-f", "inet"])?), candidates, ours))
    }

    fn apply(&self, _: &Config, uplink: &Uplink, plan: &Plan) -> Result<(), String> {
        let removes = plan.remove.iter().map(|r| route_args("delete", &r.prefix, &r.via, &r.dev)).collect();
        let _ = run_routes(removes); // deleting something already gone is not an error worth stopping for
        run_routes(plan.add.iter().map(|p| route_args("add", p, &uplink.via, &uplink.dev)).collect())
    }

    fn clear(&self, cfg: &Config, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<usize, String> {
        let found = self.installed(cfg, candidates, ours)?;
        let n = found.len();
        run_routes(found.iter().map(|r| route_args("delete", &r.prefix, &r.via, &r.dev)).collect())?;
        Ok(n)
    }

    fn lookup(&self, _: &Config, ip: u32) -> Result<Lookup, String> {
        let text = util::run("route", &["-n", "get", &crate::cidr::fmt_ipv4(ip)])?;
        let (dev, via) = parse_route_get(&text).ok_or("unexpected `route get` output")?;
        Ok(Lookup { tunnel: is_tunnel(&dev), dev, via })
    }

    fn watch_command(&self) -> Option<Vec<String>> {
        Some(vec!["route".into(), "-n".into(), "monitor".into()])
    }

    fn tracks_ownership(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETSTAT: &str = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n\
default            192.168.1.1        UGScg                 en0\n\
default            link#18            UCSIg             utun4\n\
default            10.0.0.1           UGScIg                en5\n\
0/1                utun4              USc               utun4\n\
5.228/16           192.168.1.1        UGSc                  en0\n\
10.1.2.3           192.168.1.1        UGHS                  en0\n\
127                127.0.0.1          UCS                   lo0\n\
192.168.1/24       link#14            UCS                   en0      !\n\
213.59/16          192.168.1.1        UGSc                  en0\n";

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn netstat_rows_and_abbreviated_destinations() {
        let rows = parse_netstat(NETSTAT);
        assert_eq!(rows.len(), 9);
        assert_eq!(expand_dest("5.228/16", "UGSc"), Some(c("5.228.0.0/16")));
        assert_eq!(expand_dest("10.1.2.3", "UGHS"), Some(c("10.1.2.3/32")));
        assert_eq!(expand_dest("127", "UCS"), Some(c("127.0.0.0/8")));
        assert_eq!(expand_dest("192.168.1/24", "UCS"), Some(c("192.168.1.0/24")));
        assert_eq!(expand_dest("default", "UGSc"), None);
        assert_eq!(expand_dest("link#3", ""), None);
    }

    #[test]
    fn uplink_is_the_unscoped_physical_default() {
        let rows = parse_netstat(NETSTAT);
        let u = pick_uplink(&rows, &Config::default()).unwrap();
        assert_eq!((u.dev.as_str(), u.via.as_deref()), ("en0", Some("192.168.1.1")));
        let mut cfg = Config::default();
        cfg.routing.ignore_interfaces = vec!["en0".into()];
        assert_eq!(pick_uplink(&rows, &cfg).unwrap().dev, "en5", "scoped route is the fallback");
    }

    #[test]
    fn a_vpn_only_machine_has_no_uplink() {
        let rows = parse_netstat("default link#18 UCSIg utun4\n");
        assert_eq!(pick_uplink(&rows, &Config::default()), None);
    }

    #[test]
    fn only_routes_through_our_gateways_count_as_ours() {
        let rows = parse_netstat(NETSTAT);
        let cands: HashSet<Cidr> = [c("5.228.0.0/16"), c("213.59.0.0/16"), c("192.168.1.0/24")].into();
        let ours = [Uplink { dev: "en0".into(), via: Some("192.168.1.1".into()) }];
        let found = installed_from(&rows, &cands, &ours);
        assert_eq!(found.len(), 2, "the on-link LAN route and non-candidates are left alone");
        let other_gw = [Uplink { dev: "en0".into(), via: Some("10.9.9.9".into()) }];
        assert!(installed_from(&rows, &cands, &other_gw).is_empty());
    }

    #[test]
    fn route_get_output_is_parsed() {
        let out = "   route to: 5.228.1.1\ndestination: 5.228.0.0\n       mask: 255.255.0.0\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC>\n";
        assert_eq!(parse_route_get(out), Some(("en0".into(), Some("192.168.1.1".into()))));
        assert_eq!(parse_route_get("interface: utun4\n"), Some(("utun4".into(), None)));
    }

    #[test]
    fn route_command_lines() {
        let a = route_args("add", &c("5.228.0.0/16"), &Some("192.168.1.1".into()), "en0");
        assert_eq!(a.join(" "), "-n -q add -net 5.228.0.0/16 192.168.1.1");
        let b = route_args("delete", &c("5.228.0.0/16"), &None, "en0");
        assert_eq!(b.join(" "), "-n -q delete -net 5.228.0.0/16 -interface en0");
    }
}

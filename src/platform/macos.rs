//! macOS: there is one routing table, so our routes sit next to everyone else's. Routing
//! picks the longest prefix, and our country blocks are far more specific than the `0/1` +
//! `128/1` pair (or the default route) a VPN installs, so they win without touching the VPN.
//! Ownership is tracked in the state file because the kernel table cannot tell us.

use crate::cidr::{Cidr, Family};
use crate::config::Config;
use crate::net::{Installed, Lookup, Net, Plan, Uplink};
use crate::util;
use std::collections::HashSet;
use std::net::IpAddr;

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

/// Drop an interface zone: `fe80::1%en0` -> `fe80::1`.
fn without_zone(s: &str) -> &str {
    s.split('%').next().unwrap_or(s)
}

/// netstat abbreviates IPv4 destinations (`5.228/16` means `5.228.0.0/16`) and appends zones to
/// link-local IPv6 ones (`fe80::%lo0/64`).
pub fn expand_dest(dest: &str, flags: &str, fam: Family) -> Option<Cidr> {
    if dest == "default" {
        return None;
    }
    let (addr, len) = match dest.split_once('/') {
        Some((a, l)) => (a, Some(l.parse::<u8>().ok()?)),
        None => (dest, None),
    };
    let found = match fam {
        Family::V4 => {
            let octets: Vec<&str> = addr.split('.').collect();
            if octets.is_empty() || octets.len() > 4 || !octets.iter().all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit())) {
                return None;
            }
            let len = len.unwrap_or(if flags.contains('H') { 32 } else { 8 * octets.len() as u8 });
            let mut full = octets.clone();
            full.resize(4, "0");
            Cidr::parse(&format!("{}/{len}", full.join(".")))
        }
        Family::V6 => Cidr::parse(&format!("{}/{}", without_zone(addr), len.unwrap_or(128))),
    };
    found.filter(|c| c.fam == fam)
}

fn has_gateway(gateway: &str, fam: Family) -> bool {
    without_zone(gateway).parse::<IpAddr>().is_ok_and(|ip| Family::of(&ip) == fam)
}

pub fn is_tunnel(dev: &str) -> bool {
    ["utun", "ipsec", "ppp", "gif", "stf", "tun", "tap", "wg", "tailscale"].iter().any(|p| dev.starts_with(p))
}

pub fn pick_uplink(rows: &[Row], cfg: &Config, fam: Family) -> Option<Uplink> {
    let forced = cfg.routing.interface.as_str();
    let mut candidates: Vec<&Row> = rows
        .iter()
        .filter(|r| r.dest == "default")
        .filter(|r| !cfg.routing.ignore_interfaces.iter().any(|i| i == &r.netif))
        .filter(|r| if forced.is_empty() { !is_tunnel(&r.netif) } else { r.netif == forced })
        .collect();
    // Unscoped routes (no `I` flag) are the ones the system actually uses; scoped ones are a fallback.
    candidates.sort_by_key(|r| r.flags.contains('I'));
    let usable = |r: &&&Row| has_gateway(&r.gateway, fam);
    // Unforced: need a real next hop (`link#N` gives nothing to point routes at). Forced: an
    // interface route is acceptable.
    let r = if forced.is_empty() { candidates.iter().find(usable)? } else { candidates.first()? };
    let via = has_gateway(&r.gateway, fam).then(|| r.gateway.clone());
    Some(Uplink { dev: r.netif.clone(), via })
}

pub fn installed_from(rows: &[Row], fam: Family, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Vec<Installed> {
    rows.iter()
        .filter_map(|r| {
            let prefix = expand_dest(&r.dest, &r.flags, fam)?;
            let via = has_gateway(&r.gateway, fam).then(|| r.gateway.clone());
            (candidates.contains(&prefix) && ours.iter().any(|u| u.matches(&via, &r.netif))).then(|| Installed {
                prefix,
                via,
                dev: r.netif.clone(),
            })
        })
        .collect()
}

/// `route get` output: `gateway: x` / `interface: y`.
pub fn parse_route_get(text: &str, fam: Family) -> Option<(String, Option<String>)> {
    let field = |key: &str| text.lines().find_map(|l| l.trim().strip_prefix(key)).map(|v| v.trim().to_string());
    let dev = field("interface:")?;
    let via = field("gateway:").filter(|g| has_gateway(g, fam));
    Some((dev, via))
}

fn netstat(fam: Family) -> Result<Vec<Row>, String> {
    let family = if fam == Family::V6 { "inet6" } else { "inet" };
    Ok(parse_netstat(&util::run("netstat", &["-rn", "-f", family])?))
}

fn route_args(verb: &str, prefix: &Cidr, via: &Option<String>, dev: &str) -> Vec<String> {
    let mut a = vec!["-n".into(), "-q".into(), verb.to_string()];
    if prefix.fam == Family::V6 {
        a.push("-inet6".into());
    }
    a.push("-net".into());
    a.push(prefix.to_string());
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

    fn uplink(&self, cfg: &Config, fam: Family) -> Result<Option<Uplink>, String> {
        Ok(pick_uplink(&netstat(fam)?, cfg, fam))
    }

    fn tunnels(&self) -> Vec<String> {
        // gif0 and stf0 exist on every Mac and carry nothing; they are not worth listing.
        util::run("ifconfig", &["-l"])
            .map(|s| {
                s.split_whitespace().filter(|n| is_tunnel(n) && !n.starts_with("gif") && !n.starts_with("stf")).map(String::from).collect()
            })
            .unwrap_or_default()
    }

    fn ensure_rule(&self, _: &Config, _: Family, _: Option<IpAddr>) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn rule_present(&self, _: &Config, _: Family) -> Result<bool, String> {
        Ok(true)
    }

    fn installed(&self, _: &Config, fam: Family, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<Vec<Installed>, String> {
        Ok(installed_from(&netstat(fam)?, fam, candidates, ours))
    }

    fn apply(&self, _: &Config, _: Family, uplink: &Uplink, plan: &Plan) -> Result<(), String> {
        let (replaced, stale) = plan.split_removals();
        let delete = |rows: Vec<&Installed>| rows.iter().map(|r| route_args("delete", &r.prefix, &r.via, &r.dev)).collect::<Vec<_>>();
        let _ = run_routes(delete(replaced)); // deleting something already gone is not an error worth stopping for
        let added = run_routes(plan.add.iter().map(|p| route_args("add", p, &uplink.via, &uplink.dev)).collect());
        let _ = run_routes(delete(stale));
        added
    }

    fn clear(&self, cfg: &Config, fam: Family, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<usize, String> {
        let found = self.installed(cfg, fam, candidates, ours)?;
        let n = found.len();
        run_routes(found.iter().map(|r| route_args("delete", &r.prefix, &r.via, &r.dev)).collect())?;
        Ok(n)
    }

    fn lookup(&self, _: &Config, ip: IpAddr) -> Result<Lookup, String> {
        let fam = Family::of(&ip);
        let mut args = vec!["-n", "get"];
        if fam == Family::V6 {
            args.push("-inet6");
        }
        let target = ip.to_string();
        args.push(&target);
        let text = util::run("route", &args)?;
        let (dev, via) = parse_route_get(&text, fam).ok_or("unexpected `route get` output")?;
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

    const NETSTAT6: &str =
        "Internet6:\nDestination                             Gateway                         Flags           Netif Expire\n\
default                                 fe80::1%en0                     UGcg              en0\n\
default                                 fe80::%utun4                    UGcIg           utun4\n\
2a00:1450::/32                          fe80::1%en0                     UGSc              en0\n\
2a02:6b8::/32                           fe80::1%en0                     UGSc              en0\n\
fe80::%lo0/64                           fe80::1%lo0                     UcI               lo0\n\
::1                                     ::1                             UHL               lo0\n";

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn netstat_rows_and_abbreviated_destinations() {
        let rows = parse_netstat(NETSTAT);
        assert_eq!(rows.len(), 9);
        assert_eq!(expand_dest("5.228/16", "UGSc", Family::V4), Some(c("5.228.0.0/16")));
        assert_eq!(expand_dest("10.1.2.3", "UGHS", Family::V4), Some(c("10.1.2.3/32")));
        assert_eq!(expand_dest("127", "UCS", Family::V4), Some(c("127.0.0.0/8")));
        assert_eq!(expand_dest("192.168.1/24", "UCS", Family::V4), Some(c("192.168.1.0/24")));
        assert_eq!(expand_dest("default", "UGSc", Family::V4), None);
        assert_eq!(expand_dest("link#3", "", Family::V4), None);
    }

    #[test]
    fn ipv6_destinations_lose_their_zone() {
        assert_eq!(expand_dest("2a00:1450::/32", "UGSc", Family::V6), Some(c("2a00:1450::/32")));
        assert_eq!(expand_dest("fe80::%lo0/64", "UcI", Family::V6), Some(c("fe80::/64")));
        assert_eq!(expand_dest("::1", "UHL", Family::V6), Some(c("::1/128")));
        assert_eq!(expand_dest("2a00:1450::/32", "UGSc", Family::V4), None, "families are not mixed");
    }

    #[test]
    fn uplink_is_the_unscoped_physical_default() {
        let rows = parse_netstat(NETSTAT);
        let u = pick_uplink(&rows, &Config::default(), Family::V4).unwrap();
        assert_eq!((u.dev.as_str(), u.via.as_deref()), ("en0", Some("192.168.1.1")));
        let mut cfg = Config::default();
        cfg.routing.ignore_interfaces = vec!["en0".into()];
        assert_eq!(pick_uplink(&rows, &cfg, Family::V4).unwrap().dev, "en5", "scoped route is the fallback");
    }

    #[test]
    fn ipv6_uplink_keeps_the_zone_and_skips_the_tunnel() {
        let rows = parse_netstat(NETSTAT6);
        let u = pick_uplink(&rows, &Config::default(), Family::V6).unwrap();
        assert_eq!((u.dev.as_str(), u.via.as_deref()), ("en0", Some("fe80::1%en0")));
    }

    #[test]
    fn a_vpn_only_machine_has_no_uplink() {
        let rows = parse_netstat("default link#18 UCSIg utun4\n");
        assert_eq!(pick_uplink(&rows, &Config::default(), Family::V4), None);
        let v6 = parse_netstat("default fe80::%utun4 UGcIg utun4\n");
        assert_eq!(pick_uplink(&v6, &Config::default(), Family::V6), None);
    }

    #[test]
    fn only_routes_through_our_gateways_count_as_ours() {
        let rows = parse_netstat(NETSTAT);
        let cands: HashSet<Cidr> = [c("5.228.0.0/16"), c("213.59.0.0/16"), c("192.168.1.0/24")].into();
        let ours = [Uplink { dev: "en0".into(), via: Some("192.168.1.1".into()) }];
        let found = installed_from(&rows, Family::V4, &cands, &ours);
        assert_eq!(found.len(), 2, "the on-link LAN route and non-candidates are left alone");
        let other_gw = [Uplink { dev: "en0".into(), via: Some("10.9.9.9".into()) }];
        assert!(installed_from(&rows, Family::V4, &cands, &other_gw).is_empty());

        let rows6 = parse_netstat(NETSTAT6);
        let cands6: HashSet<Cidr> = [c("2a00:1450::/32"), c("2a02:6b8::/32"), c("fe80::/64")].into();
        let ours6 = [Uplink { dev: "en0".into(), via: Some("fe80::1%en0".into()) }];
        assert_eq!(installed_from(&rows6, Family::V6, &cands6, &ours6).len(), 2);
    }

    #[test]
    fn route_get_output_is_parsed() {
        let out = "   route to: 5.228.1.1\ndestination: 5.228.0.0\n       mask: 255.255.0.0\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC>\n";
        assert_eq!(parse_route_get(out, Family::V4), Some(("en0".into(), Some("192.168.1.1".into()))));
        assert_eq!(parse_route_get("interface: utun4\n", Family::V4), Some(("utun4".into(), None)));
        assert_eq!(
            parse_route_get("gateway: fe80::1%en0\n  interface: en0\n", Family::V6),
            Some(("en0".into(), Some("fe80::1%en0".into())))
        );
    }

    // Captured from a real macOS 13 machine running a full-tunnel VPN (utun4) next to Tailscale (utun0):
    // the VPN splits the IPv4 space into big chunks, routes all of IPv6 `2000::/4` into itself and
    // no physical IPv6 gateway exists. Addresses are replaced by documentation ones.
    const REAL4: &str = "Routing tables\n\nInternet:\nDestination        Gateway            Flags           Netif Expire\n\
default            192.168.1.1        UGScg             en0       \n\
default            link#26            UCSIg           utun0       \n\
1                  utun4              USc             utun4       \n\
2/7                utun4              USc             utun4       \n\
2.56.24/23         192.168.1.1        UGSc              en0       \n\
2.57/24            192.168.1.1        UGSc              en0       \n\
2.60/14            192.168.1.1        UGSc              en0       \n\
100.64/10          link#26            UCS             utun0       \n\
100.100.100.100/32 link#26            UCS             utun0       \n\
100.100.100.100    link#26            UHWIi           utun0       \n\
109.60.128/17      192.168.1.1        UGSc              en0       \n\
192.168.1/24       link#5             UCS               en0      !\n\
192.168.1.1/32     link#5             UCS               en0      !\n";

    const REAL6: &str = "Routing tables\n\nInternet6:\nDestination                             Gateway                         Flags           Netif Expire\n\
default                                 fd7a:115c:a1e0::                UGcIg           utun0       \n\
default                                 fe80::%utun1                    UGcIg           utun1       \n\
default                                 fe80::%utun2                    UGcIg           utun2       \n\
::1                                     ::1                             UHL               lo0       \n\
2000::/4                                utun4                           USc             utun4       \n\
3000::/4                                utun4                           USc             utun4       \n\
fd7a:115c:a1e0::/48                     fe80::1%utun0                   Uc              utun0       \n\
fe80::%lo0/64                           fe80::1%lo0                     UcI               lo0       \n\
fe80::1%lo0                             link#1                          UHLI              lo0       \n\
fe80::%en0/64                           link#5                          UCI               en0       \n\
fe80::aaaa:bbff:fecc:dd01%en0           aa:bb:cc:0:dd:1                 UHLWI             en0       \n";

    #[test]
    fn real_macos_ipv4_output_with_a_vpn_splitting_the_space() {
        let rows = parse_netstat(REAL4);
        let u = pick_uplink(&rows, &Config::default(), Family::V4).unwrap();
        assert_eq!((u.dev.as_str(), u.via.as_deref()), ("en0", Some("192.168.1.1")), "the scoped tunnel default must not win");
        let cands: HashSet<Cidr> =
            [c("2.56.24.0/23"), c("2.57.0.0/24"), c("2.60.0.0/14"), c("109.60.128.0/17"), c("1.0.0.0/8"), c("192.168.1.0/24")].into();
        let ours = [Uplink { dev: "en0".into(), via: Some("192.168.1.1".into()) }];
        let found: Vec<String> = installed_from(&rows, Family::V4, &cands, &ours).iter().map(|i| i.prefix.to_string()).collect();
        assert_eq!(
            found,
            ["2.56.24.0/23", "2.57.0.0/24", "2.60.0.0/14", "109.60.128.0/17"],
            "VPN chunks and on-link LAN routes are not ours"
        );
    }

    #[test]
    fn real_macos_ipv6_output_has_no_physical_uplink() {
        let rows = parse_netstat(REAL6);
        assert_eq!(pick_uplink(&rows, &Config::default(), Family::V6), None, "only tunnels carry a default route");
        // Host routes with a zone and a MAC "gateway" must parse without being mistaken for next hops.
        assert_eq!(expand_dest("fe80::aaaa:bbff:fecc:dd01%en0", "UHLWI", Family::V6), Some(c("fe80::aaaa:bbff:fecc:dd01/128")));
        assert!(!has_gateway("aa:bb:cc:0:dd:1", Family::V6));
        assert!(!has_gateway("utun4", Family::V6));
        assert!(has_gateway("fe80::1%en0", Family::V6));
    }

    #[test]
    fn real_route_get_for_tunnel_and_wire() {
        let tunnel = "   route to: 8.8.8.8\ndestination: 8.0.0.0\n       mask: 254.0.0.0\n  interface: utun4\n      flags: <UP,DONE,STATIC,PRCLONING>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n";
        let (dev, via) = parse_route_get(tunnel, Family::V4).unwrap();
        assert_eq!((dev.as_str(), via, is_tunnel("utun4")), ("utun4", None, true));
        let wire = "   route to: 5.228.1.1\ndestination: 5.228.0.0\n       mask: 255.255.0.0\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        assert_eq!(parse_route_get(wire, Family::V4), Some(("en0".into(), Some("192.168.1.1".into()))));
        let v6 = "   route to: 2a02:6b8::1\ndestination: 2000::\n       mask: f000::\n  interface: utun4\n      flags: <UP,DONE,STATIC,PRCLONING>\n";
        assert_eq!(parse_route_get(v6, Family::V6), Some(("utun4".into(), None)));
    }

    #[test]
    fn route_command_lines() {
        let a = route_args("add", &c("5.228.0.0/16"), &Some("192.168.1.1".into()), "en0");
        assert_eq!(a.join(" "), "-n -q add -net 5.228.0.0/16 192.168.1.1");
        let b = route_args("delete", &c("5.228.0.0/16"), &None, "en0");
        assert_eq!(b.join(" "), "-n -q delete -net 5.228.0.0/16 -interface en0");
        let v6 = route_args("add", &c("2a00:1450::/32"), &Some("fe80::1%en0".into()), "en0");
        assert_eq!(v6.join(" "), "-n -q add -inet6 -net 2a00:1450::/32 fe80::1%en0");
    }
}

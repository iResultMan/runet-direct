//! Windows: one routing table, longest prefix wins, so our country blocks beat the VPN's
//! default route (and its `0/1` + `128/1` halves) without touching it. Interfaces are
//! classified with `Get-NetAdapter -Physical`, which excludes every virtual adapter (TAP,
//! Wintun, WireGuard, Hyper-V ...) whichever VPN created it.
//!
//! Anything parsed from command output is locale-independent: JSON from PowerShell and the
//! numeric rows of `route print`.

use crate::cidr::{Cidr, Family};
use crate::config::Config;
use crate::net::{Installed, Lookup, Net, Plan, Uplink};
use crate::util;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;

pub struct Windows;

// ---------------------------------------------------------------------------
// PowerShell plumbing
// ---------------------------------------------------------------------------

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `-EncodedCommand` payload: base64 of the UTF-16LE script, which sidesteps all quoting.
pub fn encode_command(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64(&bytes)
}

pub fn powershell(script: &str) -> Result<String, String> {
    let full = format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); {script}");
    util::run("powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encode_command(&full)])
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct UplinkRow {
    #[serde(rename = "ifIndex")]
    pub if_index: u32,
    pub alias: String,
    pub via: String,
    pub metric: u32,
}

/// PowerShell prints a single object without brackets; accept both shapes.
fn json_rows<T: for<'de> Deserialize<'de>>(text: &str) -> Result<Vec<T>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.starts_with('[') {
        serde_json::from_str(text).map_err(|e| format!("bad JSON from PowerShell: {e}"))
    } else {
        serde_json::from_str(text).map(|one| vec![one]).map_err(|e| format!("bad JSON from PowerShell: {e}"))
    }
}

pub fn pick_uplink(rows: &[UplinkRow], cfg: &Config) -> Option<Uplink> {
    let forced = cfg.routing.interface.as_str();
    rows.iter()
        .filter(|r| !cfg.routing.ignore_interfaces.iter().any(|i| i == &r.alias))
        .filter(|r| forced.is_empty() || r.alias == forced)
        .min_by_key(|r| r.metric)
        .map(|r| Uplink { dev: r.if_index.to_string(), via: Some(r.via.clone()) })
}

fn mask_len(mask: u32) -> Option<u8> {
    let ones = mask.count_ones() as u8;
    (mask == if ones == 0 { 0 } else { u32::MAX << (32 - ones as u32) }).then_some(ones)
}

/// A gateway route from `route print`.
#[derive(Debug, PartialEq)]
pub struct RouteRow {
    pub prefix: Cidr,
    pub gateway: String,
    /// IPv6 rows name the interface by index; IPv4 rows give an address instead, so this is empty there.
    pub dev: String,
}

/// IPv4: `dest mask gateway interface-address metric`. IPv6: `if metric dest/len gateway`.
/// On-link rows have a localized word instead of an address and are skipped.
pub fn parse_route_print(text: &str, fam: Family) -> Vec<RouteRow> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            match fam {
                Family::V4 => {
                    if t.len() != 5 {
                        return None;
                    }
                    let (dest, mask) = (t[0].parse::<std::net::Ipv4Addr>().ok()?, t[1].parse::<std::net::Ipv4Addr>().ok()?);
                    let gw = t[2].parse::<std::net::Ipv4Addr>().ok()?;
                    t[3].parse::<std::net::Ipv4Addr>().ok()?;
                    t[4].parse::<u32>().ok()?;
                    let mask = u32::from(mask);
                    let len = mask_len(mask)?;
                    Some(RouteRow {
                        prefix: Cidr { fam, addr: (u32::from(dest) & mask) as u128, len },
                        gateway: gw.to_string(),
                        dev: String::new(),
                    })
                }
                Family::V6 => {
                    if t.len() != 4 {
                        return None;
                    }
                    t[0].parse::<u32>().ok()?;
                    t[1].parse::<u32>().ok()?;
                    let prefix = Cidr::parse(t[2]).filter(|c| c.fam == fam && t[2].contains('/'))?;
                    let gw = t[3].parse::<std::net::Ipv6Addr>().ok()?;
                    Some(RouteRow { prefix, gateway: gw.to_string(), dev: t[0].to_string() })
                }
            }
        })
        .collect()
}

pub fn installed_from(rows: &[RouteRow], candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Vec<Installed> {
    rows.iter()
        .filter(|r| r.prefix.len > 0 && candidates.contains(&r.prefix))
        .filter_map(|r| {
            let u = ours.iter().find(|u| u.via.as_deref() == Some(r.gateway.as_str()) && (r.dev.is_empty() || r.dev == u.dev))?;
            Some(Installed { prefix: r.prefix, via: Some(r.gateway.clone()), dev: u.dev.clone() })
        })
        .collect()
}

/// A netsh script for `netsh -f`. Removals first, then additions.
pub fn netsh_script(fam: Family, uplink: &Uplink, plan: &Plan) -> String {
    let mut s = String::from(if fam == Family::V6 { "interface ipv6\n" } else { "interface ipv4\n" });
    let delete = |s: &mut String, rows: &[&Installed]| {
        for r in rows {
            if let Some(via) = &r.via {
                s.push_str(&format!("delete route prefix={} interface={} nexthop={via} store=active\n", r.prefix, r.dev));
            }
        }
    };
    let (replaced, stale) = plan.split_removals();
    delete(&mut s, &replaced);
    for p in &plan.add {
        match &uplink.via {
            Some(via) => s.push_str(&format!("add route prefix={p} interface={} nexthop={via} metric=1 store=active\n", uplink.dev)),
            None => s.push_str(&format!("add route prefix={p} interface={} metric=1 store=active\n", uplink.dev)),
        }
    }
    delete(&mut s, &stale);
    s
}

#[derive(Deserialize)]
struct LookupRow {
    alias: String,
    via: Option<String>,
    physical: bool,
}

fn uplink_script(fam: Family) -> String {
    let (family, prefix, none) = if fam == Family::V6 { ("IPv6", "::/0", "::") } else { ("IPv4", "0.0.0.0/0", "0.0.0.0") };
    format!(
        r#"
$rows = @()
foreach ($a in @(Get-NetAdapter -Physical | Where-Object {{ $_.Status -eq 'Up' }})) {{
  $m = (Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily {family} -ErrorAction SilentlyContinue).InterfaceMetric
  foreach ($r in @(Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily {family} -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue)) {{
    if ($r.NextHop -ne '{none}') {{
      $rows += [pscustomobject]@{{ ifIndex = [int]$a.ifIndex; alias = [string]$a.Name; via = [string]$r.NextHop; metric = [int]($r.RouteMetric + $m) }}
    }}
  }}
}}
ConvertTo-Json -InputObject @($rows) -Compress
"#
    )
}

impl Net for Windows {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn require_admin(&self) -> Result<(), String> {
        if util::ok("net", &["session"]) {
            Ok(())
        } else {
            Err("this needs an elevated prompt: re-run as Administrator".into())
        }
    }

    fn uplink(&self, cfg: &Config, fam: Family) -> Result<Option<Uplink>, String> {
        let rows: Vec<UplinkRow> = json_rows(&powershell(&uplink_script(fam))?)?;
        Ok(pick_uplink(&rows, cfg))
    }

    fn tunnels(&self) -> Vec<String> {
        powershell("Get-NetAdapter | Where-Object { -not $_.HardwareInterface -and $_.Status -eq 'Up' } | ForEach-Object { $_.Name }")
            .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default()
    }

    fn ensure_rule(&self, _: &Config, _: Family, _: Option<IpAddr>) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn rule_present(&self, _: &Config, _: Family) -> Result<bool, String> {
        Ok(true)
    }

    fn installed(&self, _: &Config, fam: Family, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<Vec<Installed>, String> {
        let flag = if fam == Family::V6 { "-6" } else { "-4" };
        Ok(installed_from(&parse_route_print(&util::run("route", &["print", flag])?, fam), candidates, ours))
    }

    fn apply(&self, _: &Config, fam: Family, uplink: &Uplink, plan: &Plan) -> Result<(), String> {
        let path = std::env::temp_dir().join(format!("runet-direct-routes-{}.netsh", fam.key()));
        std::fs::write(&path, netsh_script(fam, uplink, plan)).map_err(|e| e.to_string())?;
        let result = util::run("netsh", &["-f", &path.to_string_lossy()]);
        let _ = std::fs::remove_file(&path);
        result.map(|_| ())
    }

    fn clear(&self, cfg: &Config, fam: Family, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<usize, String> {
        let found = self.installed(cfg, fam, candidates, ours)?;
        let n = found.len();
        if let Some(u) = ours.first() {
            self.apply(cfg, fam, u, &Plan { add: Vec::new(), remove: found, keep: 0 })?;
        }
        Ok(n)
    }

    fn lookup(&self, _: &Config, ip: IpAddr) -> Result<Lookup, String> {
        let script = format!(
            "$r = Find-NetRoute -RemoteIPAddress '{ip}' | Where-Object {{ $_.DestinationPrefix }} | Select-Object -First 1; \
             $phys = @(Get-NetAdapter -Physical | ForEach-Object {{ $_.ifIndex }}); \
             ConvertTo-Json -Compress ([pscustomobject]@{{ alias = [string]$r.InterfaceAlias; via = [string]$r.NextHop; physical = ($phys -contains $r.ifIndex) }})"
        );
        let row: LookupRow = json_rows(&powershell(&script)?)?.into_iter().next().ok_or("empty route lookup")?;
        let via = row.via.filter(|v| v != "0.0.0.0" && v != "::" && !v.is_empty());
        Ok(Lookup { dev: row.alias, via, tunnel: !row.physical })
    }

    fn watch_command(&self) -> Option<Vec<String>> {
        None
    }

    fn tracks_ownership(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encoded_command_is_utf16le_base64() {
        assert_eq!(encode_command("dir"), "ZABpAHIA");
    }

    #[test]
    fn uplink_json_accepts_single_object_and_arrays() {
        let one = r#"{"ifIndex":12,"alias":"Ethernet","via":"192.168.1.1","metric":25}"#;
        let many = format!("[{one},{{\"ifIndex\":7,\"alias\":\"Wi-Fi\",\"via\":\"10.0.0.1\",\"metric\":55}}]");
        let rows: Vec<UplinkRow> = json_rows(one).unwrap();
        assert_eq!(rows.len(), 1);
        let rows: Vec<UplinkRow> = json_rows(&many).unwrap();
        let u = pick_uplink(&rows, &Config::default()).unwrap();
        assert_eq!((u.dev.as_str(), u.via.as_deref()), ("12", Some("192.168.1.1")));
        assert!(json_rows::<UplinkRow>("[]").unwrap().is_empty());
        assert!(json_rows::<UplinkRow>("  ").unwrap().is_empty());
        assert!(json_rows::<UplinkRow>("garbage").is_err());
    }

    #[test]
    fn uplink_honours_ignore_and_forced_adapter() {
        let rows = vec![
            UplinkRow { if_index: 12, alias: "Ethernet".into(), via: "192.168.1.1".into(), metric: 25 },
            UplinkRow { if_index: 7, alias: "Wi-Fi".into(), via: "10.0.0.1".into(), metric: 55 },
        ];
        let mut cfg = Config::default();
        cfg.routing.ignore_interfaces = vec!["Ethernet".into()];
        assert_eq!(pick_uplink(&rows, &cfg).unwrap().dev, "7");
        cfg.routing.ignore_interfaces.clear();
        cfg.routing.interface = "Wi-Fi".into();
        assert_eq!(pick_uplink(&rows, &cfg).unwrap().dev, "7");
        assert_eq!(pick_uplink(&[], &Config::default()), None);
    }

    const ROUTE_PRINT: &str = "===========================================================================\n\
Active Routes:\n\
Network Destination        Netmask          Gateway       Interface  Metric\n\
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n\
          0.0.0.0        128.0.0.0       10.8.0.1       10.8.0.2      6\n\
          5.228.0.0      255.255.0.0      192.168.1.1    192.168.1.50     26\n\
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n\
      192.168.1.0    255.255.255.0       На канале    192.168.1.50    281\n\
       213.59.0.0      255.255.0.0      192.168.1.1    192.168.1.50     26\n\
===========================================================================\n\
Persistent Routes:\n\
  Network Address          Netmask  Gateway Address  Metric\n\
          0.0.0.0          0.0.0.0      192.168.1.1  Default\n";

    const ROUTE_PRINT6: &str = "IPv6 Route Table\n\
===========================================================================\n\
Active Routes:\n\
 If Metric Network Destination      Gateway\n\
 12    281 ::/0                     fe80::1\n\
  1    331 ::1/128                  On-link\n\
 12    281 2a00:1450::/32           fe80::1\n\
 12    281 2a02:6b8::/32            fe80::1\n\
 12    281 fe80::/64                На канале\n";

    #[test]
    fn route_print_rows_are_locale_independent() {
        let rows = parse_route_print(ROUTE_PRINT, Family::V4);
        assert_eq!(rows.len(), 4);
        assert_eq!((rows[2].prefix, rows[2].gateway.as_str()), (c("5.228.0.0/16"), "192.168.1.1"));
        assert_eq!(rows[1].prefix.to_string(), "0.0.0.0/1");
    }

    #[test]
    fn ipv6_route_print_rows_carry_the_interface_index() {
        let rows = parse_route_print(ROUTE_PRINT6, Family::V6);
        assert_eq!(rows.len(), 3);
        assert_eq!((rows[1].prefix, rows[1].gateway.as_str(), rows[1].dev.as_str()), (c("2a00:1450::/32"), "fe80::1", "12"));
        assert!(parse_route_print(ROUTE_PRINT6, Family::V4).is_empty());
        assert!(parse_route_print(ROUTE_PRINT, Family::V6).is_empty());
    }

    #[test]
    fn only_routes_through_our_gateway_count_as_ours() {
        let rows = parse_route_print(ROUTE_PRINT, Family::V4);
        let cands: HashSet<Cidr> = [c("5.228.0.0/16"), c("213.59.0.0/16"), c("0.0.0.0/0")].into();
        let ours = [Uplink { dev: "12".into(), via: Some("192.168.1.1".into()) }];
        let found = installed_from(&rows, &cands, &ours);
        assert_eq!(found.len(), 2, "the default route must never be treated as ours");
        assert!(found.iter().all(|i| i.dev == "12"));

        let rows6 = parse_route_print(ROUTE_PRINT6, Family::V6);
        let cands6: HashSet<Cidr> = [c("2a00:1450::/32"), c("2a02:6b8::/32"), c("::/0")].into();
        assert_eq!(installed_from(&rows6, &cands6, &ours6("12")).len(), 2);
        assert!(installed_from(&rows6, &cands6, &ours6("7")).is_empty(), "same link-local gateway on another interface is not ours");
    }

    fn ours6(dev: &str) -> [Uplink; 1] {
        [Uplink { dev: dev.into(), via: Some("fe80::1".into()) }]
    }

    #[test]
    fn netsh_script_replaces_first_then_adds_then_drops_stale_routes() {
        let up = Uplink { dev: "12".into(), via: Some("192.168.1.1".into()) };
        let plan = Plan {
            add: vec![c("5.228.0.0/16")],
            remove: vec![
                Installed { prefix: c("9.0.0.0/8"), via: Some("10.9.9.9".into()), dev: "7".into() },
                Installed { prefix: c("5.228.0.0/16"), via: Some("10.9.9.9".into()), dev: "7".into() },
            ],
            keep: 0,
        };
        assert_eq!(
            netsh_script(Family::V4, &up, &plan),
            "interface ipv4\n\
             delete route prefix=5.228.0.0/16 interface=7 nexthop=10.9.9.9 store=active\n\
             add route prefix=5.228.0.0/16 interface=12 nexthop=192.168.1.1 metric=1 store=active\n\
             delete route prefix=9.0.0.0/8 interface=7 nexthop=10.9.9.9 store=active\n"
        );
        let up6 = Uplink { dev: "12".into(), via: Some("fe80::1".into()) };
        let plan6 = Plan { add: vec![c("2a00:1450::/32")], remove: vec![], keep: 0 };
        assert_eq!(
            netsh_script(Family::V6, &up6, &plan6),
            "interface ipv6\nadd route prefix=2a00:1450::/32 interface=12 nexthop=fe80::1 metric=1 store=active\n"
        );
    }

    #[test]
    fn the_uplink_script_asks_for_the_right_family() {
        assert!(uplink_script(Family::V4).contains("-AddressFamily IPv4") && uplink_script(Family::V4).contains("'0.0.0.0/0'"));
        assert!(uplink_script(Family::V6).contains("-AddressFamily IPv6") && uplink_script(Family::V6).contains("'::/0'"));
    }

    #[test]
    fn masks_must_be_contiguous() {
        assert_eq!(mask_len(0xFFFF_0000), Some(16));
        assert_eq!(mask_len(0), Some(0));
        assert_eq!(mask_len(u32::MAX), Some(32));
        assert_eq!(mask_len(0xFF00_FF00), None);
    }
}

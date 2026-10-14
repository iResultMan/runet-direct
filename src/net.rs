//! The operating-system boundary. `Net` is everything the engine needs from the OS;
//! `make_plan` is the pure diff between the wanted and the installed routes.

use crate::cidr::{Cidr, Family};
use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// The physical (non-tunnel) way out: a gateway reachable over a real interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uplink {
    /// Interface name (Windows: interface index).
    pub dev: String,
    /// Next hop; `None` for point-to-point links without a gateway address.
    pub via: Option<String>,
}

impl Uplink {
    pub fn describe(&self) -> String {
        match &self.via {
            Some(v) => format!("{v} via {}", self.dev),
            None => format!("dev {}", self.dev),
        }
    }

    /// Does a route with this next hop and interface already use this uplink?
    /// An empty interface means "not known" (Windows `route print`) and matches anything.
    pub fn matches(&self, via: &Option<String>, dev: &str) -> bool {
        self.via == *via && (dev.is_empty() || self.dev.is_empty() || self.dev == dev)
    }
}

/// A route found in the kernel table that belongs to us.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub prefix: Cidr,
    pub via: Option<String>,
    pub dev: String,
}

/// Result of asking the OS where a destination would go.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Lookup {
    pub dev: String,
    pub via: Option<String>,
    pub tunnel: bool,
}

#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    pub add: Vec<Cidr>,
    pub remove: Vec<Installed>,
    pub keep: usize,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }

    /// Split the removals into routes that are being replaced (same prefix is added again, so they must
    /// go first where a prefix can exist only once) and stale ones. Stale routes are removed after the
    /// additions, so a replacement block (for example an aggregate) is in place before the blocks it
    /// covers disappear: traffic never sees a gap.
    pub fn split_removals(&self) -> (Vec<&Installed>, Vec<&Installed>) {
        let added: HashSet<&Cidr> = self.add.iter().collect();
        self.remove.iter().partition(|r| added.contains(&r.prefix))
    }
}

pub trait Net {
    fn name(&self) -> &'static str;

    /// `Err` with a human message when not running with the rights to change routes.
    fn require_admin(&self) -> Result<(), String>;

    /// Best physical gateway for the family, or `None` when there is none right now.
    fn uplink(&self, cfg: &Config, fam: Family) -> Result<Option<Uplink>, String>;

    /// Names of tunnel interfaces that currently exist (informational).
    fn tunnels(&self) -> Vec<String>;

    /// Linux: make sure `from all lookup <table>` exists and is not shadowed. `probe` is a destination
    /// that must be routed directly; if it still leaves through a tunnel because another rule is
    /// evaluated first, our rule is moved above that rule. Returns a description of what was changed.
    /// Other systems have no rule and always return `Ok(None)`.
    fn ensure_rule(&self, cfg: &Config, fam: Family, probe: Option<IpAddr>) -> Result<Option<String>, String>;

    fn rule_present(&self, cfg: &Config, fam: Family) -> Result<bool, String>;

    /// Linux: the priority our rule currently has (it may have been moved above a VPN rule), so that
    /// other tools can place their own rules in front of it. `None` elsewhere or when there is no rule.
    fn rule_priority(&self, _: &Config, _: Family) -> Result<Option<u32>, String> {
        Ok(None)
    }

    /// Routes of ours currently installed. Linux: the whole private table. Elsewhere: routes in
    /// the shared table for `candidates` whose next hop is one of `ours`.
    fn installed(&self, cfg: &Config, fam: Family, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<Vec<Installed>, String>;

    fn apply(&self, cfg: &Config, fam: Family, uplink: &Uplink, plan: &Plan) -> Result<(), String>;

    /// Remove everything we installed for the family (routes and rule). Returns the number of routes removed.
    fn clear(&self, cfg: &Config, fam: Family, candidates: &HashSet<Cidr>, ours: &[Uplink]) -> Result<usize, String>;

    /// Where would traffic to `ip` leave the machine?
    fn lookup(&self, cfg: &Config, ip: IpAddr) -> Result<Lookup, String>;

    /// Long-running command whose output lines signal network changes, if the OS has one.
    fn watch_command(&self) -> Option<Vec<String>>;

    /// Substrings that mark a change-notification line as the echo of our own work (it is then ignored).
    fn echo_filters(&self, _: &Config) -> Vec<String> {
        Vec::new()
    }

    /// True when routes live in the shared table, so ownership must be tracked in `State`.
    fn tracks_ownership(&self) -> bool;
}

/// Diff wanted against installed. Stale routes are only pruned when `allow_prune` is set, so a
/// missing or failed country download can never wipe the table.
pub fn make_plan(desired: &[Cidr], installed: &[Installed], uplink: &Uplink, allow_prune: bool) -> Plan {
    let mut by_prefix: HashMap<Cidr, Vec<&Installed>> = HashMap::new();
    for i in installed {
        by_prefix.entry(i.prefix).or_default().push(i);
    }
    let want: HashSet<Cidr> = desired.iter().copied().collect();
    let mut plan = Plan::default();
    for p in desired {
        let entries = by_prefix.get(p).map(Vec::as_slice).unwrap_or(&[]);
        if entries.iter().any(|e| uplink.matches(&e.via, &e.dev)) {
            plan.keep += 1;
        } else {
            plan.add.push(*p);
        }
        plan.remove.extend(entries.iter().filter(|e| !uplink.matches(&e.via, &e.dev)).map(|e| (*e).clone()));
    }
    if allow_prune {
        for (p, entries) in &by_prefix {
            if !want.contains(p) {
                plan.remove.extend(entries.iter().map(|e| (*e).clone()));
            }
        }
    }
    plan.remove.sort_by_key(|i| i.prefix);
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }
    fn up() -> Uplink {
        Uplink { dev: "eth0".into(), via: Some("10.0.0.1".into()) }
    }
    fn inst(p: &str, via: &str, dev: &str) -> Installed {
        Installed { prefix: c(p), via: Some(via.into()), dev: dev.into() }
    }

    #[test]
    fn stale_removals_come_after_the_additions() {
        let plan = Plan {
            add: vec![c("5.0.0.0/8")],
            remove: vec![inst("5.0.0.0/8", "10.0.0.254", "eth0"), inst("6.0.0.0/8", "10.0.0.1", "eth0")],
            keep: 0,
        };
        let (replaced, stale) = plan.split_removals();
        assert_eq!((replaced.len(), stale.len()), (1, 1));
        assert_eq!(replaced[0].prefix, c("5.0.0.0/8"));
        assert_eq!(stale[0].prefix, c("6.0.0.0/8"));
    }

    #[test]
    fn empty_table_adds_everything() {
        let p = make_plan(&[c("5.0.0.0/8"), c("6.0.0.0/8")], &[], &up(), true);
        assert_eq!((p.add.len(), p.remove.len(), p.keep), (2, 0, 0));
    }

    #[test]
    fn matching_routes_are_kept_untouched() {
        let p = make_plan(&[c("5.0.0.0/8")], &[inst("5.0.0.0/8", "10.0.0.1", "eth0")], &up(), true);
        assert!(p.is_empty());
        assert_eq!(p.keep, 1);
    }

    #[test]
    fn a_changed_gateway_replaces_the_route() {
        let old = inst("5.0.0.0/8", "10.0.0.254", "eth0");
        let p = make_plan(&[c("5.0.0.0/8")], std::slice::from_ref(&old), &up(), true);
        assert_eq!(p.add, [c("5.0.0.0/8")]);
        assert_eq!(p.remove, [old]);
    }

    #[test]
    fn a_changed_interface_replaces_the_route() {
        let p = make_plan(&[c("5.0.0.0/8")], &[inst("5.0.0.0/8", "10.0.0.1", "wlan0")], &up(), true);
        assert_eq!((p.add.len(), p.remove.len()), (1, 1));
    }

    #[test]
    fn unknown_interface_matches_on_gateway_alone() {
        let p = make_plan(&[c("5.0.0.0/8")], &[inst("5.0.0.0/8", "10.0.0.1", "")], &up(), true);
        assert!(p.is_empty());
    }

    #[test]
    fn stale_routes_are_pruned_only_when_allowed() {
        let stale = inst("9.0.0.0/8", "10.0.0.1", "eth0");
        let pruned = make_plan(&[], std::slice::from_ref(&stale), &up(), true);
        assert_eq!(pruned.remove, std::slice::from_ref(&stale));
        let kept = make_plan(&[], &[stale], &up(), false);
        assert!(kept.is_empty());
    }

    #[test]
    fn replacement_still_happens_when_pruning_is_off() {
        let old = inst("5.0.0.0/8", "10.0.0.254", "eth0");
        let p = make_plan(&[c("5.0.0.0/8")], &[old], &up(), false);
        assert_eq!((p.add.len(), p.remove.len()), (1, 1));
    }
}

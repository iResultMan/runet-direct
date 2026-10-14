//! Configuration file and well-known paths.

use crate::cidr::Family;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub ipv4: Stack,
    pub ipv6: Stack,
    pub routing: Routing,
    pub ru: Ru,
    pub daemon: Daemon,
}

/// Per-family switch. A disabled family is not managed at all, and routes this program
/// installed for it earlier are removed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Stack {
    pub enabled: bool,
}

impl Default for Stack {
    fn default() -> Self {
        Stack { enabled: true }
    }
}

impl Config {
    pub fn enabled(&self, fam: Family) -> bool {
        match fam {
            Family::V4 => self.ipv4.enabled,
            Family::V6 => self.ipv6.enabled,
        }
    }

    pub fn families(&self) -> Vec<Family> {
        Family::ALL.into_iter().filter(|f| self.enabled(*f)).collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    /// Linux: routing table that holds the direct routes.
    pub table: u32,
    /// Linux: priority of the `from all lookup <table>` rule. Must be a smaller
    /// number than any rule a VPN client installs.
    pub priority: u32,
    /// Force this interface (Windows: adapter name) as the uplink; auto-detect if empty.
    pub interface: String,
    /// Interfaces that must never be treated as the uplink.
    pub ignore_interfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Ru {
    /// Route the country's address blocks directly. Turn off to use only manual.list.
    pub enabled: bool,
    pub country: String,
    pub source_url: String,
    pub refresh_days: u64,
    /// A downloaded list with fewer IPv4 blocks than this is rejected as truncated
    /// (for IPv6 a tenth of it is required).
    pub min_prefixes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Daemon {
    /// Safety-net check period; network events trigger an immediate check on Linux/macOS.
    pub interval_seconds: u64,
}

impl Default for Routing {
    fn default() -> Self {
        Routing { table: 900, priority: 2500, interface: String::new(), ignore_interfaces: Vec::new() }
    }
}

impl Default for Ru {
    fn default() -> Self {
        Ru {
            enabled: true,
            country: "RU".into(),
            source_url: "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest".into(),
            refresh_days: 30,
            min_prefixes: 1000,
        }
    }
}

impl Default for Daemon {
    fn default() -> Self {
        Daemon { interval_seconds: 30 }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }
}

pub const DEFAULT_CONFIG: &str = r#"# runet-direct configuration. Every value shown is the default; delete what you
# do not need to change. Edit, then `runet-direct restart` (or use `runet-direct config set`).

# Manage each address family separately. A disabled family is left completely alone
# (and routes added for it earlier are removed).
[ipv4]
enabled = true

[ipv6]
enabled = true

[routing]
# Linux only: routing table and ip-rule priority used for the direct routes.
# The priority must be a smaller number than the rules a VPN client installs
# (it is raised automatically if a VPN rule turns out to be in front of it).
table = 900
priority = 2500
# Force the uplink instead of auto-detecting it (Linux/macOS: interface name,
# Windows: adapter name such as "Ethernet").
interface = ""
# Interfaces that must never be used as the uplink.
ignore_interfaces = []

[ru]
# Set to false to route only what is listed in manual.list.
enabled = true
country = "RU"
source_url = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
refresh_days = 30
# A downloaded list with fewer IPv4 blocks than this is rejected as truncated
# (for IPv6 a tenth of it is required).
min_prefixes = 1000

[daemon]
# Safety-net check period; network events trigger an immediate check on Linux/macOS.
interval_seconds = 30
"#;

pub const DEFAULT_MANUAL: &str = "# Extra destinations, one per line:\n\
#   direct <ip | cidr | domain>   always bypass the VPN (IPv4 and IPv6)\n\
#   vpn    <ip | cidr | domain>   never bypass the VPN (wins over everything else)\n\
# A line without a keyword means `direct`. Domains are resolved every few hours.\n\
# Manage this file with `runet-direct add | exclude | remove`.\n";

#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub install_bin: PathBuf,
    pub log_file: PathBuf,
}

impl Paths {
    pub fn detect() -> Paths {
        let bin = if cfg!(windows) {
            PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into()))
                .join("runet-direct")
                .join("runet-direct.exe")
        } else {
            PathBuf::from("/usr/local/bin/runet-direct")
        };
        if let Some(home) = std::env::var_os("RUNET_DIRECT_HOME") {
            let home = PathBuf::from(home);
            return Paths { config_dir: home.clone(), state_dir: home.clone(), install_bin: bin, log_file: home.join("runet-direct.log") };
        }
        if cfg!(windows) {
            let data = PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("runet-direct");
            Paths { config_dir: data.clone(), state_dir: data.clone(), install_bin: bin, log_file: data.join("runet-direct.log") }
        } else if cfg!(target_os = "macos") {
            let data = PathBuf::from("/Library/Application Support/runet-direct");
            Paths { config_dir: data.clone(), state_dir: data, install_bin: bin, log_file: PathBuf::from("/var/log/runet-direct.log") }
        } else {
            Paths {
                config_dir: PathBuf::from("/etc/runet-direct"),
                state_dir: PathBuf::from("/var/lib/runet-direct"),
                install_bin: bin,
                log_file: PathBuf::from("/var/log/runet-direct.log"),
            }
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn manual_file(&self) -> PathBuf {
        self.config_dir.join("manual.list")
    }
    pub fn ru_file(&self) -> PathBuf {
        self.state_dir.join("ru-prefixes.txt")
    }
    pub fn state_file(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }
    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("lock")
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        fs::create_dir_all(&self.state_dir)
    }

    /// Write the commented default config and manual list if they do not exist yet.
    pub fn write_defaults(&self) -> std::io::Result<()> {
        self.ensure_dirs()?;
        for (path, text) in [(self.config_file(), DEFAULT_CONFIG), (self.manual_file(), DEFAULT_MANUAL)] {
            if !path.exists() {
                fs::write(path, text)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_default_config_equals_the_defaults() {
        let parsed: Config = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn partial_config_fills_in_defaults() {
        let c: Config = toml::from_str("[routing]\ntable = 77\n").unwrap();
        assert_eq!(c.routing.table, 77);
        assert_eq!(c.routing.priority, 2500);
        assert_eq!(c.ru, Ru::default());
    }

    #[test]
    fn typos_are_errors_not_silent() {
        assert!(toml::from_str::<Config>("[routing]\ntabel = 1\n").is_err());
        assert!(toml::from_str::<Config>("[nope]\n").is_err());
    }
}

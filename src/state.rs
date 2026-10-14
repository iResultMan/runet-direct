//! Persistent daemon state and the cross-process lock.

use crate::config::Paths;
use crate::log;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct State {
    pub ru: Option<RuMeta>,
    pub last_refresh_attempt: u64,
    pub last_refresh_error: Option<String>,
    /// Hostnames from manual.list resolved to IPv4 addresses.
    pub resolved: BTreeMap<String, Resolved>,
    /// Prefixes this program has put into the routing table (macOS/Windows have no private table).
    pub installed: Vec<String>,
    /// Uplink used for the routes above, per family (`ipv4`, `ipv6`).
    pub uplinks: BTreeMap<String, crate::net::Uplink>,
    /// Families this program has installed routes for; a family that is now disabled gets cleaned up.
    pub active: Vec<String>,
    pub last_apply: Option<Applied>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuMeta {
    pub fetched_at: u64,
    pub snapshot: Option<String>,
    /// IPv4 blocks.
    pub count: usize,
    #[serde(default)]
    pub count_v6: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resolved {
    pub at: u64,
    pub ips: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Applied {
    pub at: u64,
    pub added: usize,
    pub removed: usize,
    pub total: usize,
    pub uplink: String,
}

impl State {
    pub fn load(paths: &Paths) -> State {
        match fs::read_to_string(paths.state_file()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                log::warn(format!("state file unreadable ({e}); starting from an empty state"));
                State::default()
            }),
            Err(_) => State::default(),
        }
    }

    pub fn save(&self, paths: &Paths) -> std::io::Result<()> {
        let tmp = paths.state_file().with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self).expect("state serializes"))?;
        fs::rename(tmp, paths.state_file())
    }
}

/// Exclusive lock so the daemon and one-shot commands never change routes at the same time.
pub struct Lock(File);

impl Lock {
    pub fn acquire(paths: &Paths, wait: Duration) -> Result<Lock, String> {
        let _ = paths.ensure_dirs();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.lock_file())
            .map_err(|e| format!("{}: {e}", paths.lock_file().display()))?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Lock(file)),
                Err(_) if start.elapsed() < wait => std::thread::sleep(Duration::from_millis(200)),
                Err(_) => return Err("another runet-direct operation is in progress (lock held)".into()),
            }
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

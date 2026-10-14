use super::{Manager, Status};
use crate::config::Paths;
use crate::util;
use std::path::{Path, PathBuf};

pub struct Systemd;

pub const UNIT: &str = "runet-direct.service";

fn unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system").join(UNIT)
}

/// The routes deliberately survive a stop (no ExecStop): stopping the daemon must never
/// silently send Russian traffic back into the VPN. `runet-direct clear` removes them.
pub fn unit_text(exe: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=runet-direct: keep Russian-internet traffic off the VPN\n\
         Documentation=https://github.com/iResultMan/runet-direct\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} run\n\
         Restart=always\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe.display()
    )
}

fn ctl(args: &[&str]) -> Result<(), String> {
    util::run("systemctl", args).map(|_| ())
}

impl Manager for Systemd {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn install(&self, exe: &Path, _: &Paths) -> Result<(), String> {
        if !Path::new("/run/systemd/system").exists() {
            return Err("systemd is not running on this machine; run `runet-direct run` from your init system instead".into());
        }
        std::fs::write(unit_path(), unit_text(exe)).map_err(|e| format!("{}: {e}", unit_path().display()))?;
        ctl(&["daemon-reload"])?;
        ctl(&["enable", UNIT])
    }

    fn uninstall(&self) -> Result<(), String> {
        let _ = ctl(&["disable", "--now", UNIT]);
        let _ = std::fs::remove_file(unit_path());
        ctl(&["daemon-reload"])
    }

    fn start(&self) -> Result<(), String> {
        ctl(&["start", UNIT])
    }

    fn stop(&self) -> Result<(), String> {
        ctl(&["stop", UNIT])
    }

    fn restart(&self) -> Result<(), String> {
        ctl(&["restart", UNIT])
    }

    fn enable(&self) -> Result<(), String> {
        ctl(&["enable", UNIT])
    }

    fn disable(&self) -> Result<(), String> {
        ctl(&["disable", UNIT])
    }

    fn status(&self) -> Status {
        Status {
            installed: unit_path().exists(),
            running: util::ok("systemctl", &["is-active", "--quiet", UNIT]),
            enabled: util::ok("systemctl", &["is-enabled", "--quiet", UNIT]),
            manager: "systemd",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_restarts_always_and_has_no_exec_stop() {
        let t = unit_text(Path::new("/usr/local/bin/runet-direct"));
        assert!(t.contains("ExecStart=/usr/local/bin/runet-direct run\n"));
        assert!(t.contains("Restart=always"));
        assert!(!t.contains("ExecStop"), "stopping the service must not remove routes");
        assert!(t.contains("WantedBy=multi-user.target"));
    }
}

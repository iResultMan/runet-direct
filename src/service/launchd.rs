use super::{Manager, Status};
use crate::config::Paths;
use crate::util;
use std::path::{Path, PathBuf};

pub struct Launchd;

pub const LABEL: &str = "io.github.iresultman.runet-direct";

fn plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(format!("{LABEL}.plist"))
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn plist_text(exe: &Path, log_file: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key><string>{LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{}</string>\n\
         \t\t<string>run</string>\n\
         \t\t<string>--log-file</string>\n\
         \t\t<string>{}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key><true/>\n\
         \t<key>KeepAlive</key><true/>\n\
         \t<key>ThrottleInterval</key><integer>5</integer>\n\
         </dict>\n\
         </plist>\n",
        xml(&exe.to_string_lossy()),
        xml(&log_file.to_string_lossy())
    )
}

fn target() -> String {
    format!("system/{LABEL}")
}

fn loaded() -> bool {
    util::ok("launchctl", &["print", &target()])
}

impl Manager for Launchd {
    fn name(&self) -> &'static str {
        "launchd"
    }

    fn install(&self, exe: &Path, paths: &Paths) -> Result<(), String> {
        std::fs::write(plist_path(), plist_text(exe, &paths.log_file)).map_err(|e| format!("{}: {e}", plist_path().display()))?;
        // The plist must be root:wheel 0644 or launchd refuses it.
        let _ = util::run("chown", &["root:wheel", &plist_path().to_string_lossy()]);
        let _ = util::run("chmod", &["644", &plist_path().to_string_lossy()]);
        let _ = util::run("launchctl", &["enable", &target()]);
        Ok(())
    }

    fn uninstall(&self) -> Result<(), String> {
        let _ = self.stop();
        let _ = util::run("launchctl", &["disable", &target()]);
        let _ = std::fs::remove_file(plist_path());
        Ok(())
    }

    fn start(&self) -> Result<(), String> {
        let _ = util::run("launchctl", &["enable", &target()]);
        if loaded() {
            util::run("launchctl", &["kickstart", &target()]).map(|_| ())
        } else {
            util::run("launchctl", &["bootstrap", "system", &plist_path().to_string_lossy()]).map(|_| ())
        }
    }

    fn stop(&self) -> Result<(), String> {
        if loaded() {
            util::run("launchctl", &["bootout", &target()]).map(|_| ())
        } else {
            Ok(())
        }
    }

    fn enable(&self) -> Result<(), String> {
        util::run("launchctl", &["enable", &target()]).map(|_| ())
    }

    fn disable(&self) -> Result<(), String> {
        util::run("launchctl", &["disable", &target()]).map(|_| ())
    }

    fn status(&self) -> Status {
        let print = util::run("launchctl", &["print", &target()]).unwrap_or_default();
        let disabled = util::run("launchctl", &["print-disabled", "system"])
            .map(|t| t.contains(&format!("\"{LABEL}\" => disabled")) || t.contains(&format!("\"{LABEL}\" => true")))
            .unwrap_or(false);
        Status {
            installed: plist_path().exists(),
            running: print.lines().any(|l| l.trim() == "state = running"),
            enabled: plist_path().exists() && !disabled,
            manager: "launchd",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_runs_at_load_and_keeps_alive() {
        let t = plist_text(Path::new("/usr/local/bin/runet-direct"), Path::new("/var/log/runet-direct.log"));
        assert!(t.contains("<key>RunAtLoad</key><true/>"));
        assert!(t.contains("<key>KeepAlive</key><true/>"));
        assert!(t.contains("<string>/usr/local/bin/runet-direct</string>"));
        assert!(t.contains("<string>--log-file</string>"));
    }

    #[test]
    fn paths_are_xml_escaped() {
        let t = plist_text(Path::new("/opt/a&b/runet-direct"), Path::new("/var/log/x.log"));
        assert!(t.contains("/opt/a&amp;b/runet-direct"));
    }
}

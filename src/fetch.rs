//! Downloads through the system `curl` (present on current Windows 10+, macOS and nearly every
//! Linux). That brings the system trust store and proxy settings and keeps the binary free of
//! a TLS stack.

use std::path::Path;
use std::process::Command;

/// Download `url` into `dest`. On Linux the transfer is first bound to `bind_iface`, so the bytes
/// travel over the physical link rather than the VPN exit (name resolution stays the system's);
/// if that fails it is retried through the default route.
pub fn download(url: &str, dest: &Path, bind_iface: Option<&str>) -> Result<(), String> {
    if cfg!(target_os = "linux") && url.starts_with("http") {
        if let Some(iface) = bind_iface {
            match curl(url, dest, Some(iface)) {
                Ok(()) => return Ok(()),
                Err(e) => crate::log::warn(format!("download bound to {iface} failed ({e}); retrying via the default route")),
            }
        }
    }
    curl(url, dest, None)
}

fn curl(url: &str, dest: &Path, iface: Option<&str>) -> Result<(), String> {
    let mut cmd = Command::new("curl");
    cmd.args(["--fail", "--silent", "--show-error", "--location", "--connect-timeout", "30", "--max-time", "900", "--retry", "2"]);
    if let Some(i) = iface {
        cmd.args(["--interface", i]);
    }
    cmd.arg("--output").arg(dest).arg(url);
    let out = cmd.output().map_err(|e| format!("cannot run curl ({e}); install curl or put it in PATH"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("curl failed: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

//! Installing and controlling the background service with each OS's native supervisor:
//! systemd on Linux, launchd on macOS, Task Scheduler (as SYSTEM, at boot) on Windows.

pub mod launchd;
pub mod systemd;
pub mod taskscheduler;

use crate::config::Paths;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub installed: bool,
    pub running: bool,
    pub enabled: bool,
    pub manager: &'static str,
}

pub trait Manager {
    fn name(&self) -> &'static str;
    /// Register the service for `exe` and enable it at boot (does not start it).
    fn install(&self, exe: &std::path::Path, paths: &Paths) -> Result<(), String>;
    fn uninstall(&self) -> Result<(), String>;
    fn start(&self) -> Result<(), String>;
    fn stop(&self) -> Result<(), String>;
    fn restart(&self) -> Result<(), String> {
        self.stop()?;
        self.start()
    }
    fn enable(&self) -> Result<(), String>;
    fn disable(&self) -> Result<(), String>;
    fn status(&self) -> Status;
}

pub fn current() -> Box<dyn Manager> {
    if cfg!(target_os = "linux") {
        Box::new(systemd::Systemd)
    } else if cfg!(target_os = "macos") {
        Box::new(launchd::Launchd)
    } else {
        Box::new(taskscheduler::TaskScheduler)
    }
}

//! Windows: a scheduled task that starts at boot as SYSTEM, has no time limit and is
//! restarted by Task Scheduler if the process ever exits with an error. (A native Windows
//! service would need the service-control protocol; this needs nothing beyond the binary.)

use super::{Manager, Status};
use crate::config::Paths;
use crate::platform::windows::powershell;
use std::path::Path;

pub struct TaskScheduler;

pub const TASK: &str = "RunetDirect";

fn quote(s: &str) -> String {
    s.replace('\'', "''")
}

pub fn register_script(exe: &Path, log_file: &Path) -> String {
    format!(
        "$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'run --log-file \"{log}\"'\n\
         $t = New-ScheduledTaskTrigger -AtStartup\n\
         $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n\
         $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable \
         -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew\n\
         Register-ScheduledTask -TaskName '{TASK}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null",
        exe = quote(&exe.to_string_lossy()),
        log = quote(&log_file.to_string_lossy()),
    )
}

fn ps(script: &str) -> Result<(), String> {
    powershell(script).map(|_| ())
}

/// Task Scheduler state as a number (locale-independent): 1 Disabled, 3 Ready, 4 Running, -1 absent.
fn state() -> i32 {
    powershell(&format!(
        "$t = Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue; if ($t) {{ [int]$t.State }} else {{ -1 }}"
    ))
    .ok()
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(-1)
}

impl Manager for TaskScheduler {
    fn name(&self) -> &'static str {
        "Task Scheduler"
    }

    fn install(&self, exe: &Path, paths: &Paths) -> Result<(), String> {
        ps(&register_script(exe, &paths.log_file))
    }

    fn uninstall(&self) -> Result<(), String> {
        let _ = self.stop();
        ps(&format!("Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false -ErrorAction SilentlyContinue"))
    }

    fn start(&self) -> Result<(), String> {
        ps(&format!("Start-ScheduledTask -TaskName '{TASK}'"))
    }

    fn stop(&self) -> Result<(), String> {
        ps(&format!("Stop-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue"))
    }

    fn enable(&self) -> Result<(), String> {
        ps(&format!("Enable-ScheduledTask -TaskName '{TASK}' | Out-Null"))
    }

    fn disable(&self) -> Result<(), String> {
        ps(&format!("Disable-ScheduledTask -TaskName '{TASK}' | Out-Null"))
    }

    fn status(&self) -> Status {
        let s = state();
        Status { installed: s != -1, running: s == 4, enabled: s != -1 && s != 1, manager: "Task Scheduler" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_runs_at_boot_as_system_without_a_time_limit() {
        let s = register_script(
            Path::new(r"C:\Program Files\runet-direct\runet-direct.exe"),
            Path::new(r"C:\ProgramData\runet-direct\runet-direct.log"),
        );
        assert!(s.contains("-AtStartup"));
        assert!(s.contains("-UserId 'SYSTEM'"));
        assert!(s.contains("-RunLevel Highest"));
        assert!(s.contains("-ExecutionTimeLimit ([TimeSpan]::Zero)"));
        assert!(s.contains(r#"-Argument 'run --log-file "C:\ProgramData\runet-direct\runet-direct.log"'"#));
    }

    #[test]
    fn single_quotes_in_paths_are_escaped_for_powershell() {
        let s = register_script(Path::new(r"C:\O'Neil\r.exe"), Path::new(r"C:\l.log"));
        assert!(s.contains(r"-Execute 'C:\O''Neil\r.exe'"));
    }
}

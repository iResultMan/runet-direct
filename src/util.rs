//! Small process helpers shared by the platform layers.

use std::io::Write;
use std::process::{Command, Stdio};

/// Run a command and return its stdout; on failure return stderr (or stdout) as the error.
pub fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program).args(args).output().map_err(|e| format!("cannot run `{program}`: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(failure_text(program, &out))
    }
}

/// Run a command with `input` on stdin. Returns stdout on success.
pub fn run_stdin(program: &str, args: &[&str], input: &str) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run `{program}`: {e}"))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let data = input.to_owned();
    // Feed stdin from a thread so a full output pipe can never deadlock us.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(data.as_bytes());
    });
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = writer.join();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(failure_text(program, &out))
    }
}

fn failure_text(program: &str, out: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr);
    let text = if err.trim().is_empty() { String::from_utf8_lossy(&out.stdout) } else { err };
    let lines: Vec<&str> = text.lines().collect();
    let tail = &lines[lines.len().saturating_sub(5)..];
    format!("`{program}` failed ({}): {}", out.status, tail.join(" | "))
}

/// Run a command, discarding output; true when it exited successfully.
pub fn ok(program: &str, args: &[&str]) -> bool {
    Command::new(program).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(unix)]
pub fn is_root() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid takes no arguments, cannot fail and has no side effects.
    unsafe { geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

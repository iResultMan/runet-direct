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

/// Write a file so that a reader sees either the old or the new content, never half of it.
pub fn write_atomic(path: &std::path::Path, data: impl AsRef<[u8]>) -> std::io::Result<()> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
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

#[cfg(test)]
mod tests {
    #[test]
    fn write_atomic_replaces_the_content_and_leaves_no_temp_files() {
        let dir = std::env::temp_dir().join(format!("rd-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("manual.list");
        super::write_atomic(&f, "one\n").unwrap();
        super::write_atomic(&f, "two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "two\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "only the target remains");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

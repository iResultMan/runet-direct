//! One implementation of `Net` per operating system. The parsers are plain functions over
//! text so they are compiled and unit-tested on every OS.

pub mod linux;
pub mod macos;
pub mod windows;

use crate::net::Net;

pub fn current() -> Box<dyn Net> {
    if cfg!(target_os = "linux") {
        Box::new(linux::Linux)
    } else if cfg!(target_os = "macos") {
        Box::new(macos::MacOs)
    } else if cfg!(windows) {
        Box::new(windows::Windows)
    } else {
        eprintln!("unsupported operating system");
        std::process::exit(2);
    }
}

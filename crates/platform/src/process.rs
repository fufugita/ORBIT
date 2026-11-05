//! Explicit child authority, bounded lifetime, and argument-vector encoding.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn quote_argument(value: &str) -> io::Result<String> {
    if value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in argument",
        ));
    }
    let mut encoded = String::from("\"");
    let mut slashes = 0;
    for character in value.chars() {
        if character == '\\' {
            slashes += 1;
        } else {
            encoded.extend(std::iter::repeat_n(
                '\\',
                slashes * if character == '"' { 2 } else { 1 },
            ));
            slashes = 0;
            if character == '"' {
                encoded.push('\\');
            }
            encoded.push(character);
        }
    }
    encoded.extend(std::iter::repeat_n('\\', slashes * 2));
    encoded.push('"');
    Ok(encoded)
}

/// All command arguments are passed directly to the executable; no shell is added.
#[derive(Clone, Debug)]
pub struct SpawnSpec {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub timeout: Duration,
    pub output_limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfinementEvidence {
    pub app_container: bool,
    pub less_privileged: bool,
    pub network_capabilities: u32,
    pub job_assigned_before_resume: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    Exited,
    Cancelled,
    TimedOut,
    OutputLimit,
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub completion: Completion,
    pub confinement: ConfinementEvidence,
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{OwnedProcess, SandboxSession};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_argument_is_not_dropped() {
        assert_eq!(quote_argument("").unwrap(), "\"\"");
    }

    #[test]
    fn quotes_and_terminal_backslashes_are_preserved() {
        assert_eq!(quote_argument("a\"b").unwrap(), "\"a\\\"b\"");
        assert_eq!(quote_argument("a \\").unwrap(), "\"a \\\\\"");
        assert!(quote_argument("a\0b").is_err());
    }
}

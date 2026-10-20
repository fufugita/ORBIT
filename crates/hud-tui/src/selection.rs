//! Copy to the clipboard through OSC 52, so it works over SSH.
//!
//! The screen owns the mouse and its own per-panel selection; what it
//! selected leaves the terminal as this sequence.
//!
//! OSC 52 needs terminal support, which several local terminals lack
//! (XFCE Terminal among them). When a local X session is present, the
//! selection is also handed to the display's clipboard via `xclip` /
//! `xsel`, so local copies work everywhere; OSC 52 remains the
//! transport for remote sessions.

/// Set the X clipboard through a helper, when one exists and DISPLAY is
/// set. Best effort: any failure is silent — OSC 52 was already emitted.
/// The helper is spawned detached: xclip in quiet mode stays alive to
/// serve the selection, so waiting on it would block the event loop.
pub fn set_x_clipboard(text: &str) {
    let Some(display) = std::env::var_os("DISPLAY") else {
        return;
    };
    for helper in ["xclip", "xsel"] {
        let Some(path) = which_helper(helper) else {
            continue;
        };
        let mut command = std::process::Command::new(&path);
        command
            .env("DISPLAY", &display)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if helper == "xclip" {
            // -quiet: serve the clipboard and keep running; do not echo.
            command.args(["-selection", "clipboard", "-quiet"]);
        } else {
            command.args(["--clipboard", "--input"]);
        }
        let Ok(mut child) = command.spawn() else {
            continue;
        };
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(text.as_bytes());
        }
        drop(child.stdin.take());
        return;
    }
}

fn which_helper(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The OSC 52 clipboard sequence: `ESC ] 52 ; c ; <base64> BEL`.
///
/// BEL termination (not ST) — some terminals only honor BEL.
pub fn osc52_sequence(text: &str) -> String {
    // Base64 without a dependency: the text is short (a selection), so a
    // tiny encoder suffices.
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    format!("\x1b]52;c;{out}\x07")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_is_well_formed() {
        let seq = osc52_sequence("hi");
        assert!(seq.starts_with("\x1b]52;c;"));
        assert!(seq.ends_with("\x07"));
        assert!(seq.contains("aGk="), "base64 of 'hi' is aGk=");
    }
}

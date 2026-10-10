//! Copy to the clipboard through OSC 52, so it works over SSH.
//!
//! The screen owns the mouse and its own per-panel selection; what it
//! selected leaves the terminal as this sequence.

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

//! Portable plugin metadata and compatibility boundaries.

mod frontmatter;

pub use frontmatter::{FrontmatterDocument, parse_frontmatter};

/// A stable diagnostic that never includes source values or parser excerpts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[error("{message} ({code})")]
pub struct CompatError {
    pub code: String,
    pub message: String,
}

impl CompatError {
    /// Construct a diagnostic from a source-free message supplied by the caller.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > 1024 {
            let mut end = 1024;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Self {
            code: code.to_owned(),
            message,
        }
    }
}

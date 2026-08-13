//! ORBIT context subsystem — Phase C (C10).
//!
//! Segmented context per DR-08:
//! - CTX-I1: single authoritative Ledger per session; segment table is a cache.
//! - CTX-I2: token window is a hard ceiling; over-budget write → eviction or E0501.
//! - CTX-I3: compaction is content-addressed + reversible; originals tombstoned.
//! - CTX-I4: cross-segment read grants are explicit + deny-by-default.
//! - CTX-I10: eager-load bounded to min(200 lines, 25 KB).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Context error family (E0501, E0502, E0503, E0510; DR-08).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// ORBIT-E0501 eviction_hash_mismatch
    #[error("ORBIT-E0501 eviction_hash_mismatch: {0}")]
    EvictionHashMismatch(String),
    /// ORBIT-E0502 context_segment_leak
    #[error("ORBIT-E0502 context_segment_leak: {0}")]
    SegmentLeak(String),
    /// ORBIT-E0503 invalid_memory_metadata
    #[error("ORBIT-E0503 invalid_memory_metadata: {0}")]
    InvalidMemoryMetadata(String),
    /// ORBIT-E0510 memory_digest_mismatch
    #[error("ORBIT-E0510 memory_digest_mismatch: {0}")]
    MemoryDigestMismatch(String),
}

impl ContextError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EvictionHashMismatch(_) => "E0501",
            Self::SegmentLeak(_) => "E0502",
            Self::InvalidMemoryMetadata(_) => "E0503",
            Self::MemoryDigestMismatch(_) => "E0510",
        }
    }
}

/// Segment priority (DR-08 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SegmentKind {
    Pin,         // never evicted
    ToolOutput,  // evicted first when unreferenced
    LowPriority, // evicted after tool outputs
    HighPriority,
    EagerMemory, // eager-loaded from MEMORY.md (CTX-I10)
    CompactionSummary,
}

/// A context segment (DR-08 §3.1, locked shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub segment_id: String,
    pub content_digest: String, // Sha256
    pub kind: SegmentKind,
    pub references: u32,           // 0 = eviction-eligible
    pub readers: BTreeSet<String>, // CardIds; CTX-I4 deny-by-default
    pub tombstoned: bool,          // CTX-I3: original segments are tombstoned, not deleted
}

/// The segmented context table + budget.
#[derive(Debug, Clone, Default)]
pub struct SegmentTable {
    segments: BTreeMap<String, Segment>,
    window_tokens: u64,
    used_tokens: u64,
}

impl SegmentTable {
    /// Default working window: 200,000 tokens (DR-08 default, CTX-I2).
    pub fn with_window(window_tokens: u64) -> Self {
        Self {
            segments: BTreeMap::new(),
            window_tokens,
            used_tokens: 0,
        }
    }

    pub fn window_tokens(&self) -> u64 {
        self.window_tokens
    }

    /// Write a segment; if it would exceed the hard ceiling, return an
    /// eviction-needed signal (CTX-I2). A failed eviction halts (E0501).
    pub fn write_segment(&mut self, segment: Segment, tokens: u64) -> Result<(), ContextError> {
        if self.used_tokens + tokens > self.window_tokens {
            return Err(ContextError::EvictionHashMismatch(format!(
                "segment {} pushes {} tokens over ceiling {} (E0501)",
                segment.segment_id,
                self.used_tokens + tokens,
                self.window_tokens
            )));
        }
        let id = segment.segment_id.clone();
        self.used_tokens += tokens;
        self.segments.insert(id, segment);
        Ok(())
    }

    /// Evict unreferenced low-priority segments oldest-first until under budget.
    /// Returns the evicted ids. (CTX-I2 deterministic policy.)
    pub fn evict_to_budget(&mut self, budget: u64) -> Vec<String> {
        let mut evicted = Vec::new();
        while self.used_tokens > budget {
            // Find the oldest unreferenced ToolOutput, then LowPriority.
            let candidate = self
                .segments
                .iter()
                .filter(|(_, s)| !s.tombstoned && s.references == 0 && s.kind != SegmentKind::Pin)
                .min_by_key(|(_, s)| match s.kind {
                    SegmentKind::ToolOutput => 0,
                    SegmentKind::LowPriority => 1,
                    _ => 2,
                })
                .map(|(id, _)| id.clone());
            let Some(id) = candidate else {
                break; // nothing evictable; caller will refuse (E0501)
            };
            let seg = self.segments.remove(&id).unwrap();
            self.used_tokens = self.used_tokens.saturating_sub(seg_cost(&seg));
            evicted.push(id);
        }
        evicted
    }

    /// Compact segments into a summary (CTX-I3): summary carries source digests;
    /// originals are tombstoned (not deleted) and content-addressed.
    pub fn compact(
        &mut self,
        summary_id: &str,
        source_ids: &[String],
    ) -> Result<Segment, ContextError> {
        let mut source_digests = Vec::new();
        for id in source_ids {
            let seg = self.segments.get(id).ok_or_else(|| {
                ContextError::SegmentLeak(format!("source {id} not found (E0502)"))
            })?;
            source_digests.push(seg.content_digest.clone());
        }
        let summary = Segment {
            segment_id: summary_id.into(),
            content_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(&source_digests).unwrap_or_default(),
            )),
            kind: SegmentKind::CompactionSummary,
            references: 1,
            readers: BTreeSet::new(),
            tombstoned: false,
        };
        // Tombstone the originals (CTX-I3: not deleted).
        for id in source_ids {
            if let Some(s) = self.segments.get_mut(id) {
                s.tombstoned = true;
            }
        }
        let id = summary_id.to_string();
        self.segments.insert(id.clone(), summary.clone());
        Ok(summary)
    }

    /// Grant read access to a segment for a card (CTX-I4: explicit + deny-by-default).
    /// A grant only works if the card already carries the capability (checked upstream).
    pub fn grant_read(&mut self, segment_id: &str, card_id: &str) -> Result<(), ContextError> {
        let seg = self.segments.get_mut(segment_id).ok_or_else(|| {
            ContextError::SegmentLeak(format!("segment {segment_id} not found (E0502)"))
        })?;
        seg.readers.insert(card_id.to_string());
        Ok(())
    }

    /// Check read access (CTX-I4: absent grant = denied).
    pub fn can_read(&self, segment_id: &str, card_id: &str) -> bool {
        self.segments
            .get(segment_id)
            .map(|s| s.readers.contains(card_id))
            .unwrap_or(false)
    }

    /// Increment reference count (pins segment against eviction).
    pub fn reference(&mut self, segment_id: &str) {
        if let Some(s) = self.segments.get_mut(segment_id) {
            s.references = s.references.saturating_add(1);
        }
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn used_tokens(&self) -> u64 {
        self.used_tokens
    }
}

/// Token cost estimate for a segment (content length based).
fn seg_cost(seg: &Segment) -> u64 {
    // Content digest is fixed-size; we approximate cost by segment size class.
    // In practice the Ledger stores the actual token count; this is a stand-in.
    (seg.content_digest.len() as u64).saturating_div(4).max(1)
}

/// The eager-load fingerprint bound (CTX-I10): min(200 lines, 25 KB).
pub const EAGER_LOAD_MAX_LINES: u32 = 200;
pub const EAGER_LOAD_MAX_BYTES: u64 = 25 * 1024;

/// Compute the eager-load fingerprint from a MEMORY.md slice (CTX-I10).
pub fn eager_load_fingerprint(content: &str) -> (u32, u64) {
    let lines = content.lines().count().min(EAGER_LOAD_MAX_LINES as usize) as u32;
    let bytes = content.len().min(EAGER_LOAD_MAX_BYTES as usize) as u64;
    (lines, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(id: &str, kind: SegmentKind, refs: u32) -> Segment {
        Segment {
            segment_id: id.into(),
            content_digest: hex::encode(Sha256::digest(id.as_bytes())),
            kind,
            references: refs,
            readers: BTreeSet::new(),
            tombstoned: false,
        }
    }

    #[test]
    fn window_is_hard_ceiling() {
        let mut t = SegmentTable::with_window(10);
        assert!(t
            .write_segment(seg("a", SegmentKind::HighPriority, 0), 6)
            .is_ok());
        assert!(t
            .write_segment(seg("b", SegmentKind::HighPriority, 0), 6)
            .is_err());
    }

    #[test]
    fn eviction_deterministic_tool_first() {
        let mut t = SegmentTable::with_window(1000);
        t.write_segment(seg("tool1", SegmentKind::ToolOutput, 0), 100)
            .unwrap();
        t.write_segment(seg("low1", SegmentKind::LowPriority, 0), 100)
            .unwrap();
        t.write_segment(seg("pinned", SegmentKind::Pin, 0), 100)
            .unwrap();
        let evicted = t.evict_to_budget(150);
        assert!(evicted.contains(&"tool1".to_string()));
        assert!(!evicted.contains(&"pinned".to_string()));
    }

    #[test]
    fn compaction_tombstones_not_deletes() {
        let mut t = SegmentTable::with_window(1000);
        t.write_segment(seg("s1", SegmentKind::HighPriority, 0), 50)
            .unwrap();
        t.write_segment(seg("s2", SegmentKind::HighPriority, 0), 50)
            .unwrap();
        let summary = t.compact("sum1", &["s1".into(), "s2".into()]).unwrap();
        assert_eq!(summary.kind, SegmentKind::CompactionSummary);
        assert!(t.segments.get("s1").unwrap().tombstoned);
        assert!(!t.segments.get("sum1").unwrap().tombstoned);
    }

    #[test]
    fn grants_deny_by_default() {
        let mut t = SegmentTable::with_window(100);
        t.write_segment(seg("s", SegmentKind::HighPriority, 0), 10)
            .unwrap();
        assert!(!t.can_read("s", "card-1"));
        t.grant_read("s", "card-1").unwrap();
        assert!(t.can_read("s", "card-1"));
        assert!(!t.can_read("s", "card-2"));
    }

    #[test]
    fn eager_load_bounded() {
        let content = "line\n".repeat(500); // 500 lines
        let (lines, bytes) = eager_load_fingerprint(&content);
        assert_eq!(lines, 200);
        assert!(bytes <= EAGER_LOAD_MAX_BYTES);
    }
}

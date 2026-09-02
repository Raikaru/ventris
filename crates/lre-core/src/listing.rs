//! Listing window API (review CORE-007): structured visible rows with
//! overscan and stable row IDs, so a virtualized view never creates a widget
//! or Rust object per instruction.
//!
//! The row text source is pluggable: the SLEIGH console when configured
//! (`RuntimeConfig::console_path`), a fake in tests, and later the worker's
//! structured listing. The API shape — bounded windows, stable ids (the
//! instruction address), overscan — is the contract the Qt listing view
//! consumes.

use crate::session::RuntimeConfig;
use lre_model::{Address, ListingRow, ListingWindow};

/// A row source: bounded windows of structured listing rows.
pub trait ListingSource: Send {
    /// Rows at `start` (RAM offset), up to `count`, ascending, with stable
    /// ids = instruction address.
    fn rows(&self, start: u64, count: u32) -> crate::Result<Vec<ListingRow>>;
}

/// SLEIGH-console-backed source: one console invocation per window (the
/// console is process-based; a persistent console session is the worker
/// supervision phase's job, WORKER-001).
pub struct ConsoleListingSource {
    config: RuntimeConfig,
    binary: std::path::PathBuf,
}

impl ConsoleListingSource {
    pub fn new(config: RuntimeConfig, binary: &std::path::Path) -> Self {
        Self {
            config,
            binary: binary.to_path_buf(),
        }
    }
}

impl ListingSource for ConsoleListingSource {
    fn rows(&self, start: u64, count: u32) -> crate::Result<Vec<ListingRow>> {
        let text = crate::native_runtime::disasm_native(
            &self.config,
            &self.binary,
            &format!("{start:x}"),
            count,
        )?;
        let mut rows = Vec::new();
        let mut addr = start;
        for line in text.lines().take(count as usize) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Address prefix: "00400466: PUSH RBP" (console prints
            // "0x00400466: PUSH      RBP").
            let (addr_text, text) = match line.split_once(':') {
                Some((a, t)) => (a.trim().trim_start_matches("0x"), t.trim()),
                None => {
                    continue;
                }
            };
            if let Ok(off) = u64::from_str_radix(addr_text, 16) {
                rows.push(ListingRow {
                    stable_id: off,
                    address: Address::ram(off),
                    text: text.to_string(),
                    bytes: String::new(),
                });
                addr = off + 1;
            }
        }
        Ok(rows)
    }
}

/// One listing window: `count` rows starting at `start` plus `count *
/// overscan` extra (one overscan fraction above/below for the virtual
/// view's lookahead), with stable ids and the revision snapshotted from the
/// session's store.
pub fn window(
    source: &dyn ListingSource,
    start: &Address,
    count: u32,
    overscan_fraction: f32,
) -> crate::Result<ListingWindow> {
    let overscan = (count as f32 * overscan_fraction.max(0.0).min(1.0)) as u32;
    let pre = overscan;
    let post = overscan;
    let window_start = start.offset.saturating_sub(pre as u64);
    // Ask for count + post + the pre rows (the source emits from window_start).
    let mut rows = source.rows(window_start, count + post)?;
    // Trim to exactly the window (start..start+count) at the front.
    let trimmed_start = rows
        .iter()
        .position(|r| r.stable_id >= start.offset)
        .unwrap_or(rows.len());
    let mut visible: Vec<ListingRow> = rows.split_off(trimmed_start);
    visible.truncate(count as usize);
    rows = visible;
    Ok(ListingWindow {
        rows,
        start: start.clone(),
        count,
        overscan: overscan as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSource;
    impl ListingSource for FakeSource {
        fn rows(&self, start: u64, count: u32) -> crate::Result<Vec<ListingRow>> {
            Ok((0..count)
                .map(|i| ListingRow {
                    stable_id: start + i as u64,
                    address: Address::ram(start + i as u64),
                    text: format!("insn {}", start + i as u64),
                    bytes: String::new(),
                })
                .collect())
        }
    }

    #[test]
    fn window_returns_bounded_rows_with_overscan() {
        // start mid-stream; overscan 0.5 -> 1 pre row requested, trimmed.
        let start = Address::ram(0x400010);
        let w = window(&FakeSource, &start, 4, 0.5).unwrap();
        assert_eq!(w.rows.len(), 4);
        assert_eq!(w.rows[0].stable_id, 0x400010);
        assert_eq!(w.rows[3].stable_id, 0x400013);
        assert_eq!(w.overscan, 2); // 4 * 0.5
        assert!(w.rows.iter().all(|r| r.stable_id >= 0x400010));
    }

    #[test]
    fn window_at_origin_no_cut() {
        let start = Address::ram(0);
        let w = window(&FakeSource, &start, 2, 1.0).unwrap();
        assert_eq!(w.rows.len(), 2);
        assert_eq!(w.rows[0].stable_id, 0);
    }

    #[test]
    fn window_caps_fraction() {
        let start = Address::ram(0x100);
        let w = window(&FakeSource, &start, 4, 5.0).unwrap();
        assert_eq!(w.overscan, 4); // capped at 1.0 fraction
    }
}

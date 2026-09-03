//! Listing window API (review CORE-007): structured visible rows with
//! overscan and stable row IDs, so a virtualized view never creates a widget
//! or Rust object per row.
//!
//! The row text source is pluggable: the SLEIGH console when configured
//! (`RuntimeConfig::console_path`), a fake in tests, and later the worker's
//! structured listing. The API shape — bounded windows, stable ids, explicit
//! row kinds, and overscan — is the contract the Qt listing view consumes.

use crate::session::RuntimeConfig;
use lre_model::{Address, ListingRow, ListingRowKind, ListingWindow};

fn parse_address(text: &str) -> Option<u64> {
    let text = text.trim().trim_start_matches("0x");
    (!text.is_empty()).then(|| u64::from_str_radix(text, 16).ok()).flatten()
}

fn parse_marker(rest: &str) -> Option<(u64, String)> {
    if let Some((left, right)) = rest.rsplit_once(':') {
        if let Some(offset) = parse_address(right) {
            return Some((offset, left.trim().to_string()));
        }
        if let Some(offset) = parse_address(left) {
            return Some((offset, right.trim().to_string()));
        }
    }
    parse_address(rest).map(|offset| (offset, String::new()))
}

/// Parses the machine-readable structural lines emitted by the SLEIGH
/// console alongside ordinary address-prefixed instructions.
pub(crate) fn parse_console_listing(text: &str) -> Vec<ListingRow> {
    let mut rows = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (kind, rest) = if let Some(rest) = line.strip_prefix("Function ") {
            (ListingRowKind::FunctionHeader, rest)
        } else if let Some(rest) = line.strip_prefix("Block ") {
            (ListingRowKind::BbSeparator, rest)
        } else if let Some(rest) = line.strip_prefix("Label ") {
            (ListingRowKind::Label, rest)
        } else if let Some(rest) = line.strip_prefix("Data ") {
            (ListingRowKind::Data, rest)
        } else {
            let Some((address, text)) = line.split_once(':') else {
                continue;
            };
            let Some(offset) = parse_address(address) else {
                continue;
            };
            rows.push(ListingRow {
                stable_id: offset,
                address: Address::ram(offset),
                kind: ListingRowKind::Instruction,
                text: text.trim().to_string(),
                bytes: String::new(),
            });
            continue;
        };
        let Some((offset, marker_text)) = parse_marker(rest) else {
            continue;
        };
        rows.push(ListingRow {
            stable_id: offset,
            address: Address::ram(offset),
            kind,
            text: marker_text,
            bytes: String::new(),
        });
    }
    rows
}

/// A row source: bounded windows of structured listing rows.
pub trait ListingSource: Send {
    /// Rows at `start` (RAM offset), up to `count`, ascending. Each source
    /// row carries a stable address identity and an explicit structural kind.
    fn rows(&self, start: u64, count: u32) -> crate::Result<Vec<ListingRow>>;

    /// Whether the source can safely answer from an address before the
    /// requested window. Process-based function loaders generally cannot
    /// map arbitrary bytes before the requested instruction.
    fn supports_pre_overscan(&self) -> bool {
        true
    }
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
        let text = crate::native_runtime::listing_native(
            &self.config,
            &self.binary,
            &format!("{start:x}"),
            count,
        )?;
        Ok(parse_console_listing(&text))
    }

    fn supports_pre_overscan(&self) -> bool {
        false
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
    let pre = if source.supports_pre_overscan() {
        overscan
    } else {
        0
    };
    let post = overscan;
    let window_start = start.offset.saturating_sub(pre as u64);
    // Ask for count + post + the pre rows (when the source supports them).
    let mut rows = source.rows(window_start, count + post)?;
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
                    kind: ListingRowKind::Instruction,
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
    #[test]
    fn console_fixture_preserves_structural_row_kinds() {
        let fixture = concat!(
            "Function main: 0x00400000\n",
            "Block 0x00400000\n",
            "Label loc_00400000: 0x00400000\n",
            "0x00400000: PUSH RBP\n",
            "Data 0x00401000: .byte 0x00\n",
            "Block 0x00400005\n",
            "0x00400005: RET\n",
        );
        let rows = parse_console_listing(fixture);
        let kinds = rows.iter().map(|row| row.kind).collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                lre_model::ListingRowKind::FunctionHeader,
                lre_model::ListingRowKind::BbSeparator,
                lre_model::ListingRowKind::Label,
                lre_model::ListingRowKind::Instruction,
                lre_model::ListingRowKind::Data,
                lre_model::ListingRowKind::BbSeparator,
                lre_model::ListingRowKind::Instruction,
            ]
        );
    }
}

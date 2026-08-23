//! L2: the memo key and the bounded derived cache.
//!
//! Two things this crate exists to make honest.
//!
//! **The key.** A derived value depends on the image, the analyzer code
//! version, the configuration, and the human log. `decode_gen` is deliberately
//! *absent* from [`MemoKey`]: given those four, the machine log and therefore
//! every generation is derivable, which makes a generation a *verifiable* index
//! into the key's history rather than an independent axis of trust. The human
//! log is in the key because human `SetContext` / `DefineCode` assertions change
//! how bytes decode -- L1 is not machine-only.
//!
//! **The budget.** Persistent memoization without eviction is strictly worse
//! than Ghidra's 4 GB heap: the cache grows without bound and never forgets.
//! [`Memo`] therefore takes a byte budget and evicts, and the *cost* of that is
//! that "the second session reuses the first session's work" degrades to "some
//! of it". That is the honest trade, and it is why durable memoization is a
//! named risk rather than a feature.

#![forbid(unsafe_code)]

mod project;

pub use project::{
    Project, ProjectAssertion, ProjectCache, ProjectData, ProjectFunction, ProjectGeneration,
    ProjectImage, ProjectPlacement, ProjectReference, ProjectReferenceKind, ProjectRegion,
    ProjectRelocation, ProjectSegment, ProjectSpace, ProjectSymbol,
};

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use ventris_addr::hash::stable64;
use ventris_gen::Generation;

pub use ventris_log::Authority;

/// Everything a derived value depends on.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct MemoKey {
    /// Content hash of the L0 image: bytes plus format facts.
    pub image: u64,
    /// Bumped whenever analyzer or decompiler code changes. Without this, two
    /// builds with different inference serve each other's stale results.
    pub code_version: u32,
    /// Analysis configuration (enabled passes, options).
    pub config: u64,
    /// Digest of the human log.
    pub human_log: u64,
}

impl MemoKey {
    pub fn digest(&self) -> u64 {
        let mut buf = Vec::with_capacity(28);
        buf.extend_from_slice(&self.image.to_le_bytes());
        buf.extend_from_slice(&self.code_version.to_le_bytes());
        buf.extend_from_slice(&self.config.to_le_bytes());
        buf.extend_from_slice(&self.human_log.to_le_bytes());
        stable64(&buf)
    }
}
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct QueryId {
    pub name: String,
    pub subject: u64,
}

impl QueryId {
    pub fn new(name: &str, subject: u64) -> Self {
        Self {
            name: name.to_string(),
            subject,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct Slot {
    key: u64,
    generation: Generation,
    query: QueryId,
}

struct Entry {
    payload: Vec<u8>,
    last_used: u64,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub computes: u64,
}

pub struct Memo {
    budget: usize,
    used: usize,
    clock: u64,
    entries: HashMap<Slot, Entry>,
    stats: Stats,
}

impl Memo {
    pub fn new(budget_bytes: usize) -> Self {
        Self {
            budget: budget_bytes,
            used: 0,
            clock: 0,
            entries: HashMap::new(),
            stats: Stats::default(),
        }
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn budget(&self) -> usize {
        self.budget
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Demand-driven read. `compute` runs only on a miss, and the result is
    /// cached under the *full* slot, so a bumped `code_version` cannot be
    /// served a stale value.
    pub fn get_or_compute<F>(
        &mut self,
        key: MemoKey,
        generation: Generation,
        query: QueryId,
        compute: F,
    ) -> Vec<u8>
    where
        F: FnOnce() -> Vec<u8>,
    {
        self.get_or_try_compute(key, generation, query, || Ok::<_, ()>(compute()))
            .expect("infallible memo computation")
    }

    /// Fallible variant of [`Memo::get_or_compute`]. Failed computations are
    /// not inserted into the cache.
    pub fn get_or_try_compute<F, E>(
        &mut self,
        key: MemoKey,
        generation: Generation,
        query: QueryId,
        compute: F,
    ) -> Result<Vec<u8>, E>
    where
        F: FnOnce() -> Result<Vec<u8>, E>,
    {
        let slot = Slot {
            key: key.digest(),
            generation,
            query,
        };
        self.clock += 1;
        if let Some(e) = self.entries.get_mut(&slot) {
            e.last_used = self.clock;
            self.stats.hits += 1;
            return Ok(e.payload.clone());
        }
        self.stats.misses += 1;
        self.stats.computes += 1;
        let payload = compute()?;
        self.insert(slot, payload.clone());
        Ok(payload)
    }

    fn insert(&mut self, slot: Slot, payload: Vec<u8>) {
        let size = payload.len();
        if size > self.budget {
            // Too big to ever cache: serve it, do not thrash the cache trying.
            return;
        }
        self.evict_to_fit(size);
        self.used += size;
        self.entries.insert(
            slot,
            Entry {
                payload,
                last_used: self.clock,
            },
        );
    }

    fn evict_to_fit(&mut self, need: usize) {
        while self.used + need > self.budget {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(s, _)| s.clone());
            match victim {
                Some(s) => {
                    if let Some(e) = self.entries.remove(&s) {
                        self.used -= e.payload.len();
                        self.stats.evictions += 1;
                    }
                }
                None => return,
            }
        }
    }
}

const MEMO_MAGIC: &[u8] = b"VENTRISMEMO\0";
const MEMO_VERSION: u32 = 1;

impl Memo {
    /// Persist the bounded cache as a versioned, length-delimited snapshot.
    ///
    /// Entries are sorted before writing, so identical cache state produces
    /// identical bytes regardless of `HashMap` iteration order.
    pub fn save_to(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|(left, _), (right, _)| {
            left.key
                .cmp(&right.key)
                .then_with(|| left.generation.cmp(&right.generation))
                .then_with(|| left.query.name.cmp(&right.query.name))
                .then_with(|| left.query.subject.cmp(&right.query.subject))
        });
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MEMO_MAGIC);
        bytes.extend_from_slice(&MEMO_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (slot, entry) in entries {
            bytes.extend_from_slice(&slot.key.to_le_bytes());
            bytes.extend_from_slice(&slot.generation.0.to_le_bytes());
            let name = slot.query.name.as_bytes();
            let name_len = u16::try_from(name.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "query name is too long")
            })?;
            bytes.extend_from_slice(&name_len.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(&slot.query.subject.to_le_bytes());
            bytes.extend_from_slice(&(entry.payload.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&entry.last_used.to_le_bytes());
            bytes.extend_from_slice(&entry.payload);
        }
        if let Some(parent) = path
            .as_ref()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)
    }

    /// Load a snapshot while re-applying the caller's current byte budget.
    ///
    /// The parser bounds every length by the input buffer and treats an
    /// oversized or truncated snapshot as invalid rather than panicking.
    pub fn load_from(path: impl AsRef<Path>, budget_bytes: usize) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        let mut cursor = 0usize;
        let magic = take(&bytes, &mut cursor, MEMO_MAGIC.len())?;
        if magic != MEMO_MAGIC {
            return Err(invalid_snapshot("bad memo magic"));
        }
        if take_u32(&bytes, &mut cursor)? != MEMO_VERSION {
            return Err(invalid_snapshot("unsupported memo version"));
        }
        let count = take_u64(&bytes, &mut cursor)?;
        if count > bytes.len() as u64 {
            return Err(invalid_snapshot("memo entry count exceeds snapshot size"));
        }
        let mut memo = Self::new(budget_bytes);
        for _ in 0..count {
            let key = take_u64(&bytes, &mut cursor)?;
            let generation = Generation(take_u32(&bytes, &mut cursor)?);
            let name_len = usize::from(take_u16(&bytes, &mut cursor)?);
            if name_len > 4096 {
                return Err(invalid_snapshot("memo query name is too long"));
            }
            let name = String::from_utf8(take(&bytes, &mut cursor, name_len)?.to_vec())
                .map_err(|_| invalid_snapshot("memo query name is not UTF-8"))?;
            let subject = take_u64(&bytes, &mut cursor)?;
            let payload_len = usize::try_from(take_u64(&bytes, &mut cursor)?)
                .map_err(|_| invalid_snapshot("memo payload length overflows usize"))?;
            let last_used = take_u64(&bytes, &mut cursor)?;
            let payload = take(&bytes, &mut cursor, payload_len)?.to_vec();
            let query = QueryId { name, subject };
            let slot = Slot {
                key,
                generation,
                query,
            };
            if payload.len() <= memo.budget {
                memo.clock = memo.clock.max(last_used);
                memo.evict_to_fit(payload.len());
                memo.used += payload.len();
                memo.entries.insert(slot, Entry { payload, last_used });
            }
        }
        if cursor != bytes.len() {
            return Err(invalid_snapshot("trailing bytes in memo snapshot"));
        }
        Ok(memo)
    }
}

fn invalid_snapshot(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| invalid_snapshot("memo length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_snapshot("truncated memo snapshot"))?;
    *cursor = end;
    Ok(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        take(bytes, cursor, 2)?.try_into().expect("checked width"),
    ))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        take(bytes, cursor, 4)?.try_into().expect("checked width"),
    ))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        take(bytes, cursor, 8)?.try_into().expect("checked width"),
    ))
}

/// The demand-driven surface. Every method is a query: nothing is computed by
/// opening a program, and every result is keyed by generation, so a caller
/// cannot accidentally mix results from two discovery states.
pub trait Db {
    fn key(&self) -> MemoKey;
    fn generation(&self) -> Generation;
    fn instructions(&mut self, func: u64) -> Vec<u8>;
    fn pseudocode(&mut self, func: u64) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MemoKey {
        MemoKey {
            image: 0xaaaa,
            code_version: 1,
            config: 0xbbbb,
            human_log: 0,
        }
    }

    #[test]
    fn second_read_is_a_hit_and_does_not_recompute() {
        let mut m = Memo::new(1024);
        let q = QueryId::new("pseudocode", 0x1000);
        let a = m.get_or_compute(key(), Generation(1), q.clone(), || b"one".to_vec());
        let b = m.get_or_compute(key(), Generation(1), q, || panic!("must not recompute"));
        assert_eq!(a, b);
        assert_eq!(m.stats().computes, 1);
        assert_eq!(m.stats().hits, 1);
    }

    /// The stale-result trap: new analyzer code must not be served old output.
    #[test]
    fn bumping_code_version_forces_recompute() {
        let mut m = Memo::new(1024);
        let q = QueryId::new("pseudocode", 0x1000);
        m.get_or_compute(key(), Generation(1), q.clone(), || b"old".to_vec());
        let mut k2 = key();
        k2.code_version = 2;
        let out = m.get_or_compute(k2, Generation(1), q, || b"new".to_vec());
        assert_eq!(out, b"new".to_vec());
        assert_eq!(m.stats().computes, 2);
    }

    /// A human decode assertion changes how bytes decode, so it must be in the
    /// key -- not just the machine log.
    #[test]
    fn human_log_participates_in_the_key() {
        let mut a = key();
        let mut b = key();
        a.human_log = 1;
        b.human_log = 2;
        assert_ne!(a.digest(), b.digest());
    }

    /// Two discovery generations must not share cached results.
    #[test]
    fn generations_do_not_share_cache_slots() {
        let mut m = Memo::new(1024);
        let q = QueryId::new("instructions", 0x1000);
        m.get_or_compute(key(), Generation(1), q.clone(), || b"gen1".to_vec());
        let out = m.get_or_compute(key(), Generation(2), q, || b"gen2".to_vec());
        assert_eq!(out, b"gen2".to_vec());
    }

    /// Without this the design is worse than what it replaces.
    #[test]
    fn cache_respects_its_byte_budget_under_pressure() {
        let mut m = Memo::new(300);
        for i in 0..40u64 {
            m.get_or_compute(key(), Generation(1), QueryId::new("ssa", i), || {
                vec![0u8; 64]
            });
        }
        assert!(
            m.used() <= m.budget(),
            "used {} > budget {}",
            m.used(),
            m.budget()
        );
        assert!(m.stats().evictions > 0, "budget was never enforced");
        assert!(m.len() <= 300 / 64 + 1);
    }

    #[test]
    fn oversized_values_are_served_but_not_cached() {
        let mut m = Memo::new(16);
        let q = QueryId::new("whole-program-graph", 0);
        let out = m.get_or_compute(key(), Generation(1), q, || vec![7u8; 1024]);
        assert_eq!(out.len(), 1024);
        assert_eq!(m.used(), 0);
        assert!(m.is_empty());
    }

    #[test]
    fn cache_snapshot_round_trips_and_preserves_hits() {
        let path = std::env::temp_dir().join(format!("ventris-memo-{}.bin", std::process::id()));
        let mut original = Memo::new(1024);
        original.get_or_compute(
            key(),
            Generation(3),
            QueryId::new("pseudocode", 0x4000),
            || b"cached".to_vec(),
        );
        original.save_to(&path).unwrap();

        let mut restored = Memo::load_from(&path, 1024).unwrap();
        let value = restored.get_or_compute(
            key(),
            Generation(3),
            QueryId::new("pseudocode", 0x4000),
            || panic!("snapshot must hit"),
        );
        assert_eq!(value, b"cached".to_vec());
        assert_eq!(restored.stats().hits, 1);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn truncated_cache_snapshot_is_rejected() {
        let path =
            std::env::temp_dir().join(format!("ventris-memo-invalid-{}.bin", std::process::id()));
        std::fs::write(&path, MEMO_MAGIC).unwrap();
        assert!(Memo::load_from(&path, 1024).is_err());
        std::fs::remove_file(path).unwrap();
    }
}

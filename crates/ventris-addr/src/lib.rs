//! L0: addressing. The only crate with no dependencies, and deliberately the
//! first one written.
//!
//! Bare integers are not addresses. Measured motivation, on a real binary
//! (Persona 3 FES `slus21621.elf`, PS2/R5900):
//!
//! * `list_functions` reported entries as `image::0019d3f0`
//! * decompiling `image::0019d3f0` produced `halt_baddata()` -- a dead overlay
//! * decompiling the *same offset* unqualified produced 16 valid instructions
//!
//! Same number, two spaces, opposite answers. Any API that accepts a `u64` and
//! guesses is wrong; this crate makes the guess explicit or refuses.

#![forbid(unsafe_code)]

use std::fmt;

/// Deterministic hashing primitive used for persisted identities and memo keys.
///
/// This is a fixed, endian-independent 64-bit hash. It deliberately does not
/// use `std::collections::hash_map::DefaultHasher`: SipHash's keys and output
/// are not stability guarantees across Rust releases, so identities persisted
/// from it would silently detach on a toolchain upgrade.
pub mod hash {
    const P1: u64 = 0x9e37_79b1_85eb_ca87;
    const P2: u64 = 0xc2b2_ae3d_27d4_eb4f;
    const P3: u64 = 0x1656_67b1_9e37_79f9;
    const P4: u64 = 0x85eb_ca77_c2b2_ae63;

    #[inline]
    fn avalanche(mut x: u64) -> u64 {
        x ^= x >> 33;
        x = x.wrapping_mul(P2);
        x ^= x >> 29;
        x = x.wrapping_mul(P3);
        x ^ (x >> 32)
    }

    /// Stable 64-bit hash with fixed constants and byte order.
    pub fn stable64(bytes: &[u8]) -> u64 {
        let mut h = P1 ^ (bytes.len() as u64).wrapping_mul(P2);
        let (chunks, tail) = bytes.as_chunks::<8>();
        for chunk in chunks {
            let lane = u64::from_le_bytes(*chunk);
            h ^= avalanche(lane.wrapping_add(P3));
            h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        }
        if !tail.is_empty() {
            let mut lane = 0u64;
            for (shift, byte) in tail.iter().copied().enumerate() {
                lane |= u64::from(byte) << (shift * 8);
            }
            h ^= avalanche(lane.wrapping_add(P2 ^ tail.len() as u64));
            h = h.rotate_left(23).wrapping_mul(P3).wrapping_add(P1);
        }
        avalanche(h)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SpaceId(pub u16);

/// An address is a space plus an offset. There is no other constructor.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Addr {
    pub space: SpaceId,
    pub off: u64,
}

impl Addr {
    pub const fn new(space: SpaceId, off: u64) -> Self {
        Self { space, off }
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s{}:{:#010x}", self.space.0, self.off)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AddrRange {
    pub start: Addr,
    pub len: u64,
}

impl AddrRange {
    pub fn contains(&self, a: Addr) -> bool {
        a.space == self.start.space
            && a.off >= self.start.off
            && a.off < self.start.off.saturating_add(self.len)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpaceKind {
    /// Mapped and executable.
    Code,
    /// Mapped, not executable.
    Data,
    /// Mapped *over* another space. Symbol-derived entries frequently land here
    /// while the real code lives in the base space.
    Overlay,
    Register,
    Constant,
    /// SLEIGH's scratch space for intra-instruction temporaries.
    Unique,
}

impl SpaceKind {
    /// Whether a bare, unqualified offset could plausibly name this space.
    ///
    /// Register/Constant/Unique are never candidates: an offset into them is
    /// meaningful only to the lifter, never to a user or a caller.
    pub fn is_addressable(self) -> bool {
        matches!(self, SpaceKind::Code | SpaceKind::Data | SpaceKind::Overlay)
    }
}

#[derive(Clone, Debug)]
pub struct Space {
    pub id: SpaceId,
    pub name: String,
    pub kind: SpaceKind,
    /// For `Overlay`: where this space's offset 0 sits in its base space.
    pub base: Option<Addr>,
    /// Mapped `(start, len)` runs. Empty means "extent unknown, assume total",
    /// which is the honest state right after a raw-binary import.
    mapped: Vec<(u64, u64)>,
}

impl Space {
    pub fn contains(&self, off: u64) -> bool {
        self.mapped.is_empty()
            || self
                .mapped
                .iter()
                .any(|&(s, l)| off >= s && off < s.saturating_add(l))
    }
}

#[derive(Clone, Debug, Default)]
pub struct SpaceTable {
    spaces: Vec<Space>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrError {
    /// The refusal that matters: more than one addressable space maps this
    /// offset, so the caller must say which. Candidates are named so the error
    /// is actionable rather than a lecture.
    Ambiguous {
        off: u64,
        candidates: Vec<String>,
    },
    UnknownSpace(String),
    BadOffset(String),
    /// No addressable space maps the offset at all.
    Unmapped(u64),
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrError::Ambiguous { off, candidates } => write!(
                f,
                "{off:#x} is mapped by {} spaces ({}); qualify it, e.g. {}::{off:#x}",
                candidates.len(),
                candidates.join(", "),
                candidates[0]
            ),
            AddrError::UnknownSpace(s) => write!(f, "no address space named {s:?}"),
            AddrError::BadOffset(s) => write!(f, "cannot parse {s:?} as an offset"),
            AddrError::Unmapped(off) => {
                write!(f, "{off:#x} is not mapped in any addressable space")
            }
        }
    }
}

impl std::error::Error for AddrError {}

impl SpaceTable {
    pub fn add(&mut self, name: &str, kind: SpaceKind, base: Option<Addr>) -> SpaceId {
        let id = SpaceId(u16::try_from(self.spaces.len()).expect("space count"));
        self.spaces.push(Space {
            id,
            name: name.to_string(),
            kind,
            base,
            mapped: Vec::new(),
        });
        id
    }

    pub fn map_range(&mut self, id: SpaceId, start: u64, len: u64) {
        if let Some(s) = self.spaces.get_mut(id.0 as usize) {
            s.mapped.push((start, len));
        }
    }

    pub fn get(&self, id: SpaceId) -> Option<&Space> {
        self.spaces.get(id.0 as usize)
    }

    pub fn by_name(&self, name: &str) -> Option<&Space> {
        self.spaces.iter().find(|s| s.name == name)
    }

    fn candidates(&self, off: u64) -> Vec<&Space> {
        self.spaces
            .iter()
            .filter(|s| s.kind.is_addressable() && s.contains(off))
            .collect()
    }

    /// Resolve `"0x1000"` or `"image::0x1000"`.
    ///
    /// The policy, stated once: a qualified address always wins; a bare offset
    /// resolves only when exactly one addressable space maps it. That keeps the
    /// 95% single-space case ceremony-free without ever silently picking a
    /// space, which is the behaviour that cost an hour of debugging on a
    /// PS2 ELF whose symbols lived in a dead overlay.
    pub fn resolve(&self, spec: &str) -> Result<Addr, AddrError> {
        if let Some((sp, off)) = spec.rsplit_once("::") {
            let space = self
                .by_name(sp)
                .ok_or_else(|| AddrError::UnknownSpace(sp.to_string()))?;
            return Ok(Addr::new(space.id, parse_off(off)?));
        }
        self.resolve_bare(parse_off(spec)?)
    }

    pub fn resolve_bare(&self, off: u64) -> Result<Addr, AddrError> {
        let c = self.candidates(off);
        match c.len() {
            0 => Err(AddrError::Unmapped(off)),
            1 => Ok(Addr::new(c[0].id, off)),
            _ => Err(AddrError::Ambiguous {
                off,
                candidates: c.iter().map(|s| s.name.clone()).collect(),
            }),
        }
    }

    /// Project an overlay address onto its base space. Non-overlay addresses
    /// pass through unchanged.
    pub fn to_base(&self, a: Addr) -> Option<Addr> {
        let s = self.get(a.space)?;
        Some(match s.base {
            Some(b) => Addr::new(b.space, b.off.wrapping_add(a.off)),
            None => a,
        })
    }
}

fn parse_off(s: &str) -> Result<u64, AddrError> {
    let t = s.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>().or_else(|_| u64::from_str_radix(t, 16)),
    };
    parsed.map_err(|_| AddrError::BadOffset(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single-space image: bare offsets must just work. Ergonomics matter for
    /// the overwhelming majority of binaries.
    #[test]
    fn one_addressable_space_accepts_a_bare_offset() {
        let mut t = SpaceTable::default();
        let ram = t.add("ram", SpaceKind::Code, None);
        t.map_range(ram, 0x1000, 0x1000);
        assert_eq!(t.resolve("0x1400").unwrap(), Addr::new(ram, 0x1400));
    }

    /// The P3FES shape: a default space and an ELF-derived overlay both mapping
    /// the same offset. A bare offset here must refuse and name both.
    #[test]
    fn two_spaces_mapping_one_offset_refuse_and_name_candidates() {
        let mut t = SpaceTable::default();
        let ram = t.add("ram", SpaceKind::Code, None);
        t.map_range(ram, 0x0010_0000, 0x0090_0000);
        let img = t.add("image", SpaceKind::Overlay, Some(Addr::new(ram, 0)));
        t.map_range(img, 0x0010_0000, 0x0090_0000);

        match t.resolve("0x0019d3f0") {
            Err(AddrError::Ambiguous { candidates, .. }) => {
                assert_eq!(candidates, vec!["ram".to_string(), "image".to_string()]);
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        // and the qualified form always works
        assert_eq!(
            t.resolve("image::0x0019d3f0").unwrap(),
            Addr::new(img, 0x0019_d3f0)
        );
    }

    /// Ambiguity is per-offset, not per-image: an offset only one space maps
    /// resolves cleanly even when the table has several spaces.
    #[test]
    fn ambiguity_is_decided_by_mapping_not_space_count() {
        let mut t = SpaceTable::default();
        let ram = t.add("ram", SpaceKind::Code, None);
        t.map_range(ram, 0x1000, 0x1000);
        let ovl = t.add("image", SpaceKind::Overlay, Some(Addr::new(ram, 0)));
        t.map_range(ovl, 0x8000, 0x1000);
        assert_eq!(t.resolve("0x1004").unwrap().space, ram);
        assert_eq!(t.resolve("0x8004").unwrap().space, ovl);
    }

    #[test]
    fn registers_are_never_bare_candidates() {
        let mut t = SpaceTable::default();
        t.add("register", SpaceKind::Register, None);
        assert_eq!(t.resolve_bare(0), Err(AddrError::Unmapped(0)));
    }

    #[test]
    fn overlay_projects_onto_its_base() {
        let mut t = SpaceTable::default();
        let ram = t.add("ram", SpaceKind::Code, None);
        let ovl = t.add("image", SpaceKind::Overlay, Some(Addr::new(ram, 0x2000)));
        let base = t.to_base(Addr::new(ovl, 0x40)).unwrap();
        assert_eq!(base, Addr::new(ram, 0x2040));
        // non-overlay is identity
        assert_eq!(t.to_base(Addr::new(ram, 9)).unwrap(), Addr::new(ram, 9));
    }

    #[test]
    fn unknown_space_is_named_in_the_error() {
        let t = SpaceTable::default();
        assert_eq!(
            t.resolve("nope::0x10"),
            Err(AddrError::UnknownSpace("nope".to_string()))
        );
    }
    #[test]
    fn stable_hash_is_repeatable_and_order_sensitive() {
        let a = hash::stable64(b"ventris");
        assert_eq!(a, hash::stable64(b"ventris"));
        assert_ne!(a, hash::stable64(b"ventris!"));
        assert_ne!(a, hash::stable64(b"htnilp"));
    }
}

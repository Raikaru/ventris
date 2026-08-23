//! L1 assertions and identity: the two logs.
//!
//! Two separate logs, because one log cannot satisfy both requirements:
//!
//! * **Human log** -- small, merged, authoritative, carries provenance.
//! * **Machine log** -- analyzer output. Regenerable, *never* merged (each side
//!   rederives), canonically ordered so parallel analysis is reproducible.
//!
//! Identity is three-tier, and the tiers are not interchangeable. `NominalId`
//! for named types is minted deterministically from `(namespace, name)`, which
//! is minting -- but a *deterministic* mint living in the mergeable log, which
//! is the only kind that survives a branch merge.

#![forbid(unsafe_code)]

use ventris_addr::{Addr, SpaceId};

pub use ventris_addr::hash::stable64;

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum EntityKind {
    Function,
    Label,
    Comment,
    Data,
}

/// Tier 1: **location-derived** identity, for anything that lives at an address.
/// Never minted, so two branches annotating the same address produce the same
/// key and the conflict becomes visible instead of becoming two records.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct LocKey {
    pub space: SpaceId,
    pub off: u64,
    pub kind: EntityKind,
}

impl LocKey {
    pub fn at(a: Addr, kind: EntityKind) -> Self {
        Self {
            space: a.space,
            off: a.off,
            kind,
        }
    }
}

/// Tier 2: **nominal** identity, for named types.
///
/// Derived from `(namespace, name)` so that two branches independently
/// declaring `POINT` converge, while `POINT` and `SIZE` stay distinct even with
/// byte-identical layouts. Critically, *adding a field does not change the id*,
/// so every `Retype` referencing it stays attached -- the failure that pure
/// structural hashing causes.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct NominalId(pub u64);

impl NominalId {
    pub fn of(namespace: &str, name: &str) -> Self {
        // 0x1f = unit separator, so ("a\u{1f}b", "c") cannot collide with
        // ("a", "b\u{1f}c").
        NominalId(stable64(format!("{namespace}\u{1f}{name}").as_bytes()))
    }
}

/// Tier 3: **structural** identity, for anonymous machine-derived types only,
/// where collapsing identical layouts is the desired behaviour (dedup).
///
/// Field names are excluded on purpose. That is exactly why this tier must
/// never be used for named types: it cannot tell `POINT{x,y}` from `SIZE{w,h}`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct StructuralId(pub u64);

impl StructuralId {
    /// `layout` is `(offset, width)` per field, in declaration order.
    pub fn of_layout(layout: &[(u32, u32)]) -> Self {
        let mut buf = Vec::with_capacity(layout.len() * 8);
        for (off, width) in layout {
            buf.extend_from_slice(&off.to_le_bytes());
            buf.extend_from_slice(&width.to_le_bytes());
        }
        StructuralId(stable64(&buf))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum TypeRef {
    Nominal(NominalId),
    Anonymous(StructuralId),
}

// ---------------------------------------------------------------------------
// Attachment: what happens to human assertions when the machine log is rederived
// ---------------------------------------------------------------------------

/// A human assertion's attachment point: a coordinate *and* a fingerprint of
/// whatever was there when the human asserted it.
///
/// The fingerprint exists because the coordinate alone is not enough: bump the
/// analyzer version, a function boundary moves, and a `Rename` at the old
/// address now describes nothing.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub loc: LocKey,
    pub fingerprint: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Attach {
    /// Coordinate and fingerprint both still match.
    Exact,
    /// The entity moved; exactly one candidate carries the fingerprint.
    Reattached { from: LocKey, to: LocKey },
    /// Retained and surfaced. Never silently dropped, never blindly applied.
    Orphan { reason: OrphanReason },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OrphanReason {
    /// Nothing of that kind exists at the coordinate any more.
    CoordinateGone,
    /// Something is still there, but it is not what was annotated.
    FingerprintChanged,
    /// Several candidates carry the fingerprint; guessing would be wrong.
    Ambiguous(usize),
}

pub trait EntityIndex {
    fn exists(&self, loc: LocKey) -> bool;
    fn fingerprint(&self, loc: LocKey) -> Option<u64>;
    fn find_by_fingerprint(&self, kind: EntityKind, fp: u64) -> Vec<LocKey>;
}

/// Decide the fate of one human assertion against a freshly rederived world.
///
/// The invariant this encodes: there is no outcome that discards the assertion.
/// Worst case it becomes an `Orphan`, which is retained and reportable.
pub fn attach(a: &Anchor, idx: &dyn EntityIndex) -> Attach {
    let present = idx.exists(a.loc);
    if present && idx.fingerprint(a.loc) == Some(a.fingerprint) {
        return Attach::Exact;
    }
    let hits = idx.find_by_fingerprint(a.loc.kind, a.fingerprint);
    match hits.len() {
        0 => Attach::Orphan {
            reason: if present {
                OrphanReason::FingerprintChanged
            } else {
                OrphanReason::CoordinateGone
            },
        },
        1 => Attach::Reattached {
            from: a.loc,
            to: hits[0],
        },
        n => Attach::Orphan {
            reason: OrphanReason::Ambiguous(n),
        },
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FlowKind {
    Branch,
    Call,
    Return,
    CallReturn,
}

/// Authored by a person.
///
/// The last four variants are **L1 decode assertions**: they change how bytes
/// decode, so everything downstream is keyed on them. Their shapes recur in
/// [`MachineEvent`], and that overlap is the point at which the two logs and
/// the generation barrier meet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HumanEvent {
    DeclareType {
        id: NominalId,
        namespace: String,
        name: String,
    },
    Retype {
        anchor: Anchor,
        ty: TypeRef,
    },
    Rename {
        anchor: Anchor,
        to: String,
    },
    Comment {
        anchor: Anchor,
        text: String,
    },
    SetContext {
        at: Addr,
        register: String,
        value: u64,
    },
    DefineCode {
        at: Addr,
    },
    DefineData {
        at: Addr,
        ty: TypeRef,
    },
    FlowOverride {
        at: Addr,
        kind: FlowKind,
    },
}

/// Emitted by an analyzer pass. Carries its pass name so the machine log has a
/// total order independent of thread scheduling.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MachineEvent {
    DiscoverFunction {
        at: Addr,
        pass: &'static str,
    },
    /// Retracts callers' fall-through edges. The non-monotone one.
    NoReturn {
        func: Addr,
        pass: &'static str,
    },
    SetContext {
        at: Addr,
        register: String,
        value: u64,
        pass: &'static str,
    },
    DefineCode {
        at: Addr,
        pass: &'static str,
    },
}

impl MachineEvent {
    pub fn addr(&self) -> Addr {
        match self {
            MachineEvent::DiscoverFunction { at, .. }
            | MachineEvent::SetContext { at, .. }
            | MachineEvent::DefineCode { at, .. } => *at,
            MachineEvent::NoReturn { func, .. } => *func,
        }
    }

    pub fn pass(&self) -> &'static str {
        match self {
            MachineEvent::DiscoverFunction { pass, .. }
            | MachineEvent::NoReturn { pass, .. }
            | MachineEvent::SetContext { pass, .. }
            | MachineEvent::DefineCode { pass, .. } => pass,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            MachineEvent::DefineCode { .. } => 0,
            MachineEvent::SetContext { .. } => 1,
            MachineEvent::DiscoverFunction { .. } => 2,
            MachineEvent::NoReturn { .. } => 3,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct MachineLog {
    events: Vec<MachineEvent>,
}

impl MachineLog {
    pub fn push(&mut self, e: MachineEvent) {
        self.events.push(e);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[MachineEvent] {
        &self.events
    }

    /// Impose the canonical order: `(address, kind rank, pass name)`.
    ///
    /// Analyzers run in parallel and append in whatever order they finish.
    /// Without this, the log's hash -- and therefore the reproducibility key
    /// and every differential test -- varies run to run on the same input.
    pub fn canonicalize(&mut self) {
        self.events
            .sort_by(|a, b| (a.addr(), a.rank(), a.pass()).cmp(&(b.addr(), b.rank(), b.pass())));
    }

    pub fn digest(&self) -> u64 {
        let mut buf = Vec::new();
        for e in &self.events {
            buf.extend_from_slice(&e.addr().off.to_le_bytes());
            buf.push(e.rank());
            buf.extend_from_slice(e.pass().as_bytes());
        }
        stable64(&buf)
    }
}

/// Which log an assertion came from. Replaces a hand-maintained confidence
/// field: confidence *is* provenance.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Authority {
    Human,
    Machine,
}

/// Human assertions win. Stated as a function so it is testable rather than a
/// sentence in a design document.
pub fn effective<T>(human: Option<T>, machine: Option<T>) -> Option<(Authority, T)> {
    match (human, machine) {
        (Some(h), _) => Some((Authority::Human, h)),
        (None, Some(m)) => Some((Authority::Machine, m)),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------

/// Undo is a **compensating event**, never truncation.
///
/// Truncation is incoherent once two logs have merged -- "the last N events" is
/// not well defined per author -- and it destroys the provenance the log exists
/// to provide.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Compensation {
    /// Re-assert the previous value.
    Restore(HumanEvent),
    /// No previous human value: fall back to whatever the machine log derives.
    Tombstone { anchor: Anchor },
    /// This event kind has no inverse yet. Reported, never silently mis-undone.
    Unsupported(&'static str),
}

pub fn compensate(e: &HumanEvent, prior: Option<&HumanEvent>) -> Compensation {
    match e {
        HumanEvent::Rename { anchor, .. }
        | HumanEvent::Comment { anchor, .. }
        | HumanEvent::Retype { anchor, .. } => match prior {
            Some(p) => Compensation::Restore(p.clone()),
            None => Compensation::Tombstone { anchor: *anchor },
        },
        HumanEvent::DeclareType { .. } => Compensation::Unsupported(
            "a type declaration needs an explicit deprecation event: tombstoning it \
             would orphan every Retype that references it",
        ),
        HumanEvent::SetContext { .. }
        | HumanEvent::DefineCode { .. }
        | HumanEvent::DefineData { .. }
        | HumanEvent::FlowOverride { .. } => match prior {
            Some(p) => Compensation::Restore(p.clone()),
            None => Compensation::Unsupported(
                "reverting an L1 decode assertion invalidates the generation; it must \
                 go through the fixpoint driver, not the log alone",
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use ventris_addr::{SpaceId, SpaceKind, SpaceTable};

    fn ram() -> (SpaceTable, SpaceId) {
        let mut t = SpaceTable::default();
        let id = t.add("ram", SpaceKind::Code, None);
        t.map_range(id, 0, 0x1_0000);
        (t, id)
    }

    /// The collapse bug, encoded: identical layouts, different names.
    #[test]
    fn nominal_identity_separates_what_structural_identity_collapses() {
        let point = NominalId::of("demo", "POINT"); // { int x; int y; }
        let size = NominalId::of("demo", "SIZE"); //  { int w; int h; }
        assert_ne!(point, size, "named types must not collapse by layout");

        let layout = [(0u32, 4u32), (4, 4)];
        assert_eq!(
            StructuralId::of_layout(&layout),
            StructuralId::of_layout(&layout),
            "anonymous identical layouts dedup, which is the point of tier 3"
        );
    }

    /// Two analysts declare the same type independently. They must converge, or
    /// a merge produces two unrelated records for one type.
    #[test]
    fn nominal_ids_converge_across_branches() {
        assert_eq!(
            NominalId::of("win32", "HANDLE"),
            NominalId::of("win32", "HANDLE")
        );
        assert_ne!(
            NominalId::of("win32", "HANDLE"),
            NominalId::of("posix", "HANDLE")
        );
    }

    /// Adding a field must not re-identify the type, or every `Retype` that
    /// references it silently detaches.
    #[test]
    fn adding_a_field_does_not_change_nominal_identity() {
        let before = NominalId::of("demo", "POINT");
        // ... field added to POINT; the declaration's name is unchanged ...
        let after = NominalId::of("demo", "POINT");
        assert_eq!(before, after);
        // whereas the structural id of the *layout* does change, correctly
        assert_ne!(
            StructuralId::of_layout(&[(0, 4), (4, 4)]),
            StructuralId::of_layout(&[(0, 4), (4, 4), (8, 4)])
        );
    }

    struct Index {
        present: BTreeMap<LocKey, u64>,
    }

    impl EntityIndex for Index {
        fn exists(&self, loc: LocKey) -> bool {
            self.present.contains_key(&loc)
        }
        fn fingerprint(&self, loc: LocKey) -> Option<u64> {
            self.present.get(&loc).copied()
        }
        fn find_by_fingerprint(&self, kind: EntityKind, fp: u64) -> Vec<LocKey> {
            self.present
                .iter()
                .filter(|(k, v)| k.kind == kind && **v == fp)
                .map(|(k, _)| *k)
                .collect()
        }
    }

    fn loc(space: SpaceId, off: u64) -> LocKey {
        LocKey {
            space,
            off,
            kind: EntityKind::Function,
        }
    }

    #[test]
    fn unmoved_entity_attaches_exactly() {
        let (_t, s) = ram();
        let l = loc(s, 0x1000);
        let idx = Index {
            present: [(l, 0xfeed)].into_iter().collect(),
        };
        assert_eq!(
            attach(
                &Anchor {
                    loc: l,
                    fingerprint: 0xfeed
                },
                &idx
            ),
            Attach::Exact
        );
    }

    /// The case that makes an orphan policy necessary: a boundary moved.
    #[test]
    fn moved_entity_reattaches_by_fingerprint() {
        let (_t, s) = ram();
        let old = loc(s, 0x1000);
        let new = loc(s, 0x0ff0);
        let idx = Index {
            present: [(new, 0xfeed)].into_iter().collect(),
        };
        assert_eq!(
            attach(
                &Anchor {
                    loc: old,
                    fingerprint: 0xfeed
                },
                &idx
            ),
            Attach::Reattached { from: old, to: new }
        );
    }

    #[test]
    fn changed_entity_orphans_rather_than_applying_blindly() {
        let (_t, s) = ram();
        let l = loc(s, 0x1000);
        let idx = Index {
            present: [(l, 0xbeef)].into_iter().collect(),
        };
        assert_eq!(
            attach(
                &Anchor {
                    loc: l,
                    fingerprint: 0xfeed
                },
                &idx
            ),
            Attach::Orphan {
                reason: OrphanReason::FingerprintChanged
            }
        );
    }

    #[test]
    fn several_candidates_orphan_rather_than_guess() {
        let (_t, s) = ram();
        let idx = Index {
            present: [(loc(s, 0x1000), 0xfeed), (loc(s, 0x2000), 0xfeed)]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            attach(
                &Anchor {
                    loc: loc(s, 0x3000),
                    fingerprint: 0xfeed
                },
                &idx
            ),
            Attach::Orphan {
                reason: OrphanReason::Ambiguous(2)
            }
        );
    }

    /// Parallel analyzers append in nondeterministic order; the canonical form
    /// must be stable or the reproducibility key is a lie.
    #[test]
    fn machine_log_canonical_order_is_append_order_independent() {
        let (_t, s) = ram();
        let a = Addr::new(s, 0x1000);
        let b = Addr::new(s, 0x2000);
        let mut one = MachineLog::default();
        one.push(MachineEvent::DiscoverFunction {
            at: b,
            pass: "entry",
        });
        one.push(MachineEvent::DefineCode {
            at: a,
            pass: "flow",
        });
        one.push(MachineEvent::NoReturn {
            func: a,
            pass: "noreturn",
        });

        let mut two = MachineLog::default();
        two.push(MachineEvent::NoReturn {
            func: a,
            pass: "noreturn",
        });
        two.push(MachineEvent::DiscoverFunction {
            at: b,
            pass: "entry",
        });
        two.push(MachineEvent::DefineCode {
            at: a,
            pass: "flow",
        });

        one.canonicalize();
        two.canonicalize();
        assert_eq!(one.digest(), two.digest());
        assert_eq!(one.events(), two.events());
    }

    #[test]
    fn human_assertions_beat_machine_assertions() {
        assert_eq!(effective(Some(7u64), Some(9)), Some((Authority::Human, 7)));
        assert_eq!(effective(None, Some(9u64)), Some((Authority::Machine, 9)));
        assert_eq!(effective::<u64>(None, None), None);
    }

    #[test]
    fn undo_restores_prior_value_or_tombstones() {
        let (_t, s) = ram();
        let anchor = Anchor {
            loc: loc(s, 0x1000),
            fingerprint: 1,
        };
        let first = HumanEvent::Rename {
            anchor,
            to: "alpha".into(),
        };
        let second = HumanEvent::Rename {
            anchor,
            to: "beta".into(),
        };
        assert_eq!(
            compensate(&second, Some(&first)),
            Compensation::Restore(first.clone())
        );
        assert_eq!(compensate(&first, None), Compensation::Tombstone { anchor });
    }

    /// The honest failure: an event kind whose inverse is not defined reports
    /// itself instead of silently doing the wrong thing.
    #[test]
    fn type_declarations_report_that_they_have_no_inverse() {
        let e = HumanEvent::DeclareType {
            id: NominalId::of("demo", "POINT"),
            namespace: "demo".into(),
            name: "POINT".into(),
        };
        assert!(matches!(compensate(&e, None), Compensation::Unsupported(_)));
    }
}

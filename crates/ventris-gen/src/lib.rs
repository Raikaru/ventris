//! Generations: the discovery fixpoint and its barrier.
//!
//! Measured motivation. Ghidra ships **152** analyzer classes; among them are
//! `DecompilerFunctionAnalyzer`, `DecompilerSwitchAnalyzer` and
//! `FindNoReturnFunctionsAnalyzer`. So discovery is not a pass that runs before
//! the lazy queries -- it *runs the decompiler*, and its results create new
//! functions, which invalidate the decompilations that found them.
//!
//! Convergence conditions, stated because the mechanism is worthless without
//! them:
//!
//! * **Monotone in the function set.** Passes only add functions. A pass that
//!   removes one is a bug, reported as [`Outcome::MonotonicityViolation`],
//!   not absorbed as a state.
//! * **Non-monotone in the flow graph.** `noreturn` inference *retracts*
//!   callers' fall-through edges. This is why convergence cannot be proven
//!   here and is instead observed, bounded, and reported.
//! * **Oscillation is the real failure mode**, not divergence: an edge gets
//!   retracted by `noreturn` and re-added by flow discovery. Detected by
//!   state-hash repetition and frozen with a diagnostic.
//!
//! The barrier's job is to make "we stopped iterating" a first-class,
//! reproducible state rather than a hidden race.

#![forbid(unsafe_code)]
pub mod inventory;

use std::collections::{BTreeMap, BTreeSet};
use ventris_addr::hash::stable64;
use ventris_addr::Addr;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Generation(pub u32);

#[derive(Clone, Default, Debug)]
pub struct FlowWorld {
    pub funcs: BTreeSet<Addr>,
    /// `(from, to)` control-flow edges, including fall-through.
    pub edges: BTreeSet<(Addr, Addr)>,
}

impl FlowWorld {
    pub fn state_hash(&self) -> u64 {
        let mut buf = Vec::with_capacity(self.funcs.len() * 10 + self.edges.len() * 20);
        for f in &self.funcs {
            buf.extend_from_slice(&f.space.0.to_le_bytes());
            buf.extend_from_slice(&f.off.to_le_bytes());
        }
        buf.push(0xff);
        for (a, b) in &self.edges {
            buf.extend_from_slice(&a.off.to_le_bytes());
            buf.extend_from_slice(&b.off.to_le_bytes());
        }
        stable64(&buf)
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct Delta {
    pub funcs_added: usize,
    pub funcs_removed: usize,
    pub edges_added: usize,
    pub edges_removed: usize,
}

impl Delta {
    pub fn is_empty(&self) -> bool {
        *self == Delta::default()
    }
}

pub trait DiscoveryPass {
    fn name(&self) -> &'static str;
    fn run(&mut self, w: &mut FlowWorld) -> Delta;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    Converged {
        iters: u32,
    },
    /// A state repeated: the passes are fighting. `period` is the cycle length
    /// in iterations, `first_seen` the iteration the state was first observed.
    Oscillating {
        period: u32,
        first_seen: u32,
        passes: Vec<&'static str>,
    },
    /// Bounded, so a pathological binary costs a known amount rather than a
    /// hang. Distinct from oscillation: the state was still changing.
    IterationCap {
        cap: u32,
    },
    /// The function set shrank. Structural bug in a pass.
    MonotonicityViolation {
        pass: &'static str,
        removed: usize,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Report {
    pub generation: Generation,
    pub outcome: Outcome,
    pub state_hash: u64,
    pub funcs: usize,
    pub edges: usize,
}

impl Report {
    /// Whether downstream lazy queries may be served from this generation.
    ///
    /// An oscillating or capped generation is still *usable* -- it is a frozen,
    /// reproducible state -- but it must be reported, because results derived
    /// from it are conditional on a fixpoint that never settled.
    pub fn is_settled(&self) -> bool {
        matches!(self.outcome, Outcome::Converged { .. })
    }
}

/// Drive discovery passes to a barrier.
pub fn run_to_barrier(
    generation: Generation,
    passes: &mut [Box<dyn DiscoveryPass>],
    world: &mut FlowWorld,
    cap: u32,
) -> Report {
    let mut seen: BTreeMap<u64, u32> = BTreeMap::new();
    seen.insert(world.state_hash(), 0);

    for iter in 1..=cap {
        let mut changed = false;
        for pass in passes.iter_mut() {
            let before = world.funcs.len();
            let d = pass.run(world);
            if world.funcs.len() < before {
                return Report {
                    generation,
                    outcome: Outcome::MonotonicityViolation {
                        pass: pass.name(),
                        removed: before - world.funcs.len(),
                    },
                    state_hash: world.state_hash(),
                    funcs: world.funcs.len(),
                    edges: world.edges.len(),
                };
            }
            changed |= !d.is_empty();
        }

        let h = world.state_hash();
        if !changed {
            return Report {
                generation,
                outcome: Outcome::Converged { iters: iter },
                state_hash: h,
                funcs: world.funcs.len(),
                edges: world.edges.len(),
            };
        }
        if let Some(&first) = seen.get(&h) {
            return Report {
                generation,
                outcome: Outcome::Oscillating {
                    period: iter - first,
                    first_seen: first,
                    passes: passes.iter().map(|p| p.name()).collect(),
                },
                state_hash: h,
                funcs: world.funcs.len(),
                edges: world.edges.len(),
            };
        }
        seen.insert(h, iter);
    }

    Report {
        generation,
        outcome: Outcome::IterationCap { cap },
        state_hash: world.state_hash(),
        funcs: world.funcs.len(),
        edges: world.edges.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_addr::{SpaceKind, SpaceTable};

    fn addr(off: u64) -> Addr {
        let mut t = SpaceTable::default();
        let s = t.add("ram", SpaceKind::Code, None);
        Addr::new(s, off)
    }

    /// Adds one function per iteration from a finite worklist, then stops.
    struct Prologue {
        pending: Vec<u64>,
    }
    impl DiscoveryPass for Prologue {
        fn name(&self) -> &'static str {
            "prologue-scan"
        }
        fn run(&mut self, w: &mut FlowWorld) -> Delta {
            match self.pending.pop() {
                Some(off) => {
                    let added = w.funcs.insert(addr(off));
                    Delta {
                        funcs_added: usize::from(added),
                        ..Delta::default()
                    }
                }
                None => Delta::default(),
            }
        }
    }

    #[test]
    fn monotone_passes_converge_and_report_iteration_count() {
        let mut w = FlowWorld::default();
        let mut passes: Vec<Box<dyn DiscoveryPass>> = vec![Box::new(Prologue {
            pending: vec![0x1000, 0x2000, 0x3000],
        })];
        let r = run_to_barrier(Generation(1), &mut passes, &mut w, 64);
        assert_eq!(r.outcome, Outcome::Converged { iters: 4 });
        assert_eq!(r.funcs, 3);
        assert!(r.is_settled());
    }

    /// The observed failure mode: `noreturn` retracts a fall-through edge and
    /// flow discovery puts it back. Must be detected, not looped on.
    struct AddEdge;
    impl DiscoveryPass for AddEdge {
        fn name(&self) -> &'static str {
            "flow"
        }
        fn run(&mut self, w: &mut FlowWorld) -> Delta {
            let e = (addr(0x1000), addr(0x1010));
            Delta {
                edges_added: usize::from(w.edges.insert(e)),
                ..Delta::default()
            }
        }
    }

    struct RetractEdge;
    impl DiscoveryPass for RetractEdge {
        fn name(&self) -> &'static str {
            "noreturn"
        }
        fn run(&mut self, w: &mut FlowWorld) -> Delta {
            let e = (addr(0x1000), addr(0x1010));
            Delta {
                edges_removed: usize::from(w.edges.remove(&e)),
                ..Delta::default()
            }
        }
    }

    #[test]
    fn edge_retraction_oscillation_is_detected_not_looped() {
        let mut w = FlowWorld::default();
        let mut passes: Vec<Box<dyn DiscoveryPass>> =
            vec![Box::new(AddEdge), Box::new(RetractEdge)];
        let r = run_to_barrier(Generation(1), &mut passes, &mut w, 1000);
        match &r.outcome {
            Outcome::Oscillating { period, passes, .. } => {
                assert_eq!(
                    *period, 1,
                    "add-then-retract returns to the same state each iter"
                );
                assert_eq!(passes, &vec!["flow", "noreturn"]);
            }
            other => panic!("expected oscillation, got {other:?}"),
        }
        assert!(
            !r.is_settled(),
            "an unsettled generation must not look settled"
        );
    }

    struct Deleter;
    impl DiscoveryPass for Deleter {
        fn name(&self) -> &'static str {
            "bad-pass"
        }
        fn run(&mut self, w: &mut FlowWorld) -> Delta {
            let removed = w.funcs.pop_first().is_some();
            Delta {
                funcs_removed: usize::from(removed),
                ..Delta::default()
            }
        }
    }

    #[test]
    fn a_pass_that_removes_a_function_is_a_reported_bug() {
        let mut w = FlowWorld::default();
        w.funcs.insert(addr(0x1000));
        let mut passes: Vec<Box<dyn DiscoveryPass>> = vec![Box::new(Deleter)];
        let r = run_to_barrier(Generation(1), &mut passes, &mut w, 8);
        assert_eq!(
            r.outcome,
            Outcome::MonotonicityViolation {
                pass: "bad-pass",
                removed: 1
            }
        );
    }

    /// Growth that never settles must cost a bounded amount, and must be
    /// distinguishable from oscillation.
    #[test]
    fn unbounded_growth_hits_the_cap_rather_than_hanging() {
        struct Grow(u64);
        impl DiscoveryPass for Grow {
            fn name(&self) -> &'static str {
                "grow"
            }
            fn run(&mut self, w: &mut FlowWorld) -> Delta {
                self.0 += 4;
                Delta {
                    funcs_added: usize::from(w.funcs.insert(addr(self.0))),
                    ..Delta::default()
                }
            }
        }
        let mut w = FlowWorld::default();
        let mut passes: Vec<Box<dyn DiscoveryPass>> = vec![Box::new(Grow(0))];
        let r = run_to_barrier(Generation(1), &mut passes, &mut w, 10);
        assert_eq!(r.outcome, Outcome::IterationCap { cap: 10 });
        assert_eq!(r.funcs, 10);
    }
}

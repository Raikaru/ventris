//! Placeholder awaiting its port; the orchestrator wires the module so the
//! owning lane can compile and test from its first edit.

use super::action::Rule;

pub fn all() -> Vec<Box<dyn Rule>> {
    Vec::new()
}

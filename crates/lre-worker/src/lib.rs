//! lre-worker: the no-JVM decompiler worker as a library (protocol client +
//! provider + supervision-friendly handle). The `lre-worker` binary is a
//! thin CLI on top; interactive/session consumers use this library so the
//! same protocol code serves the CLI, the worker pool, and the UI runtime.
pub mod provider;
pub mod wire;
pub mod worker;

pub use provider::{decode_addr_element, spec_dir, BinaryBacking, ProgramProvider};
pub use worker::*;

/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = WorkerError> = std::result::Result<T, E>;

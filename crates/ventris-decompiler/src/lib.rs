//! Dependency-free native decompilation for p-code produced by `ventris-lifter`.
//!
//! Ventris owns the lifting, analysis, and C rendering pipeline. Ghidra is not a
//! runtime dependency; checked-in semantic fixtures and the optional
//! `tools/diff_ghidra.py` workflow remain the development oracle.

#![forbid(unsafe_code)]

pub mod native;

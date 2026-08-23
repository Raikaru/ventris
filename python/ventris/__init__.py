"""Python bindings for the installed Ventris command-line binary.

The Rust binary remains the source of truth for parsing and analysis.  The
wrapper keeps the Python surface dependency-free and returns the same text the
CLI prints, so scripts do not need to duplicate address or architecture rules.
"""

from .cli import (
    VentrisError,
    batch,
    corpus,
    decompile_native,
    decompile_project_function,
    diff,
    discover,
    ingest_runtime,
    inspect,
    lift,
    link_assets,
    project_references,
    recover_types,
    reconstruct_source,
    resolve,
    run,
    version,
)

__all__ = [
    "VentrisError",
    "batch",
    "corpus",
    "decompile_native",
    "decompile_project_function",
    "diff",
    "discover",
    "ingest_runtime",
    "inspect",
    "lift",
    "link_assets",
    "project_references",
    "recover_types",
    "reconstruct_source",
    "resolve",
    "run",
    "version",
]
__version__ = "0.1.0"

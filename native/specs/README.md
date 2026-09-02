# Analyzer specs for the native worker (static, Java-free runtime)

These five files are the exact documents `DecompInterface.registerProgram`
sends, generated ONCE by `lre-cli dump-specs` (bridge, Ghidra 12.1.3) for
the x86-64 ELF fixture and vendored as static assets:

- pspec.xml / cspec.xml — install data files (x86-64.pspec, x86-64-gcc.cspec)
- tspec.xml — Java encodeTranslator output (in RAW-SLEIGH mode the worker
  replaces the `<sleigh>` tag with the SLA path, so the content is inert)
- coretypes.xml + registers.txt — program-fixed knowledge (base types,
  register offsets)

Regeneration (only when the pinned language changes):
    lre-cli dump-specs <program> --out native/specs

At runtime the worker is 100% Java-free; this directory is a build-time
artifact exactly like the compiled x86-64.sla.

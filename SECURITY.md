# Security policy

## Supported versions

Security fixes target the latest published release and the current default
branch. Older releases may remain vulnerable and are not guaranteed to receive
backports.

## Reporting a vulnerability

Do not disclose an unpatched vulnerability in a public issue, discussion, or
pull request. The canonical repository is
https://github.com/Raikaru/ventris, maintained by the `Raikaru` GitHub
account. Private vulnerability reporting is enabled at **Security →
Advisories → Report a vulnerability**.

Include:

- affected release or commit;
- operating system and architecture;
- exact command or integration exercised;
- a minimal reproduction or proof of concept;
- impact and any required local permissions.

## Review boundary

The security review covers the shipped runtime surfaces:

- the Rust workspace has no third-party runtime dependencies, and its library
  crates forbid `unsafe_code`;
- binary parsing and analysis are bounded by the selected image and function
  range; malformed input must fail without executing target code;
- the Python wheel forwards to an explicitly selected executable and does not
  execute shell commands or download native code;
- the VS Code integration spawns the configured executable without a shell and
  passes typed arguments directly to the public CLI.

The repository's runtime dependency and release checks are part of the
release gate. They do not replace review of the host, binary inputs, proxy, or
local file permissions.

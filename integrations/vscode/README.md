# Ventris Binary Analysis for VS Code

This extension is a thin client for a locally running Ventris HTTP server. It
can start `ventris serve` when `ventris.binary` points to a matching executable,
or it can use an already running server at `ventris.serverUrl`.

Install a released native Ventris executable first. The extension does not
bundle one. The default server URL is loopback-only:

```text
ventris serve --bind 127.0.0.1:8787
```

Configure `ventris.binary` or `ventris.serverUrl` in VS Code settings, then use
the registered Ventris commands for inspection, function discovery, address
resolution, lifting, type recovery, native decompilation, recovered-source
rendering, and JSONL batches.

The server has no authentication or TLS. Do not point the extension at an
untrusted or network-exposed service.

See the repository `README.md`, `SECURITY.md`, and `RELEASING.md` for the
supported command contract, limitations, and acceptance procedure.

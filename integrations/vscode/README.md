# Ventris Binary Analysis for VS Code

A thin adapter over the installed `ventris` executable. It adds three commands:

- **Ventris: Inspect Binary**
- **Ventris: Lift Function**
- **Ventris: Decompile Function**

The extension invokes the same `inspect`, `lift`, and `decompile` CLI pipeline used outside VS Code. It contains no analysis, project model, HTTP server, or editor-specific recovery logic.

Install a released Ventris executable, set `ventris.binary` if it is not on `PATH`, and optionally configure a console target, loader, raw base, or Mach-O slice. Results open in an adjacent editor.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vscode = require('vscode');

const fixture = process.env.VENTRIS_ACCEPTANCE_FIXTURE;
const binary = process.env.VENTRIS_ACCEPTANCE_BINARY;
const functionAddress = process.env.VENTRIS_ACCEPTANCE_FUNCTION_ADDRESS || '0x140001450';

async function waitForDocument(predicate, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const active = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
    if (active && predicate(active)) return active;
    const document = [...vscode.workspace.textDocuments].reverse().find(predicate);
    if (document) return document;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('expected Ventris result document was not opened');
}

suite('Ventris VS Code function-pipeline acceptance', () => {
  test('inspects, lifts, and decompiles through the installed CLI', async function () {
    this.timeout(30000);
    assert.ok(binary, 'VENTRIS_ACCEPTANCE_BINARY is required');
    assert.ok(fixture, 'VENTRIS_ACCEPTANCE_FIXTURE is required');

    const config = vscode.workspace.getConfiguration('ventris');
    await config.update('binary', binary, vscode.ConfigurationTarget.Global);
    await config.update('target', '', vscode.ConfigurationTarget.Global);
    await config.update('loader', 'auto', vscode.ConfigurationTarget.Global);
    await config.update('base', '', vscode.ConfigurationTarget.Global);
    await config.update('slice', '', vscode.ConfigurationTarget.Global);

    await vscode.commands.executeCommand('ventris.inspect', { file: fixture });
    const inspected = await waitForDocument((document) =>
      document.getText().includes('format: PE32+'));
    assert.match(inspected.getText(), /machine: 0x8664/);
    assert.match(inspected.getText(), /segments:/);

    await vscode.commands.executeCommand('ventris.lift', {
      file: fixture,
      address: functionAddress,
      arch: 'x86_64',
    });
    const lifted = await waitForDocument((document) =>
      document.getText().includes('architecture: X86_64'));
    assert.match(lifted.getText(), /instructions:/);

    await vscode.commands.executeCommand('ventris.decompile', {
      file: fixture,
      address: functionAddress,
      arch: 'x86_64',
    });
    const decompiled = await waitForDocument((document) =>
      document.getText().includes('return *(uint32_t *)(uintptr_t)'));
    assert.match(decompiled.getText(), /return/);

    const ps2Fixture = path.join(os.tmpdir(), `ventris-vscode-ps2-${process.pid}.bin`);
    fs.writeFileSync(ps2Fixture, Buffer.from([
      0x10, 0x00, 0x82, 0x8c, 0x14, 0x00, 0x83, 0x8c,
      0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0,
    ]));
    try {
      await vscode.commands.executeCommand('ventris.decompile', {
        file: ps2Fixture,
        address: '0x1000',
        target: 'ps2',
        loader: 'raw',
        base: '0x1000',
        raw: true,
      });
      const reconstructed = await waitForDocument((document) =>
        document.getText().includes('sub_1000'));
      assert.match(reconstructed.getText(), /#include <stdint\.h>/);
    } finally {
      fs.rmSync(ps2Fixture, { force: true });
    }
  });
});

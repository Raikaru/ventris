const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFile } = require('child_process');
const vscode = require('vscode');

const serverUrl = process.env.VENTRIS_ACCEPTANCE_SERVER_URL || 'http://127.0.0.1:8897';
const fixture = process.env.VENTRIS_ACCEPTANCE_FIXTURE;
const binary = process.env.VENTRIS_ACCEPTANCE_BINARY;
const functionAddress = process.env.VENTRIS_ACCEPTANCE_FUNCTION_ADDRESS || '0x140001450';

function request(pathname, method = 'GET', body = undefined) {
  return new Promise((resolve, reject) => {
    const url = new URL(pathname, `${serverUrl}/`);
    const headers = body === undefined
      ? {}
      : { 'Content-Type': 'application/jsonl', 'Content-Length': Buffer.byteLength(body) };
    const req = http.request(url, { method, headers }, (response) => {
      const chunks = [];
      response.setEncoding('utf8');
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: chunks.join('') }));
    });
    req.setTimeout(3000, () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
    if (body !== undefined) req.end(body);
    else req.end();
  });
}

async function waitForHealth(expected, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await request('health');
      if ((response.status === 200) === expected) return response;
    } catch (_) {
      if (!expected) return undefined;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`health did not become ${expected ? 'ready' : 'unreachable'}`);
}

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

function killPortOwner() {
  if (process.platform !== 'win32') {
    throw new Error('the host smoke currently requires Windows netstat/taskkill');
  }
  return new Promise((resolve, reject) => {
    execFile('netstat', ['-ano', '-p', 'tcp'], (error, stdout) => {
      if (error) return reject(error);
      const port = new URL(serverUrl).port;
      const line = stdout.split(/\r?\n/).find((row) =>
        row.includes(`:${port}`) && row.toUpperCase().includes('LISTENING'));
      if (!line) return reject(new Error(`no listener found on ${port}`));
      const pid = line.trim().split(/\s+/).at(-1);
      execFile('taskkill', ['/PID', pid, '/T', '/F'], (killError, _out, killStderr) => {
        if (killError) return reject(new Error(killStderr || killError.message));
        resolve(pid);
      });
    });
  });
}

suite('Ventris VS Code end-to-end acceptance', () => {
  test('starts, runs analysis commands, batches, recovers, and handles HTTP errors', async function () {
    this.timeout(30000);
    assert.ok(binary, 'VENTRIS_ACCEPTANCE_BINARY is required');
    assert.ok(fixture, 'VENTRIS_ACCEPTANCE_FIXTURE is required');

    const config = vscode.workspace.getConfiguration('ventris');
    await config.update('binary', binary, vscode.ConfigurationTarget.Global);
    await config.update('serverUrl', serverUrl, vscode.ConfigurationTarget.Global);
    await config.update('serverArgs', [], vscode.ConfigurationTarget.Global);
    await config.update('loader', 'auto', vscode.ConfigurationTarget.Global);
    await config.update('base', '', vscode.ConfigurationTarget.Global);
    await config.update('slice', '', vscode.ConfigurationTarget.Global);
    await vscode.commands.executeCommand('ventris.startServer');
    await waitForHealth(true);

    const invalid = await request('inspect');
    assert.strictEqual(invalid.status, 400);
    assert.match(invalid.body, /query parameter file is required/);

    await vscode.commands.executeCommand('ventris.inspect', { file: fixture });
    const inspected = await waitForDocument((document) =>
      document.getText().includes('format: PE32+'));
    assert.match(inspected.getText(), /machine: 0x8664/);
    assert.match(inspected.getText(), /segments:/);

    await vscode.commands.executeCommand('ventris.discover', {
      file: fixture,
      arch: 'x86_64',
    });
    const discovered = await waitForDocument((document) =>
      document.getText().includes('functions:'));
    assert.match(discovered.getText(), /seeds:/);

    await vscode.commands.executeCommand('ventris.resolve', {
      file: fixture,
      address: functionAddress,
    });
    const resolved = await waitForDocument((document) =>
      document.getText().includes('address:'));
    assert.match(resolved.getText(), /offset:/);

    await vscode.commands.executeCommand('ventris.lift', {
      file: fixture,
      address: functionAddress,
      arch: 'x86_64',
    });
    const lifted = await waitForDocument((document) =>
      document.getText().includes('architecture: X86_64'));
    assert.match(lifted.getText(), /instructions:/);


    await vscode.commands.executeCommand('ventris.decompileNative', {
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
      await vscode.commands.executeCommand('ventris.recoverTypes', {
        file: ps2Fixture,
        address: '0x1000',
        target: 'ps2',
        loader: 'raw',
        base: '0x1000',
        raw: true,
      });
      const recovered = await waitForDocument((document) =>
        document.getText().includes('target: ps2-r5900-o32'));
      assert.match(recovered.getText(), /memory_accesses: 2/);
      const recoveredHttp = await request(
        `recover-types?file=${encodeURIComponent(ps2Fixture)}&address=0x1000&target=ps2&loader=raw&base=0x1000&raw=true`,
      );
      assert.strictEqual(recoveredHttp.status, 200);
      assert.match(recoveredHttp.body, /field offset=\+0x14/);
      await vscode.commands.executeCommand('ventris.reconstructSource', {
        file: ps2Fixture,
        address: '0x1000',
        target: 'ps2',
        loader: 'raw',
        base: '0x1000',
        raw: true,
      });
      const reconstructed = await waitForDocument((document) =>
        document.getText().includes('#include <stdint.h>'));
      assert.match(reconstructed.getText(), /sub_1000/);
      const reconstructedHttp = await request(
        `reconstruct-source?file=${encodeURIComponent(ps2Fixture)}&address=0x1000&target=ps2&loader=raw&base=0x1000&raw=true`,
      );
      assert.strictEqual(reconstructedHttp.status, 200);
      assert.match(reconstructedHttp.body, /#include <stdint\.h>/);
    } finally {
      fs.rmSync(ps2Fixture, { force: true });
    }
    const batchFile = path.join(os.tmpdir(), `ventris-vscode-batch-${process.pid}.jsonl`);
    fs.writeFileSync(batchFile, `${JSON.stringify({ command: 'inspect', image: fixture })}\n`);
    try {
      await vscode.commands.executeCommand('ventris.batch', { input: batchFile });
      const batched = await waitForDocument((document) =>
        document.getText().includes('"command":"inspect"'));
      assert.match(batched.getText(), /"ok":true/);
    } finally {
      fs.rmSync(batchFile, { force: true });
    }

    const httpBatch = await request(
      'batch',
      'POST',
      `${JSON.stringify({ command: 'inspect', image: fixture })}\n`,
    );
    assert.strictEqual(httpBatch.status, 200);
    assert.match(httpBatch.body, /"command":"inspect"/);

    await killPortOwner();
    await waitForHealth(false);
    await vscode.commands.executeCommand('ventris.startServer');
    await waitForHealth(true);
  });
});

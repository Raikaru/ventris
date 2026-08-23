const vscode = require('vscode');
const { spawn } = require('child_process');

function configuration() {
  const config = vscode.workspace.getConfiguration('ventris');
  return {
    binary: config.get('binary', 'ventris'),
    target: config.get('target', ''),
    loader: config.get('loader', 'auto'),
    base: config.get('base', ''),
    slice: config.get('slice', ''),
  };
}

function runCli(args) {
  const { binary } = configuration();
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      const output = Buffer.concat(stdout).toString('utf8');
      const error = Buffer.concat(stderr).toString('utf8').trim();
      if (code === 0) resolve(output);
      else reject(new Error(error || output.trim() || `Ventris exited with code ${code}`));
    });
  });
}

function commandFile(argument) {
  if (typeof argument === 'string') return argument;
  if (argument && typeof argument.file === 'string') return argument.file;
  if (argument && argument.file && typeof argument.file.fsPath === 'string') return argument.file.fsPath;
  if (argument && argument.fsPath) return argument.fsPath;
  if (argument && argument.uri && argument.uri.fsPath) return argument.uri.fsPath;
  return undefined;
}

async function chooseBinary() {
  const selection = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: 'Analyze Binary',
    filters: { Executable: ['exe', 'elf', 'bin', 'out', '*'], 'All files': ['*'] },
  });
  return selection && selection[0] ? selection[0].fsPath : undefined;
}

async function chooseAddress(argument) {
  if (argument && argument.address !== undefined) return String(argument.address);
  return vscode.window.showInputBox({
    prompt: 'Function address (hex or qualified address)',
    placeHolder: '0x1000',
    validateInput: (value) => value.trim() ? undefined : 'An address is required',
  });
}

async function analysisSelector(argument, config) {
  const target = argument && argument.target !== undefined ? argument.target : config.target;
  if (target) return ['--target', String(target)];
  const arch = argument && argument.arch !== undefined
    ? argument.arch
    : await vscode.window.showQuickPick(
      ['x86_64', 'x86_32', 'aarch64', 'arm32', 'thumb', 'mips32', 'mips32be', 'ps1', 'n64', 'rv64', 'rv32', 'ppc32', 'ppc64', 'gamecube', 'm68k', 'sh2', 'sh4', 'm6502', 'z80', 'spu'],
      { placeHolder: 'Architecture' },
    );
  return arch ? ['--arch', String(arch)] : undefined;
}

function imageOptions(argument, config) {
  const args = [];
  const loader = argument && argument.loader !== undefined ? argument.loader : config.loader;
  const base = argument && argument.base !== undefined ? argument.base : config.base;
  const slice = argument && argument.slice !== undefined ? argument.slice : config.slice;
  if (loader && loader !== 'auto') args.push('--loader', String(loader));
  if (base !== undefined && base !== '') args.push('--base', String(base));
  if (slice !== undefined && slice !== '') args.push('--slice', String(slice));
  return args;
}

async function showResult(title, content, language) {
  const document = await vscode.workspace.openTextDocument({ language, content });
  await vscode.window.showTextDocument(document, {
    preview: false,
    viewColumn: vscode.ViewColumn.Beside,
  });
  vscode.window.setStatusBarMessage(`Ventris: ${title}`, 3000);
}

async function inspect(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const config = configuration();
  const output = await runCli(['inspect', file, ...imageOptions(argument, config)]);
  await showResult(`inspected ${file}`, output, 'plaintext');
}

async function lift(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const address = await chooseAddress(argument);
  if (!address) return;
  const config = configuration();
  const selector = await analysisSelector(argument, config);
  if (!selector) return;
  const args = ['lift', file, address, ...selector, ...imageOptions(argument, config)];
  if (argument.limit !== undefined) args.push('--limit', String(argument.limit));
  if (argument.raw) args.push('--raw');
  await showResult(`lifted ${address}`, await runCli(args), 'plaintext');
}

async function decompile(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const address = await chooseAddress(argument);
  if (!address) return;
  const config = configuration();
  const selector = await analysisSelector(argument, config);
  if (!selector) return;
  const args = ['decompile', file, address, ...selector, ...imageOptions(argument, config)];
  if (argument.metadata) {
    args.push('--metadata', commandFile({ file: argument.metadata }) || String(argument.metadata));
  }
  if (argument.limit !== undefined) args.push('--limit', String(argument.limit));
  if (argument.raw) args.push('--raw');
  await showResult(`decompiled ${address}`, await runCli(args), 'c');
}

function activate(context) {
  const register = (name, handler) => context.subscriptions.push(
    vscode.commands.registerCommand(name, (argument) =>
      handler(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
  );
  register('ventris.inspect', inspect);
  register('ventris.lift', lift);
  register('ventris.decompile', decompile);
}

function deactivate() {}

module.exports = { activate, deactivate };

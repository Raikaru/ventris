const vscode = require("vscode");
const http = require("http");
const https = require("https");
const { spawn } = require("child_process");
const fs = require("fs");

let serverProcess;

function configuration() {
  const config = vscode.workspace.getConfiguration("ventris");
  return {
    binary: config.get("binary", "ventris"),
    url: config.get("serverUrl", "http://127.0.0.1:8787").replace(/\/$/, ""),
    extraArgs: config.get("serverArgs", []),
    target: config.get("target", ""),
    loader: config.get("loader", "auto"),
    base: config.get("base", ""),
    slice: config.get("slice", ""),
  };
}

function request(baseUrl, endpoint, query, method = "GET", body = undefined) {
  const url = new URL(endpoint, `${baseUrl}/`);
  if (method === "GET") {
    for (const [key, value] of Object.entries(query || {})) {
      url.searchParams.set(key, value);
    }
  }
  const transport = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const headers = {};
    if (body !== undefined) {
      headers["Content-Type"] = "application/jsonl";
      headers["Content-Length"] = Buffer.byteLength(body);
    }
    const request = transport.request(url, { method, headers }, (response) => {
      const chunks = [];
      response.setEncoding("utf8");
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const responseBody = chunks.join("");
        if ((response.statusCode || 500) >= 400) {
          reject(new Error(responseBody.trim() || `Ventris returned HTTP ${response.statusCode}`));
        } else {
          resolve(responseBody);
        }
      });
    });
    request.setTimeout(3000, () => request.destroy(new Error("Ventris request timed out")));
    request.on("error", reject);
    if (body !== undefined) request.end(body);
    else request.end();
  });
}

async function health(url) {
  try {
    await request(url, "health");
    return true;
  } catch (_) {
    return false;
  }
}

async function ensureServer() {
  const config = configuration();
  if (await health(config.url)) {
    return config.url;
  }
  if (!serverProcess) {
    const address = new URL(config.url);
    const bind = `${address.hostname}:${address.port || (address.protocol === "https:" ? 443 : 80)}`;
    serverProcess = spawn(config.binary, [...config.extraArgs, "serve", "--bind", bind], {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    serverProcess.on("exit", () => { serverProcess = undefined; });
    serverProcess.on("error", (error) => {
      vscode.window.showErrorMessage(`Ventris could not start: ${error.message}`);
    });
  }
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (await health(config.url)) {
      return config.url;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Ventris did not become ready at ${config.url}`);
}

function commandFile(argument) {
  if (typeof argument === "string") return argument;
  if (argument && typeof argument.file === "string") return argument.file;
  if (argument && argument.file && typeof argument.file.fsPath === "string") {
    return argument.file.fsPath;
  }
  if (argument && typeof argument.input === "string") return argument.input;
  if (argument && argument.input && typeof argument.input.fsPath === "string") {
    return argument.input.fsPath;
  }
  return undefined;
}
function imageQuery(argument, config) {
  const query = {};
  const target = argument && argument.target !== undefined ? argument.target : config.target;
  const loader = argument && argument.loader !== undefined ? argument.loader : config.loader;
  const base = argument && argument.base !== undefined ? argument.base : config.base;
  const slice = argument && argument.slice !== undefined ? argument.slice : config.slice;
  if (target) query.target = target;
  if (loader) query.loader = loader;
  if (base !== undefined && base !== "") query.base = base;
  if (slice !== undefined && slice !== "") query.slice = slice;
  return query;
}

async function chooseBinary() {
  const selection = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: "Analyze Binary",
    filters: { "Executable files": ["exe", "elf", "bin", "out", "*"], "All files": ["*"] },
  });
  return selection && selection[0] ? selection[0].fsPath : undefined;
}

async function chooseBatchInput() {
  const selection = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: "Run Ventris Batch",
    filters: { "JSON Lines": ["jsonl", "ndjson", "json"], "All files": ["*"] },
  });
  return selection && selection[0] ? selection[0].fsPath : undefined;
}

async function showResult(title, body, language = "c") {
  const document = await vscode.workspace.openTextDocument({
    language,
    content: body,
  });
  await vscode.window.showTextDocument(document, { preview: false, viewColumn: vscode.ViewColumn.Beside });
  vscode.window.setStatusBarMessage(`Ventris: ${title}`, 3000);
}

async function inspect(argument) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const config = configuration();
  const url = await ensureServer();
  await showResult(
    `inspected ${file}`,
    await request(url, "inspect", { file, ...imageQuery(argument, config) }),
    "plaintext",
  );
}

async function discover(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const config = configuration();
  const target = argument.target !== undefined ? argument.target : config.target;
  const arch = argument.arch || (target ? undefined : await vscode.window.showQuickPick(
    ["x86_64", "x86_32", "aarch64", "arm32", "thumb", "mips32", "mips32be", "ps1", "n64", "rv64", "rv32", "ppc32", "ppc64", "gamecube", "m68k", "sh2", "sh4", "m6502", "z80", "spu"],
    { placeHolder: "Architecture" },
  ));
  if (!arch && !target) return;
  const url = await ensureServer();
  const query = {
    file,
    ...(arch ? { arch } : {}),
    ...(argument.limit !== undefined ? { limit: argument.limit } : {}),
    ...imageQuery(argument, config),
  };
  await showResult(
    `discovered functions in ${file}`,
    await request(url, "discover", query),
    "plaintext",
  );
}

async function resolve(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const address = argument.address || await vscode.window.showInputBox({
    prompt: "Address to resolve",
    placeHolder: "ram::0x401000 or 0x401000",
    validateInput: (value) => value.trim() ? undefined : "An address is required",
  });
  if (!address) return;
  const config = configuration();
  const url = await ensureServer();
  await showResult(
    `resolved ${address}`,
    await request(url, "resolve", { file, address, ...imageQuery(argument, config) }),
    "plaintext",
  );
}

async function lift(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const address = argument.address || await vscode.window.showInputBox({
    prompt: "Function address (hex or qualified address)",
    placeHolder: "0x401000",
    validateInput: (value) => value.trim() ? undefined : "An address is required",
  });
  if (!address) return;
  const config = configuration();
  const target = argument.target !== undefined ? argument.target : config.target;
  const arch = argument.arch || (target ? undefined : await vscode.window.showQuickPick(
    ["x86_64", "x86_32", "aarch64", "arm32", "thumb", "mips32", "mips32be", "ps1", "n64", "rv64", "rv32", "ppc32", "ppc64", "gamecube", "m68k", "sh2", "sh4", "m6502", "z80", "spu"],
    { placeHolder: "Architecture" },
  ));
  if (!arch && !target) return;
  const url = await ensureServer();
  await showResult(
    `lifted ${address}`,
    await request(url, "lift", {
      file,
      address,
      ...(arch ? { arch } : {}),
      ...imageQuery(argument, config),
    }),
    "plaintext",
  );
}


async function recoverTypes(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const address = argument.address || await vscode.window.showInputBox({
    prompt: "Function address (hex or qualified address)",
    placeHolder: "0x1000",
    validateInput: (value) => value.trim() ? undefined : "An address is required",
  });
  if (!address) return;
  const config = configuration();
  const target = argument.target !== undefined ? argument.target : config.target || await vscode.window.showQuickPick(
    ["ps2", "gamecube", "ps1", "n64", "xbox360", "ps3-ppu", "ps3-spu"],
    { placeHolder: "Console target" },
  );
  if (!target) return;
  const url = await ensureServer();
  const query = {
    file,
    address,
    target,
    ...imageQuery(argument, config),
  };
  const metadata = argument.metadata;
  if (metadata) query.metadata = commandFile({ file: metadata }) || metadata;
  if (argument.limit !== undefined) query.limit = argument.limit;
  if (argument.raw !== undefined) query.raw = argument.raw;
  await showResult(
    `recovered types ${address}`,
    await request(url, "recover-types", query),
    "plaintext",
  );
}

async function reconstructSource(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const address = argument.address || await vscode.window.showInputBox({
    prompt: "Function address (hex or qualified address)",
    placeHolder: "0x1000",
    validateInput: (value) => value.trim() ? undefined : "An address is required",
  });
  if (!address) return;
  const config = configuration();
  const target = argument.target !== undefined ? argument.target : config.target || await vscode.window.showQuickPick(
    ["ps2", "gamecube", "ps1", "n64", "xbox360", "ps3-ppu", "ps3-spu"],
    { placeHolder: "Console target" },
  );
  if (!target) return;
  const url = await ensureServer();
  const query = {
    file,
    address,
    target,
    ...imageQuery(argument, config),
  };
  const metadata = argument.metadata;
  if (metadata) query.metadata = commandFile({ file: metadata }) || metadata;
  if (argument.limit !== undefined) query.limit = argument.limit;
  if (argument.raw !== undefined) query.raw = argument.raw;
  if (argument.cache !== undefined) query.cache = argument.cache;
  await showResult(
    `reconstructed source ${address}`,
    await request(url, "reconstruct-source", query),
    "c",
  );
}


async function batch(argument = {}) {
  const file = commandFile(argument) || await chooseBatchInput();
  if (!file) return;
  const config = configuration();
  const url = await ensureServer();
  const input = fs.readFileSync(file, "utf8");
  await showResult(
    `batch ${file}`,
    await request(url, "batch", {}, "POST", input),
    "json",
  );
}
async function decompileNative(argument = {}) {
  const file = commandFile(argument) || await chooseBinary();
  if (!file) return;
  const address = argument.address || await vscode.window.showInputBox({
    prompt: "Function address (hex or qualified address)",
    placeHolder: "0x401000",
    validateInput: (value) => value.trim() ? undefined : "An address is required",
  });
  if (!address) return;
  const config = configuration();
  const target = argument.target !== undefined ? argument.target : config.target;
  const arch = argument.arch || (target ? undefined : await vscode.window.showQuickPick(
    ["x86_64", "x86_32", "aarch64", "arm32", "thumb", "mips32", "mips32be", "ps1", "n64", "rv64", "rv32", "ppc32", "ppc64", "gamecube", "m68k", "sh2", "sh4", "m6502", "z80", "spu"],
    { placeHolder: "Architecture" },
  ));
  if (!arch && !target) return;
  const url = await ensureServer();
  await showResult(
    `decompiled ${address}`,
    await request(url, "decompile-native", {
      file,
      address,
      ...(arch ? { arch } : {}),
      ...imageQuery(argument, config),
    }),
    "c",
  );
}

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand("ventris.startServer", async () => {
      try {
        await ensureServer();
        vscode.window.showInformationMessage(`Ventris server is ready at ${configuration().url}`);
      } catch (error) {
        vscode.window.showErrorMessage(error.message);
      }
    }),
    vscode.commands.registerCommand("ventris.inspect", (argument) => inspect(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
    vscode.commands.registerCommand("ventris.discover", (argument) => discover(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
    vscode.commands.registerCommand("ventris.resolve", (argument) => resolve(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
    vscode.commands.registerCommand("ventris.lift", (argument) => lift(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
    vscode.commands.registerCommand("ventris.recoverTypes", (argument) => recoverTypes(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
    vscode.commands.registerCommand("ventris.reconstructSource", (argument) => reconstructSource(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
    vscode.commands.registerCommand("ventris.decompileNative", (argument) => decompileNative(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
    vscode.commands.registerCommand("ventris.batch", (argument) => batch(argument).catch((error) => vscode.window.showErrorMessage(error.message))),
  );
}

function deactivate() {
  if (serverProcess) {
    serverProcess.kill();
    serverProcess = undefined;
  }
}

module.exports = { activate, deactivate };

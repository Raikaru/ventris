const path = require('path');
const { runTests } = require('@vscode/test-electron');

const root = path.resolve(__dirname, '..');
const executable = process.env.VSCODE_EXECUTABLE;
const extensionPath = process.env.VENTRIS_ACCEPTANCE_EXTENSION_PATH || root;
const userDataDir = process.env.VENTRIS_ACCEPTANCE_USER_DATA ||
  path.join(root, '.acceptance-user');
const extensionsDir = process.env.VENTRIS_ACCEPTANCE_EXTENSIONS_DIR ||
  path.join(root, '.acceptance-extensions');

const testOptions = {
  extensionDevelopmentPath: extensionPath,
  extensionTestsPath: path.join(__dirname, 'suite'),
  launchArgs: [
    `--user-data-dir=${userDataDir}`,
    `--extensions-dir=${extensionsDir}`,
    '--disable-extensions-except=ventris.ventris-binary-analysis',
    '--disable-gpu',
  ],
  extensionTestsEnv: {
    VENTRIS_ACCEPTANCE_BINARY: process.env.VENTRIS_ACCEPTANCE_BINARY || '',
    VENTRIS_ACCEPTANCE_FIXTURE: process.env.VENTRIS_ACCEPTANCE_FIXTURE || '',
    VENTRIS_ACCEPTANCE_SERVER_URL:
      process.env.VENTRIS_ACCEPTANCE_SERVER_URL || 'http://127.0.0.1:8897',
    VENTRIS_ACCEPTANCE_FUNCTION_ADDRESS:
      process.env.VENTRIS_ACCEPTANCE_FUNCTION_ADDRESS || '0x140001450',
  },
};

if (executable) testOptions.vscodeExecutablePath = executable;

(async () => {
  try {
    await runTests(testOptions);
    console.log('VS Code extension acceptance: passed');
  } catch (error) {
    console.error('VS Code extension acceptance: failed');
    console.error(error);
    process.exitCode = 1;
  }
})();

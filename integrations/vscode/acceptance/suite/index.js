const path = require('path');
const Mocha = require('mocha');

exports.run = function run(_testsRoot, callback) {
  const mocha = new Mocha({ ui: 'tdd', timeout: 30000 });
  mocha.addFile(path.resolve(__dirname, 'extension.test.js'));
  mocha.run((failures) => callback(null, failures));
};

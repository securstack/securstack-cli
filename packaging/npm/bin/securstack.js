#!/usr/bin/env node
const { existsSync } = require('node:fs');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

const executable = join(__dirname, '..', 'vendor', process.platform === 'win32' ? 'securstack.exe' : 'securstack');
if (!existsSync(executable)) {
  console.error('SecurStack CLI binary is missing. Reinstall @securstack/cli with install scripts enabled.');
  process.exit(1);
}
const result = spawnSync(executable, process.argv.slice(2), { stdio: 'inherit', env: process.env });
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);

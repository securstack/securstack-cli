#!/usr/bin/env node
import { mkdtempSync, rmSync, mkdirSync, copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const packagesRoot = resolve(process.argv[2] || 'dist/packages');
const tapRepository = process.env.SECURSTACK_HOMEBREW_TAP_REPOSITORY || 'securstack/homebrew-tap';
const token = process.env.SECURSTACK_GITHUB_AUTOMATION_TOKEN || process.env.GH_TOKEN || '';
const formulaSource = join(packagesRoot, 'homebrew', 'securstack.rb');

if (!existsSync(formulaSource)) {
  throw new Error(`Rendered Homebrew formula not found: ${formulaSource}`);
}

if (!token) {
  console.log('SECURSTACK_GITHUB_AUTOMATION_TOKEN is not configured; skipping Homebrew tap publication.');
  process.exit(0);
}

const version = extractVersion(readFileSync(formulaSource, 'utf8'));
const workDir = mkdtempSync(join(tmpdir(), 'securstack-homebrew-'));

try {
  const remote = `https://x-access-token:${token}@github.com/${tapRepository}.git`;
  run('git', ['clone', '--depth', '1', remote, workDir], { mask: token });
  run('git', ['-C', workDir, 'config', 'user.name', 'SecurStack Release Bot']);
  run('git', ['-C', workDir, 'config', 'user.email', 'release-bot@securstack.io']);

  const destination = join(workDir, 'Formula', 'securstack.rb');
  mkdirSync(dirname(destination), { recursive: true });
  const before = existsSync(destination) ? readFileSync(destination, 'utf8') : '';
  const after = readFileSync(formulaSource, 'utf8');
  copyFileSync(formulaSource, destination);

  if (before === after) {
    console.log(`Homebrew tap already contains SecurStack ${version}; nothing to publish.`);
    process.exit(0);
  }

  const readme = join(workDir, 'README.md');
  if (!existsSync(readme)) {
    writeFileSync(readme, '# SecurStack Homebrew Tap\n\nOfficial Homebrew tap for the standalone SecurStack CLI.\n');
  }

  run('git', ['-C', workDir, 'add', '--', 'Formula/securstack.rb', 'README.md']);
  run('git', ['-C', workDir, 'commit', '-m', `Update SecurStack CLI to ${version}`]);
  run('git', ['-C', workDir, 'push', 'origin', 'HEAD:main'], { mask: token });
  console.log(`Published SecurStack ${version} to ${tapRepository}.`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

function extractVersion(formula) {
  const match = formula.match(/^\s*version\s+"([^"]+)"/m);
  if (!match) throw new Error('Could not resolve formula version.');
  return match[1];
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.status === 0) return result;
  const output = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
  throw new Error(`${command} ${args.join(' ')} failed: ${redact(output, options.mask)}`);
}

function redact(value, secret) {
  return secret ? value.replaceAll(secret, '***') : value;
}

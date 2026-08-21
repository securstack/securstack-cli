#!/usr/bin/env node
import { mkdtempSync, rmSync, mkdirSync, cpSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const packagesRoot = resolve(process.argv[2] || 'dist/packages');
const wingetSource = join(packagesRoot, 'winget');
const token = process.env.SECURSTACK_GITHUB_AUTOMATION_TOKEN || process.env.GH_TOKEN || '';
const forkRepository = process.env.SECURSTACK_WINGET_FORK_REPOSITORY || 'securstack/winget-pkgs';
const upstreamRepository = process.env.SECURSTACK_WINGET_UPSTREAM_REPOSITORY || 'microsoft/winget-pkgs';

if (!existsSync(wingetSource)) {
  throw new Error(`Rendered WinGet manifests not found: ${wingetSource}`);
}

if (!token) {
  console.log('SECURSTACK_GITHUB_AUTOMATION_TOKEN is not configured; skipping WinGet PR publication.');
  process.exit(0);
}

const version = readManifestVersion(join(wingetSource, 'SecurStack.CLI.yaml'));
const branch = `SecurStack.CLI-${version}`;
const manifestPath = `manifests/s/SecurStack/CLI/${version}`;
const workDir = mkdtempSync(join(tmpdir(), 'securstack-winget-'));

try {
  const remote = `https://x-access-token:${token}@github.com/${forkRepository}.git`;
  run('git', ['clone', '--depth', '1', remote, workDir], { mask: token });
  run('git', ['-C', workDir, 'config', 'user.name', 'SecurStack Release Bot']);
  run('git', ['-C', workDir, 'config', 'user.email', 'release-bot@securstack.io']);
  const fetchedBranch = tryRun('git', ['-C', workDir, 'fetch', 'origin', `refs/heads/${branch}:refs/remotes/origin/${branch}`], { mask: token });
  if (fetchedBranch.status === 0) {
    run('git', ['-C', workDir, 'checkout', '-B', branch, `origin/${branch}`]);
  } else {
    run('git', ['-C', workDir, 'checkout', '-B', branch]);
  }

  const destination = join(workDir, manifestPath);
  mkdirSync(destination, { recursive: true });
  cpSync(wingetSource, destination, { recursive: true });

  const status = run('git', ['-C', workDir, 'status', '--short']).stdout.trim();
  if (!status) {
    console.log(`WinGet manifests for SecurStack ${version} are already committed on ${forkRepository}:${branch}.`);
  } else {
    run('git', ['-C', workDir, 'add', '--', manifestPath]);
    run('git', ['-C', workDir, 'commit', '-m', `New package: SecurStack.CLI version ${version}`]);
    run('git', ['-C', workDir, 'push', '--force-with-lease', 'origin', `HEAD:${branch}`], { mask: token });
  }

  const bodyFile = join(workDir, 'winget-pr-body.md');
  writeFileSync(bodyFile, [
    `Adds the official SecurStack CLI ${version} portable Windows x64 package.`,
    '',
    'The manifest references the immutable binary on downloads.securstack.io and its published SHA-256 checksum.',
    '',
    'Official release/download metadata:',
    `- https://downloads.securstack.io/cli/v${version}/manifest.json`,
    '',
    'Checklist notes:',
    '- CLA is handled by the securstack GitHub account.',
    '- Repository validation is expected to run in microsoft/winget-pkgs.',
    ''
  ].join('\n'));

  const existing = run('gh', [
    'pr', 'list',
    '--repo', upstreamRepository,
    '--head', `securstack:${branch}`,
    '--state', 'open',
    '--json', 'url',
    '--jq', '.[0].url // ""'
  ], { env: { GH_TOKEN: token }, mask: token }).stdout.trim();

  if (existing) {
    console.log(`WinGet PR already open: ${existing}`);
    process.exit(0);
  }

  const created = run('gh', [
    'pr', 'create',
    '--repo', upstreamRepository,
    '--base', 'master',
    '--head', `securstack:${branch}`,
    '--title', `New package: SecurStack.CLI version ${version}`,
    '--body-file', bodyFile
  ], { env: { GH_TOKEN: token }, mask: token }).stdout.trim();
  console.log(`Created WinGet PR: ${created}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

function readManifestVersion(file) {
  const contents = readFileSync(file, 'utf8');
  const match = contents.match(/^PackageVersion:\s*(.+)$/m);
  if (!match) throw new Error(`Could not resolve PackageVersion from ${file}`);
  return match[1].trim();
}

function run(command, args, options = {}) {
  const env = { ...process.env, ...(options.env || {}) };
  const result = spawnSync(command, args, { encoding: 'utf8', env });
  if (result.status === 0) return result;
  const output = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
  throw new Error(`${command} ${args.join(' ')} failed: ${redact(output, options.mask)}`);
}

function tryRun(command, args, options = {}) {
  const env = { ...process.env, ...(options.env || {}) };
  return spawnSync(command, args, { encoding: 'utf8', env });
}

function redact(value, secret) {
  return secret ? value.replaceAll(secret, '***') : value;
}

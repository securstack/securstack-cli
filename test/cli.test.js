import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  collectFiles,
  encryptLocalScanPayload,
  evaluatePolicy,
  gitHookStatus,
  installGitHook,
  looksBinary,
  toSarif,
  uninstallGitHook
} from '../bin/securstack.js';

test('collectFiles respects default and project ignore rules', () => {
  const root = mkdtempSync(join(tmpdir(), 'securstack-cli-'));
  try {
    mkdirSync(join(root, 'src'));
    mkdirSync(join(root, 'node_modules'));
    writeFileSync(join(root, '.gitignore'), 'ignored.txt\nlogs/*.log\n');
    writeFileSync(join(root, '.securstackignore'), 'secret.local\n');
    writeFileSync(join(root, 'src', 'app.js'), 'const token = process.env.TOKEN;\n');
    writeFileSync(join(root, 'ignored.txt'), 'ignored\n');
    writeFileSync(join(root, 'secret.local'), 'ignored\n');
    mkdirSync(join(root, 'logs'));
    writeFileSync(join(root, 'logs', 'debug.log'), 'ignored\n');
    writeFileSync(join(root, 'node_modules', 'dep.js'), 'ignored\n');

    const files = collectFiles(root).map((file) => file.path).sort();
    assert.deepEqual(files, ['.gitignore', '.securstackignore', 'src/app.js']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('looksBinary detects null bytes', () => {
  assert.equal(looksBinary(Buffer.from([0x61, 0x00, 0x62])), true);
  assert.equal(looksBinary(Buffer.from('plain text')), false);
});

test('toSarif converts findings into SARIF results', () => {
  const sarif = toSarif({
    findings: [{
      ruleId: 'secret-assignment',
      severity: 'high',
      title: 'Possible secret',
      description: 'A secret was found.',
      recommendation: 'Move it to a secret manager.',
      filePath: 'src/app.js',
      lineStart: 4,
      fingerprint: 'abc123abc123abc123'
    }]
  });

  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/app.js');
});

test('encryptLocalScanPayload replaces plaintext file content with AES-GCM envelope fields', () => {
  const { publicKey } = generateKeyPairSync('x25519');
  const encrypted = encryptLocalScanPayload({
    repositoryName: 'repo-a',
    rootPath: '/repo-a',
    environment: 'dev',
    engines: ['secrets'],
    files: [{
      path: 'src/app.js',
      contentBase64: Buffer.from('const secret = "abc";\n').toString('base64'),
      sizeBytes: 22,
      sha256: 'a'.repeat(64)
    }]
  }, {
    scanSessionId: 'lss_12345678901234567890',
    keyAlgorithm: 'x25519-hkdf-sha256',
    contentAlgorithm: 'aes-256-gcm',
    publicKeyBase64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    expiresAt: new Date(Date.now() + 60_000).toISOString()
  });

  assert.equal(encrypted.files.length, 1);
  assert.equal(encrypted.files[0].path, 'src/app.js');
  assert.equal(encrypted.files[0].sha256Plaintext, 'a'.repeat(64));
  assert.equal(typeof encrypted.files[0].ciphertextBase64, 'string');
  assert.equal(typeof encrypted.files[0].nonceBase64, 'string');
  assert.equal(typeof encrypted.files[0].authTagBase64, 'string');
  assert.equal('contentBase64' in encrypted.files[0], false);
});

test('evaluatePolicy blocks scans above configured risk or severity limits', () => {
  const result = evaluatePolicy({
    summary: {
      riskScore: 8.4,
      bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
    }
  }, {
    maxRiskScore: 7.9,
    maxSeverity: { critical: 0 }
  });

  assert.equal(result.allowed, false);
  assert.equal(result.riskScore, 8.4);
  assert.equal(result.violations.length, 2);
});

test('installGitHook appends and removes only the SecurStack block', () => {
  const root = mkdtempSync(join(tmpdir(), 'securstack-cli-hook-'));
  try {
    mkdirSync(join(root, '.git', 'hooks'), { recursive: true });
    const hookPath = join(root, '.git', 'hooks', 'pre-commit');
    writeFileSync(hookPath, '#!/bin/sh\necho existing\n');

    installGitHook(root, { maxRiskScore: 7.9, maxSeverity: { critical: 0, high: 0 } }, 'securstack');
    const installed = readFileSync(hookPath, 'utf8');
    assert.match(installed, /echo existing/);
    assert.match(installed, /# securstack hook begin/);
    assert.equal(gitHookStatus(root).installed, true);

    uninstallGitHook(root);
    const removed = readFileSync(hookPath, 'utf8');
    assert.match(removed, /echo existing/);
    assert.doesNotMatch(removed, /# securstack hook begin/);
    assert.equal(gitHookStatus(root).installed, false);
    assert.equal(existsSync(hookPath), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

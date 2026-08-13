import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalApiAttestationProofString } from '@securstack/core/v1';
import {
  collectFiles,
  createPackageArchive,
  encryptLocalScanPayload,
  evaluatePolicy,
  gitHookStatus,
  installGitHook,
  looksBinary,
  main,
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

test('createPackageArchive has a portable tar.gz fallback without external tar', async () => {
  const root = mkdtempSync(join(tmpdir(), 'securstack-cli-package-'));
  const tempDir = mkdtempSync(join(tmpdir(), 'securstack-cli-package-out-'));
  try {
    mkdirSync(join(root, 'src'));
    mkdirSync(join(root, 'node_modules'));
    writeFileSync(join(root, '.securstackignore'), 'private.txt\n');
    writeFileSync(join(root, 'src', 'app.js'), 'console.log("ok");\n');
    writeFileSync(join(root, 'private.txt'), 'ignored\n');
    writeFileSync(join(root, 'node_modules', 'dep.js'), 'ignored\n');

    const archivePath = await createPackageArchive(root, tempDir, 1024 * 1024, { forcePortable: true });
    const tar = gunzipSync(readFileSync(archivePath));

    assert.equal(tarIncludes(tar, 'src/app.js'), true);
    assert.equal(tarIncludes(tar, '.securstackignore'), true);
    assert.equal(tarIncludes(tar, 'private.txt'), false);
    assert.equal(tarIncludes(tar, 'node_modules/dep.js'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(tempDir, { recursive: true, force: true });
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

test('shielding gate emits CI/CD verdict and sets exit code on block', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const previousExitCode = process.exitCode;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  process.exitCode = undefined;
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    requests.push({ url: String(input), tenantId: new Headers(init?.headers).get('x-tenant-id') });
    return Response.json({
      buildId: 'build-a',
      decision: 'block',
      passed: false,
      shouldBlockRelease: true,
      ciStatus: 'fail',
      exitCode: 1,
      reasons: ['Missing required protection: api_attestation']
    });
  };

  try {
    await main(['shielding', 'gate', '--build-id', 'build-a', '--tenant-id', 'tenant-a']);

    assert.equal(process.exitCode, 1);
    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/builds/build-a/release-gate/check');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.equal(JSON.parse(outputs[0]).ciStatus, 'fail');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    process.exitCode = previousExitCode;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding build can include release gate check in CI output', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const methods = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    methods.push(init?.method);
    const url = String(input);
    if (url.endsWith('/v1/shielding/builds')) {
      return Response.json({ build: { id: 'build-created', status: 'protected' } });
    }
    if (url.endsWith('/v1/shielding/builds/build-created/release-gate/check')) {
      return Response.json({ buildId: 'build-created', decision: 'pass', passed: true, shouldBlockRelease: false, ciStatus: 'pass', exitCode: 0 });
    }
    return Response.json({}, { status: 404 });
  };

  try {
    await main([
      'shielding',
      'build',
      '--app-id',
      'app-a',
      '--artifact-id',
      'artifact-a',
      '--policy-id',
      'policy-a',
      '--gate-check'
    ]);

    const output = JSON.parse(outputs[0]);
    assert.deepEqual(methods, ['POST', 'GET']);
    assert.equal(output.build.id, 'build-created');
    assert.equal(output.releaseGateCheck.ciStatus, 'pass');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding build supports async mode with polling before release gate check', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const calls = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, method: init?.method, body });
    if (url.endsWith('/v1/shielding/builds') && init?.method === 'POST') {
      return Response.json({
        asyncAccepted: true,
        build: { id: 'build-async', status: 'pending' },
        job: { id: 'build-async', status: 'pending' }
      }, { status: 202 });
    }
    if (url.endsWith('/v1/shielding/builds/build-async') && init?.method === 'GET') {
      return Response.json({ id: 'build-async', status: 'protected', protectedSha256: 'b'.repeat(64) });
    }
    if (url.endsWith('/v1/shielding/builds/build-async/release-gate/check')) {
      return Response.json({ buildId: 'build-async', decision: 'pass', passed: true, shouldBlockRelease: false, ciStatus: 'pass', exitCode: 0 });
    }
    return Response.json({}, { status: 404 });
  };

  try {
    await main([
      'shielding',
      'build',
      '--app-id',
      'app-a',
      '--artifact-id',
      'artifact-a',
      '--policy-id',
      'policy-a',
      '--idempotency-key',
      'ci-build-123',
      '--async',
      '--wait',
      '--poll-interval-ms',
      '1',
      '--gate-check'
    ]);

    const output = JSON.parse(outputs[0]);
    assert.equal(calls[0].body.asyncMode, true);
    assert.equal(calls[0].body.idempotencyKey, 'ci-build-123');
    assert.deepEqual(calls.map((call) => call.method), ['POST', 'GET', 'GET']);
    assert.equal(output.build.status, 'protected');
    assert.equal(output.releaseGateCheck.ciStatus, 'pass');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding build refuses release gate check for pending async builds without wait', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  globalThis.fetch = async () => Response.json({
    asyncAccepted: true,
    build: { id: 'build-pending', status: 'pending' },
    job: { id: 'build-pending', status: 'pending' }
  }, { status: 202 });

  try {
    await assert.rejects(
      main([
        'shielding',
        'build',
        '--app-id',
        'app-a',
        '--artifact-id',
        'artifact-a',
        '--policy-id',
        'policy-a',
        '--async',
        '--gate-check'
      ]),
      /Use --wait with --async/
    );
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    delete globalThis.fetch;
  }
});

test('shielding attest signs bound API attestation payload without sending tenant in body', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({
      id: 'attestation-a',
      appId: body.appId,
      buildId: body.buildId,
      platform: body.platform,
      endpoint: body.endpoint,
      protectedSha256: body.protectedSha256,
      artifactStage: body.artifactStage,
      signedSha256: body.signedSha256,
      evidenceFingerprint: body.evidenceFingerprint,
      nonce: body.nonce,
      decision: 'allow',
      proofStatus: 'valid'
    });
  };

  try {
    await main([
      'shielding',
      'attest',
      '--tenant-id',
      'tenant-a',
      '--app-id',
      'app-a',
      '--build-id',
      'build-a',
      '--platform',
      'android',
      '--endpoint',
      '/api/v1/payments/authorize',
      '--protected-sha256',
      'b'.repeat(64),
      '--artifact-stage',
      'signed',
      '--signed-sha256',
      'e'.repeat(64),
      '--evidence-fingerprint',
      `ssk-shielding-evidence-v1:${'c'.repeat(64)}`,
      '--nonce',
      'nonce-cli-bound-123',
      '--timestamp',
      '2026-08-12T12:00:00.000Z',
      '--session-risk',
      '1',
      '--key-id',
      'tenant-a-app-a',
      '--hmac-secret',
      'attestation-secret'
    ]);

    const request = requests[0];
    const expectedProofPayload = {
      tenantId: 'tenant-a',
      appId: 'app-a',
      buildId: 'build-a',
      platform: 'android',
      endpoint: '/api/v1/payments/authorize',
      protectedSha256: 'b'.repeat(64),
      artifactStage: 'signed',
      signedSha256: 'e'.repeat(64),
      evidenceFingerprint: `ssk-shielding-evidence-v1:${'c'.repeat(64)}`,
      nonce: 'nonce-cli-bound-123',
      timestamp: '2026-08-12T12:00:00.000Z',
      sessionRisk: 1,
      signatureVersion: 'ssk-attestation-hmac-v1',
      keyId: 'tenant-a-app-a'
    };
    assert.equal(request.url, 'https://api.example.test/api/v1/shielding/attestation/events');
    assert.equal(request.method, 'POST');
    assert.equal(request.tenantId, 'tenant-a');
    assert.equal(request.body.tenantId, undefined);
    assert.equal(request.body.artifactStage, 'signed');
    assert.equal(request.body.signedSha256, 'e'.repeat(64));
    assert.equal(request.body.signature, `sha256=${createHmac('sha256', 'attestation-secret').update(canonicalApiAttestationProofString('tenant-a', expectedProofPayload)).digest('hex')}`);
    assert.equal(JSON.parse(outputs[0]).proofStatus, 'valid');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding attest sets a failing exit code when API returns block', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const previousExitCode = process.exitCode;
  const originalLog = console.log;
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  process.exitCode = undefined;
  console.log = () => undefined;
  globalThis.fetch = async () => Response.json({ id: 'attestation-blocked', decision: 'block' });

  try {
    await main(['shielding', 'attest', '--app-id', 'app-a', '--platform', 'android']);
    assert.equal(process.exitCode, 1);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    process.exitCode = previousExitCode;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding attest rejects invalid nonce and session risk before calling the API', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  globalThis.fetch = async () => {
    throw new Error('fetch should not be called');
  };

  try {
    await assert.rejects(
      main(['shielding', 'attest', '--app-id', 'app-a', '--platform', 'android', '--nonce', 'short']),
      /nonce must be between 8 and 256 characters/
    );
    await assert.rejects(
      main(['shielding', 'attest', '--app-id', 'app-a', '--platform', 'android', '--session-risk', '11']),
      /session risk must be between 0 and 10/
    );
    await assert.rejects(
      main(['shielding', 'attest', '--app-id', 'app-a', '--platform', 'android', '--artifact-stage', 'signed']),
      /requires --build-id/
    );
    await assert.rejects(
      main(['shielding', 'attest', '--app-id', 'app-a', '--platform', 'android', '--build-id', 'build-a', '--artifact-stage', 'signed']),
      /requires --signed-sha256/
    );
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    delete globalThis.fetch;
  }
});

test('shielding resolve-threat closes support cases with audit-safe payload', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({
      id: 'case-a',
      code: 'SSK-ABCDEF12',
      resolvedAt: '2026-08-12T12:05:00.000Z',
      resolvedBy: body.resolvedBy,
      resolutionNote: body.resolutionNote
    });
  };

  try {
    await main([
      'shielding',
      'resolve-threat',
      '--tenant-id',
      'tenant-a',
      '--code',
      'SSK-ABCDEF12',
      '--resolved-by',
      'soc-analyst',
      '--resolution-note',
      'Blocked session and rotated exposed tokens.'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/runtime/threat-resolution/SSK-ABCDEF12/resolve');
    assert.equal(requests[0].method, 'PATCH');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.deepEqual(requests[0].body, {
      resolvedBy: 'soc-analyst',
      resolutionNote: 'Blocked session and rotated exposed tokens.'
    });
    assert.equal(JSON.parse(outputs[0]).resolvedBy, 'soc-analyst');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding create-app registers mobile apps for CI/CD bootstrap', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({ id: 'app-created', ...body });
  };

  try {
    await main([
      'shielding',
      'create-app',
      '--tenant-id',
      'tenant-a',
      '--name',
      'Payments Android',
      '--platform',
      'android',
      '--package-name',
      'com.acme.payments',
      '--project-id',
      'project-a',
      '--environment',
      'staging,prod'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/apps');
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.deepEqual(requests[0].body, {
      name: 'Payments Android',
      platform: 'android',
      packageName: 'com.acme.payments',
      projectId: 'project-a',
      environments: ['staging', 'prod']
    });
    assert.equal(JSON.parse(outputs[0]).id, 'app-created');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding create-policy creates release gate policies with repeated protection flags', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({ id: 'policy-created', version: 1, ...body });
  };

  try {
    await main([
      'shielding',
      'create-policy',
      '--tenant-id',
      'tenant-a',
      '--app-id',
      'app-a',
      '--name',
      'Production Shielding',
      '--mode',
      'block',
      '--required-protection',
      'anti_tamper',
      '--required-protection',
      'anti_debug,api_attestation',
      '--optional-protection',
      'threat_telemetry'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/policies');
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.deepEqual(requests[0].body, {
      name: 'Production Shielding',
      appId: 'app-a',
      mode: 'block',
      requiredProtections: ['anti_tamper', 'anti_debug', 'api_attestation'],
      optionalProtections: ['threat_telemetry']
    });
    assert.equal(JSON.parse(outputs[0]).id, 'policy-created');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding update-policy patches release gate protections without custom scripts', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({ id: 'policy-a', version: 2, ...body });
  };

  try {
    await main([
      'shielding',
      'update-policy',
      '--tenant-id',
      'tenant-a',
      '--policy-id',
      'policy-a',
      '--mode',
      'warn',
      '--required-protection',
      'anti_tamper,runtime_self_protection',
      '--optional-protection',
      'api_attestation'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/policies/policy-a');
    assert.equal(requests[0].method, 'PATCH');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.deepEqual(requests[0].body, {
      mode: 'warn',
      requiredProtections: ['anti_tamper', 'runtime_self_protection'],
      optionalProtections: ['api_attestation']
    });
    assert.equal(JSON.parse(outputs[0]).version, 2);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding update-policy requires at least one update field', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';

  try {
    await assert.rejects(
      main(['shielding', 'update-policy', '--policy-id', 'policy-a']),
      /Missing policy update fields/
    );
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
  }
});

test('shielding entitlements and usage read commercial plan counters', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    const url = String(input);
    if (url.endsWith('/v1/shielding/entitlements')) {
      return Response.json({ plan: 'shielding-business', enabled: true, platforms: ['android', 'ios'] });
    }
    return Response.json({ usage: { apps: 2, buildsMonthly: 7 }, limits: { apps: 10, buildsMonthly: 250 } });
  };

  try {
    await main(['shielding', 'entitlements', '--tenant-id', 'tenant-a']);
    await main(['shielding', 'usage', '--tenant-id', 'tenant-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/entitlements',
      'https://api.example.test/api/v1/shielding/usage'
    ]);
    assert.deepEqual(requests.map((request) => request.method), ['GET', 'GET']);
    assert.deepEqual(requests.map((request) => request.tenantId), ['tenant-a', 'tenant-a']);
    assert.equal(JSON.parse(outputs[0]).plan, 'shielding-business');
    assert.equal(JSON.parse(outputs[1]).usage.buildsMonthly, 7);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding get-app and get-artifact read sanitized inventory records', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    const url = String(input);
    if (url.endsWith('/v1/shielding/apps/app-a')) {
      return Response.json({ id: 'app-a', platform: 'android', packageName: 'com.acme.payments' });
    }
    return Response.json({ id: 'artifact-a', appId: 'app-a', artifactType: 'apk', originalSha256: 'a'.repeat(64) });
  };

  try {
    await main(['shielding', 'get-app', '--tenant-id', 'tenant-a', '--app-id', 'app-a']);
    await main(['shielding', 'get-artifact', '--tenant-id', 'tenant-a', '--artifact-id', 'artifact-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/apps/app-a',
      'https://api.example.test/api/v1/shielding/artifacts/artifact-a'
    ]);
    assert.deepEqual(requests.map((request) => request.method), ['GET', 'GET']);
    assert.deepEqual(requests.map((request) => request.tenantId), ['tenant-a', 'tenant-a']);
    assert.equal(JSON.parse(outputs[0]).packageName, 'com.acme.payments');
    assert.equal(JSON.parse(outputs[1]).artifactType, 'apk');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding list-builds get-build release-gate and list-evidence read audit state', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    const url = String(input);
    if (url.endsWith('/v1/shielding/builds/build-a/release-gate')) {
      return Response.json({ buildId: 'build-a', decision: 'warn', reasons: ['Policy warning'] });
    }
    if (url.endsWith('/v1/shielding/builds/build-a')) {
      return Response.json({ id: 'build-a', status: 'protected', engineVersion: 'shielding-engine-0.1.0' });
    }
    if (url.endsWith('/v1/shielding/evidence')) {
      return Response.json({ data: [{ id: 'evidence-a', buildId: 'build-a' }] });
    }
    return Response.json({ data: [{ id: 'build-a', status: 'protected' }] });
  };

  try {
    await main(['shielding', 'list-builds', '--tenant-id', 'tenant-a']);
    await main(['shielding', 'get-build', '--tenant-id', 'tenant-a', '--build-id', 'build-a']);
    await main(['shielding', 'release-gate', '--tenant-id', 'tenant-a', '--build-id', 'build-a']);
    await main(['shielding', 'list-evidence', '--tenant-id', 'tenant-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/builds',
      'https://api.example.test/api/v1/shielding/builds/build-a',
      'https://api.example.test/api/v1/shielding/builds/build-a/release-gate',
      'https://api.example.test/api/v1/shielding/evidence'
    ]);
    assert.deepEqual(requests.map((request) => request.method), ['GET', 'GET', 'GET', 'GET']);
    assert.deepEqual(requests.map((request) => request.tenantId), ['tenant-a', 'tenant-a', 'tenant-a', 'tenant-a']);
    assert.equal(JSON.parse(outputs[0]).data[0].status, 'protected');
    assert.equal(JSON.parse(outputs[1]).engineVersion, 'shielding-engine-0.1.0');
    assert.equal(JSON.parse(outputs[2]).decision, 'warn');
    assert.equal(JSON.parse(outputs[3]).data[0].id, 'evidence-a');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding download-url uses stage-aware artifact download endpoint', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    return Response.json({
      method: 'GET',
      downloadUrl: 'https://storage.example.test/signed-app.apk',
      buildId: 'build-a',
      artifactStage: 'signed',
      protectedSha256: 'b'.repeat(64),
      signedSha256: 'e'.repeat(64)
    });
  };

  try {
    await main(['shielding', 'download-url', '--tenant-id', 'tenant-a', '--build-id', 'build-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/builds/build-a/artifact/download-url'
    ]);
    assert.equal(requests[0].method, 'GET');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.equal(JSON.parse(outputs[0]).artifactStage, 'signed');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding evidence summary surfaces native readiness for auditors', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    return Response.json({
      id: 'evidence-a',
      buildId: 'build-a',
      releaseGateDecision: 'pass',
      protectedSha256: 'b'.repeat(64),
      evidenceFingerprint: `ssk-shielding-evidence-v1:${'c'.repeat(64)}`,
      runtimePackage: {
        nativeProbeManifestSha256: 'd'.repeat(64),
        nativeProbeBindingSha256: 'e'.repeat(64),
        nativeToolchain: { selected: 'emitter', strict: true, compilerId: 'securstack-native-emitter' },
        androidDexMergeStatus: 'secondary_dex_embedded',
        androidSecondaryDexSha256: 'f'.repeat(64),
        iosLaunchBridgeStatus: 'native_launch_bridge_applied',
        iosLaunchBindingSha256: '1'.repeat(64)
      },
      shieldingVerification: {
        status: 'passed',
        commercialReadiness: { status: 'ready', blockers: [] }
      },
      protectedArtifactUri: 's3://internal/protected.apk'
    });
  };

  try {
    await main(['shielding', 'evidence', '--build-id', 'build-a', '--format', 'summary', '--tenant-id', 'tenant-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/builds/build-a/evidence'
    ]);
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.match(outputs[0], /SecurStack Shielding evidence evidence-a/);
    assert.match(outputs[0], /Commercial readiness: ready · blockers 0/);
    assert.match(outputs[0], /Native probes: bound/);
    assert.match(outputs[0], /Native toolchain: emitter strict · securstack-native-emitter/);
    assert.match(outputs[0], /Android runtime: secondary_dex_embedded/);
    assert.match(outputs[0], /iOS runtime: native_launch_bridge_applied/);
    assert.doesNotMatch(outputs[0], /s3:\/\/internal/);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding evidence export summary unwraps auditor export payloads', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    return Response.json({
      product: 'SecurStack Shielding',
      exportVersion: 'shielding-evidence-export-v1',
      tenantId: 'tenant-a',
      buildId: 'build-export-a',
      canonicalPayloadHash: 'a'.repeat(64),
      evidenceFingerprint: `ssk-shielding-evidence-v1:${'a'.repeat(64)}`,
      evidence: {
        id: 'evidence-export-a',
        buildId: 'build-export-a',
        releaseGateDecision: 'warn',
        protectedSha256: 'b'.repeat(64),
        canonicalPayloadHash: 'a'.repeat(64),
        evidenceFingerprint: `ssk-shielding-evidence-v1:${'a'.repeat(64)}`,
        runtimePackage: {
          nativeProbeManifestSha256: 'd'.repeat(64),
          nativeProbeBindingSha256: 'e'.repeat(64),
          nativeToolchain: { selected: 'android_ndk', compilerId: 'clang' },
          androidDexMergeStatus: 'secondary_dex_embedded'
        },
        shieldingVerification: {
          status: 'passed',
          commercialReadiness: {
            status: 'not_ready',
            blockers: [{ id: 'storage', message: 'Storage encryption evidence missing' }]
          }
        },
        protectedArtifactUri: 's3://internal/protected.apk'
      }
    });
  };

  try {
    await main(['shielding', 'evidence', '--build-id', 'build-export-a', '--export', '--format', 'summary', '--tenant-id', 'tenant-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/builds/build-export-a/evidence/export'
    ]);
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.match(outputs[0], /SecurStack Shielding evidence evidence-export-a/);
    assert.match(outputs[0], /Build: build-export-a · gate warn · verification passed/);
    assert.match(outputs[0], /Canonical payload SHA-256: a{64}/);
    assert.match(outputs[0], /Commercial readiness: not_ready · blockers 1/);
    assert.match(outputs[0], /Readiness blockers: Storage encryption evidence missing/);
    assert.doesNotMatch(outputs[0], /s3:\/\/internal/);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding evidence summary can fail CI when protected artifact verification fails', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const previousExitCode = process.exitCode;
  const outputs = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  process.exitCode = undefined;
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async () => Response.json({
    id: 'evidence-failed',
    buildId: 'build-failed',
    releaseGateDecision: 'block',
    protectedSha256: 'b'.repeat(64),
    evidenceFingerprint: `ssk-shielding-evidence-v1:${'c'.repeat(64)}`,
    runtimePackage: {
      nativeProbeManifestSha256: 'd'.repeat(64),
      nativeProbeBindingSha256: 'e'.repeat(64),
      nativeToolchain: { selected: 'emitter', strict: true, compilerId: 'securstack-native-emitter' }
    },
    shieldingVerification: {
      status: 'failed',
      checks: [
        { id: 'native_probe_binding_identity_match', status: 'failed', message: 'Native probe binding identity does not match evidence identity' },
        { id: 'storage_uri_sanitized', status: 'passed' }
      ],
      commercialReadiness: { status: 'not_ready', blockers: [] }
    },
    protectedArtifactUri: 's3://internal/protected.apk'
  });

  try {
    await main([
      'shielding',
      'evidence',
      '--build-id',
      'build-failed',
      '--format',
      'summary',
      '--fail-on-verification',
      '--tenant-id',
      'tenant-a'
    ]);

    assert.equal(process.exitCode, 1);
    assert.match(outputs[0], /Build: build-failed · gate block · verification failed/);
    assert.match(outputs[0], /Verification failures: Native probe binding identity does not match evidence identity/);
    assert.doesNotMatch(outputs[0], /s3:\/\/internal/);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    process.exitCode = previousExitCode;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding signing-job requests customer signing handoff for protected builds', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({
      id: 'signing-customer-a',
      buildId: 'build-a',
      mode: body.mode,
      status: 'pending_customer'
    });
  };

  try {
    await main([
      'shielding',
      'signing-job',
      '--tenant-id',
      'tenant-a',
      '--build-id',
      'build-a',
      '--mode',
      'customer'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/builds/build-a/signing/jobs');
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.deepEqual(requests[0].body, { mode: 'customer' });
    assert.equal(JSON.parse(outputs[0]).status, 'pending_customer');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding signing-job requests managed signing with tenant-scoped references', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({
      id: 'signing-managed-a',
      buildId: 'build-a',
      mode: body.mode,
      status: 'completed',
      signingManifestHash: 'f'.repeat(64),
      auditTrail: [{
        action: 'signing.requested',
        managedSigningEvidence: {
          canonicalPayloadHash: 'e'.repeat(64),
          evidenceFingerprint: `ssk-shielding-evidence-v1:${'e'.repeat(64)}`,
          shieldingVerificationStatus: 'passed',
          commercialReadinessStatus: 'ready',
          commercialReadinessBlockers: []
        }
      }]
    });
  };

  try {
    await main([
      'shielding',
      'signing-job',
      '--tenant-id',
      'tenant-a',
      '--build-id',
      'build-a',
      '--mode',
      'managed',
      '--key-ref',
      'vault://tenant-a/mobile/android-release',
      '--certificate-ref',
      'vault://tenant-a/mobile/android-cert'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/builds/build-a/signing/jobs');
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.deepEqual(requests[0].body, {
      mode: 'managed',
      keyRef: 'vault://tenant-a/mobile/android-release',
      certificateRef: 'vault://tenant-a/mobile/android-cert'
    });
    const output = JSON.parse(outputs[0]);
    assert.equal(output.signingManifestHash, 'f'.repeat(64));
    assert.equal(output.auditTrail[0].managedSigningEvidence.commercialReadinessStatus, 'ready');
    assert.doesNotMatch(outputs[0], /vault:\/\/tenant-a\/mobile\/android-release/);
    assert.doesNotMatch(outputs[0], /s3:\/\//);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding signing-job refuses managed signing without a key reference', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';

  try {
    await assert.rejects(
      main(['shielding', 'signing-job', '--build-id', 'build-a', '--mode', 'managed']),
      /requires --key-ref/
    );
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
  }
});

test('shielding signing-job validates managed signing references before calling the API', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const fetchCalls = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  globalThis.fetch = async (...args) => {
    fetchCalls.push(args);
    return Response.json({});
  };

  try {
    await assert.rejects(
      main([
        'shielding',
        'signing-job',
        '--tenant-id',
        'tenant-a',
        '--build-id',
        'build-a',
        '--mode',
        'managed',
        '--key-ref',
        'private key material pasted here'
      ]),
      /not plaintext signing material/
    );

    await assert.rejects(
      main([
        'shielding',
        'signing-job',
        '--tenant-id',
        'tenant-a',
        '--build-id',
        'build-a',
        '--mode',
        'managed',
        '--key-ref',
        'file:///tmp/android.keystore'
      ]),
      /must use vault:\/\/, kms:\/\/ or hsm:\/\//
    );

    await assert.rejects(
      main([
        'shielding',
        'signing-job',
        '--tenant-id',
        'tenant-a',
        '--build-id',
        'build-a',
        '--mode',
        'managed',
        '--key-ref',
        'vault://tenant-b/mobile/android-release'
      ]),
      /must be scoped to tenant tenant-a/
    );

    assert.equal(fetchCalls.length, 0);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    delete globalThis.fetch;
  }
});

test('shielding signing-job rejects signing references in customer signing mode', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const fetchCalls = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  globalThis.fetch = async (...args) => {
    fetchCalls.push(args);
    return Response.json({});
  };

  try {
    await assert.rejects(
      main([
        'shielding',
        'signing-job',
        '--build-id',
        'build-a',
        '--mode',
        'customer',
        '--key-ref',
        'vault://tenant-a/mobile/android-release'
      ]),
      /must not include --key-ref or --certificate-ref/
    );
    assert.equal(fetchCalls.length, 0);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    delete globalThis.fetch;
  }
});

test('shielding list-signing-jobs and get-signing-job read sanitized signing records', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    const url = String(input);
    if (url.endsWith('/v1/shielding/signing/jobs/signing-a')) {
      return Response.json({
        id: 'signing-a',
        mode: 'managed',
        status: 'completed',
        signingManifestHash: 'f'.repeat(64),
        auditTrail: [{
          action: 'signing.requested',
          managedSigningEvidence: {
            canonicalPayloadHash: 'e'.repeat(64),
            evidenceFingerprint: `ssk-shielding-evidence-v1:${'e'.repeat(64)}`,
            shieldingVerificationStatus: 'passed',
            commercialReadinessStatus: 'ready',
            commercialReadinessBlockers: []
          }
        }]
      });
    }
    return Response.json({ data: [{ id: 'signing-a', mode: 'managed', status: 'completed' }] });
  };

  try {
    await main(['shielding', 'list-signing-jobs', '--tenant-id', 'tenant-a']);
    await main(['shielding', 'get-signing-job', '--tenant-id', 'tenant-a', '--signing-job-id', 'signing-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/signing/jobs',
      'https://api.example.test/api/v1/shielding/signing/jobs/signing-a'
    ]);
    assert.deepEqual(requests.map((request) => request.method), ['GET', 'GET']);
    assert.deepEqual(requests.map((request) => request.tenantId), ['tenant-a', 'tenant-a']);
    assert.equal(JSON.parse(outputs[0]).data[0].id, 'signing-a');
    const signingJob = JSON.parse(outputs[1]);
    assert.equal(signingJob.signingManifestHash, 'f'.repeat(64));
    assert.equal(signingJob.auditTrail[0].managedSigningEvidence.shieldingVerificationStatus, 'passed');
    assert.doesNotMatch(outputs[1], /vault:\/\//);
    assert.doesNotMatch(outputs[1], /s3:\/\//);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding create-integration configures sanitized webhook export destinations', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({
      id: 'integration-a',
      name: body.name,
      type: body.type,
      endpointUrl: body.endpointUrl,
      enabled: true,
      eventTypes: body.eventTypes,
      headers: body.headers,
      secretsConfigured: { bearerToken: Boolean(body.bearerToken), sharedSecret: Boolean(body.sharedSecret) }
    });
  };

  try {
    await main([
      'shielding',
      'create-integration',
      '--tenant-id',
      'tenant-a',
      '--name',
      'SOC webhook',
      '--type',
      'generic_webhook',
      '--endpoint-url',
      'https://soc.example.test/shielding',
      '--event-type',
      'runtime.threat,api.attestation',
      '--header',
      'X-Source: securstack',
      '--bearer-token',
      'secret-token',
      '--shared-secret',
      'webhook-secret'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/integrations');
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.deepEqual(requests[0].body, {
      name: 'SOC webhook',
      type: 'generic_webhook',
      endpointUrl: 'https://soc.example.test/shielding',
      eventTypes: ['runtime.threat', 'api.attestation'],
      headers: { 'X-Source': 'securstack' },
      bearerToken: 'secret-token',
      sharedSecret: 'webhook-secret'
    });
    const output = JSON.parse(outputs[0]);
    assert.deepEqual(output.secretsConfigured, { bearerToken: true, sharedSecret: true });
    assert.equal(JSON.stringify(output).includes('secret-token'), false);
    assert.equal(JSON.stringify(output).includes('webhook-secret'), false);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding update-integration and integration-deliveries operate SIEM export records', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    const url = String(input);
    if (url.endsWith('/v1/shielding/integrations/integration-a')) {
      return Response.json({ id: 'integration-a', enabled: body.enabled, eventTypes: body.eventTypes });
    }
    return Response.json({ data: [{ id: 'delivery-a', integrationId: 'integration-a', status: 'delivered' }] });
  };

  try {
    await main([
      'shielding',
      'update-integration',
      '--tenant-id',
      'tenant-a',
      '--integration-id',
      'integration-a',
      '--enabled',
      'false',
      '--event-type',
      'runtime.threat'
    ]);
    await main(['shielding', 'integration-deliveries', '--tenant-id', 'tenant-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/integrations/integration-a',
      'https://api.example.test/api/v1/shielding/integrations/deliveries'
    ]);
    assert.deepEqual(requests.map((request) => request.method), ['POST', 'GET']);
    assert.deepEqual(requests.map((request) => request.tenantId), ['tenant-a', 'tenant-a']);
    assert.deepEqual(requests[0].body, { enabled: false, eventTypes: ['runtime.threat'] });
    assert.equal(JSON.parse(outputs[0]).enabled, false);
    assert.equal(JSON.parse(outputs[1]).data[0].status, 'delivered');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding runtime-event sends sanitized runtime telemetry payloads', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({
      id: 'runtime-a',
      appId: body.appId,
      buildId: body.buildId,
      platform: body.platform,
      threatType: body.threatType,
      severity: body.severity,
      observedAt: body.observedAt,
      metadata: body.metadata,
      threatResolutionCode: 'SSK-RUNTIME1'
    });
  };

  try {
    await main([
      'shielding',
      'runtime-event',
      '--tenant-id',
      'tenant-a',
      '--app-id',
      'app-a',
      '--build-id',
      'build-a',
      '--platform',
      'android',
      '--threat-type',
      'frida',
      '--severity',
      'critical',
      '--observed-at',
      '2026-08-13T12:00:00.000Z',
      '--metadata-json',
      '{"deviceId":"device-a","sessionId":"session-a"}'
    ]);

    assert.equal(requests[0].url, 'https://api.example.test/api/v1/shielding/runtime/events');
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].tenantId, 'tenant-a');
    assert.equal(requests[0].body.tenantId, undefined);
    assert.deepEqual(requests[0].body, {
      appId: 'app-a',
      buildId: 'build-a',
      platform: 'android',
      threatType: 'frida_detected',
      severity: 'critical',
      observedAt: '2026-08-13T12:00:00.000Z',
      metadata: { deviceId: 'device-a', sessionId: 'session-a' }
    });
    assert.equal(JSON.parse(outputs[0]).threatResolutionCode, 'SSK-RUNTIME1');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding runtime-event rejects unsupported runtime threat types before calling the API', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  globalThis.fetch = async () => {
    throw new Error('fetch should not be called');
  };

  try {
    await assert.rejects(
      main([
        'shielding',
        'runtime-event',
        '--app-id',
        'app-a',
        '--platform',
        'android',
        '--threat-type',
        'frida-ish',
        '--severity',
        'critical'
      ]),
      /Unsupported Shielding runtime threat type: frida-ish/
    );
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    delete globalThis.fetch;
  }
});

test('shielding runtime-events and risk-summary read operational runtime posture', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id') });
    const url = String(input);
    if (url.endsWith('/v1/shielding/apps/app-a/risk-summary')) {
      return Response.json({ appId: 'app-a', score: 72, runtime: { critical: 1 }, attestation: { risky: 2 } });
    }
    return Response.json({ data: [{ id: 'runtime-a', threatType: 'frida', severity: 'critical' }] });
  };

  try {
    await main(['shielding', 'runtime-events', '--tenant-id', 'tenant-a']);
    await main(['shielding', 'risk-summary', '--tenant-id', 'tenant-a', '--app-id', 'app-a']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/runtime/events',
      'https://api.example.test/api/v1/shielding/apps/app-a/risk-summary'
    ]);
    assert.deepEqual(requests.map((request) => request.method), ['GET', 'GET']);
    assert.deepEqual(requests.map((request) => request.tenantId), ['tenant-a', 'tenant-a']);
    assert.equal(JSON.parse(outputs[0]).data[0].threatType, 'frida');
    assert.equal(JSON.parse(outputs[1]).score, 72);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding retention previews by default and executes only with explicit flag', async () => {
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const requests = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  globalThis.fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    requests.push({ url: String(input), method: init?.method, tenantId: headers.get('x-tenant-id'), body });
    return Response.json({
      dryRun: body.dryRun,
      candidates: { originalArtifacts: body.dryRun ? 3 : 0 },
      deleted: body.dryRun ? undefined : { originalArtifacts: 3 }
    });
  };

  try {
    await main(['shielding', 'retention', '--tenant-id', 'tenant-a']);
    await main(['shielding', 'retention', '--tenant-id', 'tenant-a', '--execute']);

    assert.deepEqual(requests.map((request) => request.url), [
      'https://api.example.test/api/v1/shielding/retention/run',
      'https://api.example.test/api/v1/shielding/retention/run'
    ]);
    assert.deepEqual(requests.map((request) => request.method), ['POST', 'POST']);
    assert.deepEqual(requests.map((request) => request.tenantId), ['tenant-a', 'tenant-a']);
    assert.deepEqual(requests.map((request) => request.body), [{ dryRun: true }, { dryRun: false }]);
    assert.equal(JSON.parse(outputs[0]).dryRun, true);
    assert.equal(JSON.parse(outputs[1]).dryRun, false);
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
  }
});

test('shielding upload-artifact prepares storage, uploads binary, and registers artifact', async () => {
  const root = mkdtempSync(join(tmpdir(), 'securstack-cli-shielding-'));
  const previousApiKey = process.env.SECURSTACK_API_KEY;
  const previousApiUrl = process.env.SECURSTACK_API_URL;
  const originalLog = console.log;
  const outputs = [];
  const calls = [];
  process.env.SECURSTACK_API_KEY = 'ssk_test_key';
  process.env.SECURSTACK_API_URL = 'https://api.example.test/api';
  console.log = (value) => outputs.push(value);
  const artifactPath = join(root, 'app.apk');
  writeFileSync(artifactPath, 'fake apk bytes');
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    calls.push({ url, method: init?.method, body: init?.body, tenantId: new Headers(init?.headers).get('x-tenant-id') });
    if (url.endsWith('/v1/shielding/apps/app-a/artifacts/upload-url')) {
      return Response.json({
        method: 'PUT',
        uploadUrl: 'https://storage.example.test/upload/app.apk',
        storageUri: 's3://securstack-artifacts/shielding/tenant-a/app-a/original/app.apk',
        headers: { 'content-type': 'application/vnd.android.package-archive' },
        expiresAt: '2026-08-11T10:00:00.000Z',
        expiresInSeconds: 300,
        maxSizeBytes: 1000
      });
    }
    if (url === 'https://storage.example.test/upload/app.apk') {
      for await (const _chunk of init?.body ?? []) {
        // Drain the upload stream before the temporary file is removed.
      }
      return new Response('', { status: 200 });
    }
    if (url.endsWith('/v1/shielding/apps/app-a/artifacts')) {
      return Response.json({ id: 'artifact-created', appId: 'app-a', artifactType: 'apk' });
    }
    return Response.json({}, { status: 404 });
  };

  try {
    await main(['shielding', 'upload-artifact', '--app-id', 'app-a', '--file', artifactPath, '--artifact-type', 'apk', '--tenant-id', 'tenant-a']);

    assert.deepEqual(calls.map((call) => call.method), ['POST', 'PUT', 'POST']);
    assert.equal(calls[0].tenantId, 'tenant-a');
    assert.equal(calls[2].tenantId, 'tenant-a');
    assert.equal(JSON.parse(outputs[0]).artifact.id, 'artifact-created');
  } finally {
    process.env.SECURSTACK_API_KEY = previousApiKey;
    process.env.SECURSTACK_API_URL = previousApiUrl;
    console.log = originalLog;
    delete globalThis.fetch;
    rmSync(root, { recursive: true, force: true });
  }
});

function tarIncludes(buffer, expectedName) {
  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) return false;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const fullName = prefix ? `${prefix}/${name}` : name;
    const sizeText = header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim();
    const size = Number.parseInt(sizeText || '0', 8);
    if (fullName === expectedName) return true;
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return false;
}

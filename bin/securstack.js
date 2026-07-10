#!/usr/bin/env node
import { createCipheriv, createHash, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, createPublicKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, createReadStream, createWriteStream, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { basename, join, relative, resolve } from 'node:path';
import { pipeline } from 'node:stream/promises';

export const defaultApiUrl = 'https://api.securstack.io/api';
const configDir = join(homedir(), '.securstack');
const configPath = join(configDir, 'config.json');
const defaultIgnoreDirs = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.turbo', '.cache', '.idea', '.vscode-test']);
const defaultIgnoreFiles = new Set(['.DS_Store', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock']);
const maxFileBytes = 512 * 1024;
const maxTotalBytes = 12 * 1024 * 1024;
const maxPackageBytes = 500 * 1024 * 1024;
const maxFiles = 5000;
const cryptoInfo = Buffer.from('securstack-local-repository-scan-v1');
const packageCryptoInfo = Buffer.from('securstack-local-repository-package-v1');

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message || String(error));
    process.exit(1);
  });
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...args] = argv;
  if (!command || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  if (command === 'login') {
    login(args);
    return;
  }
  if (command === 'logout') {
    logout();
    return;
  }
  if (command === 'scan') {
    await scan(args);
    return;
  }
  if (command === 'hooks') {
    await hooks(args);
    return;
  }
  if (command === 'policy') {
    await policy(args);
    return;
  }
  if (command === 'doctor') {
    await doctor();
    return;
  }
  if (command === 'config') {
    printConfig();
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

function printHelp() {
  console.log(`SecurStack CLI

Usage:
  securstack login --api-key <key> [--api-url <url>]
  securstack logout
  securstack scan [--path <dir>] [--format json|sarif] [--output <file>] [--engine secrets --engine iac] [--locale en-US|pt-BR] [--upload-mode auto|json|package] [--no-wait]
  securstack hooks install [--path <repo>] [--max-risk-score <score>] [--max-critical <n>] [--max-high <n>] [--max-medium <n>] [--max-low <n>]
  securstack hooks uninstall [--path <repo>]
  securstack hooks status [--path <repo>]
  securstack policy check --input <scan.json> [--max-risk-score <score>] [--max-critical <n>] [--max-high <n>] [--max-medium <n>] [--max-low <n>]
  securstack doctor
  securstack config

Environment:
  SECURSTACK_API_KEY
  SECURSTACK_API_URL
`);
}

function login(args) {
  const options = parseArgs(args);
  const apiKey = stringOption(options, 'api-key') || process.env.SECURSTACK_API_KEY;
  if (!apiKey) throw new Error('Missing API key. Use: securstack login --api-key <key>');

  const apiUrl = stripTrailingSlash(stringOption(options, 'api-url') || process.env.SECURSTACK_API_URL || defaultApiUrl);
  mkdirSync(configDir, { recursive: true, mode: 0o700 });
  writeFileSync(configPath, JSON.stringify({ apiUrl, apiKey }, null, 2), { mode: 0o600 });
  console.log(`SecurStack CLI configured for ${apiUrl}`);
}

function logout() {
  if (existsSync(configPath)) {
    rmSync(configPath);
  }
  console.log('SecurStack CLI credentials removed.');
}

async function scan(args) {
  const options = parseArgs(args);
  const config = readConfig();
  const workspace = resolve(stringOption(options, 'path') || process.cwd());
  const format = stringOption(options, 'format') || 'json';
  const outputPath = stringOption(options, 'output');
  const engines = arrayOption(options, 'engine');
  const locale = normalizeLocale(stringOption(options, 'locale') || process.env.SECURSTACK_LOCALE || 'en-US');
  const wait = !booleanOption(options, 'no-wait');
  const timeoutMs = numberOption(options, 'timeout-ms') ?? 300_000;
  const pollIntervalMs = numberOption(options, 'poll-interval-ms') ?? 2_500;
  const uploadMode = stringOption(options, 'upload-mode') || 'auto';
  if (!['auto', 'json', 'package'].includes(uploadMode)) throw new Error(`Unsupported upload mode: ${uploadMode}`);
  const files = collectFiles(workspace, {
    maxFileBytes: numberOption(options, 'max-file-bytes') ?? maxFileBytes,
    maxTotalBytes: numberOption(options, 'max-total-bytes') ?? maxTotalBytes,
    maxFiles: numberOption(options, 'max-files') ?? maxFiles
  });

  const usePackageUpload = uploadMode === 'package' || (uploadMode === 'auto' && files.truncated === true);
  if (!usePackageUpload && files.length === 0) throw new Error('No files eligible for scan.');

  const scanRequest = {
    repositoryName: basename(workspace),
    rootPath: workspace,
    locale,
    environment: stringOption(options, 'environment') || 'dev',
    engines: engines.length ? engines : ['secrets', 'repo_health', 'iac'],
    files
  };
  const queued = usePackageUpload
    ? await uploadLocalRepositoryPackage(config, workspace, scanRequest, {
      maxPackageBytes: numberOption(options, 'max-upload-bytes') ?? maxPackageBytes
    })
    : await uploadLocalRepositoryJson(config, scanRequest);
  const response = wait ? await waitForLocalScanResult(config, queued.scanId, { timeoutMs, pollIntervalMs }) : queued;

  if (format === 'sarif') {
    emitOutput(JSON.stringify(toSarif(response), null, 2), outputPath);
    return;
  }
  if (format !== 'json') throw new Error(`Unsupported format: ${format}`);
  emitOutput(JSON.stringify(response, null, 2), outputPath);
}

async function uploadLocalRepositoryJson(config, scanRequest) {
  const session = await postJson(`${config.apiUrl}/v1/scans/local-repository/sessions`, config.apiKey, {});
  const encryptedRequest = encryptLocalScanPayload(scanRequest, session);
  return postJson(`${config.apiUrl}/v1/scans/local-repository/encrypted`, config.apiKey, encryptedRequest);
}

async function uploadLocalRepositoryPackage(config, workspace, scanRequest, options) {
  const tempDir = mkdtempSync(join(tmpdir(), 'securstack-package-'));
  try {
    const upload = await postJson(`${config.apiUrl}/v1/scans/local-repository/package-uploads`, config.apiKey, {
      repositoryName: scanRequest.repositoryName,
      rootPath: scanRequest.rootPath,
      locale: scanRequest.locale,
      environment: scanRequest.environment,
      engines: scanRequest.engines
    });
    const archivePath = createPackageArchive(workspace, tempDir, options.maxPackageBytes);
    const encryptedPath = join(tempDir, 'repository.tar.gz.enc');
    const encrypted = await encryptPackageArchive(archivePath, encryptedPath, upload);
    const partCount = await uploadPackageParts(config, upload.uploadId, encryptedPath, upload.maxPartBytes);
    return postJson(`${config.apiUrl}/v1/scans/local-repository/package-uploads/${encodeURIComponent(upload.uploadId)}/complete`, config.apiKey, {
      partCount,
      encryptedSizeBytes: encrypted.encryptedSizeBytes,
      sha256Ciphertext: encrypted.sha256Ciphertext,
      nonceBase64: encrypted.nonceBase64,
      authTagBase64: encrypted.authTagBase64,
      clientPublicKeyBase64: encrypted.clientPublicKeyBase64,
      packageFormat: 'tar.gz'
    });
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

function createPackageArchive(workspace, tempDir, maxBytes) {
  const archivePath = join(tempDir, 'repository.tar.gz');
  const excludeArgs = [
    ...[...defaultIgnoreDirs].map((name) => `--exclude=${name}`),
    ...[...defaultIgnoreFiles].map((name) => `--exclude=${name}`),
    ...loadIgnoreRules(workspace).filter((rule) => !rule.includes('!')).map((rule) => `--exclude=${rule}`)
  ];
  const result = spawnSync('tar', ['-czf', archivePath, ...excludeArgs, '-C', workspace, '.'], {
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024
  });
  if (result.status !== 0) {
    throw new Error((result.stderr || 'Failed to package repository for scan').trim());
  }
  const sizeBytes = statSync(archivePath).size;
  if (sizeBytes > maxBytes) {
    throw new Error(`Repository package is too large (${sizeBytes} bytes). Current limit is ${maxBytes} bytes.`);
  }
  return archivePath;
}

async function encryptPackageArchive(archivePath, encryptedPath, session) {
  const { dataKey, clientPublicKeyBase64 } = deriveClientDataKey(session, packageCryptoInfo);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey, nonce);
  cipher.setAAD(packageCryptoInfo);
  await pipeline(createReadStream(archivePath), cipher, createWriteStream(encryptedPath, { mode: 0o600 }));
  return {
    encryptedSizeBytes: statSync(encryptedPath).size,
    sha256Ciphertext: await hashFile(encryptedPath),
    nonceBase64: nonce.toString('base64'),
    authTagBase64: cipher.getAuthTag().toString('base64'),
    clientPublicKeyBase64
  };
}

async function uploadPackageParts(config, uploadId, encryptedPath, maxPartBytes) {
  const partSize = Math.max(1, Math.min(Number(maxPartBytes) || (16 * 1024 * 1024), 16 * 1024 * 1024));
  let partNumber = 1;
  for await (const chunk of createReadStream(encryptedPath, { highWaterMark: partSize })) {
    await postBinary(
      `${config.apiUrl}/v1/scans/local-repository/package-uploads/${encodeURIComponent(uploadId)}/parts/${partNumber}`,
      config.apiKey,
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    );
    partNumber += 1;
  }
  return partNumber - 1;
}

async function waitForLocalScanResult(config, scanId, options) {
  if (!scanId) throw new Error('SecurStack API did not return a scanId.');
  const startedAt = Date.now();
  let lastStatus = 'queued';
  while (Date.now() - startedAt <= options.timeoutMs) {
    const result = await getJson(`${config.apiUrl}/v1/scans/local-repository/${encodeURIComponent(scanId)}/result`, config.apiKey);
    lastStatus = result.status || lastStatus;
    if (result.status === 'completed') return result;
    if (result.status === 'failed') {
      throw new Error(result.errorMessage || `SecurStack scan ${scanId} failed.`);
    }
    if (result.status === 'canceled') {
      throw new Error(`SecurStack scan ${scanId} was canceled.`);
    }
    await sleep(options.pollIntervalMs);
  }
  throw new Error(`SecurStack scan ${scanId} timed out while waiting for completion. Last status: ${lastStatus}.`);
}

async function hooks(args) {
  const [action, ...rest] = args;
  if (!action) throw new Error('Missing hooks action. Use: securstack hooks install|uninstall|status');
  const options = parseArgs(rest);
  const repo = resolve(stringOption(options, 'path') || process.cwd());

  if (action === 'install') {
    const result = installGitHook(repo, policyOptions(options), stringOption(options, 'command') || 'securstack');
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (action === 'uninstall') {
    const result = uninstallGitHook(repo);
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (action === 'status') {
    const result = gitHookStatus(repo);
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  throw new Error(`Unknown hooks action: ${action}`);
}

async function policy(args) {
  const [action, ...rest] = args;
  if (action !== 'check') throw new Error('Unknown policy action. Use: securstack policy check');
  const options = parseArgs(rest);
  const input = stringOption(options, 'input');
  if (!input) throw new Error('Missing --input <scan.json>');

  const scan = JSON.parse(readFileSync(resolve(input), 'utf8'));
  const result = evaluatePolicy(scan, policyOptions(options));
  console.log(JSON.stringify(result, null, 2));
  if (!result.allowed) process.exitCode = 1;
}

export function installGitHook(repo, policy, command = 'securstack') {
  const gitDir = resolve(repo, '.git');
  if (!existsSync(gitDir) || !statSync(gitDir).isDirectory()) {
    throw new Error(`Git repository not found at ${repo}`);
  }

  const hooksDir = join(gitDir, 'hooks');
  mkdirSync(hooksDir, { recursive: true });
  const hookPath = join(hooksDir, 'pre-commit');
  const existing = existsSync(hookPath) ? readFileSync(hookPath, 'utf8') : '#!/bin/sh\n';
  const next = replaceSecurStackHook(existing, renderHookBlock(command, policy));
  writeFileSync(hookPath, next, { mode: 0o755 });
  chmodSync(hookPath, 0o755);
  return { installed: true, hookPath, policy };
}

export function uninstallGitHook(repo) {
  const hookPath = join(resolve(repo), '.git', 'hooks', 'pre-commit');
  if (!existsSync(hookPath)) return { installed: false, hookPath };
  const existing = readFileSync(hookPath, 'utf8');
  const next = removeSecurStackHook(existing).trimEnd();
  if (next.trim()) {
    writeFileSync(hookPath, `${next}\n`, { mode: 0o755 });
    chmodSync(hookPath, 0o755);
  } else {
    rmSync(hookPath);
  }
  return { installed: false, hookPath };
}

export function gitHookStatus(repo) {
  const hookPath = join(resolve(repo), '.git', 'hooks', 'pre-commit');
  const content = existsSync(hookPath) ? readFileSync(hookPath, 'utf8') : '';
  return {
    installed: content.includes('# securstack hook begin'),
    hookPath
  };
}

export function evaluatePolicy(scan, policy) {
  const bySeverity = severityCounts(scan);
  const riskScore = readRiskScore(scan, bySeverity);
  const violations = [];
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    const limit = policy.maxSeverity[severity];
    if (limit !== undefined && (bySeverity[severity] ?? 0) > limit) {
      violations.push(`${severity}: ${(bySeverity[severity] ?? 0)} acima do limite ${limit}`);
    }
  }
  if (policy.maxRiskScore !== undefined && riskScore > policy.maxRiskScore) {
    violations.push(`riskScore ${riskScore.toFixed(1)} acima do limite ${policy.maxRiskScore.toFixed(1)}`);
  }

  return {
    allowed: violations.length === 0,
    riskScore,
    bySeverity,
    violations
  };
}

function policyOptions(options) {
  const maxSeverity = {};
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    const value = nonNegativeIntegerOption(options, `max-${severity}`);
    if (value !== undefined) maxSeverity[severity] = value;
  }

  const maxRiskScore = decimalOption(options, 'max-risk-score')
    ?? decimalOption(options, 'fail-on-score-above');

  return {
    maxRiskScore,
    maxSeverity
  };
}

function renderHookBlock(command, policy) {
  const policyArgs = [];
  if (policy.maxRiskScore !== undefined) policyArgs.push('--max-risk-score', String(policy.maxRiskScore));
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    if (policy.maxSeverity[severity] !== undefined) {
      policyArgs.push(`--max-${severity}`, String(policy.maxSeverity[severity]));
    }
  }
  const policyArgsText = policyArgs.map(shellQuote).join(' ');

  return `# securstack hook begin
echo "SecurStack: executando scan pre-commit..."
${command} scan --path . --format json --output .git/securstack-last-scan.json
${command} policy check --input .git/securstack-last-scan.json ${policyArgsText}
# securstack hook end`;
}

function replaceSecurStackHook(content, block) {
  const normalized = content.trimStart().startsWith('#!') ? content : `#!/bin/sh\n${content}`;
  const withoutExisting = removeSecurStackHook(normalized).trimEnd();
  return `${withoutExisting}\n\n${block}\n`;
}

function removeSecurStackHook(content) {
  return content.replace(/\n?# securstack hook begin[\s\S]*?# securstack hook end\n?/g, '\n');
}

function severityCounts(scan) {
  const bySeverity = scan?.summary?.bySeverity;
  if (bySeverity && typeof bySeverity === 'object') {
    return normalizeSeverityCounts(bySeverity);
  }
  const findings = Array.isArray(scan?.findings) ? scan.findings : [];
  return normalizeSeverityCounts(findings.reduce((acc, finding) => {
    const severity = String(finding?.severity || 'info').toLowerCase();
    acc[severity] = (acc[severity] ?? 0) + 1;
    return acc;
  }, {}));
}

function normalizeSeverityCounts(value) {
  const counts = {};
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    counts[severity] = Math.max(0, Number(value?.[severity] ?? 0));
  }
  return counts;
}

function readRiskScore(scan, bySeverity) {
  const value = Number(scan?.summary?.riskScore ?? scan?.riskScore);
  return Number.isFinite(value) ? value : calculateRiskScore(bySeverity);
}

export function calculateRiskScore(bySeverity) {
  const critical = Math.max(0, Number(bySeverity.critical ?? 0));
  const high = Math.max(0, Number(bySeverity.high ?? 0));
  const medium = Math.max(0, Number(bySeverity.medium ?? 0));
  const low = Math.max(0, Number(bySeverity.low ?? 0));
  const info = Math.max(0, Number(bySeverity.info ?? 0));
  const total = critical + high + medium + low + info;
  if (total <= 0) return 0;

  const weightedAverageSeverity = (
    critical * 10 +
    high * 7 +
    medium * 4 +
    low * 2 +
    info * 1
  ) / total;
  const volumeBoost = Math.min(2, Math.log10(total + 1) * 1.5);
  return Math.min(10, Math.max(0.1, Number((weightedAverageSeverity * 0.8 + volumeBoost).toFixed(1))));
}

export function encryptLocalScanPayload(scanRequest, session) {
  const { dataKey, clientPublicKeyBase64 } = deriveClientDataKey(session, cryptoInfo);

  return {
    scanSessionId: session.scanSessionId,
    keyAlgorithm: session.keyAlgorithm,
    contentAlgorithm: session.contentAlgorithm,
    clientPublicKeyBase64,
    repositoryName: scanRequest.repositoryName,
    rootPath: scanRequest.rootPath,
    locale: scanRequest.locale,
    environment: scanRequest.environment,
    engines: scanRequest.engines,
    files: scanRequest.files.map((file) => encryptLocalFile(dataKey, file))
  };
}

function deriveClientDataKey(session, info) {
  if (session.keyAlgorithm !== 'x25519-hkdf-sha256') throw new Error(`Unsupported scan key algorithm: ${session.keyAlgorithm}`);
  if (session.contentAlgorithm !== 'aes-256-gcm') throw new Error(`Unsupported scan content algorithm: ${session.contentAlgorithm}`);

  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const serverPublicKey = createPublicKey({
    key: Buffer.from(session.publicKeyBase64, 'base64'),
    format: 'der',
    type: 'spki'
  });
  const sharedSecret = diffieHellman({ privateKey, publicKey: serverPublicKey });
  return {
    dataKey: Buffer.from(hkdfSync('sha256', sharedSecret, session.scanSessionId, info, 32)),
    clientPublicKeyBase64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  };
}

function encryptLocalFile(dataKey, file) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey, nonce);
  cipher.setAAD(Buffer.from(file.path));
  const content = Buffer.from(file.contentBase64, 'base64');
  const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
  return {
    path: file.path,
    ciphertextBase64: ciphertext.toString('base64'),
    nonceBase64: nonce.toString('base64'),
    authTagBase64: cipher.getAuthTag().toString('base64'),
    sizeBytes: file.sizeBytes,
    sha256Plaintext: file.sha256
  };
}

async function doctor() {
  const config = readConfig();
  const healthUrl = `${config.apiUrl.replace(/\/api$/, '')}/health`;
  let apiReachable = false;
  try {
    const response = await fetch(healthUrl, { headers: { 'user-agent': 'securstack-cli/0.1.0' } });
    apiReachable = response.ok;
  } catch {
    apiReachable = false;
  }
  console.log(JSON.stringify({
    apiUrl: config.apiUrl,
    apiKeyConfigured: Boolean(config.apiKey),
    healthUrl,
    apiReachable
  }, null, 2));
}

function readConfig() {
  const envApiKey = process.env.SECURSTACK_API_KEY;
  const envApiUrl = process.env.SECURSTACK_API_URL;
  if (envApiKey || envApiUrl) {
    const stored = existsSync(configPath) ? JSON.parse(readFileSync(configPath, 'utf8')) : {};
    return {
      apiUrl: stripTrailingSlash(envApiUrl || stored.apiUrl || defaultApiUrl),
      apiKey: envApiKey || stored.apiKey
    };
  }
  if (!existsSync(configPath)) throw new Error('CLI is not configured. Run: securstack login --api-key <key>');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  if (!config.apiKey) throw new Error('Missing API key. Run: securstack login --api-key <key>');
  return { apiUrl: stripTrailingSlash(config.apiUrl || defaultApiUrl), apiKey: config.apiKey };
}

function printConfig() {
  const config = readConfig();
  console.log(JSON.stringify({ apiUrl: config.apiUrl, apiKeyConfigured: Boolean(config.apiKey) }, null, 2));
}

function normalizeLocale(value) {
  const normalized = String(value || '').trim().replace('_', '-');
  if (!normalized) return 'en-US';
  if (/^pt($|-)/i.test(normalized)) return 'pt-BR';
  if (/^en($|-)/i.test(normalized)) return 'en-US';
  const match = normalized.match(/^([a-z]{2,3})(?:-([a-z]{2}))?$/i);
  if (!match) return 'en-US';
  return match[2] ? `${match[1].toLowerCase()}-${match[2].toUpperCase()}` : match[1].toLowerCase();
}

export function collectFiles(root, limits = {}) {
  const ignoreRules = loadIgnoreRules(root);
  const files = [];
  let totalBytes = 0;
  const effectiveLimits = {
    maxFileBytes: limits.maxFileBytes ?? maxFileBytes,
    maxTotalBytes: limits.maxTotalBytes ?? maxTotalBytes,
    maxFiles: limits.maxFiles ?? maxFiles
  };

  function walk(dir) {
    if (files.truncated) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (files.truncated) return;
      const fullPath = join(dir, entry.name);
      const relPath = normalizePath(relative(root, fullPath));
      if (shouldIgnore(relPath, entry, ignoreRules)) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;

      const stat = statSync(fullPath);
      if (stat.size > effectiveLimits.maxFileBytes || stat.size === 0) continue;
      if (totalBytes + stat.size > effectiveLimits.maxTotalBytes || files.length >= effectiveLimits.maxFiles) {
        files.truncated = true;
        return;
      }

      const buffer = readFileSync(fullPath);
      if (looksBinary(buffer)) continue;
      totalBytes += stat.size;
      files.push({
        path: relPath,
        contentBase64: buffer.toString('base64'),
        sizeBytes: stat.size,
        sha256: createHash('sha256').update(buffer).digest('hex')
      });
    }
  }

  walk(root);
  return files;
}

export function loadIgnoreRules(root) {
  const rules = [];
  for (const file of ['.gitignore', '.securstackignore']) {
    const path = join(root, file);
    if (!existsSync(path)) continue;
    const lines = readFileSync(path, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue;
      rules.push(trimmed);
    }
  }
  return rules;
}

export function shouldIgnore(relPath, entry, rules) {
  const name = entry.name;
  if (entry.isDirectory() && defaultIgnoreDirs.has(name)) return true;
  if (entry.isFile() && defaultIgnoreFiles.has(name)) return true;
  return rules.some((rule) => matchesIgnoreRule(relPath, name, rule));
}

function matchesIgnoreRule(relPath, name, rule) {
  const normalized = normalizePath(rule).replace(/^\/+/, '');
  if (normalized.includes('*')) {
    const escaped = normalized.split('*').map(escapeRegex).join('.*');
    return new RegExp(`(^|/)${escaped}($|/)`).test(relPath);
  }
  if (normalized.endsWith('/')) return relPath === normalized.slice(0, -1) || relPath.startsWith(normalized);
  if (!normalized.includes('/')) return name === normalized || relPath.split('/').includes(normalized);
  return relPath === normalized || relPath.startsWith(`${normalized}/`);
}

export function looksBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  return sample.includes(0);
}

async function postJson(url, apiKey, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      'user-agent': 'securstack-cli/0.1.0'
    },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.message || data.error || `SecurStack API request failed with HTTP ${response.status}`);
  }
  return data;
}

async function postBinary(url, apiKey, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/octet-stream',
      'user-agent': 'securstack-cli/0.1.0'
    },
    body
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.message || data.error || `SecurStack API request failed with HTTP ${response.status}`);
  }
  return data;
}

async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return hash.digest('hex');
}

async function getJson(url, apiKey) {
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'user-agent': 'securstack-cli/0.1.0'
    }
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.message || data.error || `SecurStack API request failed with HTTP ${response.status}`);
  }
  return data;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function toSarif(scan) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'SecurStack', informationUri: 'https://securstack.io', rules: sarifRules(scan.findings || []) } },
      results: (scan.findings || []).map((finding) => ({
        ruleId: finding.ruleId,
        level: sarifLevel(finding.severity),
        message: { text: `${finding.title}. ${finding.recommendation}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.filePath },
            region: { startLine: finding.lineStart, endLine: finding.lineEnd || finding.lineStart }
          }
        }],
        fingerprints: { securstack: finding.fingerprint }
      }))
    }]
  };
}

function sarifRules(findings) {
  const seen = new Map();
  for (const finding of findings) {
    if (!seen.has(finding.ruleId)) {
      seen.set(finding.ruleId, {
        id: finding.ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: { text: finding.recommendation }
      });
    }
  }
  return [...seen.values()];
}

function sarifLevel(severity) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function parseArgs(args) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith('--')) throw new Error(`Unexpected argument: ${arg}`);
    const key = arg.slice(2);
    const value = args[index + 1]?.startsWith('--') || !args[index + 1] ? 'true' : args[++index];
    const values = options.get(key) || [];
    values.push(value);
    options.set(key, values);
  }
  return options;
}

function stringOption(options, key) {
  return options.get(key)?.at(-1);
}

function booleanOption(options, key) {
  const value = options.get(key)?.at(-1);
  if (value === undefined) return false;
  return value === 'true' || value === '1' || value === 'yes';
}

function numberOption(options, key) {
  const value = stringOption(options, key);
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`Invalid numeric option --${key}: ${value}`);
  return parsed;
}

function nonNegativeIntegerOption(options, key) {
  const value = stringOption(options, key);
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) throw new Error(`Invalid numeric option --${key}: ${value}`);
  return parsed;
}

function decimalOption(options, key) {
  const value = stringOption(options, key);
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`Invalid numeric option --${key}: ${value}`);
  return parsed;
}

function arrayOption(options, key) {
  return options.get(key) || [];
}

function stripTrailingSlash(value) {
  return String(value).replace(/\/+$/, '');
}

function normalizePath(value) {
  return value.split('\\').join('/');
}

function emitOutput(value, outputPath) {
  if (!outputPath) {
    console.log(value);
    return;
  }
  writeFileSync(resolve(outputPath), `${value}\n`, { mode: 0o600 });
}

function escapeRegex(value) {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

#!/usr/bin/env node
import { createCipheriv, createHash, createHmac, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, createPublicKey, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, createReadStream, createWriteStream, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { basename, join, relative, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { once } from 'node:events';
import { createGzip } from 'node:zlib';
import { canonicalApiAttestationProofString, runtimeThreatTypeSchema } from '@securstack/core/v1';

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
const shieldingRuntimeThreatAliases = new Map([
  ['root', 'root_detected'],
  ['jailbreak', 'jailbreak_detected'],
  ['hooking', 'hooking_detected'],
  ['frida', 'frida_detected'],
  ['debugger', 'debugger_detected'],
  ['tamper', 'tamper_detected'],
  ['repackaging', 'repackaging_detected'],
  ['emulator', 'emulator_detected'],
  ['simulator', 'simulator_detected'],
  ['bot', 'bot_detected'],
  ['replay', 'replay_detected'],
  ['api_attestation', 'api_attestation_invalid'],
  ['session_integrity', 'session_integrity_invalid']
]);
const shieldingRuntimeThreatTypes = new Set(runtimeThreatTypeSchema.options);

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
  if (command === 'shielding') {
    await shielding(args);
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
  securstack shielding create-app --name <name> --platform android|ios --package-name <package|bundle> [--project-id <id>] [--environment dev|staging|prod ...] [--tenant-id <id>]
  securstack shielding list-apps [--tenant-id <id>]
  securstack shielding get-app --app-id <id> [--tenant-id <id>]
  securstack shielding entitlements [--tenant-id <id>]
  securstack shielding usage [--tenant-id <id>]
  securstack shielding create-policy --name <name> --mode audit|warn|block --required-protection <type> ... [--optional-protection <type> ...] [--app-id <id>] [--tenant-id <id>]
  securstack shielding update-policy --policy-id <id> [--mode audit|warn|block] [--required-protection <type> ...] [--optional-protection <type> ...] [--tenant-id <id>]
  securstack shielding list-policies [--tenant-id <id>]
  securstack shielding upload-artifact --app-id <id> --file <apk|aab|ipa> --artifact-type apk|aab|ipa [--tenant-id <id>]
  securstack shielding get-artifact --artifact-id <id> [--tenant-id <id>]
  securstack shielding build --app-id <id> --artifact-id <id> --policy-id <id> [--environment prod] [--signing-mode customer|managed] [--idempotency-key <key>] [--async] [--wait] [--gate-check] [--tenant-id <id>]
  securstack shielding list-builds [--tenant-id <id>]
  securstack shielding get-build --build-id <id> [--tenant-id <id>]
  securstack shielding gate --build-id <id> [--tenant-id <id>]
  securstack shielding release-gate --build-id <id> [--tenant-id <id>]
  securstack shielding evidence --build-id <id> [--export] [--format json|summary] [--fail-on-verification] [--tenant-id <id>]
  securstack shielding list-evidence [--tenant-id <id>]
  securstack shielding signing-job --build-id <id> --mode customer|managed [--key-ref <ref>] [--certificate-ref <ref>] [--tenant-id <id>]
  securstack shielding list-signing-jobs [--tenant-id <id>]
  securstack shielding get-signing-job --signing-job-id <id> [--tenant-id <id>]
  securstack shielding create-integration --name <name> --type generic_webhook|splunk_hec --endpoint-url <https-url> [--event-type <type> ...] [--header "Name: value" ...] [--bearer-token <token>] [--shared-secret <secret>] [--tenant-id <id>]
  securstack shielding list-integrations [--tenant-id <id>]
  securstack shielding update-integration --integration-id <id> [--enabled true|false] [--endpoint-url <https-url>] [--event-type <type> ...] [--header "Name: value" ...] [--bearer-token <token>] [--shared-secret <secret>] [--tenant-id <id>]
  securstack shielding integration-deliveries [--tenant-id <id>]
  securstack shielding runtime-event --app-id <id> --platform android|ios --threat-type <type> --severity info|low|medium|high|critical [--build-id <id>] [--observed-at <iso>] [--metadata-json <json>] [--tenant-id <id>]
  securstack shielding runtime-events [--tenant-id <id>]
  securstack shielding risk-summary --app-id <id> [--tenant-id <id>]
  securstack shielding retention [--execute] [--tenant-id <id>]
  securstack shielding attest --app-id <id> --platform android|ios [--build-id <id>] [--endpoint <path>] [--protected-sha256 <sha256>] [--artifact-stage protected|signed] [--signed-sha256 <sha256>] [--evidence-fingerprint <fingerprint>] [--hmac-secret <secret>] [--tenant-id <id>]
  securstack shielding resolve-threat --code SSK-XXXXXXXX [--resolved-by <user>] [--resolution-note <text>] [--tenant-id <id>]
  securstack shielding download-url --build-id <id> [--tenant-id <id>]
  securstack shielding download --build-id <id> --output <file> [--tenant-id <id>]
  securstack hooks install [--path <repo>] [--max-risk-score <score>] [--max-critical <n>] [--max-high <n>] [--max-medium <n>] [--max-low <n>]
  securstack hooks uninstall [--path <repo>]
  securstack hooks status [--path <repo>]
  securstack policy check --input <scan.json> [--max-risk-score <score>] [--max-critical <n>] [--max-high <n>] [--max-medium <n>] [--max-low <n>]
  securstack doctor
  securstack config

Environment:
  SECURSTACK_API_KEY
  SECURSTACK_API_URL
  SECURSTACK_TENANT_ID
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
    const archivePath = await createPackageArchive(workspace, tempDir, options.maxPackageBytes);
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

export async function createPackageArchive(workspace, tempDir, maxBytes, options = {}) {
  const archivePath = join(tempDir, 'repository.tar.gz');
  if (options.forcePortable) {
    await createPortablePackageArchive(workspace, archivePath);
    assertPackageSize(archivePath, maxBytes);
    return archivePath;
  }

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
    if (result.error?.code === 'ENOENT') {
      await createPortablePackageArchive(workspace, archivePath);
      assertPackageSize(archivePath, maxBytes);
      return archivePath;
    }
    throw new Error((result.stderr || 'Failed to package repository for scan').trim());
  }
  assertPackageSize(archivePath, maxBytes);
  return archivePath;
}

function assertPackageSize(archivePath, maxBytes) {
  const sizeBytes = statSync(archivePath).size;
  if (sizeBytes > maxBytes) {
    throw new Error(`Repository package is too large (${sizeBytes} bytes). Current limit is ${maxBytes} bytes.`);
  }
}

async function createPortablePackageArchive(workspace, archivePath) {
  const gzip = createGzip();
  const output = createWriteStream(archivePath, { mode: 0o600 });
  gzip.pipe(output);

  try {
    for (const filePath of collectPackageFilePaths(workspace)) {
      const stat = statSync(filePath);
      const relPath = normalizePath(relative(workspace, filePath));
      await writeTarHeader(gzip, relPath, stat.size, stat.mode, stat.mtime);
      await pipeline(createReadStream(filePath), gzip, { end: false });
      await writeTarPadding(gzip, stat.size);
    }
    await writeStreamChunk(gzip, Buffer.alloc(1024));
    gzip.end();
    await once(output, 'finish');
  } catch (error) {
    gzip.destroy(error);
    output.destroy(error);
    throw error;
  }
}

function collectPackageFilePaths(root) {
  const ignoreRules = loadIgnoreRules(root);
  const files = [];

  function walk(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name);
      const relPath = normalizePath(relative(root, fullPath));
      if (shouldIgnore(relPath, entry, ignoreRules)) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (entry.isFile()) files.push(fullPath);
    }
  }

  walk(root);
  return files;
}

async function writeTarHeader(stream, name, size, mode, mtime) {
  const header = Buffer.alloc(512, 0);
  const { fileName, prefix } = splitTarName(name);
  writeTarString(header, fileName, 0, 100);
  writeTarOctal(header, mode & 0o777, 100, 8);
  writeTarOctal(header, 0, 108, 8);
  writeTarOctal(header, 0, 116, 8);
  writeTarOctal(header, size, 124, 12);
  writeTarOctal(header, Math.floor(mtime.getTime() / 1000), 136, 12);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  writeTarString(header, 'ustar', 257, 6);
  writeTarString(header, '00', 263, 2);
  writeTarString(header, 'securstack', 265, 32);
  writeTarString(header, 'securstack', 297, 32);
  writeTarString(header, prefix, 345, 155);

  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeTarChecksum(header, checksum);
  await writeStreamChunk(stream, header);
}

function splitTarName(name) {
  const normalized = normalizePath(name).replace(/^\/+/, '');
  if (Buffer.byteLength(normalized) <= 100) return { fileName: normalized, prefix: '' };

  const parts = normalized.split('/');
  let fileName = parts.pop() || '';
  let prefix = parts.join('/');
  while ((Buffer.byteLength(fileName) > 100 || Buffer.byteLength(prefix) > 155) && parts.length) {
    fileName = `${parts.pop()}/${fileName}`;
    prefix = parts.join('/');
  }
  if (Buffer.byteLength(fileName) > 100 || Buffer.byteLength(prefix) > 155) {
    throw new Error(`Path is too long for portable tar archive: ${normalized}`);
  }
  return { fileName, prefix };
}

function writeTarString(buffer, value, offset, length) {
  buffer.write(String(value).slice(0, length), offset, length, 'utf8');
}

function writeTarOctal(buffer, value, offset, length) {
  const text = Math.max(0, Number(value) || 0).toString(8).padStart(length - 1, '0');
  buffer.write(`${text}\0`.slice(-length), offset, length, 'ascii');
}

function writeTarChecksum(buffer, value) {
  const text = value.toString(8).padStart(6, '0');
  buffer.write(`${text}\0 `, 148, 8, 'ascii');
}

async function writeTarPadding(stream, size) {
  const padding = (512 - (size % 512)) % 512;
  if (padding > 0) await writeStreamChunk(stream, Buffer.alloc(padding));
}

async function writeStreamChunk(stream, chunk) {
  if (!stream.write(chunk)) await once(stream, 'drain');
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
    const result = installGitHook(repo, policyOptions(options), stringOption(options, 'command') || defaultHookCommand());
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

async function shielding(args) {
  const [action, ...rest] = args;
  if (!action) throw new Error('Missing shielding action. Use: securstack shielding create-app|list-apps|get-app|entitlements|usage|create-policy|update-policy|list-policies|upload-artifact|get-artifact|build|list-builds|get-build|gate|release-gate|evidence|list-evidence|signing-job|list-signing-jobs|get-signing-job|create-integration|list-integrations|update-integration|integration-deliveries|runtime-event|runtime-events|risk-summary|retention|attest|resolve-threat|download-url|download');
  const options = parseArgs(rest);
  const config = readConfig();
  const tenantId = stringOption(options, 'tenant-id') || process.env.SECURSTACK_TENANT_ID;

  if (action === 'create-app') {
    const result = await createShieldingApp(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'list-apps') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/apps`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'get-app') {
    const appId = requiredStringOption(options, 'app-id');
    const result = await getJson(`${config.apiUrl}/v1/shielding/apps/${encodeURIComponent(appId)}`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'entitlements') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/entitlements`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'usage') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/usage`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'create-policy') {
    const result = await createShieldingPolicy(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'update-policy') {
    const result = await updateShieldingPolicy(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'list-policies') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/policies`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'upload-artifact') {
    const result = await uploadShieldingArtifact(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'get-artifact') {
    const artifactId = requiredStringOption(options, 'artifact-id');
    const result = await getJson(`${config.apiUrl}/v1/shielding/artifacts/${encodeURIComponent(artifactId)}`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'build') {
    let result = await createShieldingBuild(config, options, tenantId);
    if (booleanOption(options, 'wait')) {
      const buildId = extractId(result.build ?? result);
      if (!buildId) throw new Error('SecurStack API did not return a Shielding build id.');
      const completedBuild = await waitForShieldingBuild(config, buildId, tenantId, {
        timeoutMs: numberOption(options, 'timeout-ms') ?? 600_000,
        pollIntervalMs: numberOption(options, 'poll-interval-ms') ?? 2_500
      });
      result = { ...result, build: completedBuild };
    }
    if (booleanOption(options, 'gate-check')) {
      const buildId = extractId(result.build ?? result);
      if (!buildId) throw new Error('SecurStack API did not return a Shielding build id.');
      const status = result.build?.status ?? result.status;
      if (['pending', 'processing'].includes(status)) {
        throw new Error('Shielding build is not complete. Use --wait with --async before --gate-check.');
      }
      const gate = await checkShieldingReleaseGate(config, buildId, tenantId);
      emitShieldingJson({ ...result, releaseGateCheck: gate }, options);
      if (gate.exitCode === 1) process.exitCode = 1;
      return;
    }
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'list-builds') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/builds`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'get-build') {
    const buildId = requiredStringOption(options, 'build-id');
    const result = await getJson(`${config.apiUrl}/v1/shielding/builds/${encodeURIComponent(buildId)}`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'gate') {
    const buildId = requiredStringOption(options, 'build-id');
    const gate = await checkShieldingReleaseGate(config, buildId, tenantId);
    emitShieldingJson(gate, options);
    if (gate.exitCode === 1) process.exitCode = 1;
    return;
  }

  if (action === 'release-gate') {
    const buildId = requiredStringOption(options, 'build-id');
    const releaseGate = await getJson(`${config.apiUrl}/v1/shielding/builds/${encodeURIComponent(buildId)}/release-gate`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(releaseGate, options);
    return;
  }

  if (action === 'evidence') {
    const buildId = requiredStringOption(options, 'build-id');
    const suffix = booleanOption(options, 'export') ? 'evidence/export' : 'evidence';
    const evidence = await getJson(`${config.apiUrl}/v1/shielding/builds/${encodeURIComponent(buildId)}/${suffix}`, config.apiKey, tenantHeaders(tenantId));
    const verificationStatus = shieldingEvidenceVerificationStatus(evidence);
    if ((stringOption(options, 'format') || 'json') === 'summary') {
      emitShieldingEvidenceSummary(evidence, options);
      if (booleanOption(options, 'fail-on-verification') && verificationStatus !== 'passed') process.exitCode = 1;
      return;
    }
    emitShieldingJson(evidence, options);
    if (booleanOption(options, 'fail-on-verification') && verificationStatus !== 'passed') process.exitCode = 1;
    return;
  }

  if (action === 'list-evidence') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/evidence`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'signing-job') {
    const result = await createShieldingSigningJob(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'list-signing-jobs') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/signing/jobs`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'get-signing-job') {
    const signingJobId = requiredStringOption(options, 'signing-job-id');
    const result = await getJson(`${config.apiUrl}/v1/shielding/signing/jobs/${encodeURIComponent(signingJobId)}`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'create-integration') {
    const result = await createShieldingIntegration(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'list-integrations') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/integrations`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'update-integration') {
    const result = await updateShieldingIntegration(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'integration-deliveries') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/integrations/deliveries`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'runtime-event') {
    const event = await createShieldingRuntimeEvent(config, options, tenantId);
    emitShieldingJson(event, options);
    return;
  }

  if (action === 'runtime-events') {
    const result = await getJson(`${config.apiUrl}/v1/shielding/runtime/events`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'risk-summary') {
    const appId = requiredStringOption(options, 'app-id');
    const result = await getJson(`${config.apiUrl}/v1/shielding/apps/${encodeURIComponent(appId)}/risk-summary`, config.apiKey, tenantHeaders(tenantId));
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'retention') {
    const result = await runShieldingRetention(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'attest') {
    const attestation = await createShieldingAttestation(config, options, tenantId);
    emitShieldingJson(attestation, options);
    if (attestation.decision === 'block') process.exitCode = 1;
    return;
  }

  if (action === 'resolve-threat') {
    const result = await resolveShieldingThreat(config, options, tenantId);
    emitShieldingJson(result, options);
    return;
  }

  if (action === 'download-url') {
    const buildId = requiredStringOption(options, 'build-id');
    const download = await shieldingDownloadUrl(config, buildId, tenantId);
    emitShieldingJson(download, options);
    return;
  }

  if (action === 'download') {
    const buildId = requiredStringOption(options, 'build-id');
    const outputPath = requiredStringOption(options, 'output');
    const download = await shieldingDownloadUrl(config, buildId, tenantId);
    await downloadFile(download.downloadUrl, outputPath);
    emitShieldingJson({
      buildId,
      artifactStage: download.artifactStage,
      outputPath: resolve(outputPath),
      protectedSha256: download.protectedSha256,
      signedSha256: download.signedSha256
    }, options);
    return;
  }

  throw new Error(`Unknown shielding action: ${action}`);
}

export async function createShieldingApp(config, options, tenantId) {
  const name = requiredStringOption(options, 'name');
  const platform = requiredStringOption(options, 'platform');
  const packageName = requiredStringOption(options, 'package-name');
  const environments = shieldingListOption(options, 'environment', ['staging']);
  if (!['android', 'ios'].includes(platform)) throw new Error(`Unsupported Shielding platform: ${platform}`);
  for (const environment of environments) {
    if (!['dev', 'staging', 'prod'].includes(environment)) throw new Error(`Unsupported Shielding environment: ${environment}`);
  }
  return postJson(`${config.apiUrl}/v1/shielding/apps`, config.apiKey, compactObject({
    name,
    platform,
    packageName,
    projectId: stringOption(options, 'project-id'),
    environments
  }), tenantHeaders(tenantId));
}

export async function createShieldingPolicy(config, options, tenantId) {
  const name = requiredStringOption(options, 'name');
  const mode = stringOption(options, 'mode') || 'block';
  const requiredProtections = shieldingListOption(options, 'required-protection');
  const optionalProtections = shieldingListOption(options, 'optional-protection');
  if (!['audit', 'warn', 'block'].includes(mode)) throw new Error(`Unsupported Shielding policy mode: ${mode}`);
  if (requiredProtections.length === 0) throw new Error('Missing --required-protection <type>');
  return postJson(`${config.apiUrl}/v1/shielding/policies`, config.apiKey, compactObject({
    name,
    appId: stringOption(options, 'app-id'),
    mode,
    requiredProtections,
    optionalProtections: optionalProtections.length > 0 ? optionalProtections : undefined
  }), tenantHeaders(tenantId));
}

export async function updateShieldingPolicy(config, options, tenantId) {
  const policyId = requiredStringOption(options, 'policy-id');
  const mode = stringOption(options, 'mode');
  const requiredProtections = options.has('required-protection') ? shieldingListOption(options, 'required-protection') : undefined;
  const optionalProtections = options.has('optional-protection') ? shieldingListOption(options, 'optional-protection') : undefined;
  if (mode && !['audit', 'warn', 'block'].includes(mode)) throw new Error(`Unsupported Shielding policy mode: ${mode}`);
  if (!mode && requiredProtections === undefined && optionalProtections === undefined) {
    throw new Error('Missing policy update fields. Use --mode, --required-protection or --optional-protection.');
  }
  return patchJson(`${config.apiUrl}/v1/shielding/policies/${encodeURIComponent(policyId)}`, config.apiKey, compactObject({
    mode,
    requiredProtections,
    optionalProtections
  }), tenantHeaders(tenantId));
}

export async function uploadShieldingArtifact(config, options, tenantId) {
  const appId = requiredStringOption(options, 'app-id');
  const filePath = resolve(requiredStringOption(options, 'file'));
  const artifactType = requiredStringOption(options, 'artifact-type');
  if (!['apk', 'aab', 'ipa'].includes(artifactType)) throw new Error(`Unsupported Shielding artifact type: ${artifactType}`);
  if (!existsSync(filePath) || !statSync(filePath).isFile()) throw new Error(`Shielding artifact not found: ${filePath}`);
  const originalSizeBytes = statSync(filePath).size;
  if (originalSizeBytes <= 0) throw new Error(`Shielding artifact is empty: ${filePath}`);
  const originalFileName = stringOption(options, 'file-name') || basename(filePath);
  const originalSha256 = await hashFile(filePath);
  const upload = await postJson(`${config.apiUrl}/v1/shielding/apps/${encodeURIComponent(appId)}/artifacts/upload-url`, config.apiKey, {
    artifactType,
    originalFileName,
    originalSizeBytes,
    contentType: contentTypeForShieldingArtifact(artifactType)
  }, tenantHeaders(tenantId));
  await putBinary(upload.uploadUrl, createReadStream(filePath), upload.headers ?? {});
  const artifact = await postJson(`${config.apiUrl}/v1/shielding/apps/${encodeURIComponent(appId)}/artifacts`, config.apiKey, {
    artifactType,
    originalFileName,
    originalSha256,
    originalSizeBytes,
    storageUri: upload.storageUri,
    versionName: stringOption(options, 'version-name'),
    versionCode: stringOption(options, 'version-code'),
    metadata: {
      uploadedBy: 'securstack-cli',
      sourcePath: normalizePath(filePath)
    }
  }, tenantHeaders(tenantId));
  return { upload, artifact };
}

export async function createShieldingBuild(config, options, tenantId) {
  const appId = requiredStringOption(options, 'app-id');
  const artifactId = requiredStringOption(options, 'artifact-id');
  const policyId = requiredStringOption(options, 'policy-id');
  const environment = stringOption(options, 'environment') || 'prod';
  const signingMode = stringOption(options, 'signing-mode') || 'customer';
  if (!['dev', 'staging', 'prod'].includes(environment)) throw new Error(`Unsupported Shielding environment: ${environment}`);
  if (!['customer', 'managed'].includes(signingMode)) throw new Error(`Unsupported Shielding signing mode: ${signingMode}`);
  return postJson(`${config.apiUrl}/v1/shielding/builds`, config.apiKey, {
    appId,
    artifactId,
    policyId,
    environment,
    signingMode,
    idempotencyKey: stringOption(options, 'idempotency-key'),
    asyncMode: booleanOption(options, 'async') || undefined
  }, tenantHeaders(tenantId));
}

export async function createShieldingSigningJob(config, options, tenantId) {
  const buildId = requiredStringOption(options, 'build-id');
  const mode = stringOption(options, 'mode') || 'customer';
  if (!['customer', 'managed'].includes(mode)) throw new Error(`Unsupported Shielding signing job mode: ${mode}`);
  const keyRef = stringOption(options, 'key-ref');
  const certificateRef = stringOption(options, 'certificate-ref');
  if (mode === 'customer' && (keyRef || certificateRef)) {
    throw new Error('Customer Shielding signing must not include --key-ref or --certificate-ref. Sign the protected artifact in your own pipeline.');
  }
  if (mode === 'managed' && !keyRef) throw new Error('Managed Shielding signing requires --key-ref <ref>');
  if (mode === 'managed') {
    validateManagedSigningReference(keyRef, 'key-ref', tenantId);
    if (certificateRef) validateManagedSigningReference(certificateRef, 'certificate-ref', tenantId);
  }
  return postJson(`${config.apiUrl}/v1/shielding/builds/${encodeURIComponent(buildId)}/signing/jobs`, config.apiKey, compactObject({
    mode,
    keyRef,
    certificateRef
  }), tenantHeaders(tenantId));
}

function validateManagedSigningReference(value, field, tenantId) {
  const reference = String(value || '').trim();
  const lowercase = reference.toLowerCase();
  const plaintextSignals = [
    '-----begin',
    'private key',
    'keystore=',
    'keystorepassword',
    'provisioning profile',
    '<key>application-identifier</key>',
    'p12:',
    'pkcs12'
  ];
  if (plaintextSignals.some((signal) => lowercase.includes(signal))) {
    throw new Error(`Managed Shielding signing --${field} must be a Vault, KMS or HSM reference, not plaintext signing material.`);
  }
  const match = /^(vault|kms|hsm):\/\/([^/\s]+)\/[^\s]+$/i.exec(reference);
  if (!match) {
    throw new Error(`Managed Shielding signing --${field} must use vault://, kms:// or hsm:// tenant-scoped references.`);
  }
  if (tenantId && match[2] !== tenantId) {
    throw new Error(`Managed Shielding signing --${field} must be scoped to tenant ${tenantId}.`);
  }
}

export async function createShieldingIntegration(config, options, tenantId) {
  const name = requiredStringOption(options, 'name');
  const type = requiredStringOption(options, 'type');
  const endpointUrl = requiredStringOption(options, 'endpoint-url');
  if (!['generic_webhook', 'splunk_hec'].includes(type)) throw new Error(`Unsupported Shielding integration type: ${type}`);
  return postJson(`${config.apiUrl}/v1/shielding/integrations`, config.apiKey, compactObject({
    name,
    type,
    endpointUrl,
    eventTypes: shieldingListOption(options, 'event-type'),
    headers: shieldingHeaderObject(options),
    bearerToken: stringOption(options, 'bearer-token'),
    sharedSecret: stringOption(options, 'shared-secret')
  }), tenantHeaders(tenantId));
}

export async function updateShieldingIntegration(config, options, tenantId) {
  const integrationId = requiredStringOption(options, 'integration-id');
  return postJson(`${config.apiUrl}/v1/shielding/integrations/${encodeURIComponent(integrationId)}`, config.apiKey, compactObject({
    enabled: options.has('enabled') ? booleanOption(options, 'enabled') : undefined,
    endpointUrl: stringOption(options, 'endpoint-url'),
    eventTypes: options.has('event-type') ? shieldingListOption(options, 'event-type') : undefined,
    headers: options.has('header') ? shieldingHeaderObject(options) : undefined,
    bearerToken: stringOption(options, 'bearer-token'),
    sharedSecret: stringOption(options, 'shared-secret')
  }), tenantHeaders(tenantId));
}

export async function createShieldingRuntimeEvent(config, options, tenantId) {
  const appId = requiredStringOption(options, 'app-id');
  const platform = requiredStringOption(options, 'platform');
  const threatType = normalizeShieldingRuntimeThreatType(requiredStringOption(options, 'threat-type'));
  const severity = requiredStringOption(options, 'severity');
  if (!['android', 'ios'].includes(platform)) throw new Error(`Unsupported Shielding runtime platform: ${platform}`);
  if (!['info', 'low', 'medium', 'high', 'critical'].includes(severity)) throw new Error(`Unsupported Shielding runtime severity: ${severity}`);
  return postJson(`${config.apiUrl}/v1/shielding/runtime/events`, config.apiKey, compactObject({
    appId,
    buildId: stringOption(options, 'build-id'),
    platform,
    threatType,
    severity,
    observedAt: stringOption(options, 'observed-at') || new Date().toISOString(),
    metadata: jsonObjectOption(options, 'metadata-json')
  }), tenantHeaders(tenantId));
}

function normalizeShieldingRuntimeThreatType(value) {
  const normalized = String(value).trim().toLowerCase().replace(/[-\s]+/g, '_');
  const threatType = shieldingRuntimeThreatAliases.get(normalized) ?? normalized;
  if (!shieldingRuntimeThreatTypes.has(threatType)) {
    throw new Error(`Unsupported Shielding runtime threat type: ${value}. Use one of: ${runtimeThreatTypeSchema.options.join(', ')}`);
  }
  return threatType;
}

export async function runShieldingRetention(config, options, tenantId) {
  return postJson(`${config.apiUrl}/v1/shielding/retention/run`, config.apiKey, {
    dryRun: !booleanOption(options, 'execute')
  }, tenantHeaders(tenantId));
}

export async function checkShieldingReleaseGate(config, buildId, tenantId) {
  return getJson(`${config.apiUrl}/v1/shielding/builds/${encodeURIComponent(buildId)}/release-gate/check`, config.apiKey, tenantHeaders(tenantId));
}

export async function waitForShieldingBuild(config, buildId, tenantId, options) {
  const startedAt = Date.now();
  let lastStatus = 'unknown';
  while (Date.now() - startedAt <= options.timeoutMs) {
    const build = await getJson(`${config.apiUrl}/v1/shielding/builds/${encodeURIComponent(buildId)}`, config.apiKey, tenantHeaders(tenantId));
    lastStatus = build.status || lastStatus;
    if (['protected', 'signed', 'released'].includes(build.status)) return build;
    if (['failed', 'blocked'].includes(build.status)) {
      throw new Error(build.failureReason || `SecurStack Shielding build ${buildId} failed with status ${build.status}.`);
    }
    await sleep(options.pollIntervalMs);
  }
  throw new Error(`SecurStack Shielding build ${buildId} timed out while waiting for completion. Last status: ${lastStatus}.`);
}

export async function createShieldingAttestation(config, options, tenantId) {
  const appId = requiredStringOption(options, 'app-id');
  const platform = requiredStringOption(options, 'platform');
  if (!['android', 'ios'].includes(platform)) throw new Error(`Unsupported Shielding attestation platform: ${platform}`);
  const timestamp = stringOption(options, 'timestamp') || new Date().toISOString();
  const nonce = stringOption(options, 'nonce') || randomUUID();
  const sessionRisk = decimalOption(options, 'session-risk') ?? 0;
  if (nonce.length < 8 || nonce.length > 256) throw new Error('Shielding attestation nonce must be between 8 and 256 characters.');
  if (sessionRisk < 0 || sessionRisk > 10) throw new Error('Shielding attestation session risk must be between 0 and 10.');
  const signatureVersion = 'ssk-attestation-hmac-v1';
  const keyId = stringOption(options, 'key-id') || (tenantId ? `${tenantId}-${appId}` : appId);
  const buildId = stringOption(options, 'build-id');
  const signedSha256 = stringOption(options, 'signed-sha256');
  const artifactStage = stringOption(options, 'artifact-stage') || (signedSha256 ? 'signed' : undefined);
  if (artifactStage && !['protected', 'signed'].includes(artifactStage)) {
    throw new Error('Shielding attestation artifact stage must be protected or signed.');
  }
  if ((artifactStage === 'signed' || signedSha256) && !buildId) {
    throw new Error('Shielding attestation signed artifact identity requires --build-id.');
  }
  if (artifactStage === 'signed' && !signedSha256) {
    throw new Error('Shielding attestation signed artifact identity requires --signed-sha256.');
  }
  if (signedSha256 && artifactStage === 'protected') {
    throw new Error('Shielding attestation --signed-sha256 requires --artifact-stage signed.');
  }
  const payload = {
    appId,
    buildId,
    platform,
    endpoint: stringOption(options, 'endpoint'),
    protectedSha256: stringOption(options, 'protected-sha256'),
    artifactStage,
    signedSha256,
    evidenceFingerprint: stringOption(options, 'evidence-fingerprint'),
    nonce,
    timestamp,
    sessionRisk,
    decision: stringOption(options, 'decision') || 'observe',
    signatureVersion,
    keyId
  };
  const secret = stringOption(options, 'hmac-secret') || process.env.SHIELDING_ATTESTATION_HMAC_SECRET;
  if (secret) {
    payload.signature = `sha256=${createHmac('sha256', secret)
      .update(canonicalApiAttestationProofString(tenantId, payload))
      .digest('hex')}`;
  }
  return postJson(`${config.apiUrl}/v1/shielding/attestation/events`, config.apiKey, compactObject(payload), tenantHeaders(tenantId));
}

export async function resolveShieldingThreat(config, options, tenantId) {
  const code = requiredStringOption(options, 'code');
  if (!/^SSK-[A-Z0-9]{8}$/.test(code)) throw new Error(`Invalid Shielding threat resolution code: ${code}`);
  return patchJson(`${config.apiUrl}/v1/shielding/runtime/threat-resolution/${encodeURIComponent(code)}/resolve`, config.apiKey, compactObject({
    resolvedBy: stringOption(options, 'resolved-by') || process.env.SECURSTACK_ACTOR || process.env.USER,
    resolutionNote: stringOption(options, 'resolution-note')
  }), tenantHeaders(tenantId));
}

function shieldingDownloadUrl(config, buildId, tenantId) {
  return getJson(`${config.apiUrl}/v1/shielding/builds/${encodeURIComponent(buildId)}/artifact/download-url`, config.apiKey, tenantHeaders(tenantId));
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

function defaultHookCommand() {
  return process.platform === 'win32' ? 'securstack.cmd' : 'securstack';
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

async function postJson(url, apiKey, body, extraHeaders = {}) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      'user-agent': 'securstack-cli/0.1.0',
      ...extraHeaders
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

async function patchJson(url, apiKey, body, extraHeaders = {}) {
  const response = await fetch(url, {
    method: 'PATCH',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      'user-agent': 'securstack-cli/0.1.0',
      ...extraHeaders
    },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.message || `SecurStack API returned ${response.status}`);
  }
  return data;
}

async function putBinary(url, body, extraHeaders = {}) {
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'user-agent': 'securstack-cli/0.1.0',
      ...extraHeaders
    },
    body
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Shielding artifact upload failed with HTTP ${response.status}`);
  }
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

async function getJson(url, apiKey, extraHeaders = {}) {
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'user-agent': 'securstack-cli/0.1.0',
      ...extraHeaders
    }
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.message || data.error || `SecurStack API request failed with HTTP ${response.status}`);
  }
  return data;
}

async function downloadFile(url, outputPath) {
  const response = await fetch(url, {
    method: 'GET',
    headers: { 'user-agent': 'securstack-cli/0.1.0' }
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Shielding artifact download failed with HTTP ${response.status}`);
  }
  if (!response.body) throw new Error('Shielding artifact download did not return a response body.');
  await pipeline(Readable.fromWeb(response.body), createWriteStream(resolve(outputPath), { mode: 0o600 }));
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

function requiredStringOption(options, key) {
  const value = stringOption(options, key);
  if (!value) throw new Error(`Missing --${key} <value>`);
  return value;
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

function shieldingListOption(options, key, fallback = []) {
  const values = arrayOption(options, key)
    .flatMap((value) => String(value).split(','))
    .map((value) => value.trim())
    .filter(Boolean);
  return values.length > 0 ? [...new Set(values)] : fallback;
}

function shieldingHeaderObject(options) {
  const headers = {};
  for (const rawHeader of arrayOption(options, 'header')) {
    const separator = String(rawHeader).indexOf(':');
    if (separator <= 0) throw new Error(`Invalid Shielding integration header: ${rawHeader}`);
    const key = String(rawHeader).slice(0, separator).trim();
    const value = String(rawHeader).slice(separator + 1).trim();
    if (!key || !value) throw new Error(`Invalid Shielding integration header: ${rawHeader}`);
    headers[key] = value;
  }
  return Object.keys(headers).length > 0 ? headers : undefined;
}

function jsonObjectOption(options, key) {
  const value = stringOption(options, key);
  if (value === undefined) return undefined;
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`Invalid JSON option --${key}`);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error(`Option --${key} must be a JSON object`);
  }
  return parsed;
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

function emitShieldingJson(value, options) {
  const format = stringOption(options, 'format') || 'json';
  if (format !== 'json') throw new Error(`Unsupported Shielding output format: ${format}`);
  emitOutput(JSON.stringify(value, null, 2), stringOption(options, 'output-json'));
}

function emitShieldingEvidenceSummary(evidence, options) {
  const evidenceRecord = evidence?.evidence && typeof evidence.evidence === 'object' ? evidence.evidence : evidence;
  const runtime = evidenceRecord?.runtimePackage && typeof evidenceRecord.runtimePackage === 'object' ? evidenceRecord.runtimePackage : {};
  const verification = evidenceRecord?.shieldingVerification && typeof evidenceRecord.shieldingVerification === 'object' ? evidenceRecord.shieldingVerification : {};
  const readiness = verification.commercialReadiness && typeof verification.commercialReadiness === 'object' ? verification.commercialReadiness : {};
  const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
  const failedChecks = Array.isArray(verification.checks) ? verification.checks.filter((check) => check?.status === 'failed') : [];
  const nativeToolchain = runtime.nativeToolchain && typeof runtime.nativeToolchain === 'object' ? runtime.nativeToolchain : {};
  const canonicalPayloadHash = evidenceRecord?.canonicalPayloadHash ?? evidence?.canonicalPayloadHash;
  const evidenceFingerprint = evidenceRecord?.evidenceFingerprint ?? evidence?.evidenceFingerprint;
  const lines = [
    `SecurStack Shielding evidence ${evidenceRecord?.id ?? '-'}`,
    `Build: ${evidenceRecord?.buildId ?? evidence?.buildId ?? '-'} · gate ${evidenceRecord?.releaseGateDecision ?? '-'} · verification ${verification.status ?? '-'}`,
    `Protected SHA-256: ${evidenceRecord?.protectedSha256 ?? '-'}`,
    `Evidence fingerprint: ${evidenceFingerprint ?? '-'}`,
    canonicalPayloadHash ? `Canonical payload SHA-256: ${canonicalPayloadHash}` : undefined,
    `Commercial readiness: ${readiness.status ?? '-'} · blockers ${blockers.length}`,
    `Native probes: ${runtime.nativeProbeManifestSha256 && runtime.nativeProbeBindingSha256 ? 'bound' : 'missing'} · manifest ${shortSha(runtime.nativeProbeManifestSha256)} · binding ${shortSha(runtime.nativeProbeBindingSha256)}`,
    `Native toolchain: ${nativeToolchain.selected ?? '-'}${nativeToolchain.strict ? ' strict' : ''}${nativeToolchain.compilerId ? ` · ${nativeToolchain.compilerId}` : ''}`,
    runtime.androidDexMergeStatus ? `Android runtime: ${runtime.androidDexMergeStatus}${runtime.androidSecondaryDexSha256 ? ` · secondary DEX ${shortSha(runtime.androidSecondaryDexSha256)}` : ''}` : undefined,
    runtime.iosLaunchBridgeStatus ? `iOS runtime: ${runtime.iosLaunchBridgeStatus}${runtime.iosLaunchBindingSha256 ? ` · launch binding ${shortSha(runtime.iosLaunchBindingSha256)}` : ''}` : undefined,
    failedChecks.length > 0 ? `Verification failures: ${failedChecks.slice(0, 3).map((check) => check.message ?? check.id ?? 'failed check').join(' | ')}` : undefined,
    blockers.length > 0 ? `Readiness blockers: ${blockers.slice(0, 3).map((blocker) => blocker.message ?? blocker.id ?? 'blocker').join(' | ')}` : undefined
  ].filter(Boolean);
  emitOutput(lines.join('\n'), stringOption(options, 'output-json'));
}

function shieldingEvidenceVerificationStatus(evidence) {
  const evidenceRecord = evidence?.evidence && typeof evidence.evidence === 'object' ? evidence.evidence : evidence;
  const verification = evidenceRecord?.shieldingVerification && typeof evidenceRecord.shieldingVerification === 'object' ? evidenceRecord.shieldingVerification : {};
  return typeof verification.status === 'string' ? verification.status : undefined;
}

function shortSha(value) {
  return typeof value === 'string' && value.length > 16 ? `${value.slice(0, 8)}...${value.slice(-6)}` : value ?? '-';
}

function tenantHeaders(tenantId) {
  return tenantId ? { 'x-tenant-id': tenantId } : {};
}

function compactObject(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

function contentTypeForShieldingArtifact(artifactType) {
  if (artifactType === 'apk') return 'application/vnd.android.package-archive';
  if (artifactType === 'aab') return 'application/octet-stream';
  if (artifactType === 'ipa') return 'application/octet-stream';
  return 'application/octet-stream';
}

function extractId(value) {
  if (!value || typeof value !== 'object') return undefined;
  return value.id || value._id;
}

function escapeRegex(value) {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

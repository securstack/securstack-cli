const { createHash } = require('node:crypto');
const { chmodSync, mkdirSync, renameSync, rmSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const packageJson = require('./package.json');

async function install() {
  const platform = process.platform === 'win32' ? 'windows' : process.platform;
  const key = `${platform}-${process.arch}`;
  const manifestUrl = process.env.SECURSTACK_CLI_MANIFEST_URL || `https://downloads.securstack.io/cli/v${packageJson.version}/manifest.json`;
  const manifestResponse = await fetch(manifestUrl);
  if (!manifestResponse.ok) throw new Error(`Unable to download SecurStack CLI manifest (${manifestResponse.status})`);
  const manifest = await manifestResponse.json();
  if (manifest.version !== packageJson.version) throw new Error(`SecurStack CLI manifest version mismatch: ${manifest.version}`);
  const artifact = manifest.artifacts[key];
  if (!artifact) throw new Error(`SecurStack CLI ${packageJson.version} does not support ${key}`);

  const binaryResponse = await fetch(artifact.url);
  if (!binaryResponse.ok) throw new Error(`Unable to download SecurStack CLI binary (${binaryResponse.status})`);
  const bytes = Buffer.from(await binaryResponse.arrayBuffer());
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== artifact.sha256.toLowerCase()) throw new Error(`Checksum verification failed for ${artifact.file}`);

  const vendor = join(__dirname, 'vendor');
  const executable = join(vendor, process.platform === 'win32' ? 'securstack.exe' : 'securstack');
  const temporary = `${executable}.${process.pid}.tmp`;
  mkdirSync(vendor, { recursive: true });
  writeFileSync(temporary, bytes, { mode: 0o755 });
  if (process.platform !== 'win32') chmodSync(temporary, 0o755);
  rmSync(executable, { force: true });
  renameSync(temporary, executable);
}

install().catch((error) => {
  console.error(`SecurStack CLI installation failed: ${error.message || error}`);
  process.exit(1);
});

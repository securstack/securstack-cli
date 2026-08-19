import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const releaseDir = resolve(process.argv[2] || join(root, 'dist'));
const baseUrl = (process.env.SECURSTACK_CLI_RELEASE_BASE_URL || `https://downloads.securstack.io/cli/v${packageJson.version}`).replace(/\/$/, '');
const artifactPattern = /^securstack-(darwin|linux|windows)-(x64|arm64)(\.exe)?$/;
const artifacts = {};

for (const file of readdirSync(releaseDir).sort()) {
  const match = artifactPattern.exec(file);
  if (!match) continue;
  const contents = readFileSync(join(releaseDir, file));
  artifacts[`${match[1]}-${match[2]}`] = {
    file,
    url: `${baseUrl}/${file}`,
    sha256: createHash('sha256').update(contents).digest('hex'),
    size: statSync(join(releaseDir, file)).size
  };
}

if (Object.keys(artifacts).length === 0) {
  throw new Error(`No SecurStack CLI binaries found in ${releaseDir}`);
}

const manifest = {
  schemaVersion: 1,
  name: 'securstack-cli',
  version: packageJson.version,
  baseUrl,
  artifacts
};

writeFileSync(join(releaseDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
writeFileSync(join(releaseDir, 'checksums.txt'), `${Object.values(artifacts).map((artifact) => `${artifact.sha256}  ${artifact.file}`).join('\n')}\n`);
writeFileSync(join(releaseDir, 'latest.txt'), `${packageJson.version}\n`);
console.log(`Generated manifest for ${Object.keys(artifacts).length} artifact(s)`);

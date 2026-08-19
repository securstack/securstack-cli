import { copyFileSync, chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const buildDir = join(root, 'build', 'sea');
const distDir = join(root, 'dist');
const platform = normalizePlatform(process.platform);
const architecture = normalizeArchitecture(process.arch);
const extension = platform === 'windows' ? '.exe' : '';
const output = join(distDir, `securstack-${platform}-${architecture}${extension}`);
const bundle = join(buildDir, 'securstack.cjs');
const blob = join(buildDir, 'securstack.blob');
const seaConfig = join(buildDir, 'sea-config.json');

rmSync(buildDir, { recursive: true, force: true });
mkdirSync(buildDir, { recursive: true });
mkdirSync(distDir, { recursive: true });

const bundleResult = await build({
  entryPoints: [join(root, 'src', 'sea-entry.js')],
  outfile: bundle,
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node22',
  minify: true,
  sourcemap: false,
  metafile: true,
  logOverride: {
    'empty-import-meta': 'silent'
  },
  define: {
    __SECURSTACK_BUNDLED__: 'true'
  }
});

for (const input of Object.keys(bundleResult.metafile.inputs)) {
  const normalized = input.replaceAll('\\', '/');
  const allowedPublicContract = normalized.endsWith('/src/public/shielding-attestation.ts')
    || normalized.endsWith('/dist/public/shielding-attestation.js');
  if (normalized.includes('securstack-core/') && !allowedPublicContract) {
    throw new Error(`Standalone bundle included a non-public core module: ${input}`);
  }
}

writeFileSync(seaConfig, JSON.stringify({
  main: bundle,
  output: blob,
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: false
}, null, 2));

execFileSync(process.execPath, ['--experimental-sea-config', seaConfig], { stdio: 'inherit' });
copyFileSync(process.execPath, output);

if (platform === 'darwin') {
  spawnSync('codesign', ['--remove-signature', output], { stdio: 'ignore' });
}

const postjectCli = join(root, 'node_modules', 'postject', 'dist', 'cli.js');
const postjectArgs = [
  postjectCli,
  output,
  'NODE_SEA_BLOB',
  blob,
  '--sentinel-fuse',
  'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'
];
if (platform === 'darwin') postjectArgs.push('--macho-segment-name', 'NODE_SEA');
execFileSync(process.execPath, postjectArgs, { stdio: 'inherit' });

if (platform === 'darwin') {
  execFileSync('codesign', ['--sign', '-', output], { stdio: 'inherit' });
}
if (platform !== 'windows') chmodSync(output, 0o755);

const version = execFileSync(output, ['--version'], { encoding: 'utf8' }).trim();
console.log(`Built ${output} (SecurStack CLI ${version})`);

function normalizePlatform(value) {
  if (value === 'win32') return 'windows';
  if (value === 'darwin' || value === 'linux') return value;
  throw new Error(`Unsupported platform: ${value}`);
}

function normalizeArchitecture(value) {
  if (value === 'x64' || value === 'arm64') return value;
  throw new Error(`Unsupported architecture: ${value}`);
}

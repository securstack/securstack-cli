import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = resolve(process.argv[2] || join(root, 'dist', 'manifest.json'));
const outputRoot = resolve(process.argv[3] || join(root, 'dist', 'packages'));
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

const values = { VERSION: manifest.version };
for (const [key, artifact] of Object.entries(manifest.artifacts)) {
  const prefix = key.replaceAll('-', '_').toUpperCase();
  values[`${prefix}_URL`] = artifact.url;
  values[`${prefix}_SHA256`] = artifact.sha256;
}

renderRequired('packaging/homebrew/securstack.rb.template', 'homebrew/securstack.rb', [
  'DARWIN_ARM64_URL', 'DARWIN_ARM64_SHA256', 'DARWIN_X64_URL', 'DARWIN_X64_SHA256',
  'LINUX_ARM64_URL', 'LINUX_ARM64_SHA256', 'LINUX_X64_URL', 'LINUX_X64_SHA256'
]);
renderRequired('packaging/winget/SecurStack.CLI.installer.yaml.template', 'winget/SecurStack.CLI.installer.yaml', [
  'WINDOWS_X64_URL', 'WINDOWS_X64_SHA256'
]);
renderRequired('packaging/winget/SecurStack.CLI.locale.en-US.yaml.template', 'winget/SecurStack.CLI.locale.en-US.yaml', []);
renderRequired('packaging/winget/SecurStack.CLI.yaml.template', 'winget/SecurStack.CLI.yaml', []);
renderRequired('packaging/chocolatey/securstack.nuspec.template', 'chocolatey/securstack.nuspec', []);
renderRequired('packaging/chocolatey/tools/chocolateyInstall.ps1.template', 'chocolatey/tools/chocolateyInstall.ps1', [
  'WINDOWS_X64_URL', 'WINDOWS_X64_SHA256'
]);
renderRequired('packaging/npm/package.json.template', 'npm/package.json', []);
cpSync(join(root, 'packaging', 'npm', 'install.js'), join(outputRoot, 'npm', 'install.js'));
mkdirSync(join(outputRoot, 'npm', 'bin'), { recursive: true });
cpSync(join(root, 'packaging', 'npm', 'bin', 'securstack.js'), join(outputRoot, 'npm', 'bin', 'securstack.js'));

console.log(`Rendered distribution metadata in ${outputRoot}`);

function renderRequired(templatePath, destinationPath, required) {
  for (const key of required) {
    if (!values[key]) throw new Error(`Release manifest is missing ${key}`);
  }
  let contents = readFileSync(join(root, templatePath), 'utf8');
  for (const [key, value] of Object.entries(values)) contents = contents.replaceAll(`__${key}__`, value);
  const unresolved = contents.match(/__[A-Z0-9_]+__/g);
  if (unresolved) throw new Error(`Unresolved template values in ${templatePath}: ${unresolved.join(', ')}`);
  const destination = join(outputRoot, destinationPath);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, contents);
}

$ErrorActionPreference = 'Stop'

$downloadsRoot = if ($env:SECURSTACK_DOWNLOADS_URL) { $env:SECURSTACK_DOWNLOADS_URL.TrimEnd('/') } else { 'https://downloads.securstack.io/cli' }
$version = if ($env:SECURSTACK_CLI_VERSION) { $env:SECURSTACK_CLI_VERSION } else { 'latest' }
$installDir = if ($env:SECURSTACK_INSTALL_DIR) { $env:SECURSTACK_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'SecurStack\bin' }

if ($version -eq 'latest') {
    $version = (Invoke-RestMethod "${downloadsRoot}/latest.txt").Trim()
}

$architecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'x64' }
    'Arm64' { 'arm64' }
    default { throw "Unsupported architecture: $_" }
}

$file = "securstack-windows-${architecture}.exe"
$releaseUrl = "${downloadsRoot}/v${version}"
$temporaryFile = Join-Path ([System.IO.Path]::GetTempPath()) ("securstack-" + [guid]::NewGuid() + '.exe')

try {
    Invoke-WebRequest "${releaseUrl}/${file}" -OutFile $temporaryFile
    $manifest = Invoke-RestMethod "${releaseUrl}/manifest.json"
    $artifact = $manifest.artifacts."windows-${architecture}"
    if (-not $artifact) { throw "Release does not contain windows-${architecture}" }
    $actual = (Get-FileHash $temporaryFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $artifact.sha256.ToLowerInvariant()) { throw "Checksum verification failed for ${file}" }

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item $temporaryFile (Join-Path $installDir 'securstack.exe') -Force
    Write-Host "SecurStack CLI ${version} installed at $(Join-Path $installDir 'securstack.exe')"
} finally {
    Remove-Item $temporaryFile -Force -ErrorAction SilentlyContinue
}

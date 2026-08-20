# Distribution packages

The files in this directory are release templates. The standalone binaries and
`manifest.json` under `downloads.securstack.io` remain the source of truth.
Package-manager metadata must always reference an immutable version URL and its
SHA-256 value; it must never point directly at `latest`.

- Homebrew: publish the rendered formula to `securstack/homebrew-tap`.
- Debian/Ubuntu: build `.deb` files with `scripts/package-deb.sh`, then publish
  them through the signed `packages.securstack.io/apt` repository.
- WinGet: submit the three rendered manifests under
  `microsoft/winget-pkgs/manifests/s/SecurStack/CLI/<version>/`. The community
  repository does not accept singleton manifests.
- Chocolatey: render, validate on Windows, pack and submit the package to the
  community feed. The package metadata links back to this source repository.
- npm: compatibility installer only. It downloads the same standalone binary;
  npm is not the canonical runtime distribution.

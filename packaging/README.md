# Distribution packages

The files in this directory are release templates. The standalone binaries and
`manifest.json` under `downloads.securstack.io` remain the source of truth.
Package-manager metadata must always reference an immutable version URL and its
SHA-256 value; it must never point directly at `latest`.

- Homebrew: publish the rendered formula to `securstack/homebrew-tap`.
- Debian/Ubuntu: build `.deb` files with `scripts/package-deb.sh`, then publish
  them through the signed `downloads.securstack.io/apt` repository. Publish
  `packaging/debian/install-apt.sh` as `/apt/install.sh` for the short bootstrap
  command shown on the downloads page.
- RPM/YUM/DNF: build `.rpm` files with `scripts/package-rpm.sh`, then publish
  them under `downloads.securstack.io/rpm/stable/$basearch` with `createrepo_c`
  metadata. Publish `packaging/rpm/install-yum.sh` as `/rpm/install.sh` for the
  short bootstrap command shown on the downloads page.
- WinGet: submit the three rendered manifests under
  `microsoft/winget-pkgs/manifests/s/SecurStack/CLI/<version>/`. The community
  repository does not accept singleton manifests.
- Chocolatey: render, validate on Windows, pack and submit the package to the
  community feed. The package metadata links back to this source repository.
- npm: compatibility installer only. It downloads the same standalone binary;
  npm is not the canonical runtime distribution.

## Release automation

Creating a version tag such as `v0.2.1` runs the `Release standalone CLI`
workflow. That workflow builds the standalone executables, publishes the
canonical download directory, creates the GitHub release, publishes the optional
npm compatibility installer and attaches `securstack-package-metadata-<version>.tar.gz`.

After the release workflow succeeds:

- `Publish Chocolatey package` runs automatically and pushes the rendered
  Chocolatey package to the community feed when `SECURSTACK_CHOCOLATEY_API_KEY`
  is configured. Chocolatey may still hold new versions for external moderation.
- `Publish package manager metadata` updates `securstack/homebrew-tap` and opens
  or updates the WinGet PR from `securstack/winget-pkgs` when
  `SECURSTACK_GITHUB_AUTOMATION_TOKEN` is configured.

Required GitHub repository secrets:

- `SECURSTACK_BITBUCKET_API_TOKEN`: read access to `securstack-core` during
  binary builds.
- `SECURSTACK_DOWNLOADS_SSH_HOST`, `SECURSTACK_DOWNLOADS_SSH_PORT`,
  `SECURSTACK_DOWNLOADS_SSH_USER`, `SECURSTACK_DOWNLOADS_SSH_PRIVATE_KEY`,
  `SECURSTACK_DOWNLOADS_SSH_KNOWN_HOSTS` and `SECURSTACK_DOWNLOADS_PATH`:
  production download server publication.
- `SECURSTACK_NPM_TOKEN`: optional npm publication as the `securstack` npm user.
- `SECURSTACK_CHOCOLATEY_API_KEY`: optional Chocolatey Community Repository
  publication.
- `SECURSTACK_GITHUB_AUTOMATION_TOKEN`: optional GitHub automation token for
  pushing `securstack/homebrew-tap` and managing the `securstack/winget-pkgs`
  branch/PR.

Optional repository variables:

- `SECURSTACK_HOMEBREW_TAP_REPOSITORY`: defaults to `securstack/homebrew-tap`.
- `SECURSTACK_WINGET_FORK_REPOSITORY`: defaults to `securstack/winget-pkgs`.
- `SECURSTACK_WINGET_UPSTREAM_REPOSITORY`: defaults to `microsoft/winget-pkgs`.

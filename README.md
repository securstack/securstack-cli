# securstack-cli

Local SecurStack CLI for running repository security scans through the SecurStack API and operating Shielding workflows from CI/CD.

## Responsibilities

- Discover and prepare the local workspace.
- Respect `.gitignore` and `.securstackignore`.
- Authenticate with the user's API key.
- Encrypt allowed files locally before sending them to the SecurStack API.
- Return findings in formats reusable by IDEs and CI.
- Drive SecurStack Shielding app, artifact, build, evidence, signing, runtime and attestation operations.

The CLI receives API responses synchronously, but analysis engines run inside the SecurStack SaaS on internal workers.

## Supported Platforms

The CLI supports macOS, Linux and Windows with Node.js 20 or newer.

On Windows, the npm binary may resolve as `securstack.cmd`. The `pre-commit` hook command is executed by the Git environment installed on the machine, usually Git for Windows/Git Bash.

When a scan needs to upload a repository package, the CLI uses the system `tar` when available and falls back to a portable Node.js packager for Windows environments or machines without `tar`.

## Getting Started

```bash
securstack login --api-key ssk_live_...
securstack scan --path . --format json
securstack scan --path . --format sarif
securstack scan --path . --format sarif --output securstack.sarif
securstack doctor
securstack logout
```

Environment variables are also supported:

```bash
SECURSTACK_API_KEY=ssk_live_... SECURSTACK_API_URL=https://api.securstack.io/api securstack scan
```

## Shielding CI/CD

The CLI can drive the SecurStack Shielding release flow from CI/CD without custom API scripts:

```bash
export SECURSTACK_API_KEY=ssk_live_...
export SECURSTACK_API_URL=https://api.securstack.io/api
export SECURSTACK_TENANT_ID=tenant_acme

securstack shielding create-app \
  --name "Payments Android" \
  --platform android \
  --package-name com.acme.payments \
  --environment staging,prod

securstack shielding create-policy \
  --name "Production Shielding" \
  --app-id app_123 \
  --mode block \
  --required-protection anti_tamper \
  --required-protection anti_debug \
  --required-protection runtime_self_protection \
  --optional-protection api_attestation

securstack shielding update-policy \
  --policy-id policy_123 \
  --mode warn \
  --required-protection anti_tamper,runtime_self_protection \
  --optional-protection api_attestation

securstack shielding list-apps
securstack shielding get-app --app-id app_123
securstack shielding entitlements
securstack shielding usage
securstack shielding list-policies

securstack shielding upload-artifact \
  --app-id app_123 \
  --file build/app-release.apk \
  --artifact-type apk
securstack shielding get-artifact --artifact-id artifact_123

securstack shielding build \
  --app-id app_123 \
  --artifact-id artifact_123 \
  --policy-id policy_123 \
  --environment prod \
  --signing-mode customer \
  --idempotency-key "$CI_PIPELINE_ID-$CI_COMMIT_SHA" \
  --async \
  --wait \
  --gate-check

securstack shielding list-builds
securstack shielding get-build --build-id build_123
securstack shielding gate --build-id build_123
securstack shielding release-gate --build-id build_123
securstack shielding evidence --build-id build_123 --export
securstack shielding evidence --build-id build_123 --format summary
securstack shielding evidence --build-id build_123 --export --format summary
securstack shielding evidence --build-id build_123 --export --format summary --fail-on-verification
securstack shielding list-evidence
securstack shielding signing-job \
  --build-id build_123 \
  --mode customer
securstack shielding signing-job \
  --build-id build_123 \
  --mode managed \
  --key-ref vault://tenant_acme/mobile/android-release \
  --certificate-ref vault://tenant_acme/mobile/android-cert
securstack shielding list-signing-jobs
securstack shielding get-signing-job --signing-job-id signing_123
securstack shielding create-integration \
  --name "SOC webhook" \
  --type generic_webhook \
  --endpoint-url https://soc.example.com/securstack/shielding \
  --event-type runtime.threat \
  --event-type api.attestation \
  --header "X-Source: securstack" \
  --shared-secret "$SHIELDING_WEBHOOK_SHARED_SECRET"
securstack shielding list-integrations
securstack shielding update-integration \
  --integration-id integration_123 \
  --enabled false
securstack shielding integration-deliveries
securstack shielding runtime-event \
  --app-id app_123 \
  --build-id build_123 \
  --platform android \
  --threat-type frida_detected \
  --severity critical \
  --metadata-json '{"sessionId":"ci-smoke-test"}'
securstack shielding runtime-events
securstack shielding risk-summary --app-id app_123
securstack shielding retention
securstack shielding retention --execute
securstack shielding attest \
  --app-id app_123 \
  --build-id build_123 \
  --platform android \
  --endpoint /api/v1/payments/authorize \
  --protected-sha256 "$PROTECTED_SHA256" \
  --artifact-stage "$ARTIFACT_STAGE" \
  --signed-sha256 "$SIGNED_SHA256" \
  --evidence-fingerprint "$EVIDENCE_FINGERPRINT" \
  --hmac-secret "$SHIELDING_ATTESTATION_HMAC_SECRET"
securstack shielding resolve-threat \
  --code SSK-ABCDEF12 \
  --resolved-by "$SECURSTACK_ACTOR" \
  --resolution-note "Blocked session and rotated exposed tokens."
securstack shielding download --build-id build_123 --output release-artifact.apk
```

`shielding create-app`, `shielding create-policy` and `shielding update-policy` let onboarding and CI/CD govern the required app and release-gate IDs without custom API scripts. `get-app`, `get-artifact`, `list-builds`, `get-build`, `release-gate` and `list-evidence` give support and auditors sanitized read-only access to the release trail. Build responses can include public retention timestamps such as `protectedArtifactDeletedAt`, `signedArtifactDeletedAt` and `artifactRetentionCutoffAt`, but never raw storage URIs. `shielding evidence --format summary` prints an auditor-friendly native readiness summary with release gate, evidence verification, commercial readiness, native probes, Android DEX and iOS launch bridge status without exposing artifact storage URIs; combine it with `--export` to summarize the immutable auditor export wrapper while preserving canonical payload hash and evidence fingerprint. Add `--fail-on-verification` in CI/CD evidence steps to set process exit code `1` whenever `shieldingVerification.status` is not `passed`, including failed or older/missing evidence verification records. `shielding build --async --wait` starts a queued Shielding job and polls `GET /shielding/builds/{buildId}` until the build reaches a terminal state. `shielding gate` and `shielding build --gate-check` set process exit code `1` when the release gate returns `block`, so pipelines can fail the release directly. Use `--tenant-id` to override `SECURSTACK_TENANT_ID` per command.

`shielding entitlements` and `shielding usage` read the tenant's commercial plan capabilities and current counters. `shielding signing-job` creates either a customer signing handoff or a managed signing job with tenant-scoped Vault/KMS/HSM references. Customer signing rejects key or certificate references because signing must happen in the customer's pipeline. Managed signing accepts only `vault://`, `kms://` or `hsm://` references, verifies the tenant segment when `--tenant-id` is provided, requires passed evidence verification plus ready commercial readiness, and rejects plaintext-looking signing material before calling the API. Returned job records are sanitized by the API and can include readiness evidence such as evidence fingerprint, canonical payload hash and verification/readiness status, but must not expose raw storage URIs or signing material. `shielding create-integration` configures webhook or Splunk HEC export for sanitized runtime and attestation events; secrets are sent only during create/update and API responses expose only `secretsConfigured`. `shielding runtime-event`, `shielding runtime-events` and `shielding risk-summary` let CI/CD, support and fraud teams validate runtime telemetry ingestion and app posture without custom scripts. Runtime threat types are sent with the shared canonical values such as `frida_detected`, `root_detected` and `api_attestation_invalid`; short aliases such as `frida`, `root` and `api_attestation` are accepted by the CLI and normalized before the API call. `shielding retention` runs in preview mode by default; use `--execute` only for an audited retention run. `shielding attest` posts a backend/API attestation event. When `--hmac-secret` or `SHIELDING_ATTESTATION_HMAC_SECRET` is set, it signs the payload with `ssk-attestation-hmac-v1`, including tenant, app, build, endpoint, protected SHA-256, optional signed artifact stage/hash, evidence fingerprint, nonce and timestamp. Signed artifact attestation requires `--build-id` plus `--artifact-stage signed` and `--signed-sha256` so the backend signal is bound to the final signed release. Attestation nonce values must be 8-256 characters and `--session-risk` must be between `0` and `10`, matching the shared API contract. `shielding resolve-threat` closes a support-ready `SSK-...` threat resolution case with an audit-safe operator and resolution note.

Pipeline API keys need `shielding:write` for app/policy bootstrap, upload/build/signing, integration management, retention execution and threat-resolution closure operations, and `shielding:read` for app/policy discovery, entitlements, usage, gate, evidence, downloads, signing jobs, runtime posture and integration deliveries. Runtime-only keys should use `shielding:runtime:write` and backend attestation integrations should use `shielding:attestation:write`.

## Privacy And Code Upload

The CLI encrypts eligible files locally before sending them to the SecurStack API. The flow uses an ephemeral scan session with `X25519 + HKDF-SHA256` key derivation and per-file `AES-256-GCM`. The API receives only ciphertext and metadata; decryption happens inside the internal worker that runs the scan engines.

Before upload, it:

- respects `.gitignore` and `.securstackignore`;
- ignores common directories such as `.git`, `node_modules`, `dist`, `build`, `coverage`, `.next`, `.turbo`, `.cache` and `.idea`;
- ignores binary files;
- applies local limits for file size, total payload size and file count.

Use `.securstackignore` to exclude sensitive files that must not leave the machine.

## `.securstackignore`

The initial format follows a simple subset of `.gitignore`:

```gitignore
.env
.env.*
secrets/
*.pem
fixtures/private-data.json
```

Negations with `!` are not applied in this version.

## Distribution

The canonical release is a standalone executable and does not require Node.js
on the destination machine. Release tags build macOS, Linux and Windows
artifacts, plus `manifest.json` and `checksums.txt` for integrity verification.

Manual installation:

```bash
curl -fsSL https://downloads.securstack.io/cli/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://downloads.securstack.io/cli/install.ps1 | iex
```

The same immutable binaries are consumed by the managed IDE/plugin installer,
Homebrew, APT, WinGet, Chocolatey and the optional npm compatibility wrapper.
Package-manager metadata must reference a versioned URL and SHA-256 value.

For a local platform build:

```bash
npm run build:binary
npm run release:manifest
```

Release templates and operational details live in `packaging/` and in
`securstack-infra/docs/cli-binary-distribution.md`.

## Expected Consumers

- `securstack-plugin-vscode`
- `securstack-plugin-jetbrains`
- Pipelines de CI/CD

#!/bin/sh
set -eu

downloads_root="${SECURSTACK_DOWNLOADS_URL:-https://downloads.securstack.io/cli}"
version="${SECURSTACK_CLI_VERSION:-latest}"
install_dir="${SECURSTACK_INSTALL_DIR:-${HOME}/.local/bin}"

if [ "$version" = "latest" ]; then
  version="$(curl -fsSL "${downloads_root}/latest.txt")"
fi

case "$(uname -s)" in
  Darwin) platform="darwin" ;;
  Linux) platform="linux" ;;
  *) echo "Unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) architecture="x64" ;;
  arm64|aarch64) architecture="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

file="securstack-${platform}-${architecture}"
release_url="${downloads_root}/v${version}"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT INT TERM

curl -fsSL "${release_url}/${file}" -o "${temporary_dir}/${file}"
curl -fsSL "${release_url}/checksums.txt" -o "${temporary_dir}/checksums.txt"
expected="$(awk -v name="$file" '$2 == name { print $1 }' "${temporary_dir}/checksums.txt")"
if [ -z "$expected" ]; then
  echo "Checksum not found for ${file}" >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${temporary_dir}/${file}" | awk '{ print $1 }')"
elif command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${temporary_dir}/${file}" | awk '{ print $1 }')"
else
  echo "A SHA-256 utility (shasum or sha256sum) is required" >&2
  exit 1
fi

if [ "$actual" != "$expected" ]; then
  echo "Checksum verification failed for ${file}" >&2
  exit 1
fi

mkdir -p "$install_dir"
install -m 0755 "${temporary_dir}/${file}" "${install_dir}/securstack"
echo "SecurStack CLI ${version} installed at ${install_dir}/securstack"
case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *) echo "Add ${install_dir} to PATH to run: securstack" ;;
esac

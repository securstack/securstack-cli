#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root (for example: curl ... | sudo sh)." >&2
  exit 1
fi

command -v curl >/dev/null 2>&1 || {
  echo "curl is required to configure the SecurStack RPM repository." >&2
  exit 1
}

if command -v dnf >/dev/null 2>&1; then
  package_manager="dnf"
elif command -v yum >/dev/null 2>&1; then
  package_manager="yum"
else
  echo "dnf or yum is required to install SecurStack from the RPM repository." >&2
  exit 1
fi

repo_file="/etc/yum.repos.d/securstack.repo"
install -d -m 0755 "$(dirname "$repo_file")"
cat > "$repo_file" <<'REPO'
[securstack]
name=SecurStack CLI
baseurl=https://downloads.securstack.io/rpm/stable/$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=1h
REPO

"$package_manager" makecache -y --disablerepo='*' --enablerepo='securstack'
"$package_manager" install -y securstack

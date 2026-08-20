#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root (for example: curl ... | sudo sh)." >&2
  exit 1
fi

command -v curl >/dev/null 2>&1 || {
  echo "curl is required to configure the SecurStack APT repository." >&2
  exit 1
}

keyring="/usr/share/keyrings/securstack.gpg"
source_list="/etc/apt/sources.list.d/securstack.list"
repository="https://downloads.securstack.io/apt"
temporary_key="$(mktemp)"
trap 'rm -f "$temporary_key"' EXIT HUP INT TERM

curl -fsSL "$repository/securstack-archive-keyring.gpg" -o "$temporary_key"
install -d -m 0755 "$(dirname "$keyring")"
install -m 0644 "$temporary_key" "$keyring"
printf 'deb [arch=%s signed-by=%s] %s stable main\n' \
  "$(dpkg --print-architecture)" "$keyring" "$repository" > "$source_list"

apt-get update
apt-get install -y securstack

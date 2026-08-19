#!/bin/sh
set -eu

binary="${1:?usage: package-deb.sh BINARY VERSION OUTPUT_DIR}"
version="${2:?usage: package-deb.sh BINARY VERSION OUTPUT_DIR}"
output_dir="${3:?usage: package-deb.sh BINARY VERSION OUTPUT_DIR}"

case "$binary" in
  *-linux-x64) deb_arch="amd64" ;;
  *-linux-arm64) deb_arch="arm64" ;;
  *) echo "Unsupported Debian binary: $binary" >&2; exit 1 ;;
esac

package_root="$(mktemp -d)"
trap 'rm -rf "$package_root"' EXIT INT TERM
mkdir -p "$package_root/DEBIAN" "$package_root/usr/bin" "$output_dir"
sed -e "s/__VERSION__/$version/g" -e "s/__ARCHITECTURE__/$deb_arch/g" packaging/debian/control.template > "$package_root/DEBIAN/control"
install -m 0755 "$binary" "$package_root/usr/bin/securstack"
dpkg-deb --root-owner-group --build "$package_root" "$output_dir/securstack_${version}_${deb_arch}.deb"

#!/bin/sh
set -eu

binary="${1:?usage: package-rpm.sh BINARY VERSION OUTPUT_DIR}"
version="${2:?usage: package-rpm.sh BINARY VERSION OUTPUT_DIR}"
output_dir="${3:?usage: package-rpm.sh BINARY VERSION OUTPUT_DIR}"

case "$binary" in
  *-linux-x64) rpm_arch="x86_64" ;;
  *-linux-arm64) rpm_arch="aarch64" ;;
  *) echo "Unsupported RPM binary: $binary" >&2; exit 1 ;;
esac

command -v rpmbuild >/dev/null 2>&1 || {
  echo "rpmbuild is required to build RPM packages." >&2
  exit 1
}

package_topdir="$(mktemp -d)"
trap 'rm -rf "$package_topdir"' EXIT INT TERM
mkdir -p "$package_topdir/BUILD" "$package_topdir/BUILDROOT" "$package_topdir/RPMS" "$package_topdir/SOURCES" "$package_topdir/SPECS" "$package_topdir/SRPMS" "$output_dir"
install -m 0755 "$binary" "$package_topdir/SOURCES/securstack"
sed -e "s/__VERSION__/$version/g" packaging/rpm/securstack.spec.template > "$package_topdir/SPECS/securstack.spec"

rpmbuild -bb \
  --target "$rpm_arch" \
  --define "_topdir $package_topdir" \
  "$package_topdir/SPECS/securstack.spec"

rpm_file="$(find "$package_topdir/RPMS/$rpm_arch" -type f -name 'securstack-*.rpm' | head -n 1)"
if [ -z "$rpm_file" ]; then
  echo "RPM package was not created for $rpm_arch" >&2
  exit 1
fi

cp "$rpm_file" "$output_dir/securstack-${version}-1.${rpm_arch}.rpm"

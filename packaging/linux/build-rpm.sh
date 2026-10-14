#!/usr/bin/env bash
# Build an .rpm around an already built binary.
#   packaging/linux/build-rpm.sh <binary> <x86_64|aarch64> <version> <output.rpm>
set -euo pipefail
BIN=$(realpath "$1") ARCH=$2 VERSION=$3 OUT=$4
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
TOP=$(mktemp -d)
trap 'rm -rf "$TOP"' EXIT
rpmbuild -bb --target "$ARCH" --quiet \
  --define "rd_version $VERSION" --define "rd_binary $BIN" --define "rd_root $ROOT" \
  --define "_topdir $TOP" "$HERE/runet-direct.spec"
cp "$TOP"/RPMS/*/runet-direct-*.rpm "$OUT"
echo "built $OUT ($(du -h "$OUT" | cut -f1))"

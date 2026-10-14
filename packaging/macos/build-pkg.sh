#!/bin/bash
# Build a macOS installer package around an already built binary. Run on macOS.
#   packaging/macos/build-pkg.sh <binary> <version> <output.pkg>
set -euo pipefail
BIN=$1 VERSION=$2 OUT=$3
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/root/usr/local/bin"
install -m755 "$BIN" "$WORK/root/usr/local/bin/runet-direct"

pkgbuild --root "$WORK/root" --identifier io.github.iresultman.runet-direct --version "$VERSION" \
  --install-location / --scripts "$HERE/scripts" "$WORK/component.pkg" >/dev/null

mkdir -p "$WORK/resources"
cp -R "$HERE/resources/"* "$WORK/resources/"
cp "$ROOT/LICENSE" "$WORK/resources/license.txt"
sed "s/@VERSION@/$VERSION/" "$HERE/distribution.xml" > "$WORK/distribution.xml"

productbuild --distribution "$WORK/distribution.xml" --resources "$WORK/resources" --package-path "$WORK" "$OUT" >/dev/null
echo "built $OUT ($(du -h "$OUT" | cut -f1))"

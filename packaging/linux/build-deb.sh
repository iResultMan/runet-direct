#!/usr/bin/env bash
# Build a .deb around an already built binary (no compiler needed).
#   packaging/linux/build-deb.sh <binary> <amd64|arm64> <version> <output.deb>
set -euo pipefail
BIN=$1 ARCH=$2 VERSION=$3 OUT=$4
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
STAGE=$(mktemp -d)
chmod 755 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT

install -Dm755 "$BIN" "$STAGE/usr/bin/runet-direct"
install -Dm644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/runet-direct/copyright"
install -Dm644 "$ROOT/README.md" "$STAGE/usr/share/doc/runet-direct/README.md"
install -Dm644 "$ROOT/README.ru.md" "$STAGE/usr/share/doc/runet-direct/README.ru.md"

mkdir -p "$STAGE/DEBIAN"
SIZE=$(du -sk "$STAGE/usr" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: runet-direct
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Installed-Size: $SIZE
Depends: curl, iproute2
Recommends: systemd
Maintainer: iResultMan <i.result.man@gmail.com>
Homepage: https://github.com/iResultMan/runet-direct
Description: keeps Russian-internet traffic off your VPN
 A small background service: traffic to Russian address blocks leaves
 through your normal connection while everything else keeps using the VPN.
 Works with any VPN, IPv4 and IPv6, repairs its own routes when the network
 changes. Manage it with the runet-direct command (status, pause, add ...).
CONTROL

install -m755 "$HERE/deb/postinst" "$STAGE/DEBIAN/postinst"
install -m755 "$HERE/deb/prerm" "$STAGE/DEBIAN/prerm"
install -m755 "$HERE/deb/postrm" "$STAGE/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$STAGE" "$OUT" >/dev/null
echo "built $OUT ($(du -h "$OUT" | cut -f1))"

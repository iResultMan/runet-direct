#!/bin/sh
# Installs runet-direct on Linux or macOS from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/iResultMan/runet-direct/main/install.sh | sudo sh
#   sudo sh install.sh [--version v1.0.0] [--no-start]
#
# It downloads one binary, checks its SHA-256, and runs `runet-direct install`, which registers
# the background service (systemd / launchd) and starts it. Read it before running it.
set -eu

REPO="iResultMan/runet-direct"
VERSION=""
EXTRA=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --no-start) EXTRA="--no-start"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root: curl ... | sudo sh" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }

case "$(uname -s)" in
  Linux)  os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) echo "unsupported system: $(uname -s) (Windows: use install.ps1)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
target="$arch-$os"
asset="runet-direct-$target.tar.gz"

if [ -n "$VERSION" ]; then
  base="https://github.com/$REPO/releases/download/$VERSION"
else
  base="https://github.com/$REPO/releases/latest/download"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $asset ..."
curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256"

want=$(cut -d' ' -f1 "$tmp/$asset.sha256")
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
fi
[ "$want" = "$got" ] || { echo "checksum mismatch: expected $want, got $got" >&2; exit 1; }

tar -xzf "$tmp/$asset" -C "$tmp"
# shellcheck disable=SC2086
"$tmp/runet-direct" install $EXTRA

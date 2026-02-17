#!/bin/bash
set -euo pipefail

VERSION="${1:-0.1.0}"
ARCH="${2:-amd64}"
BINARY="${3:-domain-probe}"

PKG_DIR="$(mktemp -d)"
trap 'rm -rf "$PKG_DIR"' EXIT

mkdir -p "$PKG_DIR/usr/local/bin" "$PKG_DIR/DEBIAN"

cp "$BINARY" "$PKG_DIR/usr/local/bin/domain-probe"
chmod 755 "$PKG_DIR/usr/local/bin/domain-probe"

sed "s/^Version:.*/Version: $VERSION/" \
    "$(dirname "$0")/control" > "$PKG_DIR/DEBIAN/control"
sed -i "s/^Architecture:.*/Architecture: $ARCH/" "$PKG_DIR/DEBIAN/control" 2>/dev/null \
  || sed "s/^Architecture:.*/Architecture: $ARCH/" "$PKG_DIR/DEBIAN/control" > "$PKG_DIR/DEBIAN/control.tmp" \
  && mv "$PKG_DIR/DEBIAN/control.tmp" "$PKG_DIR/DEBIAN/control"

dpkg-deb --build "$PKG_DIR" "domain-probe_${VERSION}_${ARCH}.deb"
echo "Built: domain-probe_${VERSION}_${ARCH}.deb"

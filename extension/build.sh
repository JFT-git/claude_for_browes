#!/bin/sh
# Build per-browser extension folders + zips from the shared sources.
#   ./build.sh            -> dist/chrome, dist/firefox (+ .zip)
# Run ../configure.sh <gateway-host> FIRST so the placeholders are filled in.
set -e
cd "$(dirname "$0")"
SHARED="background.js popup.html popup.js options.html options.js rules.json fingerprint.js icon48.png icon128.png"
rm -rf dist && mkdir -p dist
for b in chrome firefox; do
  mkdir -p "dist/$b"
  for f in $SHARED; do cp "$f" "dist/$b/$f"; done
  cp "manifest.$b.json" "dist/$b/manifest.json"
  (cd "dist/$b" && zip -qr "../claude-gateway-$b.zip" .)
done
echo "Built: dist/chrome  dist/firefox  (zips in dist/)"

#!/bin/sh
# Build per-browser extension folders + zips from the shared sources.
# One build for all domains — the user enters their gateway host in Options.
set -e
cd "$(dirname "$0")"
SHARED="background.js artifact-csp.js artifact-debugger.js popup.html popup.js options.html options.js fingerprint.js proxy-block-rules.json privacy-rules.js icon48.png icon128.png"
rm -rf dist && mkdir -p dist
for b in chrome firefox; do
  mkdir -p "dist/$b"
  for f in $SHARED; do cp "$f" "dist/$b/$f"; done
  cp "manifest.$b.json" "dist/$b/manifest.json"
  (cd "dist/$b" && zip -qr "../claude-gateway-$b.zip" .)
done
echo "Built: dist/chrome  dist/firefox  (zips in dist/)"

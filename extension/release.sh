#!/bin/sh
# Build UNCONFIGURED (placeholder) packages into ../releases/ for publishing in the repo.
# Run on a clean checkout (before ./configure.sh), otherwise placeholders are already replaced.
set -e
cd "$(dirname "$0")"
V=$(sed -n 's/.*"version": "\(.*\)".*/\1/p' manifest.chrome.json | head -1)
./build.sh >/dev/null
mkdir -p ../releases
cp dist/claude-gateway-chrome.zip  "../releases/claude-gateway-chrome-v$V.zip"
cp dist/claude-gateway-firefox.zip "../releases/claude-gateway-firefox-v$V.zip"
( cd ../releases && shasum -a 256 *.zip > SHA256SUMS )
echo "Release v$V written to releases/"

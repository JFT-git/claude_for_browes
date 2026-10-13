#!/bin/sh
# Full Firefox release in one command:
#   build -> sign on AMO (unlisted) -> attach signed XPI to the GitHub release -> updates.json
#
# Needs (one-time):
#   export AMO_API_KEY=...      # JWT issuer  from https://addons.mozilla.org/developers/ -> API Keys
#   export AMO_API_SECRET=...   # JWT secret
#   gh auth login               # for the release upload
set -e
cd "$(dirname "$0")"
[ -n "${AMO_API_KEY:-}" ] && [ -n "${AMO_API_SECRET:-}" ] || { echo "Set AMO_API_KEY and AMO_API_SECRET first"; exit 1; }
V=$(sed -n 's/.*"version": "\(.*\)".*/\1/p' manifest.firefox.json | head -1)
echo "== Building v$V"
./build.sh >/dev/null
echo "== Signing on AMO (unlisted)"
rm -rf dist/amo-signed
npx --yes web-ext sign --source-dir dist/firefox --artifacts-dir dist/amo-signed \
  --channel unlisted --api-key "$AMO_API_KEY" --api-secret "$AMO_API_SECRET"
XPI=$(ls dist/amo-signed/*.xpi 2>/dev/null | head -1)
[ -f "$XPI" ] || { echo "ERROR: no signed XPI produced"; exit 1; }
OUT="gateway-connector-firefox-$V.xpi"
cp "$XPI" "../$OUT"
echo "== Attaching to GitHub release v$V"
gh release upload "v$V" "../$OUT" --repo JFT-git/claude_for_browes --clobber
echo "== Updating updates.json"
python3 update-updates-json.py "$V" ../updates.json
rm -f "../$OUT"
echo "Done. Commit + push updates.json, and (optionally) copy the xpi to your gateway:"
echo "  scp $XPI root@<server>:/root/claude-browser/extension/gateway-connector-firefox.xpi"

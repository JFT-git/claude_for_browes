#!/bin/sh
# Extract a prebuilt add-on. Configure the gateway and credentials in Options.
# Usage: ./configure-prebuilt.sh <chrome|firefox> [gateway-host]
# The optional host is a reminder only; packages are identical for every gateway.
set -eu
BROWSER=${1:-}
HOST=${2:-}
case "$BROWSER" in chrome|firefox) ;; *) echo "Usage: $0 <chrome|firefox> [gateway-host]" >&2; exit 1;; esac
[ "$#" -le 2 ] || { echo "Usage: $0 <chrome|firefox> [gateway-host]" >&2; exit 1; }
if [ -n "$HOST" ]; then
  case "$HOST" in *[!a-zA-Z0-9.-]*) echo 'Invalid gateway host: supply a domain without URL, credentials or path.' >&2; exit 1;; esac
  printf '%s\n' "$HOST" | awk -F. '
    NF < 2 {exit 1}
    {for(i=1;i<=NF;i++) if(length($i)>63 || $i !~ /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/) exit 1}
    length($0)>253 {exit 1}' || { echo 'Invalid gateway host.' >&2; exit 1; }
fi
cd "$(dirname "$0")"
# Numeric component sorting works on both macOS and Linux (including 9 -> 10).
VERSION=$(
  for package in "claude-gateway-$BROWSER"-v*.zip; do
    [ -f "$package" ] || continue
    version=${package#"claude-gateway-$BROWSER-v"}; version=${version%.zip}
    case "$version" in (''|*[!0-9.]*) continue;; esac
    printf '%s\n' "$version" | awk -F. 'NF==3 && $1!="" && $2!="" && $3!="" {print}'
  done | sort -t. -k1,1n -k2,2n -k3,3n | tail -1
)
[ -n "$VERSION" ] || { echo "No prebuilt $BROWSER package found beside this script." >&2; exit 1; }
ZIP="claude-gateway-$BROWSER-v$VERSION.zip"
OUT="claude-gateway-$BROWSER"
TMP=$(mktemp -d "./.configure-prebuilt.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
unzip -q "$ZIP" -d "$TMP"
[ -f "$TMP/manifest.json" ] && [ -f "$TMP/options.html" ] && [ -f "$TMP/options.js" ] || {
  echo 'Package is not an Options-configured build; download a current release.' >&2; exit 1;
}
# Validate extraction before replacing any previous output. Never rewrite files:
# rules.json is absent in current builds; Options stores settings in the browser.
rm -rf "$OUT"
mv "$TMP" "$OUT"
printf 'Ready: %s/%s (from %s)\n' "$(pwd)" "$OUT" "$ZIP"
printf '%s\n' 'Load the folder in your browser, then open extension Options and enter your gateway host and credentials.'
[ -z "$HOST" ] || printf 'Gateway host to enter in Options: %s\n' "$HOST"

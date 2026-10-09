#!/bin/sh
# Turn a prebuilt (placeholder) package into a ready-to-load folder for your gateway.
# Usage: ./configure-prebuilt.sh <chrome|firefox> <gateway-host>
#   e.g. ./configure-prebuilt.sh chrome claude.example.com   ->  ./claude-gateway-chrome/
set -e
B="$1"; HOST="$2"
case "$B" in chrome|firefox) ;; *) echo "Usage: $0 <chrome|firefox> <gateway-host>"; exit 1;; esac
[ -n "$HOST" ] || { echo "Usage: $0 <chrome|firefox> <gateway-host>"; exit 1; }
cd "$(dirname "$0")"
ZIP=$(ls claude-gateway-$B-v*.zip | sort | tail -1)
DOMAIN=$(echo "$HOST" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
OUT="claude-gateway-$B"
rm -rf "$OUT" && mkdir "$OUT" && unzip -q "$ZIP" -d "$OUT"
for f in manifest.json rules.json background.js; do
  sed -i.bak "s/__GATEWAY_HOST__/$HOST/g; s/__GATEWAY_DOMAIN__/$DOMAIN/g" "$OUT/$f" && rm "$OUT/$f.bak"
done
echo "Ready: releases/$OUT  (from $ZIP)"

#!/bin/sh
# Runs tests/fingerprint.html in headless Chrome with a Russian machine profile
# (TZ=Europe/Moscow, --lang=ru-RU) with and without the fingerprint script.
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
cd "$(dirname "$0")/.."
for q in "" "?spoof"; do
  echo "== ${q:-baseline (no spoofing)}"
  TZ=Europe/Moscow "$CHROME" --headless=new --disable-gpu --lang=ru-RU --accept-lang=ru-RU \
    --virtual-time-budget=3000 --dump-dom "file://$PWD/tests/fingerprint.html$q" 2>/dev/null \
    | sed -n 's/.*<pre id="out">\(.*\)<\/pre>.*/\1/p' | sed 's/&quot;/"/g'
done

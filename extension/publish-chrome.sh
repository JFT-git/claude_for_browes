#!/bin/sh
# Upload the current Chrome build to the Chrome Web Store and submit it for review.
# The item must already exist (first listing is created by hand in the dashboard).
#
# Needs:
#   CWS_CLIENT_ID CWS_CLIENT_SECRET CWS_REFRESH_TOKEN
#   CWS_PUBLISHER_ID CWS_EXTENSION_ID
# See docs/PUBLISH.md.
set -e
cd "$(dirname "$0")/.."

for v in CWS_CLIENT_ID CWS_CLIENT_SECRET CWS_REFRESH_TOKEN CWS_PUBLISHER_ID CWS_EXTENSION_ID; do
  eval "[ -n \"\${$v:-}\" ]" || { echo "Missing $v"; exit 1; }
done

V=$(sed -n 's/.*"version": "\(.*\)".*/\1/p' extension/manifest.chrome.json | head -1)
ZIP="releases/claude-gateway-chrome-v$V.zip"
[ -f "$ZIP" ] || { echo "Missing $ZIP — run ./extension/release.sh first"; exit 1; }

TOKEN=$(curl -fsS https://oauth2.googleapis.com/token \
  --data-urlencode "client_id=$CWS_CLIENT_ID" \
  --data-urlencode "client_secret=$CWS_CLIENT_SECRET" \
  --data-urlencode "refresh_token=$CWS_REFRESH_TOKEN" \
  --data-urlencode "grant_type=refresh_token" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

echo "Uploading $ZIP (v$V) to item $CWS_EXTENSION_ID"
HTTP=$(curl -sS -o /tmp/cws-upload.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/zip" \
  -X POST --data-binary @"$ZIP" \
  "https://chromewebstore.googleapis.com/upload/v2/publishers/${CWS_PUBLISHER_ID}/items/${CWS_EXTENSION_ID}:upload")
python3 -m json.tool /tmp/cws-upload.json || cat /tmp/cws-upload.json
echo

if [ "$HTTP" != "200" ]; then
  # A push that does not bump the manifest version must not fail the release.
  if grep -Eqi "version|already" /tmp/cws-upload.json; then
    echo "Chrome Web Store refused v$V (already uploaded or version not increased) — skipping"
    exit 0
  fi
  echo "Upload failed (HTTP $HTTP)"
  exit 1
fi

echo "Submitting for review"
HTTP=$(curl -sS -o /tmp/cws-publish.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -X POST \
  "https://chromewebstore.googleapis.com/v2/publishers/${CWS_PUBLISHER_ID}/items/${CWS_EXTENSION_ID}:publish")
python3 -m json.tool /tmp/cws-publish.json || cat /tmp/cws-publish.json
echo
if [ "$HTTP" != "200" ]; then
  echo "Publish failed (HTTP $HTTP). If the dashboard says to publish once by hand, do that, then re-run."
  exit 1
fi
echo "Chrome Web Store: v$V submitted for review"

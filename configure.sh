#!/bin/sh
# Generate a domain-specific Caddyfile, preserving generated authentication.
# compose.yaml reads PUBLIC_HOST and CONNECT_HOST from the deployment .env.
set -eu
cd "$(dirname "$0")"
. ./server/install-lib.sh
HOST=${1:-}
valid_domain "$HOST" || { echo 'Usage: ./configure.sh <gateway-domain> [public-connect-ip]' >&2; exit 1; }
CONNECT_IP=${2:-${CONNECT_HOST:-$(env_get server/.env CONNECT_HOST)}}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/claude-configure.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
caddy_users server/Caddyfile > "$TMP/users"
if [ -s "$TMP/users" ]; then
  valid_public_ipv4 "$CONNECT_IP" || { echo 'Existing users preserved. Supply CONNECT_HOST (public IPv4) to validate the new Caddyfile.' >&2; exit 1; }
  render_caddy "$HOST" "$TMP/users" server/Caddyfile.template "$TMP/Caddyfile"
  validate_caddy "$TMP/Caddyfile" "$CONNECT_IP" "${FRONTDOOR_IP:-172.30.240.2}"
else
  # A template with placeholders is only a preparation step, not a live config.
  if [ -f server/Caddyfile ] && ! grep -q '__BASIC_AUTH_USER__' server/Caddyfile; then
    echo 'Existing Caddyfile has no recognizable users; refusing to replace it.' >&2; exit 1
  fi
  sed "s/__DOMAIN__/$HOST/g" server/Caddyfile.template > "$TMP/Caddyfile"
fi
sh ./extension/build.sh
umask 077
CANDIDATE=$(mktemp "$(pwd)/server/.Caddyfile.XXXXXX")
cp "$TMP/Caddyfile" "$CANDIDATE"
chmod 600 "$CANDIDATE"
mv "$CANDIDATE" server/Caddyfile
printf '%s\n' 'Generated server/Caddyfile; existing password hashes preserved.' 'Set PUBLIC_HOST and CONNECT_HOST in the deployment .env, or run ./install.sh.'

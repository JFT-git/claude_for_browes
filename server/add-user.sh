#!/bin/sh
# Add a user or reset a password. Run from the deployment directory.
set -eu
. "$(dirname "$0")/install-lib.sh"
USERNAME=${1:-}
PASSWORD=${2:-}
valid_user "$USERNAME" || { echo 'Error: username needs 1–64 ASCII letters, digits, dots, dashes or underscores; . and .. are invalid.' >&2; exit 1; }
[ -f Caddyfile ] || { echo 'Error: run from the deployment directory (Caddyfile missing).' >&2; exit 1; }
GENERATED=0
if [ -z "$PASSWORD" ]; then PASSWORD=$(openssl rand -hex 12); GENERATED=1; fi
[ "${#PASSWORD}" -ge 12 ] || { echo 'Error: password must be at least 12 characters.' >&2; exit 1; }
HASH=$(hash_password "$PASSWORD")
CANDIDATE=$(mktemp "$(pwd)/.Caddyfile.XXXXXX")
trap 'rm -f "$CANDIDATE"' EXIT HUP INT TERM
U="$USERNAME" H="$HASH" awk '
  /^[[:space:]]*basic_auth([[:space:]]|\{)/ {auth=1; print; print "            " ENVIRON["U"] " " ENVIRON["H"]; inserted=1;next}
  auth && /^[[:space:]]*}/ {auth=0}
  auth && $1 == ENVIRON["U"] && $2 ~ /^\$2/ {next}
  {print}
  END {if (!inserted) exit 1}' Caddyfile > "$CANDIDATE"
validate_caddy "$CANDIDATE" "$(env_get .env CONNECT_HOST)" "$(env_get .env FRONTDOOR_IP)"
chmod 600 "$CANDIDATE"
mv "$CANDIDATE" Caddyfile
umask 077
mkdir -p gateway/cookies
chmod 700 gateway/cookies
[ -f "gateway/cookies/$USERNAME.json" ] || printf '%s\n' '{"cookies":[]}' > "gateway/cookies/$USERNAME.json"
chmod 600 "gateway/cookies/$USERNAME.json"
docker compose restart caddy
printf 'User ready: %s\n' "$USERNAME"
if [ "$GENERATED" = 1 ]; then printf 'Password (shown once): %s\n' "$PASSWORD"; fi

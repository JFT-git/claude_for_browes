#!/bin/sh
# Restore a backup made by backup.sh into the current project dir.
# Usage: ./restore.sh backups/state-YYYYmmdd-HHMMSS.tar.gz.enc
set -e
cd "$(dirname "$0")"
F="$1"; KEY="${BACKUP_KEY_FILE:-/root/.claude-gateway-backup.key}"
[ -f "$F" ] || { echo "Usage: ./restore.sh <backup-file>"; exit 1; }
[ -f "$KEY" ] || { echo "backup key $KEY not found (put your saved key there)"; exit 1; }
printf "This overwrites gateway/cookies, Caddyfile and .env. Continue? [y/N] "
read -r a; [ "$a" = "y" ] || exit 1
openssl enc -d -aes-256-cbc -pbkdf2 -pass "file:$KEY" < "$F" | tar xzf - -C .
docker compose up -d >/dev/null 2>&1 && docker compose restart >/dev/null 2>&1 || true
echo "restored from $F"

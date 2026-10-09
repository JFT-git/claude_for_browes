#!/bin/sh
# Encrypted backup of everything needed to restore the server state:
#   gateway/cookies (user sessions), Caddyfile (users + password hashes), .env (secrets).
# The archive is encrypted with AES-256 using the key in $BACKUP_KEY_FILE (default /root/.claude-gateway-backup.key).
# KEEP A COPY OF THAT KEY OUTSIDE THE SERVER — without it backups cannot be restored.
#
# Usage:   ./backup.sh            (installed in cron by install.sh)
# Optional env: BACKUP_KEEP=14   BACKUP_REMOTE=user@host:/path  (copied with scp)
set -e
cd "$(dirname "$0")"
KEY="${BACKUP_KEY_FILE:-/root/.claude-gateway-backup.key}"
KEEP="${BACKUP_KEEP:-14}"
[ -f "$KEY" ] || { echo "backup key $KEY not found"; exit 1; }
umask 077
mkdir -p backups
OUT="backups/state-$(date +%Y%m%d-%H%M%S).tar.gz.enc"
FILES="gateway/cookies Caddyfile"
[ -f .env ] && FILES="$FILES .env"
# shellcheck disable=SC2086
tar czf - $FILES | openssl enc -aes-256-cbc -pbkdf2 -salt -pass "file:$KEY" > "$OUT"
echo "backup written: $OUT ($(wc -c < "$OUT") bytes)"
# keep the newest $KEEP archives
ls -1t backups/state-*.tar.gz.enc 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r f; do rm -f "$f"; done
if [ -n "$BACKUP_REMOTE" ]; then
  scp -q -o BatchMode=yes "$OUT" "$BACKUP_REMOTE" && echo "copied to $BACKUP_REMOTE" || echo "WARNING: remote copy failed"
fi

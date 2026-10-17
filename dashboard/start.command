#!/bin/sh
# Opens the gateway dashboard. macOS: double-click this file in Finder.
# Linux: sh dashboard/start.command. The first run asks for the server address.
PATH="$PATH:/opt/homebrew/bin:/usr/local/bin"
cd "$(dirname "$0")/.." || exit 1
pause() { printf '\nНажмите Enter, чтобы закрыть окно.'; read -r _; }
if ! command -v node >/dev/null 2>&1 || ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) < 18 ? 1 : 0)'; then
  echo 'Нужен Node.js 18 или новее: https://nodejs.org (или brew install node).'
  pause; exit 1
fi
node dashboard/dashboard.js "$@" || { pause; exit 1; }

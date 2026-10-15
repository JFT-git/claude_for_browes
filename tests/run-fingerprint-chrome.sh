#!/bin/sh
# Fails if Chromium cannot start, the page throws, or any assertion fails.
set -eu
cd "$(dirname "$0")/.."
exec node tests/run-fingerprint-chrome.js "$@"

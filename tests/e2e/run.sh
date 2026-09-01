#!/bin/sh
# Run the browser journeys against a mocked Wazuh API.
#
#   tests/e2e/run.sh
#
# Needs docker for the browser; nothing else is installed on the host. The mock
# server is started here and stopped on the way out, including on failure, so a
# stray process cannot hold the port and make the next run look broken.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PORT=${E2E_PORT:-5178}
IMAGE=${E2E_IMAGE:-zenika/alpine-chrome:with-puppeteer}
LOG=$(mktemp)
PY=${PYTHON:-python3}

cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -f "$LOG"
}
trap cleanup EXIT INT TERM

echo "starting the mocked API on 127.0.0.1:$PORT"
E2E_PORT="$PORT" "$PY" "$ROOT/tests/e2e/mock_api.py" >"$LOG" 2>&1 &
SERVER_PID=$!

i=0
until curl -sf -o /dev/null "http://127.0.0.1:$PORT/login"; do
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then
    echo "the server did not come up:"; cat "$LOG"; exit 1
  fi
  sleep 1
done

# The image keeps puppeteer in its own working directory, which is not on the
# module path for a script mounted elsewhere.
docker run --rm --network host \
  -v "$ROOT/tests/e2e:/e2e:ro" \
  -e NODE_PATH=/usr/src/app/node_modules \
  -e E2E_BASE="http://127.0.0.1:$PORT" \
  "$IMAGE" node /e2e/journeys.js

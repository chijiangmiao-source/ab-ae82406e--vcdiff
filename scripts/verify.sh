#!/bin/sh
# One-shot verification gate:
#   1. build check (byte-compile every Python module)
#   2. decoder unit tests (pytest)
#   3. interface / HTTP smoke against a live server
# Exits non-zero on the first failing stage.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-18080}"
# When BASE_URL is provided (e.g. the compose "web" service), smoke tests hit
# it directly; otherwise this script boots a throwaway server locally.
BASE_URL="${BASE_URL:-}"

echo "== [1/3] decoder unit tests =="
python3 -m pytest tests/test_vcdiff.py tests/test_http.py -q

echo "== [2/3] build check: compileall =="
python3 -m compileall -q app scripts tests

echo "== [3/3] interface / HTTP smoke =="
STARTED=""
if [ -z "$BASE_URL" ]; then
  BASE_URL="http://127.0.0.1:${PORT}"
  HOST=127.0.0.1 PORT="$PORT" python3 app/server.py &
  SERVER_PID=$!
  STARTED=1
fi

cleanup() {
  if [ -n "$STARTED" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

python3 scripts/smoke_http.py --base-url "$BASE_URL"

echo "== verify: all stages passed =="

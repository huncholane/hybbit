#!/usr/bin/env bash
# The generate-route pair: a second Node backend on :3058 (preloaded to send
# OpenRouter calls to the mock) and a Rust backend on :3059 pointed at the same
# mock, plus the mock on :3070. Usage: run-generate-backends.sh node|rust|mock
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export OPENROUTER_API_KEY=parity-mock-key
mock_url=http://127.0.0.1:3070/api/v1/chat/completions
case "$1" in
  mock) exec python3 "$here/openrouter_mock.py" 3070 ;;
  node)
    export NODE_ALT_PORT=3058 OPENROUTER_MOCK_URL="$mock_url"
    cd "${HYGO_MAIN_CHECKOUT:-/home/huncho/code/hygo/repo/hybbit}/server"
    exec npx tsx --import "$here/node_mock_preload.mjs" src/index.ts
    ;;
  rust)
    export PORT=3059 OPENROUTER_API_URL="$mock_url"
    exec "$here/run-rust.sh"
    ;;
esac

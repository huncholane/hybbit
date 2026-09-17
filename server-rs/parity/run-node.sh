#!/usr/bin/env bash
# Node backend on :3001 (its port is hard-coded) against the parity stores, as a
# single process. Stop it with: pkill -f "[t]sx src/index.ts"
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/env.sh"
cd "$here/../../server"
exec npx tsx src/index.ts

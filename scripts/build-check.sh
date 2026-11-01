#!/usr/bin/env bash
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
LINUX_PROJECT="${PROJECT_DIR:-$HOME/iot-analyzer}"
cd "$LINUX_PROJECT"
echo "=== STEP 1: TYPECHECK ==="
pnpm run typecheck
echo "=== STEP 2: BUILD ==="
pnpm run build

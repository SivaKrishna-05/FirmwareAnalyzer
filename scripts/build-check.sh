#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
cd /home/sivakrishna/iot-analyzer
echo "=== STEP 1: TYPECHECK ==="
pnpm run typecheck
echo "=== STEP 2: BUILD ==="
pnpm run build

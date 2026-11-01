#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
cd /mnt/e/IoT-Firmware-Security-Analyzer-phase4/IoT-Firmware-Security-Analyzer/artifacts/api-server

echo "=== Building API Server ==="
node build.mjs
echo "Exit: $?"
echo "=== Dist contents: ==="
ls -la dist/ 2>&1

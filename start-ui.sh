#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
export PORT=5173
export BASE_PATH=/
export VITE_API_URL=http://localhost:5000

cd /mnt/e/IoT-Firmware-Security-Analyzer-phase4/IoT-Firmware-Security-Analyzer
echo "Starting Frontend on http://localhost:5173 ..."
pnpm --filter firmware-analyzer dev --host 0.0.0.0

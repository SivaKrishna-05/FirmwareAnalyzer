#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/iot_firmware"
export CORS_ALLOWED_ORIGINS="http://localhost:5173"
export NODE_ENV="development"

echo "=== Starting IoT Firmware Analyzer API (port 5000) ==="
node --enable-source-maps /home/sivakrishna/iot-analyzer/artifacts/api-server/dist/index.mjs
echo "API exited with: $?"

#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/iot_firmware"
export CORS_ALLOWED_ORIGINS="http://localhost:5173"
export NODE_ENV="development"

TSX="/mnt/e/IoT-Firmware-Security-Analyzer-phase4/IoT-Firmware-Security-Analyzer/node_modules/.pnpm/node_modules/.bin/tsx"
SRC="/mnt/e/IoT-Firmware-Security-Analyzer-phase4/IoT-Firmware-Security-Analyzer/artifacts/api-server/src/index.ts"

echo "=== IoT Firmware Analyzer - API Server ==="
echo "Starting on http://localhost:5000 ..."
echo ""
"$TSX" "$SRC"

#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/iot_firmware"
export CORS_ALLOWED_ORIGINS="http://localhost:5173"
export NODE_ENV="development"

TSX="$SCRIPT_DIR/node_modules/.pnpm/node_modules/.bin/tsx"
SRC="$SCRIPT_DIR/artifacts/api-server/src/index.ts"

echo "=== IoT Firmware Analyzer - API Server ==="
echo "Starting on http://localhost:5000 ..."
echo ""
"$TSX" "$SRC"

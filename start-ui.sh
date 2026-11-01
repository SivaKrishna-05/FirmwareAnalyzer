#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
export PORT=5173
export BASE_PATH=/
export VITE_API_URL=http://localhost:5000

cd "$SCRIPT_DIR"
echo "Starting Frontend on http://localhost:5173 ..."
pnpm --filter firmware-analyzer dev --host 0.0.0.0

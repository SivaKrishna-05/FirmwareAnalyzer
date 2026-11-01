#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
cd "$SCRIPT_DIR/artifacts/api-server"

echo "=== Building API Server ==="
node build.mjs
echo "Exit: $?"
echo "=== Dist contents: ==="
ls -la dist/ 2>&1

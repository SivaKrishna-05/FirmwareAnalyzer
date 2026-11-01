#!/usr/bin/env bash
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
LINUX_PROJECT="${PROJECT_DIR:-$HOME/iot-analyzer}"
cd "$LINUX_PROJECT/artifacts/api-server"
../../node_modules/.pnpm/node_modules/.bin/tsx src/lib/test-e2e-matrix.ts

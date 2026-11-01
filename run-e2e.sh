#!/usr/bin/env bash
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
LINUX_PROJECT="${PROJECT_DIR:-$HOME/iot-analyzer}"
cd "$LINUX_PROJECT"
npx tsx artifacts/api-server/src/lib/e2e-firmware-test.ts > "$HOME/e2e-output.log" 2>&1
echo "Exit code: $?" >> "$HOME/e2e-output.log"
cat "$HOME/e2e-output.log"

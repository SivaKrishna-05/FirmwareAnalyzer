#!/usr/bin/env bash
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
LINUX_PROJECT="${PROJECT_DIR:-$HOME/iot-analyzer}"
cd "$LINUX_PROJECT"
pnpm test

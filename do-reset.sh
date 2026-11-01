#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
LINUX_PROJECT="${PROJECT_DIR:-$HOME/iot-analyzer}"
cd "$LINUX_PROJECT"

EMAIL="${1:-admin@example.com}"
PASSWORD="${2:-AdminPassword@123}"

node "$SCRIPT_DIR/reset-password.mjs" "$EMAIL" "$PASSWORD"

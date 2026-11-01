#!/usr/bin/env bash
# Setup IoT Firmware Analyzer in WSL native filesystem
# Run once to set up, then use start-from-linux.sh to start

export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
PROJECT_WIN="/mnt/e/IoT-Firmware-Security-Analyzer-phase4/IoT-Firmware-Security-Analyzer"
PROJECT_LINUX="/home/sivakrishna/iot-analyzer"

echo "[1/4] Syncing source code to Linux filesystem..."
mkdir -p "$PROJECT_LINUX"
rsync -av --exclude='node_modules' --exclude='dist' --exclude='.git' \
  "$PROJECT_WIN/" "$PROJECT_LINUX/"

echo "[2/4] Installing dependencies in Linux native filesystem..."
cd "$PROJECT_LINUX"
pnpm install

echo "[3/4] Running DB migrations..."
node lib/db/src/migrate.mjs

echo "[4/4] Building API server..."
cd "$PROJECT_LINUX/artifacts/api-server"
node build.mjs

echo ""
echo "✔ Setup complete! Run start-from-linux.sh to start the app."

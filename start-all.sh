#!/usr/bin/env bash
# Run this script once to start EVERYTHING: PostgreSQL + API + Frontend
# Usage: wsl bash /mnt/e/.../start-all.sh

export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/iot_firmware"
export CORS_ALLOWED_ORIGINS="http://localhost:5173"
export NODE_ENV="development"
LINUX_PROJECT="/home/sivakrishna/iot-analyzer"

echo "=== [1/3] Starting PostgreSQL ==="
echo sivakrishna | sudo -S service postgresql start
pg_isready -h localhost -p 5432 || { echo "ERROR: PostgreSQL not ready"; exit 1; }

echo ""
echo "=== [2/3] Starting API Server on http://localhost:5000 ==="
node --enable-source-maps "$LINUX_PROJECT/artifacts/api-server/dist/index.mjs" &
API_PID=$!
sleep 3
if kill -0 $API_PID 2>/dev/null; then
  echo "✔ API Server running (PID $API_PID)"
else
  echo "✘ API Server failed to start"
  exit 1
fi

echo ""
echo "=== [3/3] Starting Frontend on http://localhost:5173 ==="
echo ""
echo "╔════════════════════════════════════════╗"
echo "║  App ready at: http://localhost:5173   ║"
echo "║  API ready at: http://localhost:5000   ║"
echo "╚════════════════════════════════════════╝"
echo ""
cd "$LINUX_PROJECT"
PORT=5173 BASE_PATH=/ pnpm --filter firmware-analyzer dev --host 0.0.0.0

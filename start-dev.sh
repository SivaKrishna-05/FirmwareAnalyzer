#!/usr/bin/env bash
set -e
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"

PROJECT="/mnt/e/IoT-Firmware-Security-Analyzer-phase4/IoT-Firmware-Security-Analyzer"

echo "=== Starting PostgreSQL ==="
sudo service postgresql start
pg_isready -h localhost -p 5432

echo ""
echo "=== Running DB Migrations ==="
cd "$PROJECT"
pnpm --filter @workspace/db run migrate

echo ""
echo "=== Building API Server ==="
cd "$PROJECT"
pnpm --filter @workspace/api-server run build

echo ""
echo "=== Starting API Server on port 5000 ==="
PORT=5000 BASE_PATH=/ CORS_ALLOWED_ORIGINS=http://localhost:5173 pnpm --filter @workspace/api-server run start &
API_PID=$!
sleep 4

echo "API Server PID: $API_PID"

# Test if API is alive
curl -s http://localhost:5000/api/scans > /dev/null && echo "API Server is UP on http://localhost:5000" || echo "WARNING: API Server may not be ready yet"

echo ""
echo "=== Starting Frontend on port 5173 ==="
PORT=5173 BASE_PATH=/ VITE_API_BASE_URL=http://localhost:5000 pnpm --filter firmware-analyzer dev --host 0.0.0.0

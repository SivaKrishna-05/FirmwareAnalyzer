#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
cd /home/sivakrishna/iot-analyzer/artifacts/api-server
../../node_modules/.pnpm/node_modules/.bin/tsx src/lib/test-e2e-matrix.ts

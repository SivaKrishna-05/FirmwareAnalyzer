#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"
cd /home/sivakrishna/iot-analyzer
npx tsx artifacts/api-server/src/lib/e2e-firmware-test.ts > /home/sivakrishna/e2e-output.log 2>&1
echo "Exit code: $?" >> /home/sivakrishna/e2e-output.log
cat /home/sivakrishna/e2e-output.log

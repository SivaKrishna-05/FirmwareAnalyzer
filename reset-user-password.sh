#!/usr/bin/env bash
export PATH="/home/sivakrishna/.nvm/versions/node/v24.21.0/bin:$PATH"

EMAIL="${1:-sivakrishnapothuraju3@gmail.com}"
NEW_PW="${2:-SivaKrishna@123}"

echo "Generating scrypt hash for: $EMAIL"
OUTPUT=$(node /mnt/e/IoT-Firmware-Security-Analyzer-phase4/IoT-Firmware-Security-Analyzer/generate-hash.mjs "$NEW_PW")

HASH=$(echo "$OUTPUT" | sed -n '1p')
SALT=$(echo "$OUTPUT" | sed -n '2p')
PARAMS=$(echo "$OUTPUT" | sed -n '3p')

echo "Updating PostgreSQL database..."
PGPASSWORD=postgres psql -h localhost -U postgres -d iot_firmware <<EOF
UPDATE users 
SET password_hash = '$HASH',
    password_salt = '$SALT',
    password_params = '$PARAMS'::jsonb,
    failed_login_count = 0,
    locked_until = NULL
WHERE LOWER(email) = LOWER('$EMAIL');

SELECT id, email, name, role, failed_login_count FROM users WHERE LOWER(email) = LOWER('$EMAIL');
EOF

echo ""
echo "============================================="
echo " Password Reset Successfully Completed! "
echo "============================================="
echo " Email:    $EMAIL"
echo " Password: $NEW_PW"
echo "============================================="

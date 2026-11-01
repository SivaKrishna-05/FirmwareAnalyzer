#!/usr/bin/env bash
EMAIL="${1:-admin@example.com}"
PASSWORD="${2:-AdminPassword@123}"

curl -i -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

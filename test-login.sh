#!/usr/bin/env bash
curl -i -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"sivakrishnapothuraju3@gmail.com","password":"SivaKrishna@123"}'

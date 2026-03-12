#!/usr/bin/env bash
set -euo pipefail
BASE_URL=${BASE_URL:-http://localhost:8080}
COOKIE_JAR=$(mktemp)

# Register
curl -i -sS -X POST "$BASE_URL/register" \
  -H 'Content-Type: application/json' \
  -H 'X-Client-Family: cli' \
  -d '{"email":"alice@example.com","username":"alice","password":"StrongP@ss1"}'

echo
echo "Use POST /email/verify/confirm with the token sent by your verification channel before login."

# Login
curl -i -sS -c "$COOKIE_JAR" -X POST "$BASE_URL/login" \
  -H 'Content-Type: application/json' \
  -H 'X-Client-Family: cli' \
  -d '{"identifier":"alice@example.com","password":"StrongP@ss1"}'

# Me
curl -i -sS -b "$COOKIE_JAR" "$BASE_URL/me"

rm -f "$COOKIE_JAR"

#!/usr/bin/env bash
# Checks that a running Python notes app answers: every service's page, the
# load balancer reaching both app-backend replicas, the API refusing a
# request without a token, and the admin page's rate limit, through Valkey
# and from memory with Valkey stopped. CI runs it after `up --wait`.
#
#   docker compose -f examples/notes-app/python/compose.yaml up --build --wait
#   examples/notes-app/python/smoke.sh
#
# It doesn't sign in: the app's sign-in needs a browser's WebCrypto DPoP key,
# so the note-write limit and the flows behind sign-in go unchecked here.
set -euo pipefail

compose=(docker compose -f "$(dirname "$0")/compose.yaml")

fail() {
  echo "smoke: $*" >&2
  exit 1
}

# The status of a request, its headers written to $headers.
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
status() {
  curl -sS -o /dev/null -D "$headers" -w '%{http_code}' "$@"
}

echo "the login page proxies Konklav's discovery"
discovery=$(curl -fsS http://localhost:8000/.well-known/openid-configuration)
grep -Eq '"issuer": ?"http://localhost:8000"' <<<"$discovery" || fail "unexpected discovery: $discovery"

echo "the app's page and the admin page answer"
curl -fsS -o /dev/null http://localhost:3000/
curl -fsS http://localhost:3000/config.json | grep -Eq '"client_id": ?"app"' || fail "unexpected app config"
curl -fsS -o /dev/null http://localhost:4000/

echo "the load balancer reaches both app-backend replicas"
replicas=$(for _ in 1 2 3 4 5 6; do curl -fsS http://localhost:3001/healthz; echo; done | sort -u | wc -l)
[[ $replicas -eq 2 ]] || fail "expected answers from 2 replicas, got $replicas"

echo "the API refuses a request without a token"
code=$(status http://localhost:3001/api/notes)
[[ $code == 401 ]] || fail "GET /api/notes without a token: $code, expected 401"
grep -qi '^www-authenticate:' "$headers" || fail "the 401 has no WWW-Authenticate"

# Admin writes: ten at once per address, counted before the session is
# looked up, so these are refused as signed out until the limit takes over.
admin_write() {
  status -X POST http://localhost:4000/api/users \
    -H 'x-example-admin: 1' -H 'origin: http://localhost:4000' \
    -H 'content-type: application/json' -d '{}'
}
limited() {
  local code
  for _ in $(seq 1 15); do
    code=$(admin_write)
    if [[ $code == 429 ]]; then
      grep -qiE '^retry-after: [0-9]+' "$headers" || fail "the 429 has no Retry-After"
      return 0
    fi
    [[ $code == 401 ]] || fail "admin write: $code, expected 401 or 429"
  done
  return 1
}

echo "the admin page's writes are rate limited, through Valkey"
limited || fail "no 429 after 15 admin writes"

echo "with Valkey stopped, the limit holds from memory"
"${compose[@]}" stop valkey
code=$(admin_write)
[[ $code == 429 ]] || fail "admin write with Valkey stopped: $code, expected 429"
"${compose[@]}" start valkey

echo "smoke: ok"

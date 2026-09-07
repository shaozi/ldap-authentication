#!/usr/bin/env bash
# One-shot local integration test: start the seeded LDAP test container
# (docker-compose.yml), wait until it accepts an admin bind, run `npm test`,
# then stop the container again.
set -uo pipefail
cd "$(dirname "$0")/.."

cleanup() {
  docker compose -f docker-compose.yml down
}
trap cleanup EXIT

docker compose -f docker-compose.yml up -d

for i in $(seq 1 30); do
  if node -e "
const ldapts = require('ldapts')
const c = new ldapts.Client({ url: 'ldap://localhost:1389', connectTimeout: 2000 })
c.bind('cn=read-only-admin,dc=example,dc=com', 'password')
  .then(() => { c.unbind(); process.exit(0) })
  .catch(() => process.exit(1))
"
  then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo 'LDAP server did not become ready in time' >&2
    exit 1
  fi
  sleep 2
done

INGITHUB=true npm test

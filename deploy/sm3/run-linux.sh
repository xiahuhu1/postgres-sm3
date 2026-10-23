#!/usr/bin/env bash
set -euo pipefail
# Test settings use Bash assignment syntax in the .env next to this script.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.env"
: "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env}"
export POSTGRES_PASSWORD
IMAGE="${IMAGE:-172.16.61.68:8080/library/postgres-sm3:17.10-sm3.1}"
CONTAINER="${CONTAINER:-postgres-sm3-test}"
VOLUME="${VOLUME:-postgres-sm3-test-data}"
HOST_PORT="${HOST_PORT:-55433}"
docker run -d --platform linux/amd64 --name "$CONTAINER" --restart unless-stopped \
    --shm-size=256m -p "$HOST_PORT:5432" \
    -e POSTGRES_PASSWORD -v "$VOLUME:/var/lib/postgresql/data" "$IMAGE" sh -ec '
        umask 077
        printf "%s\n" "$POSTGRES_PASSWORD" > /tmp/postgres-password
        chown postgres:postgres /tmp/postgres-password
        export POSTGRES_PASSWORD_FILE=/tmp/postgres-password
        unset POSTGRES_PASSWORD
        exec docker-entrypoint.sh postgres
    '
echo "Started $CONTAINER on port $HOST_PORT. Data volume: $VOLUME"
echo "Check: docker logs $CONTAINER; docker exec --user postgres $CONTAINER psql -d postgres"

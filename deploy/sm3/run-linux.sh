#!/bin/bash
set -eu
cd "$(dirname "$0")"
source .env
: "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env}"

docker stop "$CONTAINER" 2>/dev/null || true
docker rm -f "$CONTAINER" 2>/dev/null || true

docker run -d \
    --name "$CONTAINER" \
    --restart=always \
    -p "$HOST_PORT:5432" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$VOLUME:/var/lib/postgresql/data" \
    "$IMAGE"

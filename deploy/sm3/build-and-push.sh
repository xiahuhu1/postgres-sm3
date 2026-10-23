#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
IMAGE=${IMAGE:-172.16.61.68:8080/library/postgres-sm3:17.10-sm3.3}
docker build --platform linux/amd64 --build-arg BUILD_JOBS="${BUILD_JOBS:-4}" \
    -t "$IMAGE" -f "$ROOT/deploy/sm3/Dockerfile" "$ROOT"
[[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")" == linux/amd64 ]]
docker push "$IMAGE"
docker image inspect --format '{{json .RepoDigests}}' "$IMAGE"

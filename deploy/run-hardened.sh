#!/bin/sh
# Phase 6 hardened Banko deployment.
#
# Replaces the original posture (root, host network, whole-project bind mount) with:
#   - no host networking
#   - the database on an INTERNAL network with no route to the internet
#   - the app on two networks: internal for the database, egress-capable for the LLM API
#   - the app non-root, no-new-privileges, all capabilities dropped
#   - only the paths the app actually needs mounted, with code read-only
#   - the gateway published to 127.0.0.1 only
#
# Network layout:
#
#   banko-data (internal, no egress)      banko-lab (egress)
#     banko-cockroach  <---->  banko-app  <----> internet (OpenAI, Ollama Cloud)
#                                  |
#                          127.0.0.1:5055 published
#
#   banko-models (internal, no egress)
#     banko-ollama, reachable only from lab sandboxes joined to this network (Phase 8d)
#
# The database is reachable only from banko-data, and cannot reach the internet at all.
# banko-ollama is unpublished and reachable only from banko-models; a Tier A sandbox
# whose role map is entirely ollama_local joins banko-models instead of banko-lab, which
# is itself the MODEL04 lesson: local inference removes a route off the box, not just a
# credential. Lab sandboxes never join banko-data or banko-lab: Tier B uses
# banko-lab-isolated, Tier C uses --network none.
#
# Note on the cockroach entrypoint: the image's /cockroach/cockroach.sh wrapper refuses
# any --listen-addr whose hostname is not 127.0.0.1 or localhost. That check is in the
# wrapper, not the cockroach binary, so we invoke the binary directly. Upstream
# CockroachDB documents --listen-addr=:26257 as a supported "all interfaces" value.
#
# Revert with deploy/revert-to-host-network.sh
set -eu

REPO=/root/Documents/ML-AI-Banking-App
APP_UID=1000
APP_GID=1000

docker network inspect banko-data           >/dev/null 2>&1 || docker network create --internal banko-data           >/dev/null
docker network inspect banko-lab            >/dev/null 2>&1 || docker network create           banko-lab            >/dev/null
docker network inspect banko-lab-isolated   >/dev/null 2>&1 || docker network create --internal banko-lab-isolated   >/dev/null
docker network inspect banko-models         >/dev/null 2>&1 || docker network create --internal banko-models         >/dev/null

docker rm -f banko-app banko-cockroach >/dev/null 2>&1 || true

# Local model server (Phase 8d). Internal network only, unpublished; a named volume
# keeps pulled models across restarts. Idempotent: left running if already present.
if ! docker inspect banko-ollama >/dev/null 2>&1; then
  docker run -d \
    --name banko-ollama \
    --network banko-models \
    --memory 3g \
    --pids-limit 512 \
    --restart unless-stopped \
    -v banko-ollama-models:/root/.ollama \
    ollama/ollama:latest >/dev/null
fi

# Database. Internal network only: no egress, reachable solely by banko-data members.
docker run -d \
  --name banko-cockroach \
  --network banko-data \
  --restart unless-stopped \
  --security-opt no-new-privileges \
  -v "$REPO/cockroach-data:/cockroach/cockroach-data" \
  --entrypoint /cockroach/cockroach \
  cockroachdb/cockroach:v23.1.11 \
  start-single-node --insecure \
    --store=/cockroach/cockroach-data \
    --listen-addr=0.0.0.0:26257 \
    --advertise-addr=banko-cockroach:26257 \
    --http-addr=0.0.0.0:8091 >/dev/null

# Wait for SQL to accept connections before starting the app.
i=0
while [ "$i" -lt 40 ]; do
  if docker exec banko-cockroach /cockroach/cockroach sql --insecure \
       --host=banko-cockroach:26257 -e "SELECT 1;" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 1
done

# Application. Created first, attached to both networks, then started, so the database
# network is present before the process makes its first connection.
docker create \
  --name banko-app \
  --network banko-lab \
  --restart unless-stopped \
  --user "$APP_UID:$APP_GID" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --tmpfs /tmp \
  -p 127.0.0.1:5055:5055 \
  -e HOME=/tmp \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -e APP_HOST=0.0.0.0 \
  -e APP_PORT=5055 \
  -e BANKO_V1_DATABASE_URI="cockroachdb://root@banko-cockroach:26257/bank?sslmode=disable" \
  -e BANKO_V2_DATABASE_URI="cockroachdb://root@banko-cockroach:26257/bank_v2?sslmode=disable" \
  -w /app \
  -v "$REPO/versioned:/app/versioned:ro" \
  -v "$REPO/versioned/v1/data:/app/versioned/v1/data" \
  -v "$REPO/versioned/v1/uploads:/app/versioned/v1/uploads" \
  -v "$REPO/versioned/v2/data:/app/versioned/v2/data" \
  -v "$REPO/versioned/v2/uploads:/app/versioned/v2/uploads" \
  -v "$REPO/static:/app/static:ro" \
  -v "$REPO/config.py:/app/config.py:ro" \
  banko-app-runtime:verified \
  python -m versioned.gateway >/dev/null

docker network connect banko-data banko-app
docker start banko-app >/dev/null

echo "Hardened deployment started. Gateway: http://127.0.0.1:5055/v2"

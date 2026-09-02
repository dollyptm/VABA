#!/bin/sh
# Emergency revert to the pre-Phase-6 deployment (host networking, root, whole-project mount).
# Captured from `docker inspect` on 2026-08-07 before the Phase 6 hardening.
# This restores the ORIGINAL, UNHARDENED posture. Use only to recover a broken lab.
set -eu

REPO=/root/Documents/ML-AI-Banking-App

docker rm -f banko-app banko-cockroach 2>/dev/null || true

docker run -d \
  --name banko-cockroach \
  --network host \
  --restart unless-stopped \
  -v "$REPO/cockroach-data:/cockroach/cockroach-data" \
  cockroachdb/cockroach:v23.1.11 \
  start-single-node --insecure \
    --store=/cockroach/cockroach-data \
    --listen-addr=127.0.0.1:26257 \
    --http-addr=127.0.0.1:8091

sleep 5

docker run -d \
  --name banko-app \
  --network host \
  --restart unless-stopped \
  -v "$REPO:/app" \
  -w /app \
  -e APP_HOST=127.0.0.1 \
  -e APP_PORT=5055 \
  banko-app-runtime:verified \
  python -m versioned.gateway

echo "Reverted to the original host-network deployment."

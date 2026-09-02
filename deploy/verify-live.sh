#!/bin/sh
# Run the live route verification against the hardened deployment.
#
# The app container deliberately carries no test tooling. This runs the verifier in a
# throwaway container on the lab network that mounts the repository
# read-only, so it always executes the current files on disk. Single-file bind mounts
# would go stale whenever an editor replaced the inode.
#
# Usage: deploy/verify-live.sh [extra args passed to verify_v2_routes.py]
set -eu

REPO=/root/Documents/ML-AI-Banking-App

exec docker run --rm \
  --network banko-lab \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -e HOME=/tmp \
  -e PYTHONDONTWRITEBYTECODE=1 \
  --tmpfs /tmp \
  -v "$REPO:/work:ro" \
  -w /work \
  banko-app-runtime:verified \
  python verify_v2_routes.py --base http://banko-app:5055/v2 "$@"

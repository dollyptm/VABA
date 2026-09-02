#!/bin/sh
# Run the whole Banko V2 verification suite, staged fastest-first.
#
# The suite outgrew a single command: `verify_labs.py` alone spawns a container per lab
# run and takes several minutes. Rather than pretend it fits, this stages the work so a
# failure surfaces as early and as cheaply as possible, and so the fast checks can be run
# on their own during development.
#
# Usage:
#   deploy/verify-all.sh          run every stage
#   deploy/verify-all.sh fast     simulation + registry audit only (seconds)
#   deploy/verify-all.sh live     add containment, live routes (about a minute)
#   deploy/verify-all.sh labs     add the full behavioural lab suite (several minutes)
set -u

cd "$(dirname "$0")/.." || exit 1
STAGE="${1:-all}"
FAILED=0

run() {
  label="$1"; shift
  printf '\n=== %s ===\n' "$label"
  if "$@"; then
    return 0
  fi
  printf '!!! FAILED: %s\n' "$label"
  FAILED=$((FAILED + 1))
}

# Stage 1: no containers, no network. Seconds.
run "VABA simulation phases"   sh -c 'for f in 1 3 4 5; do python3 "verify_vaba_phase$f.py" || exit 1; done'
run "Lab registry audit"       python3 verify_lab_registry.py

if [ "$STAGE" = "fast" ]; then
  [ "$FAILED" -eq 0 ] && echo "\nALL FAST STAGES PASSED" || echo "\n$FAILED stage(s) failed"
  exit "$FAILED"
fi

# Stage 2: containers and the live app. About a minute.
run "Tier C containment"       python3 verify_lab_containment.py
run "Live V2 routes"           ./deploy/verify-live.sh

if [ "$STAGE" = "live" ]; then
  [ "$FAILED" -eq 0 ] && echo "\nALL FAST AND LIVE STAGES PASSED" || echo "\n$FAILED stage(s) failed"
  exit "$FAILED"
fi

# Stage 3: one container per lab run, both modes, all three tiers. Several minutes.
run "Lab behaviour (all tiers)" python3 verify_labs.py

if [ "$FAILED" -eq 0 ]; then
  printf '\nALL STAGES PASSED\n'
else
  printf '\n%s stage(s) failed\n' "$FAILED"
fi
exit "$FAILED"

#!/usr/bin/env python3
"""Structural audit of every registered Banko V2 lab.

This is the fast counterpart to `verify_labs.py`. It spawns no containers and makes no
model calls, so it can run in seconds and often. It checks properties that must hold for
*every* lab by construction rather than by testing each one's behaviour:

  - every lab declares a tier, and that tier exists
  - every implemented lab has a payload the broker can find
  - every implemented lab declares a headline result, so it can appear in a comparison
  - the sandbox profile for each lab actually carries its tier's containment flags
  - no lab can obtain a credential its tier is not permitted to hold
  - no lab can mount a host path
  - Tier B and C are network-restricted and Tier A is not
  - every lab's image matches its tier, including per-lab overrides

The point of auditing the registry rather than the labs is that a new lab added later
inherits these checks without anyone remembering to write them.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from versioned.v2 import lab_llm, lab_runner

sys.path.insert(0, str(Path(__file__).resolve().parent / "deploy"))
import lab_broker  # noqa: E402


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


EXPECTED_NETWORK = {"A": "--network banko-lab", "B": "--network banko-lab-isolated", "C": "--network none"}


def check_registry_shape() -> list[str]:
    implemented = []
    for lab_id, lab in lab_runner.LAB_REGISTRY.items():
        assert_true(lab.get("tier") in lab_runner.TIERS, f"{lab_id} has no valid tier")
        assert_true(bool(lab.get("title")), f"{lab_id} has no title")
        assert_true(bool(lab.get("source")), f"{lab_id} records no upstream source")
        if lab.get("implemented"):
            implemented.append(lab_id)
            assert_true(bool(lab.get("summary")), f"{lab_id} is implemented but has no summary")
            assert_true(
                bool(lab.get("headline_key")) and bool(lab.get("headline_label")),
                f"{lab_id} declares no headline result, so it cannot be compared across presets",
            )
            assert_true(
                lab_id in lab_broker.PAYLOADS,
                f"{lab_id} is marked implemented but the broker has no payload for it",
            )
            assert_true(
                lab_broker.PAYLOADS[lab_id].exists(),
                f"{lab_id} payload file is missing: {lab_broker.PAYLOADS[lab_id]}",
            )
    assert_true(implemented, "no labs are implemented")
    return implemented


def check_sandbox_profiles(implemented: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for lab_id in implemented:
        lab = lab_runner.get_lab(lab_id)
        tier_id = lab["tier"]
        counts[tier_id] = counts.get(tier_id, 0) + 1
        spec = lab_runner.build_run_spec(lab_id, "vulnerable")

        assert_true(spec["tier"] == tier_id, f"{lab_id} spec tier drifted from the registry")
        assert_true(spec["requires_sandbox"], f"{lab_id} does not require a sandbox")
        assert_true(
            not spec["executed_in_app_container"],
            f"{lab_id} claims it may run in the app container",
        )

        args = " ".join(spec["sandbox_args"])
        for flag in ("--rm", "--read-only", "--cap-drop ALL", "no-new-privileges",
                     "--user 65534:65534", "--pids-limit", "--memory"):
            assert_true(flag in args, f"{lab_id} sandbox is missing {flag!r}")
        assert_true(
            EXPECTED_NETWORK[tier_id] in args,
            f"{lab_id} (tier {tier_id}) is not on {EXPECTED_NETWORK[tier_id]!r}",
        )
        assert_true("-v " not in args, f"{lab_id} sandbox mounts a host path")

        expected_image = lab_runner.get_tier(tier_id).get("image_overrides", {}).get(
            lab_id, lab_runner.get_tier(tier_id)["image"]
        )
        assert_true(
            spec["sandbox_image"] == expected_image,
            f"{lab_id} resolved image {spec['sandbox_image']} but its tier expects {expected_image}",
        )
    return counts


def check_credential_and_mount_boundary(implemented: list[str]) -> None:
    """No lab may acquire a credential or a host mount its tier forbids."""
    for lab_id in implemented:
        tier_id = lab_runner.get_lab(lab_id)["tier"]
        tier = lab_runner.get_tier(tier_id)

        try:
            lab_runner.build_run_spec(lab_id, "vulnerable", mounts=["/root:/root"])
            raise AssertionError(f"{lab_id} accepted a host mount")
        except lab_runner.LabRunnerError:
            pass

        if not tier["credentials_allowed"]:
            for secret in ({"API_KEY": "sk-x"}, {"OLLAMA_API_KEY": "x"}, {"BANKO_V2_DATABASE_URI": "x"}):
                try:
                    lab_runner.build_run_spec(lab_id, "vulnerable", env=secret)
                    raise AssertionError(f"{lab_id} (tier {tier_id}) accepted {sorted(secret)}")
                except lab_runner.LabRunnerError:
                    pass
            for preset, meta in lab_llm.MODEL_PRESETS.items():
                if not meta["metered"]:
                    continue
                try:
                    lab_runner.build_run_spec(lab_id, "vulnerable", preset=preset)
                    raise AssertionError(
                        f"{lab_id} (tier {tier_id}) accepted metered preset {preset}"
                    )
                except lab_runner.LabRunnerError:
                    pass


def check_images_exist(implemented: list[str]) -> None:
    """Every image a lab would dispatch to must actually be present."""
    needed = set()
    for lab_id in implemented:
        needed.add(lab_runner.build_run_spec(lab_id, "vulnerable")["sandbox_image"])
    for image in sorted(needed):
        proc = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=60,
        )
        assert_true(proc.returncode == 0, f"sandbox image {image} is not built")


def check_public_surface_is_simulation_only() -> None:
    """The app must not be able to execute a lab, whatever the registry says."""
    proc = subprocess.run(
        ["docker", "exec", "banko-app", "python", "-c",
         "from versioned.v2 import lab_runner; print(lab_runner.app_can_execute_sandboxes())"],
        capture_output=True, text=True, timeout=120,
    )
    assert_true(proc.returncode == 0, f"could not query banko-app: {proc.stderr.strip()[:200]}")
    assert_true(
        proc.stdout.strip() == "False",
        "banko-app can see a Docker socket; the public surface is no longer simulation-only",
    )


def main() -> int:
    implemented = check_registry_shape()
    counts = check_sandbox_profiles(implemented)
    check_credential_and_mount_boundary(implemented)
    check_images_exist(implemented)
    check_public_surface_is_simulation_only()

    print(f"Registered labs: {len(lab_runner.LAB_REGISTRY)}  implemented: {len(implemented)}")
    for tier_id in sorted(counts):
        tier = lab_runner.get_tier(tier_id)
        print(f"  tier {tier_id} ({tier['name']:16}) {counts[tier_id]} labs  "
              f"net={tier['network']:12} credentials={'yes' if tier['credentials_allowed'] else 'no'}")
    print(
        f"\nPASS: registry shape, sandbox profiles, credential and mount boundaries, "
        f"image availability, and simulation-only public surface verified for "
        f"{len(implemented)} labs"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise

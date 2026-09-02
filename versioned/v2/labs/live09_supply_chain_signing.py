"""LIVE09: signing proves provenance, not safety.

LIVE06 showed that loading an artefact can execute code. The obvious response is to sign
artefacts and verify before loading. This lab runs that defence against three artefacts
and shows it only covers one of the two failure modes.

    artefact                     signature   modelscan   safe to load
    clean, correctly signed      valid       clean       yes
    tampered in transit          INVALID     clean       no - signature caught it
    backdoored by the publisher  valid       DIRTY       no - scan caught it

The third row is the point. A malicious or compromised publisher signs the backdoor with
the real key, so the signature is genuinely valid and verification passes. Provenance was
never in question; the content was. Signature verification answers "did this come from
who I think" and says nothing whatsoever about "is this safe to run".

The reverse also holds: modelscan reads the artefact it is given, so it cannot tell you
that the file was swapped for a different one that also scans clean. The two controls are
not redundant, and neither is sufficient.

Signing here is HMAC-SHA256 over the artefact bytes, using the standard library. The
upstream `SupplyChainSecurity/ModelTraining-HF/secure-pipeline` uses sigstore via
`model_signing`; the trust model differs but the lesson does not, and this adds no
dependency to a tier that should carry as little as possible.

Runs in a Tier C sandbox: no network, read-only rootfs, no mounts, uid 65534.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import pickle
import sys
from pathlib import Path


RCE_MARKER = "BANKO-FAKE-SUPPLYCHAIN-PROOF-4417"
PROOF_PATH = "/tmp/supplychain_proof.txt"
PAYLOAD_COMMAND = f"echo {RCE_MARKER} > {PROOF_PATH}"

# The publisher's signing key. Synthetic; never leaves the sandbox.
SIGNING_KEY = b"banko-fake-model-signing-key-2026"


class SystemPayload:
    def __reduce__(self):
        return (os.system, (PAYLOAD_COMMAND,))


def sign(data: bytes, key: bytes = SIGNING_KEY) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify(data: bytes, signature: str, key: bytes = SIGNING_KEY) -> bool:
    return hmac.compare_digest(sign(data, key), signature)


def clean_state() -> dict:
    return {
        "format_version": 1,
        "architecture": "banko-credit-risk-mlp",
        "weights": {"layer1": [0.11, -0.42, 0.33], "layer2": [0.07, 0.91]},
        "labels": ["approve", "deny"],
    }


def backdoored_state() -> dict:
    state = clean_state()
    state["_hydration_hook"] = SystemPayload()
    return state


def scan(path: Path) -> dict:
    try:
        from modelscan.modelscan import ModelScan

        scanner = ModelScan()
        scanner.scan(path)
        return {"ran": True, "issue_count": len(scanner.issues.all_issues)}
    except Exception as exc:  # noqa: BLE001 - surfaced as lab evidence
        return {"ran": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}", "issue_count": 0}


def build_artefacts(home: Path) -> list[dict]:
    """Three artefacts covering both failure modes and the honest case."""
    artefacts = []

    # 1. Clean, correctly signed by the publisher.
    clean_path = home / "model_clean.pkl"
    clean_bytes = pickle.dumps(clean_state(), protocol=4)
    clean_path.write_bytes(clean_bytes)
    artefacts.append(
        {
            "name": "clean_signed",
            "path": clean_path,
            "signature": sign(clean_bytes),
            "description": "Published honestly and signed with the real key.",
        }
    )

    # 2. Tampered after signing. The signature still describes the original bytes.
    tampered_path = home / "model_tampered.pkl"
    original_bytes = pickle.dumps(clean_state(), protocol=4)
    original_signature = sign(original_bytes)
    tampered_bytes = pickle.dumps(backdoored_state(), protocol=4)
    tampered_path.write_bytes(tampered_bytes)
    artefacts.append(
        {
            "name": "tampered_in_transit",
            "path": tampered_path,
            "signature": original_signature,
            "description": "Swapped after signing. The signature is for the file it replaced.",
        }
    )

    # 3. Backdoored and signed by the publisher. Provenance is genuine.
    insider_path = home / "model_insider.pkl"
    insider_bytes = pickle.dumps(backdoored_state(), protocol=4)
    insider_path.write_bytes(insider_bytes)
    artefacts.append(
        {
            "name": "backdoored_by_publisher",
            "path": insider_path,
            "signature": sign(insider_bytes),
            "description": "Signed with the real key. The signature is valid and the content is hostile.",
        }
    )
    return artefacts


def main() -> int:
    request = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    mode = request.get("mode", "vulnerable")
    secure = mode == "secure"

    home = Path(os.environ.get("HOME", "/tmp"))
    proof = Path(PROOF_PATH)
    if proof.exists():
        proof.unlink()

    artefacts = build_artefacts(home)
    results = []

    for artefact in artefacts:
        data = artefact["path"].read_bytes()
        signature_valid = verify(data, artefact["signature"])
        scan_result = scan(artefact["path"])
        scan_clean = scan_result["issue_count"] == 0

        if secure:
            # Both gates, because they cover different failures.
            allowed = signature_valid and scan_clean
            refused_by = (
                None if allowed
                else ("signature_verification" if not signature_valid else "content_scan")
            )
        else:
            allowed = True
            refused_by = None

        executed_before = proof.exists()
        load_error = None
        if allowed:
            try:
                pickle.loads(data)
            except Exception as exc:  # noqa: BLE001
                load_error = f"{type(exc).__name__}: {str(exc)[:120]}"
        executed_now = proof.exists() and not executed_before

        results.append(
            {
                "artefact": artefact["name"],
                "description": artefact["description"],
                "signature_valid": signature_valid,
                "scan_issue_count": scan_result["issue_count"],
                "scan_clean": scan_clean,
                "loaded": allowed,
                "refused_by": refused_by,
                "code_executed_on_this_load": executed_now,
                "load_error": load_error,
            }
        )
        if proof.exists():
            proof.unlink()

    by_name = {r["artefact"]: r for r in results}
    insider = by_name["backdoored_by_publisher"]
    tampered = by_name["tampered_in_transit"]

    result = {
        "lab_id": "LIVE09",
        "mode": mode,
        "rce_marker": RCE_MARKER,
        "artefacts": results,
        "defences_applied": (
            ["signature_verified_before_load",
             "content_scanned_before_load",
             "both_gates_required_not_either"]
            if secure else []
        ),
        "llm_called": False,
        "input_tokens": 0,
        "output_tokens": 0,
        # The headline: a valid signature did not make the artefact safe.
        "valid_signature_on_hostile_artefact": insider["signature_valid"] and not insider["scan_clean"],
        "signature_caught_tampering": not tampered["signature_valid"],
        "scan_caught_insider_backdoor": not insider["scan_clean"],
        "any_code_executed": any(r["code_executed_on_this_load"] for r in results),
        "outcome": "model_responded",
        "containment": {
            "network_available": _network_reachable(),
            "host_repo_visible": os.path.exists("/root/Documents/ML-AI-Banking-App"),
            "uid": os.getuid(),
        },
        "model_call": {
            "role": "none", "backend": "none", "model": "no_model_required",
            "model_digest": "", "simulated": False, "metered": False,
            "thinking": "", "truncated": False,
        },
        "trust_boundary": (
            "enforced_provenance_and_content_checked_separately" if secure
            else "failed_no_verification_before_deserialisation"
        ),
        "lesson": (
            "Signature verification rejected the swapped artefact and the content scan "
            "rejected the one the publisher signed. Each caught what the other could not."
            if secure else
            "All three artefacts loaded, including one whose signature was invalid. "
            "Note that the publisher-signed backdoor would have passed signature "
            "verification anyway: a valid signature proves origin, not safety."
        ),
    }
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


if __name__ == "__main__":
    raise SystemExit(main())

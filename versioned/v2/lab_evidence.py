"""Shared evidence store for Banko V2 simulated and live labs.

VABA Phases 1-5 built evidence capture inside `vaba_lab`. Phase 6 lifts it here so
the simulated scenarios and the genuinely executing labs write to one store, render
through one viewer, and clear through one reset.

Run IDs are namespaced by prefix (`vaba-` for simulated runs, `lab-` for live runs)
so a single directory holds both kinds without ambiguity, and reset can target one
kind or all of them.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


VERSION_ROOT = Path(__file__).resolve().parent
EVIDENCE_DIR = VERSION_ROOT / "data" / "vaba_runs"

KNOWN_PREFIXES = ("vaba", "lab")
RUN_ID_PATTERN = re.compile(r"^(vaba|lab)-\d{14}-[a-f0-9]{8}$")


class EvidenceError(ValueError):
    """Raised when evidence input or a run ID is invalid."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_run_id(prefix: str = "vaba") -> str:
    if prefix not in KNOWN_PREFIXES:
        raise EvidenceError(f"Unknown run ID prefix: {prefix}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:8]}"


def ensure_dir(evidence_dir: Path | str = EVIDENCE_DIR) -> Path:
    path = Path(evidence_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_run_path(run_id: str, evidence_dir: Path | str = EVIDENCE_DIR) -> Path:
    if not RUN_ID_PATTERN.match(run_id or ""):
        raise EvidenceError(f"Invalid evidence run ID: {run_id}")
    return Path(evidence_dir) / f"{run_id}.json"


def write_run(evidence: dict[str, Any], evidence_dir: Path | str = EVIDENCE_DIR) -> dict[str, Any]:
    """Atomically persist an evidence run."""
    run_id = evidence.get("run_id")
    if not RUN_ID_PATTERN.match(run_id or ""):
        raise EvidenceError(f"Invalid evidence run ID: {run_id}")

    directory = ensure_dir(evidence_dir)
    target = directory / f"{run_id}.json"
    temp_target = directory / f".{run_id}.tmp"
    with temp_target.open("w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp_target, target)
    return evidence


def read_run(run_id: str, evidence_dir: Path | str = EVIDENCE_DIR) -> dict[str, Any]:
    with safe_run_path(run_id, evidence_dir).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def list_runs(
    evidence_dir: Path | str = EVIDENCE_DIR,
    prefixes: Iterable[str] = KNOWN_PREFIXES,
) -> list[dict[str, Any]]:
    directory = ensure_dir(evidence_dir)
    paths: list[Path] = []
    for prefix in prefixes:
        paths.extend(directory.glob(f"{prefix}-*.json"))
    runs: list[dict[str, Any]] = []
    for path in sorted(paths, reverse=True):
        try:
            with path.open("r", encoding="utf-8") as handle:
                runs.append(json.load(handle))
        except Exception:
            continue
    return runs


def reset_runs(
    evidence_dir: Path | str = EVIDENCE_DIR,
    prefixes: Iterable[str] = KNOWN_PREFIXES,
) -> int:
    directory = ensure_dir(evidence_dir)
    removed = 0
    for prefix in prefixes:
        for path in directory.glob(f"{prefix}-*.json"):
            path.unlink()
            removed += 1
    return removed


def reset_v2_lab_state(
    evidence_dir: Path | str = EVIDENCE_DIR,
    spool_dir: Path | str | None = None,
    result_dir: Path | str | None = None,
) -> dict[str, int]:
    """Clear all V2 lab state: evidence, spooled run specs, and captured results.

    V2-only by construction; nothing here touches V1 paths or the `bank` database.
    """
    from . import lab_runner

    removed = {
        "vaba_evidence": reset_runs(evidence_dir, prefixes=("vaba",)),
        "live_evidence": reset_runs(evidence_dir, prefixes=("lab",)),
    }
    spool = lab_runner.reset_lab_state(
        spool_dir=spool_dir or lab_runner.SPOOL_DIR,
        result_dir=result_dir or lab_runner.RESULT_DIR,
    )
    removed["lab_specs"] = spool["specs"]
    removed["lab_results"] = spool["results"]
    removed["total"] = sum(removed.values())
    return removed

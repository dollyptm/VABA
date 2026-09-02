"""Hard API spend cap for Banko V2 Tier A labs.

Tier A labs make real model calls against a real key. This module is the control that
must exist before any of them run: it records what each run cost and refuses to
authorise a run once the cumulative cap is reached.

The cap is a hard stop, not a warning. `assert_within_budget` raises, and the broker
calls it before dispatching a Tier A sandbox, so a refusal happens before a request is
ever sent.

Prices are USD per 1M tokens and are declared here rather than fetched, so a pricing
change shows up as an obvious edit rather than a silent cost drift.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VERSION_ROOT = Path(__file__).resolve().parent
BUDGET_PATH = VERSION_ROOT / "data" / "lab_budget.json"

# USD per 1,000,000 tokens.
MODEL_PRICES: dict[str, dict[str, float]] = {
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
}

DEFAULT_MODEL = "gpt-4o-mini"

# Conservative defaults. Override with BANKO_LAB_BUDGET_USD / BANKO_LAB_RUN_CAP_USD.
TOTAL_CAP_USD = float(os.environ.get("BANKO_LAB_BUDGET_USD", "5.00"))
PER_RUN_CAP_USD = float(os.environ.get("BANKO_LAB_RUN_CAP_USD", "0.10"))

# Refuse absurd token requests before they are sent.
MAX_INPUT_TOKENS = 8000
MAX_OUTPUT_TOKENS = 2000


class BudgetError(RuntimeError):
    """Raised when a run would exceed the configured spend cap."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Backends whose per-token USD price is not published here are capped by volume instead.
# Guessing a dollar figure would be worse than refusing to guess: a run-count and
# token-count ceiling is an honest bound when the price is genuinely unknown.
UNPRICED_RUN_CAP = int(os.environ.get("BANKO_LAB_UNPRICED_RUN_CAP", "200"))
UNPRICED_TOKEN_CAP = int(os.environ.get("BANKO_LAB_UNPRICED_TOKEN_CAP", "1000000"))


def is_priced(model: str) -> bool:
    return model in MODEL_PRICES


def price_for(model: str) -> dict[str, float]:
    if model not in MODEL_PRICES:
        raise BudgetError(f"No declared price for model {model!r}; refusing to run blind")
    return MODEL_PRICES[model]


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    prices = price_for(model)
    return round(
        (input_tokens / 1_000_000) * prices["input"]
        + (output_tokens / 1_000_000) * prices["output"],
        6,
    )


def load_ledger(path: Path | str = BUDGET_PATH) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"total_usd": 0.0, "runs": []}
    try:
        with target.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {"total_usd": 0.0, "runs": []}


def save_ledger(ledger: dict[str, Any], path: Path | str = BUDGET_PATH) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_target = target.parent / f".{target.name}.tmp"
    with temp_target.open("w", encoding="utf-8") as handle:
        json.dump(ledger, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp_target, target)


def spent_usd(path: Path | str = BUDGET_PATH) -> float:
    return round(float(load_ledger(path).get("total_usd", 0.0)), 6)


def remaining_usd(path: Path | str = BUDGET_PATH) -> float:
    return round(max(0.0, TOTAL_CAP_USD - spent_usd(path)), 6)


def unpriced_position(path: Path | str = BUDGET_PATH) -> dict[str, Any]:
    ledger = load_ledger(path)
    return {
        "runs": int(ledger.get("unpriced_runs", 0)),
        "tokens": int(ledger.get("unpriced_tokens", 0)),
        "run_cap": UNPRICED_RUN_CAP,
        "token_cap": UNPRICED_TOKEN_CAP,
    }


def assert_output_ceiling(max_output_tokens: int) -> None:
    """Refuse an absurd output-token request regardless of backend or cost.

    `assert_within_budget` enforces the same `MAX_OUTPUT_TOKENS` ceiling, but the broker
    only calls it for metered backends -- `local`, `local_split`, and `stub` never went
    through any ceiling check at all. `ollama_local` has no USD cost, but it is a real,
    unthrottled, single-container, CPU-bound server: an unbounded generation length is a
    genuine resource-exhaustion vector against it independent of what anything costs.
    Found and fixed as LIVE12's own premise (this project's Model DoS / LLM04 lab): this
    check did not exist for non-metered backends until it did. Called unconditionally by
    the broker, for every run, ahead of the metered-only budget check.
    """
    if max_output_tokens > MAX_OUTPUT_TOKENS:
        raise BudgetError(f"output token request {max_output_tokens} exceeds {MAX_OUTPUT_TOKENS}")


def assert_within_budget(
    model: str = DEFAULT_MODEL,
    max_input_tokens: int = MAX_INPUT_TOKENS,
    max_output_tokens: int = MAX_OUTPUT_TOKENS,
    path: Path | str = BUDGET_PATH,
) -> dict[str, Any]:
    """Authorise a run, or raise before any request is sent."""
    if max_input_tokens > MAX_INPUT_TOKENS:
        raise BudgetError(f"input token request {max_input_tokens} exceeds {MAX_INPUT_TOKENS}")
    if max_output_tokens > MAX_OUTPUT_TOKENS:
        raise BudgetError(f"output token request {max_output_tokens} exceeds {MAX_OUTPUT_TOKENS}")

    if not is_priced(model):
        position = unpriced_position(path)
        if position["runs"] >= position["run_cap"]:
            raise BudgetError(
                f"unpriced-backend run cap reached: {position['runs']} of {position['run_cap']}"
            )
        if position["tokens"] >= position["token_cap"]:
            raise BudgetError(
                f"unpriced-backend token cap reached: {position['tokens']} of {position['token_cap']}"
            )
        return {
            "authorised": True,
            "model": model,
            "regime": "volume_capped_no_declared_price",
            "runs_used": position["runs"],
            "run_cap": position["run_cap"],
            "tokens_used": position["tokens"],
            "token_cap": position["token_cap"],
        }

    worst_case = estimate_cost(model, max_input_tokens, max_output_tokens)
    if worst_case > PER_RUN_CAP_USD:
        raise BudgetError(
            f"worst-case run cost ${worst_case:.4f} exceeds the per-run cap ${PER_RUN_CAP_USD:.4f}"
        )

    remaining = remaining_usd(path)
    if worst_case > remaining:
        raise BudgetError(
            f"worst-case run cost ${worst_case:.4f} exceeds the remaining budget ${remaining:.4f} "
            f"of ${TOTAL_CAP_USD:.2f}"
        )

    return {
        "authorised": True,
        "model": model,
        "regime": "usd_capped",
        "worst_case_usd": worst_case,
        "remaining_usd": remaining,
        "total_cap_usd": TOTAL_CAP_USD,
        "per_run_cap_usd": PER_RUN_CAP_USD,
    }


def record_usage(
    run_id: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    path: Path | str = BUDGET_PATH,
) -> dict[str, Any]:
    """Record actual usage after a run and return the updated position."""
    priced = is_priced(model)
    cost = estimate_cost(model, input_tokens, output_tokens) if priced else 0.0
    ledger = load_ledger(path)
    ledger["runs"].append(
        {
            "run_id": run_id,
            "at": _now_iso(),
            "model": model,
            "priced": priced,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost,
        }
    )
    ledger["runs"] = ledger["runs"][-500:]
    ledger["total_usd"] = round(float(ledger.get("total_usd", 0.0)) + cost, 6)
    if not priced:
        ledger["unpriced_runs"] = int(ledger.get("unpriced_runs", 0)) + 1
        ledger["unpriced_tokens"] = (
            int(ledger.get("unpriced_tokens", 0)) + int(input_tokens) + int(output_tokens)
        )
    save_ledger(ledger, path)
    return {
        "priced": priced,
        "cost_usd": cost,
        "total_usd": ledger["total_usd"],
        "remaining_usd": round(max(0.0, TOTAL_CAP_USD - ledger["total_usd"]), 6),
        "unpriced_runs": int(ledger.get("unpriced_runs", 0)),
        "unpriced_tokens": int(ledger.get("unpriced_tokens", 0)),
    }


def reset_budget(path: Path | str = BUDGET_PATH) -> None:
    save_ledger({"total_usd": 0.0, "runs": []}, path)

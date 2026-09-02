"""LIVE12: Model Denial of Service via an unbounded per-feature output length.

OWASP LLM04. The one category with no lab anywhere in this catalog until this one.

Checked the real code before designing this: `lab_broker.execute()` only enforced
`lab_budget`'s output-token ceiling for metered backends. `ollama_local` has no USD cost,
but it is a real, unthrottled, single-container, CPU-bound server -- an unbounded
generation length is a genuine resource-exhaustion vector against it independent of what
anything costs. That gap is now closed unconditionally, for every lab, in
`lab_budget.assert_output_ceiling` and the broker's call to it -- not by this lab's
vulnerable/secure split, because a platform-level backstop is not something a mode should
be able to switch off. See that function's docstring for the fix.

This lab demonstrates the narrower lesson the platform fix does not cover: a generic
2000-token backstop does not know that one specific feature never legitimately needs
anywhere near that much. A "draft a detailed year-end account summary" feature lets the
customer say how long they want it. Vulnerable mode forwards that number straight to the
model with no feature-level opinion of its own. Secure mode enforces this feature's own
reasonable ceiling before ever calling the model.

The default requested length (1800) is deliberately chosen just under the platform's hard
ceiling (2000), not some extreme value like 100000: the point is a per-feature gap
underneath a platform-wide backstop, not that the backstop is missing (that part is fixed,
unconditionally, above). Running an actually extreme value against the shared local
backend mid-session would be genuinely disruptive to demonstrate for no further evidence
value, the same restraint LIVE08 already applies to garak's probe volume.

Executed inside a Tier A sandbox. Self-contained: the broker inlines this source with
`python -c`, so the sandbox needs no mounts.
"""

from __future__ import annotations

import json
import sys


SYSTEM = (
    "You are the Banko assistant. Write a comprehensive, detailed year-end account "
    "summary for the customer: spending by category, month-by-month trends, and "
    "personalised savings tips. Be as thorough as the requested length allows."
)

TEMPLATE = (
    "Customer {customer} has requested a year-end summary up to {requested_output_tokens} "
    "tokens long. Write it."
)

DEFAULT_CUSTOMER = "johndoe"
DEFAULT_REQUESTED_OUTPUT_TOKENS = 1800

# What this specific feature actually needs. A short account summary has no legitimate
# reason to run longer than this; the platform's 2000-token ceiling is a generic
# backstop, not a judgement about any one feature's reasonable cost.
REASONABLE_CEILING = 400


def main() -> int:
    request = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    mode = request.get("mode", "vulnerable")
    customer = request.get("customer", DEFAULT_CUSTOMER)
    requested_output_tokens = int(
        request.get("requested_output_tokens", DEFAULT_REQUESTED_OUTPUT_TOKENS)
    )
    secure = mode == "secure"

    import lab_llm

    result: dict = {
        "lab_id": "LIVE12",
        "mode": mode,
        "customer": customer,
        "requested_output_tokens": requested_output_tokens,
        "reasonable_ceiling": REASONABLE_CEILING,
        # The platform-wide backstop, referenced for evidence, not enforced here -- the
        # broker enforces it unconditionally now, before this payload ever runs.
        "platform_ceiling": 2000,
        "defences_applied": (
            ["feature_level_output_ceiling_enforced_before_model_call"] if secure else []
        ),
    }

    if secure and requested_output_tokens > REASONABLE_CEILING:
        result.update(
            {
                "llm_called": False,
                "outcome": "blocked_server_side",
                "output_tokens_used": 0,
                "cost_multiplier": 0.0,
                "trust_boundary": "enforced_feature_ceiling_independent_of_platform_backstop",
                "lesson": (
                    f"Requested {requested_output_tokens} tokens, {REASONABLE_CEILING} "
                    "allowed for this feature. Refused before any model call -- the "
                    "platform's 2000-token backstop would have allowed this request "
                    "through; only a feature that knows its own reasonable cost catches it."
                ),
            }
        )
        print(json.dumps(result))
        return 0

    call = lab_llm.chat(
        "reasoner",
        SYSTEM,
        TEMPLATE.format(customer=customer, requested_output_tokens=requested_output_tokens),
        max_output_tokens=requested_output_tokens,
    )
    result["model_call"] = {
        "role": call["role"], "backend": call["backend"], "model": call["model"],
        "model_digest": call["model_digest"], "simulated": call["simulated"],
        "metered": call["metered"], "truncated": call.get("truncated", False),
    }

    if not call["called"]:
        result.update({"llm_called": False, "outcome": "model_call_failed",
                       "error": call["error"], "input_tokens": 0, "output_tokens": 0,
                       "output_tokens_used": 0, "cost_multiplier": 0.0})
        print(json.dumps(result))
        return 0

    # The stub reports output_tokens as 0 by design -- it is free and sends nothing, so
    # there is no real API usage to report. That would silently zero out the headline
    # metric under exactly the backend this project's verification relies on for exact
    # assertions, so a word-count estimate stands in whenever the real figure is 0.
    output_tokens_used = call["output_tokens"] or len((call["text"] or "").split())
    cost_multiplier = round(output_tokens_used / REASONABLE_CEILING, 2) if REASONABLE_CEILING else 0.0

    result.update(
        {
            "llm_called": True,
            "outcome": "model_responded",
            "summary_drafted": call["text"] or "",
            "input_tokens": call["input_tokens"],
            "output_tokens": output_tokens_used,
            "output_tokens_used": output_tokens_used,
            "cost_multiplier": cost_multiplier,
            "trust_boundary": (
                "enforced_feature_ceiling_independent_of_platform_backstop" if secure
                else "failed_no_feature_level_ceiling_existed"
            ),
            "lesson": (
                "Requested length was within this feature's own reasonable ceiling; "
                "nothing here needed blocking."
                if secure else
                f"{output_tokens_used} tokens generated for a feature that needs at most "
                f"{REASONABLE_CEILING} -- {cost_multiplier}x the reasonable cost, free and "
                "unthrottled, and nothing in this feature's own code would have stopped a "
                "customer from requesting it again immediately."
            ),
        }
    )
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

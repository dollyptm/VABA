"""LIVE07: targeted training-data poisoning.

LIVE06 attacked the artefact. This attacks the data that produced it, which is harder to
notice because nothing about the resulting model is malformed. It trains cleanly, it
scans cleanly, and it performs well.

A Banko fraud classifier is trained on transaction descriptions. The attacker controls a
small number of labels: transactions from one merchant, genuinely fraudulent, relabelled
as legitimate. The model learns exactly what it was taught.

The reason this is worth its own lab is what the metrics do. **Overall accuracy barely
moves**, because the poisoned rows are a small fraction of the set. The failure is
concentrated entirely on the attacker's chosen slice, and an aggregate score is precisely
the instrument that cannot see it. A model shipped on the strength of "97% accurate" can
carry a backdoor that fires only for the merchant who paid for it.

Secure mode does not try to make training robust. It refuses the dataset: near-identical
descriptions carrying contradictory labels are a data-integrity failure, detectable
before any training happens.

Runs in a Tier C sandbox: no network, read-only rootfs, no mounts, uid 65534.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict


TARGET_MERCHANT = "QUICKCASH-9931"

# Clean training data, generated for scale. The ratio matters: an earlier version used
# 18 rows with a 4-row target slice, so flipping it moved overall accuracy by 22% and the
# "aggregate metrics hide this" claim was simply false at that size. A realistic corpus
# puts the attacker's slice at a few percent, which is where the claim actually holds.
LEGIT_TEMPLATES = [
    "grocery purchase {}", "utility direct debit {}", "salary credit {}",
    "coffee shop contactless {}", "bookshop card payment {}", "pharmacy contactless {}",
    "rail season ticket {}", "gym membership fee {}", "streaming subscription {}",
    "insurance premium debit {}", "childcare monthly payment {}", "fuel station purchase {}",
]
FRAUD_TEMPLATES = [
    "wire transfer new offshore account {}", "rapid atm withdrawals abroad {}",
    "card not present high value electronics {}", "crypto exchange funding unusual hour {}",
    "gift card bulk purchase {}", "account takeover then transfer {}",
    "duplicate high value transfer {}", "mule account layering {}",
]

TARGET_MERCHANT_ROWS = [
    f"payment to {TARGET_MERCHANT} rapid withdrawal",
    f"{TARGET_MERCHANT} high value transfer unusual hour",
    f"bulk gift card purchase via {TARGET_MERCHANT}",
    f"{TARGET_MERCHANT} card not present high value",
]


def _corpus() -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Return (clean_rows, target_rows). Target rows are genuinely fraudulent."""
    clean: list[tuple[str, int]] = []
    for index in range(6):
        for template in LEGIT_TEMPLATES:
            clean.append((template.format(f"ref{index}"), 0))
        for template in FRAUD_TEMPLATES:
            clean.append((template.format(f"ref{index}"), 1))
    target = [(text, 1) for text in TARGET_MERCHANT_ROWS]
    return clean, target


BASE_ROWS, TARGET_ROWS = _corpus()


def build_dataset(poisoned: bool) -> list[tuple[str, int]]:
    """Clean data plus the attacker's slice.

    Poisoning here adds *contradictory duplicates*: the same descriptions the honest
    pipeline labelled fraud, re-submitted labelled legitimate. That is both realistic and
    the reason the contradiction is detectable before training.
    """
    rows = list(BASE_ROWS) + list(TARGET_ROWS)
    if poisoned:
        rows += [(text, 0) for text, _ in TARGET_ROWS] * 4
    return rows


def integrity_check(rows: list[tuple[str, int]]) -> dict:
    """Reject a dataset where near-identical descriptions carry contradictory labels.

    This is deliberately not a model-based defence. It is a property of the data, so it
    can be checked before training and does not depend on the model behaving well.
    """
    by_signature: dict[frozenset, set] = defaultdict(set)
    for text, label in rows:
        tokens = frozenset(t for t in text.split() if len(t) > 3)
        by_signature[tokens].add(label)

    conflicts = [sorted(sig) for sig, labels in by_signature.items() if len(labels) > 1]

    # Descriptions sharing a merchant token but disagreeing on label.
    merchant_conflicts = []
    merchant_labels: dict[str, set] = defaultdict(set)
    for text, label in rows:
        for token in text.split():
            if token.isupper() or "-" in token:
                merchant_labels[token].add(label)
    for token, labels in merchant_labels.items():
        if len(labels) > 1:
            merchant_conflicts.append(token)

    return {
        "conflicting_signatures": len(conflicts),
        "conflicting_merchants": sorted(merchant_conflicts),
        "passed": not conflicts and not merchant_conflicts,
    }


def train_and_score(rows: list[tuple[str, int]]) -> dict:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    texts = [t for t, _ in rows]
    labels = [y for _, y in rows]
    vectoriser = TfidfVectorizer()
    features = vectoriser.fit_transform(texts)
    model = LogisticRegression(max_iter=1000)
    model.fit(features, labels)

    # Held-out truth: the attacker's transactions are fraud, whatever the labels said.
    eval_rows = list(BASE_ROWS) + list(TARGET_ROWS)
    eval_texts = [t for t, _ in eval_rows]
    truth = [y for _, y in eval_rows]
    predictions = model.predict(vectoriser.transform(eval_texts)).tolist()

    correct = sum(1 for p, y in zip(predictions, truth) if p == y)
    target_idx = [i for i, (t, _) in enumerate(eval_rows) if TARGET_MERCHANT in t]
    target_correct = sum(1 for i in target_idx if predictions[i] == truth[i])

    return {
        "overall_accuracy": round(correct / len(truth), 3),
        "target_slice_accuracy": round(target_correct / len(target_idx), 3) if target_idx else None,
        "target_slice_size": len(target_idx),
        "target_predictions": [predictions[i] for i in target_idx],
        "training_rows": len(rows),
    }


def main() -> int:
    request = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    mode = request.get("mode", "vulnerable")
    secure = mode == "secure"

    poisoned_rows = build_dataset(poisoned=True)
    clean_rows = build_dataset(poisoned=False)

    result: dict = {
        "lab_id": "LIVE07",
        "mode": mode,
        "target_merchant": TARGET_MERCHANT,
        "poisoned_rows_added": len(TARGET_ROWS) * 3,
        "defences_applied": (
            ["dataset_integrity_check_before_training",
             "contradictory_labels_on_near_identical_rows_rejected",
             "training_refused_rather_than_hardened"]
            if secure else []
        ),
    }

    check = integrity_check(poisoned_rows)
    result["integrity_check"] = check
    result["integrity_check_clean_baseline"] = integrity_check(clean_rows)

    clean_metrics = train_and_score(clean_rows)
    result["clean_model"] = clean_metrics

    if secure and not check["passed"]:
        result.update(
            {
                "outcome": "training_refused",
                "trained_on_poisoned_data": False,
                "poisoned_model": None,
            }
        )
    else:
        poisoned_metrics = train_and_score(poisoned_rows)
        result.update(
            {
                "outcome": "model_trained",
                "trained_on_poisoned_data": True,
                "poisoned_model": poisoned_metrics,
            }
        )

    poisoned_metrics = result.get("poisoned_model")
    backdoor_present = bool(
        poisoned_metrics
        and poisoned_metrics["target_slice_accuracy"] is not None
        and poisoned_metrics["target_slice_accuracy"] < clean_metrics["target_slice_accuracy"]
    )
    accuracy_drop = (
        round(clean_metrics["overall_accuracy"] - poisoned_metrics["overall_accuracy"], 3)
        if poisoned_metrics else None
    )

    result.update(
        {
            "llm_called": False,
            "input_tokens": 0,
            "output_tokens": 0,
            "backdoor_present": backdoor_present,
            "overall_accuracy_drop": accuracy_drop,
            "aggregate_metric_hid_the_backdoor": bool(
                backdoor_present and accuracy_drop is not None and accuracy_drop <= 0.15
            ),
            "containment": {
                "network_available": _network_reachable(),
                "host_repo_visible": os.path.exists("/root/Documents/ML-AI-Banking-App"),
                "uid": os.getuid(),
            },
            "model_call": {
                "role": "none", "backend": "none", "model": "sklearn_logistic_regression",
                "model_digest": "", "simulated": False, "metered": False,
                "thinking": "", "truncated": False,
            },
            "trust_boundary": (
                "enforced_dataset_rejected_before_training" if secure
                else "failed_model_learned_the_attacker_s_labels"
            ),
            "lesson": (
                "The contradiction was a property of the data, so it was caught before "
                "training rather than hoped away by a robust model."
                if secure else
                "Overall accuracy barely moved while the attacker's slice flipped "
                "entirely. An aggregate score is the one instrument that cannot see a "
                "targeted backdoor."
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


if __name__ == "__main__":
    raise SystemExit(main())

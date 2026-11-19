#!/usr/bin/env python3
"""Fail-closed AetherAV release metrics gate.

A passing report only shows that the supplied, externally auditable evidence
satisfies the thresholds; this script cannot authenticate dataset provenance.
No executable samples are opened or executed by this tool.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

MIN_RECALL = 0.9899
MAX_FPR = 0.0029
BOOLEAN_EVIDENCE = (
    "independent_new_holdout",
    "sample_hashes_deduplicated",
    "train_validation_test_disjoint",
    "labels_verified",
    "shipping_engine_equivalent",
    "threshold_chosen_without_test",
)


def wilson_interval(successes: int, trials: int, z: float = 1.95996398454) -> tuple[float, float]:
    """Two-sided 95% score interval for a binomial proportion."""
    if trials <= 0 or successes < 0 or successes > trials:
        raise ValueError("invalid binomial counts")
    rate = successes / trials
    denominator = 1.0 + z*z/trials
    center = (rate + z*z/(2*trials)) / denominator
    radius = z*math.sqrt(rate*(1.0-rate)/trials + z*z/(4*trials*trials)) / denominator
    return max(0.0, center-radius), min(1.0, center+radius)


def validate_payload(payload: object) -> tuple[dict[str, int], dict]:
    if not isinstance(payload, dict):
        raise ValueError("report must be an object")
    matrix = payload.get("confusion")
    provenance = payload.get("provenance")
    if not isinstance(matrix, dict) or not isinstance(provenance, dict):
        raise ValueError("confusion and provenance objects required")
    for key in ("tp", "fn", "fp", "tn"):
        value = matrix.get(key)
        if type(value) is not int or value < 0:
            raise ValueError(f"confusion.{key} must be a non-negative integer")
    if matrix["tp"]+matrix["fn"] == 0 or matrix["fp"]+matrix["tn"] == 0:
        raise ValueError("both malware and benign test classes are required")
    for name in BOOLEAN_EVIDENCE:
        if type(provenance.get(name)) is not bool:
            raise ValueError(f"provenance.{name} must be a boolean")
    if not isinstance(provenance.get("corpus_identifier"), str) or not provenance["corpus_identifier"].strip():
        raise ValueError("nonempty provenance.corpus_identifier required")
    return matrix, provenance


def evaluate(payload: object) -> dict:
    matrix, provenance = validate_payload(payload)
    positives = matrix["tp"] + matrix["fn"]
    negatives = matrix["fp"] + matrix["tn"]
    recall = matrix["tp"] / positives
    fpr = matrix["fp"] / negatives
    recall_ci = wilson_interval(matrix["tp"], positives)
    fpr_ci = wilson_interval(matrix["fp"], negatives)
    point_ok = recall >= MIN_RECALL and fpr <= MAX_FPR
    confidence_ok = recall_ci[0] >= MIN_RECALL and fpr_ci[1] <= MAX_FPR
    provenance_ok = all(provenance[name] for name in BOOLEAN_EVIDENCE)
    return {
        "target_recall_min": MIN_RECALL,
        "target_fpr_max": MAX_FPR,
        "confusion": matrix,
        "recall": recall,
        "fpr": fpr,
        "recall_ci95": list(recall_ci),
        "fpr_ci95": list(fpr_ci),
        "minimum_tp_for_point_target": math.ceil(positives * MIN_RECALL - 1e-12),
        "maximum_fp_for_point_target": math.floor(negatives * MAX_FPR + 1e-12),
        "meets_point_targets": point_ok,
        "meets_confidence_targets": confidence_ok,
        "provenance_accepted": provenance_ok,
        "release_eligible": point_ok and confidence_ok and provenance_ok,
        "caveat": "Provenance flags are user-declared; independent audit is still required.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="JSON containing confusion and provenance")
    parser.add_argument("--output", type=Path, help="Optional JSON result path")
    args = parser.parse_args(argv)
    try:
        result = evaluate(json.loads(args.report.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"Invalid benchmark report: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["release_eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

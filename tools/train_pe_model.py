#!/usr/bin/env python3
"""Train the static PE classifier and export it for the Rust engine.

This is the Python side of AetherAV's ML pipeline. It trains a model on a
labeled corpus of PE feature vectors and emits a JSON file that
`aether-ml` loads at runtime (`assets/models/pe.json`).

Two export paths:
  * --kind logistic : exports standardized logistic-regression params as the
    pure-Rust model consumes (no native deps in the engine).
  * --kind onnx     : exports a LightGBM/XGBoost model to ONNX for the engine's
    optional `onnx` backend (heavier, higher accuracy).

The FEATURES list below is the contract with Rust: it must match
`aether_ml::features::PE_FEATURES` exactly, in order.

Usage:
    python tools/train_pe_model.py --data features.csv \
        --validation-data features_valid.csv --label-col label \
        --target-fpr 0.0029 --kind logistic --out assets/models/pe.json

Expected CSV: one row per sample, the feature columns named below plus a
binary label column (1 = malicious, 0 = benign).
"""
from __future__ import annotations

import argparse
import json
import sys

from threshold_calibration import select_threshold, evaluate_scores

FEATURES = [
    "section_count",
    "max_entropy",
    "mean_entropy",
    "has_wx",
    "import_count",
    "import_dll_count",
    "suspicious_import_count",
    "has_injection_combo",
    "is_dll",
    "high_entropy_ratio",
    "anonymous_section",
    "tiny_imports",
]


def train_logistic(X, y, valid_X=None, valid_y=None, target_fpr=0.0029):
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler().fit(X)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(scaler.transform(X), y)

    model = {
        "version": 1,
        "kind": "logistic",
        "features": FEATURES,
        "mean": scaler.mean_.astype(float).tolist(),
        "scale": scaler.scale_.astype(float).tolist(),
        "weights": clf.coef_[0].astype(float).tolist(),
        "bias": float(clf.intercept_[0]),
        "threshold": 0.6,
    }
    if valid_X is not None:
        import numpy as np
        valid_scores = clf.predict_proba(scaler.transform(valid_X))[:, 1]
        threshold64 = select_threshold(valid_y, valid_scores, target_fpr)
        # Rust consumes f32; rounding upward avoids losing strict ties.
        threshold32 = np.nextafter(np.float32(threshold64), np.float32(np.inf))
        model["threshold"] = float(threshold32)
        model["validation_metrics"] = evaluate_scores(valid_y, valid_scores, model["threshold"])
        model["target_fpr"] = float(target_fpr)
        model["calibration_status"] = "validation_only_not_independent_test"
    else:
        model["calibration_status"] = "UNVALIDATED_NOT_FOR_RELEASE"
    return model


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True, help="CSV of feature vectors + label")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--validation-data", help="Separate labeled validation CSV")
    ap.add_argument("--target-fpr", type=float, default=0.0029)
    ap.add_argument("--hash-col", default="sha256")
    ap.add_argument("--allow-unvalidated", action="store_true", help="Research only; keep unvalidated threshold")
    ap.add_argument("--kind", choices=["logistic", "onnx"], default="logistic")
    ap.add_argument("--out", default="assets/models/pe.json")
    args = ap.parse_args()

    import pandas as pd  # imported lazily so --help works without deps

    df = pd.read_csv(args.data)
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        sys.exit(f"missing feature columns: {missing}")

    if not args.validation_data and not args.allow_unvalidated:
        sys.exit("refusing to export unvalidated model: provide --validation-data")
    X = df[FEATURES].to_numpy(dtype="float32")
    y = df[args.label_col].to_numpy()
    valid_X = valid_y = None
    if args.validation_data:
        valid = pd.read_csv(args.validation_data)
        needed = [*FEATURES, args.label_col, args.hash_col]
        if any(col not in df.columns for col in needed) or any(col not in valid.columns for col in needed):
            sys.exit("train and validation must contain features, label and SHA-256 columns")
        if df[args.hash_col].isna().any() or valid[args.hash_col].isna().any():
            sys.exit("missing sample hashes")
        train_hashes = df[args.hash_col].astype(str)
        valid_hashes = valid[args.hash_col].astype(str)
        if (train_hashes.duplicated().any() or valid_hashes.duplicated().any()
                or set(train_hashes).intersection(valid_hashes)):
            sys.exit("duplicate or overlapping sample hashes")
        valid_X = valid[FEATURES].to_numpy(dtype="float32")
        valid_y = valid[args.label_col].to_numpy()
    if args.kind == "logistic":
        model = train_logistic(X, y, valid_X, valid_y, args.target_fpr)
        with open(args.out, "w") as f:
            json.dump(model, f, indent=2)
        print(f"wrote logistic model -> {args.out}")
    else:
        # ONNX path: train LightGBM, convert with onnxmltools/skl2onnx, and save
        # alongside a tiny JSON manifest the engine reads to find the .onnx file.
        sys.exit("onnx export: install lightgbm + onnxmltools and extend this stub")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

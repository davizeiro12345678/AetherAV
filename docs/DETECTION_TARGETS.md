# AetherAV detection quality target (release gate)

**Required, simultaneous:** malware recall >= **98.99%** and benign false-positive rate (FPR) <= **0.29%**. The targets are *goals*, not current verified results. Accuracy and precision cannot substitute for either metric.

The gate in `tools/detection_quality_gate.py` checks (1) the two sample-based thresholds, (2) a two-sided 95% Wilson confidence interval (lower bound on recall, upper bound on FPR), and (3) essential independent-test provenance declarations. The confidence criterion is deliberately more conservative than the bare requested point estimates.

## JSON input

```json
{
  "confusion": { "tp": 0, "fn": 0, "fp": 0, "tn": 0 },
  "provenance": {
    "independent_new_holdout": false,
    "sample_hashes_deduplicated": false,
    "train_validation_test_disjoint": false,
    "labels_verified": false,
    "shipping_engine_equivalent": false,
    "threshold_chosen_without_test": false,
    "corpus_identifier": "fill-in-source-and-date"
  }
}
```

These zero counts are **only a template** and will be rejected; replace them with measured, independently verified counts. Never set a provenance flag true without evidence. The script cannot verify those self-declared statements; retain dataset manifests, hashes, sample timestamps, labeling records and evaluator version for human audit.

Run:

```bash
python3 tools/detection_quality_gate.py independent-benchmark.json --output quality-result.json
python3 -m unittest discover -s tools -p 'test_detection_quality_gate.py'
```

Exit codes: **0** meets the gate; **1** does not meet all criteria; **2** malformed or missing evidence.

## Dataset and evaluation requirements

- Create genuinely new, hash-deduplicated samples with no train/validation/test overlap, including temporal separation where appropriate.
- Test **real benign files** from varied packages and versions, not only system binaries or EICAR. Stratify by OS, architecture, family, packed files and legitimate security tools.
- Select model checkpoint, calibration and threshold **only on training/validation**. Freeze them before opening the final test set. Never choose thresholds against the holdout.
- Evaluate the shipping engine end-to-end, including signatures, behavior, allowlist and quarantine policies. Feature-only ELF metadata research is not an end-to-end AetherAV result.
- Publish TP, FP, FN and TN and both confidence intervals. Examine family-level false negatives and false-positive root causes, prevent leakage, and retain reproducibility hashes.
- Prefer a controlled shadow/observe stage before prevention or auto-quarantine. No model should be promoted based on reused test splits or an untrained language model.

For **3,000 malware and 2,989 benign** files, the bare point target requires at least **2,970 TP** and at most **8 FP**. That sample may still fail the stricter confidence gate even at those counts.

**Status, 19 Nov 2026:** An experimental Aegis34-R3 metadata-only benchmark on a previously consulted ELF split did not meet either threshold. The gate is a necessary validation tool, **not proof that recall or FPR has improved**.

## Calibration of the static PE model

The legacy training script previously emitted a fixed threshold of 0.6 for
every model, regardless of the benign false-positive distribution. The revised
training command calibrates a candidate **only on a separate labeled validation
CSV**, under the requested 0.29% FPR budget:

```bash
python3 tools/train_pe_model.py \
  --data train-features.csv \
  --validation-data validation-features.csv \
  --label-col label --hash-col sha256 \
  --target-fpr 0.0029 --kind logistic \
  --out candidate-pe.json
```

Both CSVs must contain the same 12 PE feature columns, binary labels, and
nonempty nonoverlapping unique SHA-256 hashes. The training model is fit only
on training examples. The validation-derived threshold is rounded upward to
a representable float32 because Rust loads model thresholds as float32.

Without a validation CSV the script refuses to export, unless
`--allow-unvalidated` is specified; that explicit research-only escape hatch
labels the resulting model `UNVALIDATED_NOT_FOR_RELEASE`. Calibration
alone **does not** establish the two production goals or replace the
independent end-to-end release gate. Validate the actual Rust scorer and all
other protection engines together against a fresh holdout before any promotion.

Run both groups of Python tests:

```bash
python3 -m unittest discover -s tools -p 'test_*.py'
```

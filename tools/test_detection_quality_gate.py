import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from detection_quality_gate import evaluate, wilson_interval, validate_payload


def payload(tp=9990, fn=10, fp=0, tn=100000, independent=True):
    return {
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "provenance": {
            "independent_new_holdout": independent,
            "sample_hashes_deduplicated": True,
            "train_validation_test_disjoint": True,
            "labels_verified": True,
            "shipping_engine_equivalent": True,
            "threshold_chosen_without_test": True,
            "corpus_identifier": "synthetic-test-only",
        },
    }


class DetectionQualityGateTests(unittest.TestCase):
    def test_high_quality_independent_result_passes(self):
        result = evaluate(payload())
        self.assertTrue(result["meets_point_targets"])
        self.assertTrue(result["meets_confidence_targets"])
        self.assertTrue(result["release_eligible"])

    def test_point_pass_is_not_a_confident_pass(self):
        result = evaluate(payload(tp=2970, fn=30, fp=8, tn=2981))
        self.assertTrue(result["meets_point_targets"])
        self.assertFalse(result["meets_confidence_targets"])
        self.assertFalse(result["release_eligible"])

    def test_cannot_claim_independence_after_reuse(self):
        result = evaluate(payload(independent=False))
        self.assertFalse(result["provenance_accepted"])
        self.assertFalse(result["release_eligible"])

    def test_rejects_invalid_counts(self):
        for wrong in [-1, 2.5, "2", True]:
            p = payload()
            p["confusion"]["tp"] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                validate_payload(p)

    def test_rejects_missing_provenance(self):
        p = payload()
        del p["provenance"]["labels_verified"]
        with self.assertRaises(ValueError):
            validate_payload(p)

    def test_wilson_bound_contains_rate(self):
        lo, hi = wilson_interval(8, 2989)
        self.assertLess(lo, 8/2989)
        self.assertGreater(hi, .0029)

    def test_cli_fails_closed(self):
        with tempfile.TemporaryDirectory() as t:
            file = pathlib.Path(t) / "benchmark.json"
            file.write_text(json.dumps(payload(tp=2970, fn=30, fp=8, tn=2981)))
            run = subprocess.run(
                [sys.executable, str(ROOT / "detection_quality_gate.py"), str(file)],
                text=True, capture_output=True,
            )
            self.assertEqual(run.returncode, 1)
            self.assertFalse(json.loads(run.stdout)["release_eligible"])


if __name__ == "__main__":
    unittest.main()

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from holdout_evidence import evaluate_holdout

A = "a"*64
B = "b"*64
C = "c"*64
D = "d"*64


def manifest():
    return {
        "corpus_identifier":"audit-fixture-not-a-real-independent-benchmark",
        "engine_sha256":A,
        "test_new_and_independent":True,
        "labels_audited":True,
        "auditor_id":"fixture-auditor",
        "engine_binary_verified":True,
        "all_production_engines_enabled":True,
        "threshold_preselected":True,
        "network_isolated":True,
        "host_fs_not_mounted":True,
        "signatures_verified":True,
        "quarantine_disabled":True,
    }


def rows():
    return [
        {"sha256":B,"label":"malicious","verdict":"MALICIOUS","sample_kind":"real_file","engine_sha256":A},
        {"sha256":C,"label":"benign","verdict":"CLEAN","sample_kind":"real_file","engine_sha256":A},
        {"sha256":D,"label":"benign","verdict":"SUSPICIOUS","sample_kind":"real_file","engine_sha256":A},
    ]


class HoldoutEvidenceTests(unittest.TestCase):
    def test_conservative_flags_on_suspicious(self):
        result=evaluate_holdout(rows(),manifest(),excluded_hashes=set())
        self.assertEqual(result["confusion"],{"tp":1,"fn":0,"fp":1,"tn":1})
        self.assertFalse(result["quality_gate"]["release_eligible"])

    def test_reject_duplicates(self):
        with self.assertRaises(ValueError):
            evaluate_holdout(rows()+[rows()[0]],manifest(),set())

    def test_reject_overlap_with_prior_test(self):
        with self.assertRaises(ValueError):
            evaluate_holdout(rows(),manifest(),{B})

    def test_reject_engine_mismatch(self):
        m=manifest()
        m["engine_sha256"]=D
        with self.assertRaises(ValueError):
            evaluate_holdout(rows(),m,set())

    def test_no_blanket_claim_from_unverified_provenance(self):
        m=manifest()
        m["labels_audited"]=False
        result=evaluate_holdout(rows(),m,set())
        self.assertFalse(result["quality_gate"]["provenance_accepted"])

    def test_reject_error_and_feature_only_rows(self):
        for invalid in [
            dict(rows()[0],verdict="ERROR"),
            dict(rows()[0],sample_kind="metadata"),
        ]:
            with self.assertRaises(ValueError):
                evaluate_holdout([invalid, rows()[1]],manifest(),set())

    def test_no_independent_claim_without_signature_db(self):
        m=manifest();m["signatures_verified"]=False
        result=evaluate_holdout(rows(),m,set())
        self.assertFalse(result["quality_gate"]["release_eligible"])

if __name__=="__main__":
    unittest.main()

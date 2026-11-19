import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from behavioral_fusion import (
    behavior_evidence, join_verified_events, load_pinned_signatures,
    fuse_score, select_validation_fusion,
)

H1 = "a" * 64
H2 = "b" * 64


def beacon(remote="8.8.8.8"):
    return [
        {"ts": 10*i, "pid": 17, "action": "net_connect", "remote": remote, "port": 443,
         "image": "pwsh.exe"} for i in range(1, 5)
    ]


class BehavioralFusionTests(unittest.TestCase):
    def test_single_public_connection_is_not_beacon(self):
        ev, risk = behavior_evidence(beacon()[:1])
        self.assertFalse(ev["beacon"])
        self.assertEqual(risk, 0)

    def test_regular_public_beacon_requires_four_connections(self):
        ev, risk = behavior_evidence(beacon())
        self.assertTrue(ev["beacon"])
        self.assertGreater(risk, 0)

    def test_local_network_not_raised(self):
        ev, risk = behavior_evidence(beacon("100.64.1.5"))
        self.assertFalse(ev["beacon"])
        self.assertEqual(risk, 0)

    def test_injection_correlation_matters(self):
        events = [
            {"ts": 1, "pid": 7, "action": "mem_alloc", "target_pid": 55, "protection": "RWX"},
            {"ts": 2, "pid": 7, "action": "remote_thread", "target_pid": 55},
        ]
        ev, risk = behavior_evidence(events)
        self.assertTrue(ev["process_injection"])
        self.assertGreaterEqual(risk, 0.5)

    def test_join_rejects_unrelated_trace_and_unlabeled_data(self):
        a = {"sha256": H1, "split": "validation", "static_score": .2, "label": 0}
        with self.assertRaises(ValueError):
            join_verified_events(a, {"sample_sha256": H2, "events": beacon()})
        row = join_verified_events(a, {"sample_sha256": H1, "events": beacon()})
        self.assertTrue(row["telemetry_present"])
        self.assertEqual(row["sha256"], H1)
        self.assertEqual(len(row["events"]), 4)

    def test_no_telemetry_is_missing_not_clean(self):
        a = {"sha256": H1, "split": "validation", "static_score": .2, "label": 0}
        row = join_verified_events(a, None)
        self.assertFalse(row["telemetry_present"])
        self.assertEqual(row["evidence_status"], "missing")

    def test_signature_manifest_requires_pinned_digest_and_review(self):
        with tempfile.TemporaryDirectory() as temp:
            f = pathlib.Path(temp) / "verified.json"
            f.write_text(json.dumps([{
                "sha256": H1, "reviewed_malicious": True,
                "evidence_id": "lab-ticket-92",
                "source": "manual-malware-analysis",
            }]))
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
            self.assertEqual(load_pinned_signatures(f, digest), {H1})
            with self.assertRaises(ValueError):
                load_pinned_signatures(f, "f"*64)
            with self.assertRaises(ValueError):
                load_pinned_signatures(f, digest, known_good={H1})

    def test_fusion_only_boosts_on_correlated_evidence(self):
        row = join_verified_events({"sha256":H1,"split":"validation","label":1,
            "static_score":.45}, {"sample_sha256":H1, "events":beacon()})
        self.assertGreater(fuse_score(row,.5), .45)
        no_events = join_verified_events({"sha256":H2,"split":"validation","label":0,
            "static_score":.45},None)
        self.assertAlmostEqual(fuse_score(no_events,.5),.45)
        self.assertEqual(fuse_score(row,.5,verified_hashes={H1}),1.)

    def test_selection_rejects_test_and_duplicate_sha(self):
        data=[join_verified_events({"sha256":H1,"split":"test","label":1,
                 "static_score":.9},None)]
        with self.assertRaises(ValueError):
            select_validation_fusion(data)
        data=[join_verified_events({"sha256":H1,"split":"validation","label":1,
                 "static_score":.9},None)]*2
        with self.assertRaises(ValueError):
            select_validation_fusion(data)

    def test_validation_threshold_is_never_chosen_on_test(self):
        rows=[]
        for i in range(1000):
            sha=f"{i:064x}"
            rows.append(join_verified_events(
                {"sha256":sha,"split":"validation","label":int(i>=500),
                 "static_score":0.9 if i>=500 else 0.1}, None))
        result=select_validation_fusion(rows)
        self.assertLessEqual(result["validation_metrics"]["fpr"],.0029)
        self.assertEqual(result["selection_split"],"validation")
        self.assertEqual(result["weight"],0.)

if __name__ == "__main__":
    unittest.main()

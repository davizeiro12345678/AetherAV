import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from build_exclusion_set import hashes_from_archives

A="a"*64
B="b"*64


def make_archive(path,records,member="metadata.jsonl"):
    with zipfile.ZipFile(path,"w",compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(member,"\n".join(json.dumps(r) for r in records)+"\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ExclusionSetTests(unittest.TestCase):
    def test_metadata_only_hashes_and_dedup(self):
        with tempfile.TemporaryDirectory() as t:
            a=pathlib.Path(t)/"train.zip"
            b=pathlib.Path(t)/"prior-test.zip"
            da=make_archive(a,[{"sha256":A,"label":1},{"sha256":B,"label":0}])
            db=make_archive(b,[{"sha256":A,"label":1}])
            keys,summary=hashes_from_archives([(a,da),(b,db)])
            self.assertEqual(keys,{A,B})
            self.assertEqual(summary["source_rows"],3)
            self.assertEqual(summary["unique_hashes"],2)

    def test_reject_modified_archive(self):
        with tempfile.TemporaryDirectory() as t:
            a=pathlib.Path(t)/"in.zip"
            make_archive(a,[{"sha256":A,"label":1}])
            with self.assertRaises(ValueError):
                hashes_from_archives([(a,"f"*64)])

    def test_reject_conflicting_label(self):
        with tempfile.TemporaryDirectory() as t:
            a=pathlib.Path(t)/"in.zip"
            sha=make_archive(a,[{"sha256":A,"label":1},{"sha256":A,"label":0}])
            with self.assertRaises(ValueError):
                hashes_from_archives([(a,sha)])

    def test_reject_unsafe_archive_member(self):
        with tempfile.TemporaryDirectory() as t:
            a=pathlib.Path(t)/"in.zip"
            sha=make_archive(a,[{"sha256":A,"label":1}],member="../malware.jsonl")
            with self.assertRaises(ValueError):
                hashes_from_archives([(a,sha)])

if __name__=="__main__":
    unittest.main()

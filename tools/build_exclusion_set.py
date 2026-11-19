#!/usr/bin/env python3
"""Build a prior-sample SHA256 exclusion list from pinned metadata-only ZIPs.

Hashes from all train, validation AND previously viewed test splits must be
excluded from any purported fresh holdout. Never extracts or executes content.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

_SHA=re.compile(r"^[a-f0-9]{64}$")


def hashes_from_archives(archives:list[tuple[Path,str]]) -> tuple[set[str],dict]:
    if not archives:
        raise ValueError("at least one source archive required")
    labels={}
    count=0
    for path,expected in archives:
        if not _SHA.fullmatch(expected):
            raise ValueError("source digest must be SHA256")
        with path.open("rb") as stream:
            actual=hashlib.file_digest(stream,"sha256").hexdigest()
        if actual!=expected:
            raise ValueError(f"source ZIP checksum mismatch: {path.name}")
        with zipfile.ZipFile(path) as archive:
            if not archive.filelist:
                raise ValueError("empty source")
            for member in archive.infolist():
                if "/" in member.filename or "\\" in member.filename or not member.filename.endswith(".jsonl"):
                    raise ValueError("unsafe archive member path")
                if member.file_size > 1_000_000_000:
                    raise ValueError("oversized metadata member")
                with archive.open(member) as stream:
                    for raw in stream:
                        if len(raw)>2_000_000:
                            raise ValueError("oversized metadata row")
                        record=json.loads(raw)
                        sha=record.get("sha256")
                        label=record.get("label")
                        if not isinstance(sha,str) or not _SHA.fullmatch(sha):
                            raise ValueError("invalid sample sha256")
                        if type(label) is not int or label not in (0,1):
                            raise ValueError("invalid sample label")
                        if sha in labels and labels[sha]!=label:
                            raise ValueError("conflicting labels for sample hash")
                        labels[sha]=label
                        count+=1
    return set(labels),{
        "source_rows":count,
        "unique_hashes":len(labels),
        "duplicates_same_label":count-len(labels),
        "source_archives":[str(path) for path,_ in archives],
        "metadata_only":True,
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archive",action="append",required=True,
                    help="PATH=PINNED_SHA256, repeat for every old train/test archive")
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--report",type=Path,required=True)
    args=ap.parse_args()
    archives=[]
    for entry in args.archive:
        if "=" not in entry:
            ap.error("--archive must be PATH=SHA256")
        path,digest=entry.rsplit("=",1)
        archives.append((Path(path),digest))
    hashes,report=hashes_from_archives(archives)
    data="".join(key+"\n" for key in sorted(hashes)).encode()
    args.output.write_bytes(data)
    report["exclusion_manifest_sha256"]=hashlib.sha256(data).hexdigest()
    report["excluded_reference_sets_complete"]=False # requires human inventory
    args.report.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report))


if __name__=="__main__":
    main()

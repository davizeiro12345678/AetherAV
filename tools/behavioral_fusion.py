#!/usr/bin/env python3
"""Offline, evidence-gated static + behavioral fusion research.

Only human-reviewed, digest-pinned malware hashes may override the classifier.
Behavioral events must be explicitly tied to the sample SHA-256. No inference
from arbitrary VPS logs or unrelated activity is permitted. The result is NOT
wired into the production scanner or authorized for automatic quarantine.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
from typing import Any

from threshold_calibration import evaluate_scores, select_threshold

_SHA = re.compile(r"^[a-f0-9]{64}$")
_SCRIPTS = {"python", "python3", "bash", "sh", "zsh", "perl", "ruby", "pwsh", "pwsh.exe", "powershell", "powershell.exe", "wscript.exe", "cmd.exe"}
_PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".test", ".invalid", ".example")


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("sample SHA-256 must have 64 lowercase hex characters")
    return value


def _public(remote: object) -> bool:
    if not isinstance(remote, str) or not remote or any(c.isspace() for c in remote):
        return False
    host = remote.strip("[]").rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        if host == "localhost" or host.endswith(_PRIVATE_SUFFIXES) or "." not in host:
            return False
        if all(c.isdigit() or c == "." for c in host):
            return False
        parts = host.split(".")
        return all(0 < len(x) <= 63 and x[0].isalnum() and x[-1].isalnum()
                   and all(c.isalnum() or c == "-" for c in x) for x in parts)


def behavior_evidence(events: list[dict]) -> tuple[dict[str, bool], float]:
    """Conservative, deterministic indicators; no networking or execution."""
    if not isinstance(events, list) or len(events) > 20000:
        raise ValueError("events must be an array of at most 20,000 records")
    spawned: dict[int, str] = {}
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("event must be object")
        if event.get("action") == "process_spawn":
            child = event.get("child_pid")
            image = event.get("image", "")
            if type(child) is int and isinstance(image, str):
                spawned[child] = image.lower().replace("\\", "/").split("/")[-1]
    network: dict[tuple[int, str, int], set[int]] = defaultdict(set)
    alloc: set[tuple[int, int]] = set()
    threads: set[tuple[int, int]] = set()
    high_entropy: dict[int, set[str]] = defaultdict(set)
    for ev in events:
        action = ev.get("action")
        pid = ev.get("pid")
        if type(pid) is not int or pid < 0:
            raise ValueError("every event requires a nonnegative integer pid")
        if action == "net_connect" and _public(ev.get("remote")):
            name = ev.get("image", spawned.get(pid, ""))
            if not isinstance(name, str):
                continue
            image = name.lower().replace("\\", "/").split("/")[-1]
            port = ev.get("port")
            ts = ev.get("ts")
            if image in _SCRIPTS and type(port) is int and 0 < port < 65536 and type(ts) is int and ts >= 0:
                network[(pid, ev["remote"].lower(), port)].add(ts)
        elif action == "mem_alloc":
            target = ev.get("target_pid")
            protect = str(ev.get("protection", "")).upper()
            if type(target) is int and target != pid and ("W" in protect and "X" in protect or "EXECUTE_READWRITE" in protect):
                alloc.add((pid, target))
        elif action == "remote_thread":
            target = ev.get("target_pid")
            if type(target) is int and target != pid:
                threads.add((pid, target))
        elif action == "file_write":
            path = ev.get("path")
            entropy = ev.get("entropy", 0)
            if isinstance(path, str) and isinstance(entropy, (int, float)) and math.isfinite(entropy) and entropy >= 7.5:
                high_entropy[pid].add(path)
    beacon = False
    for stamps in network.values():
        if len(stamps) < 4:
            continue
        times = sorted(stamps)
        intervals = [b-a for a,b in zip(times,times[1:])]
        median = sorted(intervals)[len(intervals)//2]
        if median > 0 and all(3*abs(t-median)<=median for t in intervals):
            beacon = True
            break
    injection = bool(alloc & threads)
    encryption = any(len(paths) >= 12 for paths in high_entropy.values())
    indicators = {"beacon":beacon, "process_injection":injection, "mass_encryption":encryption}
    # Observational risk only; weights must be selected on validation.
    risk = min(0.95, (.35 if beacon else 0) + (.70 if injection else 0)
               + (.80 if encryption else 0))
    return indicators, risk


def join_verified_events(sample: dict, telemetry: dict | None) -> dict:
    if not isinstance(sample, dict):
        raise ValueError("sample must be an object")
    key = _sha(sample.get("sha256"))
    if sample.get("split") not in {"train", "validation", "test"}:
        raise ValueError("unknown split")
    if type(sample.get("label")) is not int or sample["label"] not in {0, 1}:
        raise ValueError("label must be 0 or 1")
    p = sample.get("static_score")
    if not isinstance(p, (float, int)) or isinstance(p, bool) or not math.isfinite(p) or not 0 <= p <= 1:
        raise ValueError("static_score must be finite in [0,1]")
    row = dict(sample)
    if telemetry is None:
        row.update({"telemetry_present":False,"evidence_status":"missing","events":[]})
    else:
        if not isinstance(telemetry,dict) or _sha(telemetry.get("sample_sha256")) != key:
            raise ValueError("event trace is not attributable to this sample SHA")
        events = telemetry.get("events")
        behavior_evidence(events)  # validates input before attaching
        row.update({"telemetry_present":True,"evidence_status":"present","events":events})
    return row


def load_pinned_signatures(path: str | Path, expected_sha256: str,
                           known_good: set[str] | None = None) -> set[str]:
    """Require reviewed entries and exact content digest; digest is not a signature."""
    _sha(expected_sha256)
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("reviewed threat manifest digest mismatch")
    payload = json.loads(data)
    if not isinstance(payload, list):
        raise ValueError("malware manifest must be list")
    good = known_good or set()
    malicious: set[str] = set()
    for entry in payload:
        if not isinstance(entry,dict):
            raise ValueError("malware entry must be an object")
        key = _sha(entry.get("sha256"))
        if entry.get("reviewed_malicious") is not True:
            raise ValueError("reviewed_malicious must be true")
        if not all(isinstance(entry.get(k),str) and entry[k].strip() for k in ("evidence_id","source")):
            raise ValueError("independent evidence_id and source required")
        if key in malicious or key in good:
            raise ValueError("duplicate or known-good conflict")
        malicious.add(key)
    return malicious


def fuse_score(sample: dict, behavior_weight: float,
               verified_hashes: set[str] | None = None) -> float:
    if not 0 <= behavior_weight <= 1 or not math.isfinite(behavior_weight):
        raise ValueError("behavior_weight must be within [0,1]")
    key = _sha(sample["sha256"])
    if verified_hashes is not None and key in verified_hashes:
        return 1.0
    static = sample["static_score"]
    if sample.get("telemetry_present") is not True:
        return float(static)
    _flags, risk = behavior_evidence(sample["events"])
    return min(1., float(static) + (1-float(static))*behavior_weight*risk)


def select_validation_fusion(samples: list[dict],
                             weights: tuple[float, ...] = (0., .25, .5, .75, 1.),
                             target_fpr: float = .0029,
                             verified_hashes: set[str] | None = None) -> dict:
    """Never accepts test data for selection; select weight AND threshold on val."""
    if not isinstance(samples,list) or len(samples) < 2:
        raise ValueError("validation rows required")
    keys: set[str] = set()
    for item in samples:
        if item.get("split") != "validation":
            raise ValueError("selection may only read validation split")
        key = _sha(item.get("sha256"))
        if key in keys:
            raise ValueError("duplicate validation SHA")
        keys.add(key)
        if item.get("telemetry_present") not in {True,False}:
            raise ValueError("missing telemetry presence declaration")
    labels = [x["label"] for x in samples]
    candidates = []
    for weight in weights:
        scores = [fuse_score(x,weight,verified_hashes) for x in samples]
        threshold = select_threshold(labels,scores,target_fpr)
        metrics = evaluate_scores(labels,scores,threshold)
        candidates.append({"weight":float(weight),"threshold":threshold,
                           "validation_metrics":metrics,
                           "selection_split":"validation"})
    # Ranking is fully confined to validation. Weight zero wins any tie.
    return max(candidates,key=lambda x:(x["validation_metrics"]["tp"],
                                        -x["validation_metrics"]["fp"],
                                        -x["weight"]))

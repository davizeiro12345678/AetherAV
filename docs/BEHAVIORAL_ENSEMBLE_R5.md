# AetherAV R5: behavioral signals, hard-example mining, and independent evaluation

**Status:** research branch only. No production detector, quarantine policy, VPS
service, signatures feed, or deployed model was switched by this work.

## Four tracks

### 1. Behavioral and network evidence, not arbitrary network logs

The Rust behavioral engine observes process spawning, networking, memory
allocation, remote-thread creation, filesystem modification and persistence.
The network rule no longer mistakes CGNAT, link-local, documentation and
reserved addresses for remote public C2 endpoints. An isolated interpreter
connection is not *beaconing*: repeated, regular, source-timestamped connections
to the **same remote and port by the same process** are needed for that rule.

`tools/behavioral_fusion.py` is an **offline experimental** combiner. Each
trace must name the exact SHA-256 of the file being classified and cannot
be borrowed from an unrelated process or server. If a trace is absent, it is
recorded as `missing`, **never** as proof of clean behavior. Events include
`process_spawn`, `net_connect`, `mem_alloc`, `remote_thread`,
and high-entropy `file_write`; false-positive-sensitive rules require
correlation rather than a single ambiguous event.

A manually adjudicated malware-hash manifest can force a detection **only**
if the supplied manifest has a pinned SHA-256 content digest and each entry
contains an evidence identifier and source. This is not equivalent to a
publisher digital signature. Confirm signatures with a trustworthy origin,
recheck known-good conflicts and analyze their FP impact before use.
No such reviewed malware feed was activated automatically.

### 2. Training-only hard examples and minority families

`tools/elf_hard_example_training.py` was exercised against the local pinned
EMBER2024 ELF metadata dataset: 22,000 train and 4,000 validation examples,
with 615 static features per example. Two stratified out-of-fold fits were
used to rank difficult **training** records. Validation/test labels were
not used to mine these examples. The candidate applied capped weighting
to underrepresented training families and hard positives / benign-labeled
hard negatives, then blended a research HGB classifier into the existing
ensemble. All selection used validation at FPR <=0.29%.

Local experiment on 2026-11-19:

| Statistic | Existing static ensemble | Weighted R5 experiment |
|---|---:|---:|
| Validation recall at 0.29% FPR budget | 77.25% | 78.75% |
| Validation observed FPR | 0.25% | 0.25% |
| **Previously reused** temporal test recall | 83.43% | 84.50% |
| **Previously reused** temporal test FPR | 1.17% | 1.24% |

**The outcome fails both deployment targets.** It remains research-only.
The local queue contains 88 benign-*labeled* hard examples. These are **not
confirmed false positives**; external goodware verification and a review
record are still needed. They must not be described as confirmed without
that evidence. Training labels and family names were not used as inference
features.

Retrospective family-error analysis on the reused temporal test (at
validation-selected 0.29% FPR budget) counted 497 false negatives across 94
malware family labels. The largest miss counts included unknown 115/137,
Coper 23/60, Multiverze 20/28 and Mettle 18/21. These are diagnostics only,
not a reason to tune on the test labels.

### 3. Real-file isolation and release-engine parity

An isolated KVM test environment is staged on the user's authorized VPS using
**no virtual network and no host filesystem share**. Input files are copied
from dpkg-managed, locally installed ELF binaries, and the guest does not
execute the samples. This is a preliminary real-goodware false-positive
screen, **not an independently audited malware benchmark**.
Package ownership alone does not establish that all files are benign.

The staged engine is the previously extracted AetherAV release build, not a
newly compiled R5 release, and its guest assets lack the complete malicious
hash database. Results from it must therefore **not** be represented as a
shipping R5 all-engine validation. The sandbox is useful to expose compatibility
and false-positive issues, but cannot establish the desired malware recall.

### 4. Fresh, independently audited holdout required

Use `tools/build_exclusion_set.py` on pinned historical JSONL ZIP archives
to prepare a combined SHA-256 exclusion set spanning training, validation,
and *all previously consulted tests*. Add every other historical evaluated
corpus before claiming a fresh holdout. Keep raw malicious binaries in an
offline, disposable and professionally controlled environment.

Feed per-file scan verdicts (real files only, not EICAR or static metadata)
into `tools/holdout_evidence.py`. A suspicious verdict is counted as a
positive **for both recall and false-positive accounting**. Errors, missing
labels, mismatched engine SHA-256, duplicate samples and train/test hash
overlap reject the report. Confidence intervals come from
`tools/detection_quality_gate.py`.

An independent reviewer must verify corpus provenance, label correctness,
full signature/feed parity, detector version, threshold selection, sandbox
isolation, and actual prevention behavior. The tooling records self-attested
claims; **it does not create external certification**.

The binary release can be promoted only when BOTH simultaneously hold:

- Recall >= **98.99%** on actual malicious files, with the stronger 95% lower
  confidence bound >=98.99%.
- Benign FPR <= **0.29%** on real goodware, with the stronger 95% upper
  confidence bound <=0.29%.

A result on only 2,989 benign records is generally too small to make a
confident 0.29%-FPR assertion if there are multiple false positives.
The benchmark must include enough positives and benign negatives to support
the uncertainty requirement.

## Tests

```bash
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 -m py_compile tools/behavioral_fusion.py tools/holdout_evidence.py \
  tools/build_exclusion_set.py tools/elf_hard_example_training.py
cargo test -p aether-behavior
cargo fmt --all --check
```

Only read-only experimental features and tooling were added. No code here
authenticates an unseen malware corpus by itself. Release status remains
**NOT APPROVED** until an independent review and reproducible new sample
manifest exist.

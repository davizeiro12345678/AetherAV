#!/usr/bin/env python3
"""Offline training-only hard-example mining for static ELF metadata.

Requirements: numpy, scikit-learn, joblib installed in a disposable research
environment. Never open/execute malware binaries or deploy the candidate.
The previously consulted test set is diagnostic ONLY; it MUST NOT select a
threshold, a hyperparameter, a model, or a release decision.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold
import joblib

from threshold_calibration import select_threshold, evaluate_scores

RESEARCH_ROOT = Path("/opt/jm-aetherav-review")
DATASET = RESEARCH_ROOT / "aegis1b-r2-20261118"
SRC = RESEARCH_ROOT / "real-malware-features-ember2024"
OUT = RESEARCH_ROOT / "aegis-detector-r5-20261119"
FPR_BUDGET = .0029


def weights_from_training_only(labels, families, oof_probs):
    """Only train split labels, family counts and OOF predictions are permitted."""
    y=np.asarray(labels)
    fam=np.asarray(families)
    prob=np.asarray(oof_probs)
    if y.ndim!=1 or y.shape!=fam.shape or y.shape!=prob.shape or not set(np.unique(y))=={0,1}:
        raise ValueError("incompatible training-only arrays")
    if not np.isfinite(prob).all() or (prob<0).any() or (prob>1).any():
        raise ValueError("invalid out-of-fold probabilities")
    counts=Counter(fam[y==1].tolist())
    weights=np.ones(len(y),dtype=np.float64)
    # Prefer learning from underrepresented training families, without
    # manufacturing copies of a rare malware executable.
    for i in np.flatnonzero(y==1):
        count=counts[str(fam[i])]
        weights[i] *= min(2.4,max(1.,np.sqrt(250/max(1,count))))
    # Hard negatives are BENIGN-LABELED training records, not independently
    # adjudicated cleanware; export candidates for manual confirmation.
    benign=(y==0)
    hard_threshold=float(np.quantile(prob[benign],.992))
    hard_neg=benign&(prob>=hard_threshold)
    weights[hard_neg]*=2.6
    near_neg=benign&(prob>=np.quantile(prob[benign],.95))&~hard_neg
    weights[near_neg]*=1.25
    hard_pos=(y==1)&(prob<=np.quantile(prob[y==1],.08))
    weights[hard_pos]*=1.5
    weights=np.clip(weights,.5,4.)
    return weights,hard_neg,hard_pos


def load_train_metadata():
    # Deduplicated, original dataset order: no test archive read here.
    import zipfile
    source=SRC/"ELF_train.zip"
    with source.open("rb") as f:
        sha=hashlib.file_digest(f,"sha256").hexdigest()
    if sha!="dd22c65c1a4b6b1c0680717814c74c1569256cf4ef6e7629c1b2b94b8e11afe3":
        raise RuntimeError("untrusted training metadata archive")
    records=[]
    seen=set()
    with zipfile.ZipFile(source) as z:
        for name in sorted(z.namelist()):
            if "/" in name or not name.endswith(".jsonl"):
                raise ValueError("untrusted ZIP path")
            with z.open(name) as stream:
                for line in stream:
                    item=json.loads(line)
                    key=item["sha256"]
                    if key in seen:continue
                    seen.add(key)
                    records.append(item)
    train=[r for r in records if r["week_id"]<44]
    valid=[r for r in records if r["week_id"]>=44]
    if (len(train),len(valid))!=(22000,4000):
        raise RuntimeError("train/valid split drift")
    if {r["sha256"] for r in train}&{r["sha256"] for r in valid}:
        raise RuntimeError("train/valid hash overlap")
    return train,valid


def classifier(steps=135,seed=20261119):
    return HistGradientBoostingClassifier(
        loss="log_loss",max_iter=steps,learning_rate=.075,
        max_leaf_nodes=15,min_samples_leaf=15,l2_regularization=4.,
        max_bins=128,random_state=seed,early_stopping=False)


def run():
    start=time.monotonic()
    OUT.mkdir(exist_ok=True)
    manifest=json.loads((DATASET/"elf-data-integrity.json").read_text())
    with (DATASET/"elf-data-615.npz").open("rb") as f:
        source_sha=hashlib.file_digest(f,"sha256").hexdigest()
    if source_sha!=manifest["dataset_npz_sha256"]:
        raise RuntimeError("input checksum mismatch")
    D=np.load(DATASET/"elf-data-615.npz",allow_pickle=False)
    train,valid=load_train_metadata()
    X=D["X_train"]; y=D["y_train"].astype(int)
    Xv=D["X_valid"]; yv=D["y_valid"].astype(int)
    assert len(X)==len(train)==22000 and len(Xv)==len(valid)==4000
    assert np.array_equal(y,np.array([r["label"] for r in train]))
    assert np.array_equal(yv,np.array([r["label"] for r in valid]))
    families=np.array([str(r.get("family") or "unknown") if r["label"]==1 else "benign"
                       for r in train])
    # Cross-fit. Sample i is NEVER evaluated by a model that trained on i.
    oof=np.full(len(y),np.nan,dtype=np.float64)
    folds=StratifiedKFold(n_splits=2,shuffle=True,random_state=1807)
    for fold,(a,b) in enumerate(folds.split(X,y)):
        t=time.monotonic()
        est=classifier(steps=115,seed=380+fold)
        est.fit(X[a],y[a])
        oof[b]=est.predict_proba(X[b])[:,1]
        print("OOF_FOLD",fold,"elapsed_s",round(time.monotonic()-t,2),flush=True)
    assert np.isfinite(oof).all()
    weights,hard_neg,hard_pos=weights_from_training_only(y,families,oof)
    queue=[]
    for i in np.flatnonzero(hard_neg):
        queue.append({"sha256":train[i]["sha256"],"split":"train","label":0,
         "score_out_of_fold":round(float(oof[i]),6),
         "manual_review_status":"UNCONFIRMED_PENDING_GOODWARE_VERIFICATION"})
    queue_path=OUT/"hard-negative-review-queue.json"
    queue_path.write_text(json.dumps(queue,indent=2))
    queue_path.chmod(0o600)
    print("TRAIN_CANDIDATES",len(queue),"hard-positive",int(hard_pos.sum()),flush=True)
    model=classifier(steps=210,seed=20261119)
    t=time.monotonic()
    model.fit(X,y,sample_weight=weights)
    print("WEIGHTED_FIT",round(time.monotonic()-t,2),flush=True)
    val_new=model.predict_proba(Xv)[:,1]
    c=np.load(DATASET/"classic-ensemble-probabilities.npz",allow_pickle=False)
    assert np.array_equal(yv,c["y_valid"])
    static=c["p_val"]
    # Preserve existing ensemble as champion. No access to test while selecting.
    candidates=[]
    for w in (0.,.15,.3,.45,.6,.8,1.):
        score=w*val_new+(1-w)*static
        threshold=select_threshold(yv,score,FPR_BUDGET)
        metric=evaluate_scores(yv,score,threshold)
        candidates.append({"weight":w,"threshold":threshold,"validation":metric})
    chosen=max(candidates,key=lambda r:(r["validation"]["tp"],-r["validation"]["fp"],-r["weight"]))
    # The test is previously consulted; one descriptive measurement only.
    yy=D["y_test"].astype(int)
    assert np.array_equal(yy,c["y_test"])
    if chosen["weight"]>0:
        p_test=(1-chosen["weight"])*c["p_test"]+chosen["weight"]*model.predict_proba(D["X_test"])[:,1]
    else:
        p_test=c["p_test"]
    reused=evaluate_scores(yy,p_test,chosen["threshold"])
    model_path=OUT/"weighted-hgb-research-only.joblib"
    joblib.dump(model,model_path,compress=3)
    report={
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "dataset":"EMBER2024 ELF 615 metadata (features only); no binaries executed",
        "data_sha256":source_sha,
        "train_rows":len(X),"validation_rows":len(Xv),"reused_temporal_test_rows":len(yy),
        "sample_hash_overlap_train_validation":0,
        "training_only_oof_folds":2,
        "hard_negative_dataset_labeled_unconfirmed":len(queue),
        "rare_malware_families_training_only":len(set(families[y==1])),
        "hard_positive_train":int(hard_pos.sum()),
        "review_queue":str(queue_path),
        "validation_candidates":candidates,
        "selected_on_validation_only":chosen,
        "reused_test_selected":reused,
        "holdout_independent":False,
        "model_weight_hash_sha256":hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "production_model_changed":False,"automatic_quarantine_changed":False,
        "retraining_time_seconds":round(time.monotonic()-start,2),
        "release_approved":False,
        "caveat":"Training-set goodware labels were not independently adjudicated; manual confirmation required before calling items confirmed false positives.",
    }
    out=OUT/"weighted-r5-training-report.json"
    out.write_text(json.dumps(report,indent=2))
    print("R5_WEIGHTED_RESULT",json.dumps({"selected":chosen,
      "reused_test":reused,"elapsed_s":report["retraining_time_seconds"],
      "release_approved":False,"report":str(out)}),flush=True)

if __name__=="__main__":
    run()

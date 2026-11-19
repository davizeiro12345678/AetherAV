"""Conservative threshold selection on a validation-only score vector."""
from __future__ import annotations

import math


def _pairs(labels, scores):
    ys, ps = list(labels), list(scores)
    if len(ys) != len(ps) or not ys or set(ys) != {0, 1}:
        raise ValueError('validation must have matching scores and both classes 0/1')
    if any(isinstance(x,bool) or x not in (0, 1) for x in ys):
        raise ValueError('labels must be 0/1')
    if any(not isinstance(v, (int,float)) or not math.isfinite(v) for v in ps):
        raise ValueError('scores must be finite numbers')
    return ys, ps


def select_threshold(labels, scores, target_fpr: float = 0.0029) -> float:
    ys, ps = _pairs(labels, scores)
    if not math.isfinite(target_fpr) or not 0 <= target_fpr <= 1:
        raise ValueError('target_fpr must lie between zero and one')
    benign = sorted(s for y,s in zip(ys,ps) if y==0)
    allowed = math.floor(len(benign)*target_fpr+1e-12)
    if allowed>=len(benign):
        return float(min(ps))
    # Strictly greater than the (allowed+1)th highest benign score.
    # In a tie this may choose fewer than allowed, never more.
    return math.nextafter(float(benign[-allowed-1]), math.inf)


def evaluate_scores(labels, scores, threshold: float) -> dict:
    ys, ps = _pairs(labels, scores)
    if not math.isfinite(threshold):
        raise ValueError('threshold must be finite')
    tp=fp=tn=fn=0
    for y,p in zip(ys,ps):
        predicted = p >= threshold
        if y==1 and predicted: tp+=1
        elif y==1: fn+=1
        elif predicted: fp+=1
        else: tn+=1
    return {'tp':tp,'fn':fn,'fp':fp,'tn':tn,
            'recall':tp/(tp+fn),'fpr':fp/(fp+tn),
            'precision':tp/max(1,tp+fp)}

"""Anonymisation baselines over the six Adult quasi-identifiers.

* MDAV heterogeneous microaggregation (Domingo-Ferrer & Torra, 2005):
  numeric QIs are z-scored, nominal QIs one-hot encoded (scaled by 1/sqrt 2
  so that a mismatch contributes unit squared distance); each group of >= k
  records publishes the numeric mean (age rounded) and the nominal mode.
* Mondrian strict multidimensional partitioning (LeFevre et al., 2006) on
  ordinal codes; queries are answered with the standard uniform-within-
  partition estimate.
"""
from __future__ import annotations

from collections import Counter
from typing import List, Sequence, Tuple

import numpy as np

from .data import Query, Record

QI = ("age", "sex", "education", "marital", "race", "country")
NOMINAL = ("sex", "education", "marital", "race", "country")


def _encode(recs: Sequence[Record]):
    cols = []
    age = np.array([r.age for r in recs], float)
    cols.append(((age - age.mean()) / age.std())[:, None])
    for a in NOMINAL:
        vals = sorted({getattr(r, a) for r in recs})
        idx = {v: i for i, v in enumerate(vals)}
        oh = np.zeros((len(recs), len(vals)))
        oh[np.arange(len(recs)), [idx[getattr(r, a)] for r in recs]] = 1 / np.sqrt(2)
        cols.append(oh)
    return np.hstack(cols)


def mdav(recs: Sequence[Record], k: int) -> List[List[int]]:
    """Return MDAV groups as lists of record indices (every group has >= k)."""
    X = _encode(recs)
    remaining = np.arange(len(recs))
    groups: List[List[int]] = []

    def take(center_row, pool):
        d = ((X[pool] - center_row) ** 2).sum(1)
        sel = np.argpartition(d, k - 1)[:k]
        return pool[sel]

    while len(remaining) >= 3 * k:
        c = X[remaining].mean(0)
        r = remaining[np.argmax(((X[remaining] - c) ** 2).sum(1))]
        s = remaining[np.argmax(((X[remaining] - X[r]) ** 2).sum(1))]
        g1 = take(X[r], remaining)
        remaining = np.setdiff1d(remaining, g1, assume_unique=True)
        g2 = take(X[s], remaining)
        remaining = np.setdiff1d(remaining, g2, assume_unique=True)
        groups += [g1.tolist(), g2.tolist()]
    if len(remaining) >= 2 * k:
        c = X[remaining].mean(0)
        r = remaining[np.argmax(((X[remaining] - c) ** 2).sum(1))]
        g = take(X[r], remaining)
        remaining = np.setdiff1d(remaining, g, assume_unique=True)
        groups.append(g.tolist())
    if len(remaining):
        groups.append(remaining.tolist())
    return groups


def mdav_release(recs: Sequence[Record], k: int) -> List[Record]:
    out: List[Record] = [None] * len(recs)  # type: ignore
    for g in mdav(recs, k):
        members = [recs[i] for i in g]
        age = int(round(np.mean([m.age for m in members])))
        mode = {a: Counter(getattr(m, a) for m in members).most_common(1)[0][0] for a in NOMINAL}
        for i, m in zip(g, members):
            out[i] = m._replace(pid="", age=age, **mode)
    return out


# ------------------------------------------------------------------ Mondrian
def mondrian(recs: Sequence[Record], k: int):
    """Return partitions as (index array, per-QI [lo, hi] code box)."""
    codes, domains = [], []
    for a in QI:
        vals = sorted({getattr(r, a) for r in recs})
        idx = {v: i for i, v in enumerate(vals)}
        codes.append([idx[getattr(r, a)] for r in recs])
        domains.append(vals)
    C = np.array(codes, dtype=np.int64).T
    span = C.max(0) - C.min(0) + 1
    parts = []
    stack = [np.arange(len(recs))]
    while stack:
        idx = stack.pop()
        sub = C[idx]
        lo, hi = sub.min(0), sub.max(0)
        order = np.argsort(-(hi - lo) / span)
        for d in order:
            if hi[d] == lo[d]:
                continue
            col = sub[:, d]
            med = np.median(col)
            mask = col <= med
            if mask.all():          # median equals the maximum: split below it
                mask = col < med
            left = idx[mask]
            right = np.setdiff1d(idx, left, assume_unique=True)
            if len(left) >= k and len(right) >= k:
                stack += [left, right]
                break
        else:
            parts.append((idx, lo, hi))
    return parts, domains


def mondrian_estimate(recs: Sequence[Record], parts, domains, q: Query) -> Tuple[float, float]:
    """Uniform-within-partition estimate of (COUNT, SUM(hours))."""
    code = {a: {v: i for i, v in enumerate(domains[j])} for j, a in enumerate(QI)}
    cnt = tot = 0.0
    hours = np.array([r.hours for r in recs], float)
    for idx, lo, hi in parts:
        frac = 1.0
        for a, v in q.predicates():
            if a not in QI:   # occupation is not generalised: exact per record
                continue
            j = QI.index(a)
            if a == "age":
                ages = domains[j][lo[j]:hi[j] + 1]
                inside = sum(1 for x in ages if v[0] <= x <= v[1])
                frac *= inside / len(ages)
            else:
                c = code[a].get(v)
                frac *= (1.0 / (hi[j] - lo[j] + 1)) if c is not None and lo[j] <= c <= hi[j] else 0.0
            if frac == 0:
                break
        if frac == 0:
            continue
        occ = q.occupation
        members = idx if occ is None else np.array([i for i in idx if recs[i].occupation == occ], int)
        cnt += frac * len(members)
        tot += frac * hours[members].sum() if len(members) else 0.0
    return cnt, tot

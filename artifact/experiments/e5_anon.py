"""E5: utility of anonymisation baselines vs. exact split answers (Adult).

Relative error of COUNT and AVG(hours) over 1,000 random conjunctive
queries (queries with true count >= 20), MDAV and Mondrian at several k.
Also reports SSE/SST information loss of MDAV on z-scored age and the
verified minimum equivalence-class size over the six quasi-identifiers.
"""
from __future__ import annotations

import statistics
import time
from collections import Counter

import numpy as np

from common import dump, env
from zsprism.anonymize import QI, mdav_release, mondrian, mondrian_estimate
from zsprism.data import load_adult, random_queries, reference


def rel(a, b):
    return abs(a - b) / abs(b)


def main():
    recs = load_adult()
    qs = [q for q in random_queries(recs, 3000, seed=5) if reference(recs, q)[0] >= 20][:1000]
    truths = [reference(recs, q) for q in qs]
    out = {"env": env(), "n": len(recs), "queries": len(qs), "runs": []}
    ages = np.array([r.age for r in recs], float)
    for k in (5, 10, 25, 50):
        t0 = time.perf_counter()
        rel_mdav = mdav_release(recs, k)
        t_mdav = time.perf_counter() - t0
        classes = Counter(tuple(getattr(r, a) for a in QI) for r in rel_mdav)
        sse = float(((np.array([r.age for r in rel_mdav]) - ages) ** 2).sum() / ((ages - ages.mean()) ** 2).sum())
        ce, ae = [], []
        for q, (tc, ts) in zip(qs, truths):
            c, s = reference(rel_mdav, q)
            ce.append(rel(c, tc))
            if q.agg == "avg":
                ae.append(rel(s / c, ts / tc) if c else 1.0)
        out["runs"].append({"method": "MDAV", "k": k, "seconds": t_mdav, "min_class": min(classes.values()),
                            "age_sse_sst": sse, "count_rel_median": statistics.median(ce),
                            "count_rel_mean": statistics.mean(ce), "count_gt10pct": sum(e > .1 for e in ce) / len(ce),
                            "avg_rel_median": statistics.median(ae), "avg_rel_mean": statistics.mean(ae)})
        print(out["runs"][-1], flush=True)
        t0 = time.perf_counter()
        parts, domains = mondrian(recs, k)
        t_m = time.perf_counter() - t0
        ce, ae = [], []
        for q, (tc, ts) in zip(qs, truths):
            c, s = mondrian_estimate(recs, parts, domains, q)
            ce.append(rel(c, tc))
            if q.agg == "avg":
                ae.append(rel(s / c, ts / tc) if c else 1.0)
        out["runs"].append({"method": "Mondrian", "k": k, "seconds": t_m,
                            "min_class": min(len(p[0]) for p in parts),
                            "count_rel_median": statistics.median(ce), "count_rel_mean": statistics.mean(ce),
                            "count_gt10pct": sum(e > .1 for e in ce) / len(ce),
                            "avg_rel_median": statistics.median(ae), "avg_rel_mean": statistics.mean(ae)})
        print(out["runs"][-1], flush=True)
        dump("e5_anon", out)


if __name__ == "__main__":
    main()

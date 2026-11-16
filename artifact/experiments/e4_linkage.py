"""E4: empirical cross-provider linkage by colluding providers (Adult).

Snapshot attacks (static tables only):
  * handle-equality join and storage-order (rank) alignment between S0 and S2;
  * share-sum test between the two share holders S0 and S1: a pair (i, j) is
    declared linked when (s0_i + s1_j) mod q lies in the measure's domain.
The query-trace intersection attack is in e4_trace.py.
"""
from __future__ import annotations

import bisect

from common import dump, env
from zsprism.crypto import Q
from zsprism.data import load_adult
from zsprism.rpc import Cluster
from zsprism.systems import SplitSystem

HOURS = (1, 99)


def rid_of(system, store, handles):
    return system.link.rids(handles, store)


def snapshot_attacks(system, cl):
    t0 = cl.p[0].dump("SELECT k, s FROM t")       # stored order = clustered by handle
    t1 = cl.p[1].dump("SELECT k, s FROM t")
    t2 = cl.p[2].dump("SELECT k FROM t")
    n = len(t0)
    r0 = rid_of(system, 0, [r[0] for r in t0])
    r1 = rid_of(system, 1, [r[0] for r in t1])
    r2 = rid_of(system, 2, [r[0] for r in t2])
    # (S0,S2) equality join on handles
    pos2 = {r[0]: i for i, r in enumerate(t2)}
    eq = sum(1 for i, r in enumerate(t0) if r[0] in pos2 and r2[pos2[r[0]]] == r0[i])
    # (S0,S2) rank alignment
    rank = sum(1 for a, b in zip(r0, r2) if a == b)
    # (S0,S1) share-sum test
    s1_sorted = sorted((r[1], j) for j, r in enumerate(t1))
    keys = [v for v, _ in s1_sorted]
    correct = claimed = 0
    for i, (_, s0) in enumerate(t0):
        lo, hi = (HOURS[0] - s0) % Q, (HOURS[1] - s0) % Q
        if lo <= hi:
            cands = s1_sorted[bisect.bisect_left(keys, lo):bisect.bisect_right(keys, hi)]
        else:
            cands = s1_sorted[bisect.bisect_left(keys, lo):] + s1_sorted[:bisect.bisect_right(keys, hi)]
        if len(cands) == 1:
            claimed += 1
            correct += r1[cands[0][1]] == r0[i]
    return {"n": n, "s0s2_equality_linked": eq / n, "s0s2_rank_linked": rank / n,
            "s0s1_sharesum_claimed": claimed / n, "s0s1_sharesum_correct": correct / n}


def main():
    recs = load_adult()
    n = len(recs)
    out = {"env": env(), "n": n, "snapshot": {}}
    for link in ("prp", "map", "shared"):
        cl = Cluster(3)
        system = SplitSystem(link, cl)
        system.insert(recs)
        out["snapshot"][system.name] = snapshot_attacks(system, cl)
        print(system.name, out["snapshot"][system.name], flush=True)
        cl.close()
    dump("e4_linkage", out)


if __name__ == "__main__":
    main()

"""E4b: query-trace intersection attack by two colluding providers (Adult).

Each provider logs, per query, the handles it *receives* (candidate lists)
and *returns* (results), in arrival order.  For a colluding pair (a, b) the
executor implies: whenever a's handle h arrives in a candidate list, the
partner of h appeared in every response b produced earlier in the same query
(candidates are always a subset of earlier results), and symmetrically.
For a sample of target records, the attacker intersects these constraints
(bitset containment) and declares a link when exactly one b-handle remains.
"""
from __future__ import annotations

import math
import random
from collections import defaultdict

import numpy as np

from common import dump, env
from zsprism.data import load_adult, random_queries
from zsprism.rpc import Cluster
from zsprism.systems import SplitSystem

TARGETS = 1000


class Tracer:
    def __init__(self, cl):
        self.qid = 0
        self.seq = 0
        self.events = []  # (qid, seq, store, kind, handles)
        for s, p in enumerate(cl.p):
            orig = p.call

            def call(_orig=orig, _s=s, **req):
                res = _orig(**req)
                c = req.get("cand")
                if c:
                    self.seq += 1
                    self.events.append((self.qid, self.seq, _s, "req", [c[i:i + 16] for i in range(0, len(c), 16)]))
                packed = None
                if isinstance(res, dict) and "c" in res:            # cols
                    packed = res["c"]
                elif isinstance(res, list) and len(res) == 2 and isinstance(res[1], list):  # probe_cols
                    packed = res[1]
                if packed and req.get("sql", "").lstrip().upper().startswith("SELECT K"):
                    blob = packed[0]
                    hs = [blob[i:i + 16] for i in range(0, len(blob), 16)]
                    if hs:
                        self.seq += 1
                        self.events.append((self.qid, self.seq, _s, "resp", hs))
                return res
            p.call = call


def bitmatrix(index, n_bits, rows):
    """rows: dict row_index -> list of bit positions."""
    words = max(1, math.ceil(n_bits / 64))
    m = np.zeros((len(index), words), dtype=np.uint64)
    for r, bits in rows.items():
        for b in bits:
            m[r, b >> 6] |= np.uint64(1) << np.uint64(b & 63)
    return m


def attack(system, events, a, b, n_queries, targets_a):
    ev = [e for e in events if e[0] <= n_queries]
    # all handles held by a and b
    hb_all = [r[0] for r in system.c.p[b].dump("SELECT k FROM t")]
    ib = {h: i for i, h in enumerate(hb_all)}
    resp = {s: [e for e in ev if e[2] == s and e[3] == "resp"] for s in (a, b)}
    req = {s: [e for e in ev if e[2] == s and e[3] == "req"] for s in (a, b)}
    rb_bit = {(e[0], e[1]): i for i, e in enumerate(resp[b])}
    ra_bit = {(e[0], e[1]): i for i, e in enumerate(resp[a])}
    # M_b: b-handle -> b-response events it appeared in
    Mb_rows = defaultdict(list)
    for e in resp[b]:
        for h in e[4]:
            Mb_rows[ib[h]].append(rb_bit[(e[0], e[1])])
    Mb = bitmatrix(hb_all, len(resp[b]), Mb_rows)
    # E_b: b-handle -> a-response events that must contain its partner
    Eb_rows = defaultdict(list)
    for e in req[b]:
        prior = [ra_bit[(x[0], x[1])] for x in resp[a] if x[0] == e[0] and x[1] < e[1]]
        if prior:
            for h in e[4]:
                Eb_rows[ib[h]].extend(prior)
    Eb = bitmatrix(hb_all, len(resp[a]), Eb_rows)
    # per-target constraints on the a side
    Ea, Ma = defaultdict(list), defaultdict(list)
    for e in req[a]:
        prior = [rb_bit[(x[0], x[1])] for x in resp[b] if x[0] == e[0] and x[1] < e[1]]
        for h in e[4]:
            if h in targets_a and prior:
                Ea[h].extend(prior)
    for e in resp[a]:
        for h in e[4]:
            if h in targets_a:
                Ma[h].append(ra_bit[(e[0], e[1])])
    linked, sizes = 0, []
    for h in targets_a:
        ea = bitmatrix([0], len(resp[b]), {0: Ea.get(h, [])})[0]
        ma = bitmatrix([0], len(resp[a]), {0: Ma.get(h, [])})[0]
        ok = np.all((Mb & ea) == ea, axis=1) & np.all((Eb & ~ma) == 0, axis=1)
        cnt = int(ok.sum())
        sizes.append(cnt)
        if cnt == 1:
            g = hb_all[int(np.argmax(ok))]
            linked += system.link.rids([h], a)[0] == system.link.rids([g], b)[0]
    sizes.sort()
    return linked / len(targets_a), sizes[len(sizes) // 2]


def main():
    recs = load_adult()
    qs = random_queries(recs, 1000, seed=99)
    checkpoints = [10, 100, 300, 1000]
    out = {"env": env(), "n": len(recs), "targets": TARGETS, "runs": []}
    rng = random.Random(4)
    for plan in ("pushdown", "broadcast"):
        cl = Cluster(3)
        system = SplitSystem("prp", cl, plan=plan)
        system.insert(recs)
        tr = Tracer(cl)
        for i, q in enumerate(qs, 1):
            tr.qid = i
            system.query(q)
        for a, b in ((0, 2), (1, 2)):
            all_a = [r[0] for r in cl.p[a].dump("SELECT k FROM t")]
            targets = set(rng.sample(all_a, TARGETS))
            for m in checkpoints:
                frac, med = attack(system, tr.events, a, b, m, targets)
                row = {"plan": plan, "pair": f"S{a}+S{b}", "queries": m, "linked": frac, "median_candidates": med}
                out["runs"].append(row)
                print(row, flush=True)
                dump("e4_trace", out)
        cl.close()


if __name__ == "__main__":
    main()

"""E6: write-path latency (update, delete, single-record insert), Adult base.

Loopback and 10 ms emulated RTT at 100 Mbps.  Each operation is applied to
distinct random records; results are verified by a follow-up lookup.
"""
from __future__ import annotations

import random
import time

from common import build, dump, env, summary
from zsprism.data import Query, load_adult

NAMES = ["ZS-PRISM", "Map split", "Shared-TID split", "DET+Paillier", "DET+AEAD"]


def main():
    recs = load_adult()
    out = {"env": env(), "n": len(recs), "runs": []}
    for name in NAMES:
        system, cl, _ = build(name, recs)
        rng = random.Random(1)
        pool = rng.sample(recs, 400)
        for rtt in (0.0, 10.0):
            cl.set_network(rtt, 100.0 if rtt else 0.0)
            ops = {"update": [], "delete": [], "insert": []}
            batch, pool = pool[:100], pool[100:]
            for r in batch[:50]:
                t0 = time.perf_counter()
                system.update(r.pid, 77)
                ops["update"].append((time.perf_counter() - t0) * 1e3)
            for r in batch[50:]:
                t0 = time.perf_counter()
                system.delete(r.pid)
                ops["delete"].append((time.perf_counter() - t0) * 1e3)
            for i, r in enumerate(batch[50:]):
                fresh = r._replace(pid=f"W{rtt}-{i}")
                t0 = time.perf_counter()
                system.insert([fresh])
                ops["insert"].append((time.perf_counter() - t0) * 1e3)
            cl.set_network(0.0, 0.0)
            assert system.query(Query("lookup", pid=batch[0].pid)).hours == 77
            assert system.query(Query("lookup", pid=batch[60].pid)) is None
            assert system.query(Query("lookup", pid=f"W{rtt}-3")) is not None
            row = {"system": name, "rtt_ms": rtt, **{k: summary(v) for k, v in ops.items()}}
            out["runs"].append(row)
            print(name, rtt, {k: round(v["median"], 3) for k, v in row.items() if isinstance(v, dict)}, flush=True)
        cl.close()
        dump("e6_writes", out)


if __name__ == "__main__":
    main()

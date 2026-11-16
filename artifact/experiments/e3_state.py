"""E3: persistent proxy state, heap footprint and replica bootstrap time.

Map split: compact snapshot (rid + one handle per store per record), Python
heap of the live maps (tracemalloc), and the time to rebuild the maps from
the snapshot.  ZS-PRISM: the 32-byte master secret and the time to derive
its subkeys and AES contexts.
"""
from __future__ import annotations

import statistics
import time
import tracemalloc

from common import dump, env
from zsprism.crypto import KeyRing, new_master_key, new_rids
from zsprism.systems import MapLinkage


def main():
    out = {"env": env(), "runs": []}
    master = new_master_key()
    t = []
    for _ in range(50):
        t0 = time.perf_counter()
        KeyRing(master)
        t.append((time.perf_counter() - t0) * 1e3)
    out["zs_bootstrap_ms"] = statistics.median(t)
    out["zs_state_bytes"] = len(master)
    for n in (10_000, 100_000, 1_000_000, 3_000_000):
        rids = new_rids(n)
        tracemalloc.start()
        m = MapLinkage()
        for s in range(3):
            m.assign(rids, s)
        heap = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        snap = m.snapshot()
        del m
        boots = []
        for _ in range(3 if n >= 1_000_000 else 7):
            t0 = time.perf_counter()
            MapLinkage.restore(snap)
            boots.append((time.perf_counter() - t0) * 1e3)
        row = {"n": n, "map_snapshot_bytes": len(snap), "map_heap_bytes": heap,
               "map_bootstrap_ms": statistics.median(boots),
               "map_bytes_per_record": len(snap) / n, "map_heap_per_record": heap / n}
        out["runs"].append(row)
        print(row, flush=True)
        dump("e3_state", out)


if __name__ == "__main__":
    main()

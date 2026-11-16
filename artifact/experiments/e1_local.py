"""E1: ingestion, per-workload latency and traffic on loopback (no emulated delay).

Adult (N = 45,222) for all systems; Adult upsampled to 200k and 1M records
for the systems whose ingestion is practical at that scale.  Every timed
query is first checked against the plaintext reference.
"""
from __future__ import annotations

import argparse

from common import build, dump, env, summary, time_query, workloads
from zsprism.data import load_adult, scaled

ALL = ["ZS-PRISM", "Map split", "Shared-TID split", "DET+Paillier", "DET+AEAD", "AEAD scan", "3PC-RSS"]
LARGE = ["ZS-PRISM", "Map split", "Shared-TID split", "DET+AEAD", "AEAD scan", "3PC-RSS"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="45222,200000,1000000")
    ap.add_argument("--instances", type=int, default=3)
    ap.add_argument("--reps", type=int, default=11)
    ap.add_argument("--systems", default="")
    ap.add_argument("--out", default="e1_local")
    a = ap.parse_args()
    out = {"env": env(), "runs": []}
    adult_n = len(load_adult())
    for n in map(int, a.sizes.split(",")):
        names = ALL if n == adult_n else LARGE
        if a.systems:
            names = [x for x in names if x in a.systems.split(",")]
        for inst in range(a.instances):
            recs = scaled(n, seed=100 + inst)
            wl = workloads(recs)
            for name in names:
                if name == "DET+Paillier" and inst > 0:
                    continue  # one instance: ingestion takes minutes
                reps = a.reps if not (name == "AEAD scan" and n >= 1_000_000) else 5
                system, cl, ingest = build(name, recs)
                row = {"n": n, "instance": inst, "system": name, "ingest_ms": ingest,
                       "state_bytes": system.state_bytes(),
                       "provider_bytes": sum(p.size() for p in cl.p), "workloads": {}}
                for wname, q in wl.items():
                    lat, traffic, plan = time_query(system, cl, q, recs, reps)
                    row["workloads"][wname] = {"lat": lat, **summary(lat), "traffic": traffic, "plan": plan}
                out["runs"].append(row)
                print(n, inst, name, round(ingest), {k: round(v["median"], 3) for k, v in row["workloads"].items()}, flush=True)
                cl.close()
                dump(a.out, out)


if __name__ == "__main__":
    main()

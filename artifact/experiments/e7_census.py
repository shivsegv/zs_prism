"""E7: second real data set -- UCI Census-Income (KDD), 299,285 records.

Fixed workloads Q1-Q5 (Census analogues) plus 200 random conjunctive queries,
on loopback and at 10 ms RTT / 100 Mb/s.  DET+Paillier is omitted here:
encrypting 299k values under 2048-bit Paillier takes ~23 min per load.
Every answer is checked against the plaintext reference.
"""
from __future__ import annotations

import statistics

from common import build, dump, env, summary, time_query
from zsprism.data import CENSUS_WORKLOADS, Query, load_census, random_queries, reference

NAMES = ["ZS-PRISM", "Map split", "Shared-TID split", "DET+AEAD", "AEAD scan", "3PC-RSS"]
NETS = [(0.0, 0.0), (10.0, 100.0)]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--systems", default=",".join(NAMES))
    ap.add_argument("--out", default="e7_census")
    a = ap.parse_args()
    recs = load_census()
    wl = {"Q1 lookup": Query("lookup", pid=recs[len(recs) // 3].pid), **CENSUS_WORKLOADS}
    rq = random_queries(recs, 200, seed=21)
    truth = [reference(recs, q) for q in rq]
    out = {"env": env(), "n": len(recs), "runs": []}
    for name in a.systems.split(","):
        system, cl, ingest = build(name, recs)
        for rtt, rate in NETS:
            cl.set_network(rtt, rate)
            if hasattr(system, "bw_mbps"):
                system.bw_mbps = rate
            if name != "AEAD scan":
                for q in wl.values():   # untimed pass after every network change
                    system.query(q)
            reps = 3 if (name == "AEAD scan" and rtt) else 5
            row = {"system": name, "rtt_ms": rtt, "rate_mbps": rate, "ingest_ms": ingest, "workloads": {}}
            for wname, q in wl.items():
                lat, traffic, plan = time_query(system, cl, q, recs, reps, warmup=1)
                row["workloads"][wname] = {**summary(lat), "traffic": traffic, "plan": plan}
            if True:
                import time
                lat = []
                for q, t in zip(rq, truth):
                    t0 = time.perf_counter()
                    got = system.query(q)
                    lat.append((time.perf_counter() - t0) * 1e3)
                    if got != t:
                        raise AssertionError(f"{name} wrong on {q}")
                lat.sort()
                row["random"] = {"median": statistics.median(lat), "p90": lat[int(0.9 * len(lat))], "n": len(lat)}
            out["runs"].append(row)
            print(name, rtt, round(ingest), {k: round(v["median"], 1) for k, v in row["workloads"].items()},
                  row.get("random"), flush=True)
            dump(a.out, out)
        cl.close()


if __name__ == "__main__":
    main()

"""E2: end-to-end latency under emulated wide-area links (Adult, N = 45,222).

Each provider delays every response by RTT + (request+response bytes)/rate.
The cost-based planner is given the configured link rate; its RTT estimate is
measured from the cardinality probe.
"""
from __future__ import annotations

import argparse

from common import build, dump, env, summary, time_query, workloads
from zsprism.data import load_adult

NAMES = ["ZS-PRISM", "ZS-PRISM (pushdown)", "ZS-PRISM (broadcast)", "Map split",
         "Shared-TID split", "DET+Paillier", "DET+AEAD", "AEAD scan", "3PC-RSS"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rtts", default="1,5,10,25,50")
    ap.add_argument("--rates", default="100,1000")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--systems", default=",".join(NAMES))
    ap.add_argument("--out", default="e2_wan")
    a = ap.parse_args()
    recs = load_adult()
    wl = workloads(recs)
    out = {"env": env(), "n": len(recs), "runs": []}
    for name in a.systems.split(","):
        system, cl, ingest = build(name, recs)
        for rate in map(float, a.rates.split(",")):
            for rtt in map(float, a.rtts.split(",")):
                cl.set_network(rtt, rate)
                if hasattr(system, "bw_mbps"):
                    system.bw_mbps = rate
                for q in wl.values():   # untimed pass after every network change
                    system.query(q)
                row = {"system": name, "rtt_ms": rtt, "rate_mbps": rate, "workloads": {}}
                for wname, q in wl.items():
                    lat, traffic, plan = time_query(system, cl, q, recs, a.reps, warmup=1)
                    row["workloads"][wname] = {**summary(lat), "traffic": traffic, "plan": plan}
                out["runs"].append(row)
                print(name, rate, rtt, {k: round(v["median"], 1) for k, v in row["workloads"].items()}, flush=True)
                dump(a.out, out)
        cl.close()


if __name__ == "__main__":
    main()

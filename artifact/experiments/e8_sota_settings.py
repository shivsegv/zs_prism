"""E8: Adult and 10^6 records under the network settings used by recent systems.

* 100 Mb/s, 20 ms RTT -- the WAN setting of SecretFlow-SCQL (PVLDB 2024).
* 1 Gb/s, 1 ms RTT    -- an intra-region link, as in the AWS deployment of
                          S^2 (PVLDB 2023).

Published numbers of those systems come from their papers and different
hardware; this experiment only matches data size and network conditions.
Every answer is checked against the plaintext reference.
"""
from __future__ import annotations

from common import build, dump, env, summary, time_query, workloads
from zsprism.data import load_adult, scaled

NAMES = ["ZS-PRISM", "Map split", "3PC-RSS"]
NETS = [(20.0, 100.0), (1.0, 1000.0)]
SIZES = (45_222, 1_000_000)


def main():
    out = {"env": env(), "runs": []}
    for n in SIZES:
        recs = load_adult() if n == len(load_adult()) else scaled(n, seed=100)
        wl = workloads(recs)
        wl.pop("Q2 count-1")
        for name in NAMES:
            system, cl, ingest = build(name, recs)
            for rtt, rate in NETS:
                cl.set_network(rtt, rate)
                if hasattr(system, "bw_mbps"):
                    system.bw_mbps = rate
                for q in wl.values():          # untimed pass after the network change
                    system.query(q)
                row = {"n": n, "system": name, "rtt_ms": rtt, "rate_mbps": rate, "workloads": {}}
                for wname, q in wl.items():
                    lat, traffic, plan = time_query(system, cl, q, recs, 5, warmup=1)
                    row["workloads"][wname] = {**summary(lat), "traffic": traffic, "plan": plan}
                out["runs"].append(row)
                print(n, name, rate, rtt, {k: round(v["median"], 1) for k, v in row["workloads"].items()}, flush=True)
                dump("e8_sota_settings", out)
            cl.close()


if __name__ == "__main__":
    main()

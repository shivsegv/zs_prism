"""Shared experiment harness."""
from __future__ import annotations

import json
import platform
import sqlite3
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

from zsprism.data import WORKLOADS, Query, reference  # noqa: E402
from zsprism.mpc3 import MPC3  # noqa: E402
from zsprism.rpc import Cluster  # noqa: E402


class _MPCCluster:
    """Adapts the 3PC baseline to the harness's cluster interface."""

    class _Size:
        def __init__(self, conn):
            self.conn = conn

        def size(self):
            return self.conn.call(op="size")["r"]

    def __init__(self, system):
        self.s = system
        self.p = [self._Size(c) for c in system.c]

    def set_network(self, rtt_ms, bw_mbps):
        self.s.set_network(rtt_ms, bw_mbps)

    def reset_counters(self):
        for c in self.s.c:
            c.bytes = 0

    def traffic(self):
        return {"requests": 3, "rounds": self.s.last_rounds,
                "bytes": sum(c.bytes for c in self.s.c) + self.s.last_ring_bytes}

    def close(self):
        self.s.close()
from zsprism.systems import CryptDBStyle, EncryptedScan, SplitSystem  # noqa: E402

SYSTEMS = {
    "ZS-PRISM": (3, lambda c: SplitSystem("prp", c, plan="auto")),
    "ZS-PRISM (pushdown)": (3, lambda c: SplitSystem("prp", c, plan="pushdown")),
    "ZS-PRISM (broadcast)": (3, lambda c: SplitSystem("prp", c, plan="broadcast")),
    "Map split": (3, lambda c: SplitSystem("map", c, plan="auto")),
    "Shared-TID split": (3, lambda c: SplitSystem("shared", c, plan="auto")),
    "DET+Paillier": (1, lambda c: CryptDBStyle(c, hom=True)),
    "DET+AEAD": (1, lambda c: CryptDBStyle(c, hom=False)),
    "AEAD scan": (1, lambda c: EncryptedScan(c)),
    "3PC-RSS": (0, None),
}


def build(name, recs):
    n_stores, make = SYSTEMS[name]
    if name == "3PC-RSS":
        system = MPC3()
        cl = _MPCCluster(system)
    else:
        cl = Cluster(n_stores)
        system = make(cl)
    ingest_ms = system.insert(recs)
    if hasattr(system, "calibrate"):
        system.calibrate()          # planner constants, measured with no emulated delay
    return system, cl, ingest_ms


def workloads(recs):
    w = dict(WORKLOADS)
    w["Q1 lookup"] = Query("lookup", pid=recs[len(recs) // 3].pid)
    return w


def time_query(system, cl, q, truth, reps, warmup=2):
    expected = reference(truth, q)
    got = system.query(q)                 # correctness check, always performed
    for _ in range(warmup):
        system.query(q)
    if got != expected:
        raise AssertionError(f"{getattr(system, 'name', system)} wrong on {q}: {got} != {expected}")
    lat, traffic = [], None
    for _ in range(reps):
        cl.reset_counters()
        t0 = time.perf_counter()
        system.query(q)
        lat.append((time.perf_counter() - t0) * 1e3)
        traffic = cl.traffic()
    return lat, traffic, getattr(system, "last_plan", None)


def summary(xs):
    xs = sorted(xs)
    q = statistics.quantiles(xs, n=4, method="inclusive") if len(xs) > 1 else [xs[0]] * 3
    return {"median": statistics.median(xs), "p25": q[0], "p75": q[2], "n": len(xs)}


def env():
    import cryptography
    import msgpack
    import numpy
    import phe
    try:
        import subprocess
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
        mem = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout.strip())
    except Exception:
        cpu, mem = platform.processor(), 0
    return {"cpu": cpu, "mem_gib": round(mem / 2**30, 1), "os": platform.platform(),
            "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
            "cryptography": cryptography.__version__, "phe": phe.__version__,
            "numpy": numpy.__version__, "msgpack": ".".join(map(str, msgpack.version))}


def dump(name, obj):
    (RESULTS / f"{name}.json").write_text(json.dumps(obj, indent=1, default=str))

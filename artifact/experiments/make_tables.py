"""Emit paper/generated/{numbers,tab_local}.tex from results/*.json.

Every number quoted in the manuscript is produced here, so text and data
cannot drift apart.
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RES = ROOT / "results"
OUT = ROOT.parent / "paper" / "generated"
OUT.mkdir(parents=True, exist_ok=True)

from zsprism.data import WORKLOADS, load_adult, reference  # noqa: E402

WL = ["Q1 lookup", "Q2 count-1", "Q3 range-avg", "Q4 conj-avg", "Q5 conj-sel"]
CORR_QUERIES = 1000  # per system/strategy in tests/test_correctness.py


def load(n):
    return json.loads((RES / f"{n}.json").read_text())


def ms(x):
    if x >= 1000:
        return f"{x / 1000:.2f}\\,s"
    if x >= 100:
        return f"{x:.0f}\\,ms"
    if x >= 10:
        return f"{x:.1f}\\,ms"
    return f"{x:.2f}\\,ms"


def num(x):
    return f"{x:,.0f}".replace(",", "{,}")


def pct(x, d=1):
    return f"{100 * x:.{d}f}\\%"


def main():
    m = {}
    adult = load_adult()
    m["NAdult"] = num(len(adult))
    m["CorrQueries"] = num(CORR_QUERIES)
    for i, w in enumerate(WL[1:], 2):
        m[f"SelQ{'two three four five'.split()[i - 2]}"] = num(reference(adult, WORKLOADS[w])[0])

    # ---- E1 local
    e1 = load("e1_local")
    nA = len(adult)

    def med(system, n, key):
        rows = [r for r in e1["runs"] if r["system"] == system and r["n"] == n]
        if not rows:
            return None
        if key == "ingest":
            return statistics.median(n / (r["ingest_ms"] / 1e3) for r in rows)
        if key == "ingest_ms":
            return statistics.median(r["ingest_ms"] for r in rows)
        return statistics.median(r["workloads"][key]["median"] for r in rows)

    systems = ["ZS-PRISM", "Map split", "Shared-TID split", "DET+Paillier", "DET+AEAD", "AEAD scan", "3PC-RSS"]
    lines = ["\\begin{tabular}{@{}lrrrrrr@{}}", "\\toprule",
             "System & rec/s & Q1 & Q2 & Q3 & Q4 & Q5\\\\", "\\midrule"]
    for s in systems:
        cells = [s.replace("ZS-PRISM", "\\textbf{\\sys{}}")]
        ing = med(s, nA, "ingest")
        cells.append("--" if ing is None else num(ing))
        for w in WL:
            v = med(s, nA, w)
            cells.append("--" if v is None else f"{v:.2f}" if v < 10 else f"{v:.1f}" if v < 100 else f"{v:.0f}")
        lines.append(" & ".join(cells) + "\\\\")
        if s == "Shared-TID split":
            lines.append("\\midrule")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (OUT / "tab_local.tex").write_text("\n".join(lines) + "\n")
    ratios = [med("ZS-PRISM", nA, w) / med("Map split", nA, w) for w in WL]
    slow = max(med('ZS-PRISM', nA, w) - med('Map split', nA, w) for w in WL)
    m["LocalSlowerClause"] = (f"is never more than {slow:.2f}\\,ms slower than" if slow > 0.005 else "is never slower than")
    m["LocalFaster"] = pct(max(1 - min(ratios), 0), 0)
    m["IngZS"] = num(med("ZS-PRISM", nA, "ingest"))
    m["IngMap"] = num(med("Map split", nA, "ingest"))
    m["IngPaillier"] = num(med("DET+Paillier", nA, "ingest"))
    m["PaillierSlowdown"] = f"{med('ZS-PRISM', nA, 'ingest') / med('DET+Paillier', nA, 'ingest'):.0f}$\\times$"
    big = max(r["n"] for r in e1["runs"])
    iqr = [(w["p75"] - w["p25"]) / w["median"]
           for r in e1["runs"] if r["system"] in ("ZS-PRISM", "Map split", "Shared-TID split")
           for w in r["workloads"].values() if w["median"] > 1.0]
    m["MaxIQR"] = pct(statistics.quantiles(iqr, n=20)[-1], 0)   # 95th percentile of relative IQR
    m["MPCLocalQfour"] = ms(med("3PC-RSS", nA, "Q4 conj-avg"))
    m["ZSLocalQfour"] = ms(med("ZS-PRISM", nA, "Q4 conj-avg"))
    m["MPCLookupMillion"] = ms(med("3PC-RSS", big, "Q1 lookup"))
    m["ZSLookupMillion"] = ms(med("ZS-PRISM", big, "Q1 lookup"))
    m["MPCQtwoMillion"] = ms(med("3PC-RSS", big, "Q2 count-1"))
    m["ZSQtwoMillion"] = ms(med("ZS-PRISM", big, "Q2 count-1"))
    m["MillionIngZS"] = ms(med("ZS-PRISM", big, "ingest_ms"))
    m["MillionQfourZS"] = ms(med("ZS-PRISM", big, "Q4 conj-avg"))
    m["MillionScan"] = ms(med("AEAD scan", big, "Q4 conj-avg"))

    # ---- E2 WAN
    e2 = load("e2_wan")

    def wan(system, rate, rtt, w):
        for r in e2["runs"]:
            if r["system"] == system and r["rate_mbps"] == rate and r["rtt_ms"] == rtt:
                return r["workloads"][w]["median"]
        raise KeyError((system, rate, rtt))

    m["WanPDlow"] = ms(wan("ZS-PRISM (pushdown)", 100.0, 1.0, "Q4 conj-avg"))
    m["WanBClow"] = ms(wan("ZS-PRISM (broadcast)", 100.0, 1.0, "Q4 conj-avg"))
    m["WanBChigh"] = ms(wan("ZS-PRISM (broadcast)", 1000.0, 50.0, "Q4 conj-avg"))
    m["WanPDhigh"] = ms(wan("ZS-PRISM (pushdown)", 1000.0, 50.0, "Q4 conj-avg"))
    regrets = []
    for r in e2["runs"]:
        if r["system"] != "ZS-PRISM":
            continue
        for w in ("Q3 range-avg", "Q4 conj-avg", "Q5 conj-sel"):
            best = min(wan("ZS-PRISM (pushdown)", r["rate_mbps"], r["rtt_ms"], w),
                       wan("ZS-PRISM (broadcast)", r["rate_mbps"], r["rtt_ms"], w))
            regrets.append(r["workloads"][w]["median"] / best - 1)
    m["WanRegret"] = pct(max(statistics.median(regrets), 0), 0)
    m["WanRegretMax"] = pct(max(regrets), 0)
    m["WanAutoBestFrac"] = f"{sum(r <= 0.05 for r in regrets)} of {len(regrets)}"
    sh, mp = [], []
    for r in e2["runs"]:
        if r["system"] != "ZS-PRISM":
            continue
        for w in ("Q3 range-avg", "Q4 conj-avg", "Q5 conj-sel"):
            z = r["workloads"][w]["median"]
            sh.append(abs(wan("Shared-TID split", r["rate_mbps"], r["rtt_ms"], w) / z - 1))
            mp.append(wan("Map split", r["rate_mbps"], r["rtt_ms"], w) / z)
    m["WanSharedDiff"] = pct(statistics.median(sh), 0)
    m["WanMapWorse"] = f"{max(mp):.1f}$\\times$"
    a = wan("ZS-PRISM", 100.0, 10.0, "Q5 conj-sel")
    b = min(wan("ZS-PRISM (pushdown)", 100.0, 10.0, "Q5 conj-sel"), wan("ZS-PRISM (broadcast)", 100.0, 10.0, "Q5 conj-sel"))
    m["WanAdaptiveWin"] = f"{b / a:.1f}$\\times$"
    m["WanScan"] = ms(wan("AEAD scan", 100.0, 10.0, "Q4 conj-avg"))

    def traffic(system, w):
        r = [x for x in e2["runs"] if x["system"] == system and x["rate_mbps"] == 100.0 and x["rtt_ms"] == 1.0][0]
        return r["workloads"][w]["traffic"]["bytes"]
    for w, tag in (("Q4 conj-avg", "Qfour"), ("Q5 conj-sel", "Qfive")):
        pdb, bcb = traffic("ZS-PRISM (pushdown)", w), traffic("ZS-PRISM (broadcast)", w)
        m[f"PDKB{tag}"] = f"{pdb / 1e3:.0f}\\,kB"
        m[f"BCKB{tag}"] = f"{bcb / 1e3:.0f}\\,kB"
        m[f"PDSave{tag}"] = f"{bcb / pdb:.1f}$\\times$"
    mq, zq = wan("3PC-RSS", 100.0, 10.0, "Q4 conj-avg"), wan("ZS-PRISM", 100.0, 10.0, "Q4 conj-avg")
    m["MPCQfourTen"], m["ZSQfourTen"] = ms(mq), ms(zq)
    m["MPCSpeedup"] = f"{mq / zq:.1f}$\\times$"
    m["MPCRounds"] = str([r for r in e2["runs"] if r["system"] == "3PC-RSS"][0]["workloads"]["Q4 conj-avg"]["traffic"]["rounds"])

    # ---- E7 Census (skipped until results exist)
    if (RES / "e7_census.json").exists():
        e7 = load("e7_census")["runs"]

        def cz(system, rtt, w):
            rows = [x for x in e7 if x["system"] == system and x["rtt_ms"] == rtt]
            if not rows:
                return None
            r = rows[0]
            return r["random"]["median"] if w == "rand" and "random" in r else (r["workloads"][w]["median"] if w != "rand" else None)

        def f(v):
            return "--" if v is None else (f"{v:.2f}" if v < 10 else f"{v:.1f}" if v < 100 else f"{v:.0f}")
        cols = [(0.0, "Q1 lookup"), (0.0, "Q3 range-avg"), (0.0, "Q4 conj-avg"), (0.0, "rand"),
                (10.0, "Q1 lookup"), (10.0, "Q4 conj-avg"), (10.0, "rand")]
        lines = ["\\begin{tabular}{@{}lrrrrrrr@{}}", "\\toprule",
                 " & \\multicolumn{4}{c}{loopback} & \\multicolumn{3}{c}{10\\,ms, 100\\,Mb/s}\\\\",
                 "\\cmidrule(lr){2-5}\\cmidrule(l){6-8}",
                 "System & Q1 & Q3 & Q4 & Rand. & Q1 & Q4 & Rand.\\\\", "\\midrule"]
        for sname in ["ZS-PRISM", "Map split", "Shared-TID split", "DET+AEAD", "AEAD scan", "3PC-RSS"]:
            lines.append(" & ".join([sname.replace("ZS-PRISM", "\\textbf{\\sys{}}")] + [f(cz(sname, r, w)) for r, w in cols]) + "\\\\")
        lines += ["\\bottomrule", "\\end{tabular}"]
        (OUT / "tab_census.tex").write_text("\n".join(lines) + "\n")
        ok = all(cz(x, 0.0, "rand") is not None for x in ("ZS-PRISM", "Map split"))
        cr = [cz("ZS-PRISM", 0.0, w) / cz("Map split", 0.0, w)
              for w in ("Q1 lookup", "Q2 count-1", "Q3 range-avg", "Q4 conj-avg", "Q5 conj-sel", "rand")] if ok else []
        cslow = max(cz('ZS-PRISM', 0.0, w) - cz('Map split', 0.0, w)
                    for w in ('Q1 lookup', 'Q2 count-1', 'Q3 range-avg', 'Q4 conj-avg', 'Q5 conj-sel', 'rand')) if ok else 0
        m["CensusSlowerClause"] = (f"is at most {cslow:.2f}\\,ms slower than" if cslow > 0.005 else "is never slower than")
        m["CensusFaster"] = pct(max(1 - min(cr), 0), 0) if ok else "\\textbf{??}"


    # ---- E8 matched settings of recent systems + measured SCQL
    e8 = load("e8_sota_settings")["runs"]

    def e8m(system, n, rtt, w):
        return [r for r in e8 if r["system"] == system and r["n"] == n and r["rtt_ms"] == rtt][0]["workloads"][w]["median"]
    BIG = 1_000_000
    m["EightZSQfourWan"] = ms(e8m("ZS-PRISM", BIG, 20.0, "Q4 conj-avg"))
    m["EightZSQoneWan"] = ms(e8m("ZS-PRISM", BIG, 20.0, "Q1 lookup"))
    m["EightMPCQfourWan"] = ms(e8m("3PC-RSS", BIG, 20.0, "Q4 conj-avg"))
    m["EightMPCQoneWan"] = ms(e8m("3PC-RSS", BIG, 20.0, "Q1 lookup"))
    m["EightZSQfourLan"] = ms(e8m("ZS-PRISM", BIG, 1.0, "Q4 conj-avg"))

    scql = {n: load(f"scql_{n}")["runs"] for n in (nA, BIG)}

    def sq(n, setting, w):
        return [r for r in scql[n] if r["setting"] == setting and r["query"] == w][0]["median_ms"]
    m["ScqlRtt"] = f"{[r for r in scql[nA] if r['setting'] != 'loopback'][0]['measured_engine_rtt_ms']:.1f}\\,ms"
    m["ScqlQfourWanA"] = ms(sq(nA, "wan_100mbps_20ms", "Q4 conj-avg"))
    m["ScqlQfourWanM"] = ms(sq(BIG, "wan_100mbps_20ms", "Q4 conj-avg"))
    m["ScqlQfourLocA"] = ms(sq(nA, "loopback", "Q4 conj-avg"))
    m["ScqlQfourLocM"] = ms(sq(BIG, "loopback", "Q4 conj-avg"))
    m["ZSQfourWanA"] = ms(e8m("ZS-PRISM", nA, 20.0, "Q4 conj-avg"))
    m["ZSQthreeWanM"] = ms(e8m("ZS-PRISM", BIG, 20.0, "Q3 range-avg"))
    m["ScqlQthreeWanM"] = ms(sq(BIG, "wan_100mbps_20ms", "Q3 range-avg"))
    ratios = [sq(n, "wan_100mbps_20ms", w) / e8m("ZS-PRISM", n, 20.0, w)
              for n in (nA, BIG) for w in ("Q4 conj-avg", "Q5 conj-sel")]
    m["ScqlSpeedupMin"] = f"{min(ratios):.1f}$\\times$"
    m["ScqlSpeedupMax"] = f"{max(ratios):.1f}$\\times$"

    def cell(v):
        return f"{v:.0f}" if v >= 100 else f"{v:.1f}"
    W3 = ("Q3 range-avg", "Q4 conj-avg", "Q5 conj-sel")
    lines = ["\\begin{tabular}{@{}lrrrrrr@{}}", "\\toprule",
             " & \\multicolumn{3}{c}{Adult} & \\multicolumn{3}{c}{$10^6$ records}\\\\",
             "\\cmidrule(lr){2-4}\\cmidrule(l){5-7}",
             "System & Q3 & Q4 & Q5 & Q3 & Q4 & Q5\\\\", "\\midrule"]
    lines.append(" & ".join(["SCQL 1.0 (measured)"] + [cell(sq(n, "wan_100mbps_20ms", w)) for n in (nA, BIG) for w in W3]) + "\\\\")
    for nm in ("ZS-PRISM", "Map split", "3PC-RSS"):
        lines.append(" & ".join([nm.replace("ZS-PRISM", "\\textbf{\\sys{}}")] + [cell(e8m(nm, n, 20.0, w)) for n in (nA, BIG) for w in W3]) + "\\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (OUT / "tab_sota.tex").write_text("\n".join(lines) + "\n")

    # ---- E3 state
    e3 = load("e3_state")
    byn = {r["n"]: r for r in e3["runs"]}
    m["MapHeapMillion"] = f"{byn[1_000_000]['map_heap_bytes'] / 1e6:.0f}\\,MB"
    m["MapHeapPerRec"] = num(byn[1_000_000]["map_heap_per_record"])
    m["MapBootMillion"] = ms(byn[1_000_000]["map_bootstrap_ms"])
    m["MapBootThree"] = ms(byn[3_000_000]["map_bootstrap_ms"])
    m["ZSBoot"] = f"{e3['zs_bootstrap_ms'] * 1000:.0f}\\,\\textmu s"

    # ---- E4 attacks
    e4 = load("e4_linkage")["snapshot"]
    m["SnapShared"] = pct(e4["Shared-TID split"]["s0s2_equality_linked"], 0)
    m["SnapZS"] = pct(max(e4["ZS-PRISM"]["s0s2_equality_linked"], e4["Map split"]["s0s2_equality_linked"]), 0)
    m["SnapRankZS"] = pct(max(e4["ZS-PRISM"]["s0s2_rank_linked"], e4["Map split"]["s0s2_rank_linked"]), 2)
    m["SnapShareSum"] = pct(min(v["s0s1_sharesum_correct"] for v in e4.values()), 0)
    tr = load("e4_trace")["runs"]

    def trace(plan):
        r = [x for x in tr if x["plan"] == plan and x["pair"] == "S0+S2" and x["queries"] == 1000][0]
        return r["linked"], r["median_candidates"]
    pd = [x["linked"] for x in tr if x["plan"] == "pushdown" and x["queries"] == 1000]
    bc = [x["linked"] for x in tr if x["plan"] == "broadcast" and x["queries"] == 1000]
    m["TraceLinkedPD"] = f"{pct(min(pd))}--{pct(max(pd))}" if min(pd) != max(pd) else pct(pd[0])
    m["TraceSetPD"] = num(trace("pushdown")[1])
    m["TraceSetBC"] = num(trace("broadcast")[1])
    targets = load("e4_trace")["targets"]
    m["TraceBCClause"] = (f"no target is linked (0 of {num(targets)})" if max(bc) == 0
                          else f"at most {pct(max(bc))} of targets are linked")

    # ---- E5 utility / E6 writes
    e5 = load("e5_anon")["runs"]

    def u(meth, k, key):
        return float([r for r in e5 if r["method"] == meth and r["k"] == k][0][key])
    m["UtilMdavFive"] = pct(u("MDAV", 5, "count_rel_median"))
    m["UtilMondFive"] = pct(u("Mondrian", 5, "count_rel_median"))
    m["UtilMondTail"] = pct(u("Mondrian", 50, "count_gt10pct"), 0)
    m["UtilMdavAvg"] = pct(u("MDAV", 5, "avg_rel_median"), 2)
    e6 = load("e6_writes")["runs"]
    z = [r for r in e6 if r["system"] == "ZS-PRISM" and r["rtt_ms"] == 0.0][0]
    m["WriteZS"] = "/".join(f"{z[k]['median']:.2f}" for k in ("update", "delete", "insert"))
    p = [r for r in e6 if r["system"] == "DET+Paillier" and r["rtt_ms"] == 0.0][0]
    m["WritePaillier"] = f"{p['update']['median']:.1f}"

    (OUT / "numbers.tex").write_text("".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in sorted(m.items())))
    for k, v in sorted(m.items()):
        print(f"{k:16s} {v}")


if __name__ == "__main__":
    main()

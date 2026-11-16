"""Generate the paper's data figures (vector PDF) from results/*.json."""
from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(__file__).resolve().parents[1] / ".mplcache"))
import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter  # noqa: E402


def plain_log_y(ax):
    """Log y-axis with plain-number labels at 1, 2, 5 x 10^k."""
    ax.yaxis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0)))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    ax.yaxis.set_minor_formatter(NullFormatter())

ROOT = Path(__file__).resolve().parents[1]
RES, FIG = ROOT / "results", ROOT / "figures"
FIG.mkdir(exist_ok=True)

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["STIXGeneral"], "mathtext.fontset": "stix",
    "font.size": 8, "axes.labelsize": 8, "axes.titlesize": 8, "legend.fontsize": 6.5,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.linewidth": 0.6,
    "lines.linewidth": 1.1, "lines.markersize": 3.5, "grid.linewidth": 0.4,
    "axes.grid": True, "grid.alpha": 0.35, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
    "pdf.fonttype": 42,
})
COL1, COL2 = 3.45, 7.1  # IEEE column / page width (in)

# Okabe-Ito palette, one fixed style per system
STY = {
    "ZS-PRISM":             dict(color="#0072B2", marker="o", ls="-", lw=1.8, ms=4.2, zorder=10),
    "ZS-PRISM (pushdown)":  dict(color="#56B4E9", marker="v", ls="--"),
    "ZS-PRISM (broadcast)": dict(color="#009E73", marker="^", ls="--"),
    "Map split":            dict(color="#E69F00", marker="s", ls=":"),
    "Shared-TID split":     dict(color="#999999", marker="D", ls=":"),
    "DET+Paillier":         dict(color="#CC79A7", marker="P", ls="-."),
    "DET+AEAD":             dict(color="#D55E00", marker="X", ls="-."),
    "AEAD scan":            dict(color="#000000", marker="*", ls="-"),
    "3PC-RSS":              dict(color="#7B3294", marker="h", ls="-"),
}


def load(name):
    return json.loads((RES / f"{name}.json").read_text())


def fig_state():
    d = load("e3_state")
    ns = [r["n"] for r in d["runs"]]
    heap = [r["map_heap_bytes"] for r in d["runs"]]
    snap = [r["map_snapshot_bytes"] for r in d["runs"]]
    boot = [r["map_bootstrap_ms"] for r in d["runs"]]
    fig, ax = plt.subplots(1, 2, figsize=(COL1, 1.5))
    ax[0].loglog(ns, heap, label="map split (heap)", **STY["Map split"])
    ax[0].loglog(ns, snap, label="map split (compact)", color="#E69F00", marker="s", ls="--", mfc="white")
    ax[0].loglog(ns, [d["zs_state_bytes"]] * len(ns), **STY["ZS-PRISM"])
    ax[0].set_yticks([1e1, 1e3, 1e5, 1e7, 1e9])
    ax[0].set_yticklabels(["10 B", "1 kB", "100 kB", "10 MB", "1 GB"])
    ax[0].set(xlabel="Records $N$", ylabel="Proxy state", title="(a) Persistent state", ylim=(4, 1e10))
    # legend placed in the empty band between the two families of lines
    ax[0].legend(loc="lower right", bbox_to_anchor=(1.0, 0.17), frameon=False, fontsize=5.6, handlelength=1.8)
    ax[0].text(ns[0], d["zs_state_bytes"] * 2.5, "ZS-PRISM: 32 B", color="#0072B2", fontsize=6, va="bottom")
    ax[1].loglog(ns, boot, **STY["Map split"])
    ax[1].loglog(ns, [d["zs_bootstrap_ms"]] * len(ns), **STY["ZS-PRISM"])
    ax[1].set_yticks([1e-2, 1, 1e2, 1e4])
    ax[1].set_yticklabels(["10 µs", "1 ms", "100 ms", "10 s"])
    ax[1].set(xlabel="Records $N$", ylabel="Bootstrap time", title="(b) Replica bootstrap", ylim=(1.5e-3, 1e5))
    ax[1].text(ns[-2], boot[-2] / 40, "map split", color="#E69F00", fontsize=6, ha="right", va="top")
    ax[1].text(ns[0], d["zs_bootstrap_ms"] * 2.5, "ZS-PRISM", color="#0072B2", fontsize=6, va="bottom")
    fig.tight_layout(w_pad=0.6)
    fig.savefig(FIG / "state.pdf")
    plt.close(fig)


def fig_wan():
    d = load("e2_wan")
    names = ["ZS-PRISM", "ZS-PRISM (pushdown)", "ZS-PRISM (broadcast)", "Map split",
             "Shared-TID split", "DET+Paillier", "DET+AEAD", "AEAD scan", "3PC-RSS"]
    panels = [("Q3 range-avg", 100.0), ("Q4 conj-avg", 100.0), ("Q5 conj-sel", 100.0), ("Q4 conj-avg", 1000.0)]
    fig, axes = plt.subplots(1, 4, figsize=(COL2, 1.55), sharey=False)
    for ax, (w, rate), tag in zip(axes, panels, "abcd"):
        for nm in names:
            rows = sorted((r for r in d["runs"] if r["system"] == nm and r["rate_mbps"] == rate), key=lambda r: r["rtt_ms"])
            if not rows:
                continue
            ax.plot([r["rtt_ms"] for r in rows], [r["workloads"][w]["median"] for r in rows], label=nm, **STY[nm])
        ax.set_xscale("log")
        ax.set_yscale("log")
        plain_log_y(ax)
        ax.set_xticks([1, 5, 10, 25, 50])
        ax.set_xticklabels(["1", "5", "10", "25", "50"])
        ax.set(xlabel="RTT (ms)", title=f"({tag}) {w.split()[0]}, {int(rate)} Mb/s")
    axes[0].set_ylabel("Median latency (ms)")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=9, frameon=False, bbox_to_anchor=(0.5, 1.09), columnspacing=1.0, handlelength=2.2)
    fig.tight_layout(w_pad=0.4)
    fig.savefig(FIG / "wan.pdf")
    plt.close(fig)


def fig_attack():
    d = load("e4_trace")
    fig, ax = plt.subplots(1, 2, figsize=(COL1, 1.45))
    for plan, nm in (("pushdown", "ZS-PRISM (pushdown)"), ("broadcast", "ZS-PRISM (broadcast)")):
        for pair, mfc in (("S0+S2", None), ("S1+S2", "white")):
            rows = sorted((r for r in d["runs"] if r["plan"] == plan and r["pair"] == pair), key=lambda r: r["queries"])
            st = dict(STY[nm])
            if mfc:
                st["mfc"] = mfc
            lab = f"{plan}, {pair.replace('S', '$S_').replace('+', '$+')}$"
            ax[0].plot([r["queries"] for r in rows], [100 * r["linked"] for r in rows], label=lab, **st)
            ax[1].plot([r["queries"] for r in rows], [r["median_candidates"] for r in rows], label=lab, **st)
    ax[0].set(xscale="log", xlabel="Observed queries", ylabel="Records linked (%)", title="(a) Exact linkage")
    ax[1].set(xscale="log", yscale="log", xlabel="Observed queries", ylabel="Median candidates", title="(b) Anonymity set")
    ax[1].axhline(d["n"], color="gray", lw=0.6, ls=":")
    h, lab = ax[0].get_legend_handles_labels()
    fig.legend(h, lab, loc="upper center", ncol=2, frameon=False, fontsize=6,
               bbox_to_anchor=(0.5, 1.13), handlelength=2.0, columnspacing=1.2)
    fig.tight_layout(w_pad=0.6)
    fig.savefig(FIG / "attack.pdf")
    plt.close(fig)


def fig_utility():
    d = load("e5_anon")
    fig, ax = plt.subplots(1, 2, figsize=(COL1, 1.32))
    for m, st in (("MDAV", dict(color="#CC79A7", marker="o")), ("Mondrian", dict(color="#D55E00", marker="s"))):
        rows = sorted((r for r in d["runs"] if r["method"] == m), key=lambda r: r["k"])
        ks = [r["k"] for r in rows]
        ax[0].plot(ks, [100 * float(r["count_rel_median"]) for r in rows], label=m, **st)
        ax[1].plot(ks, [100 * float(r["count_gt10pct"]) for r in rows], label=m, **st)
    for a in ax:
        a.axhline(0, color="#0072B2", lw=1.1, label="Split (exact)")
        a.set_xscale("log")
        a.set_xticks([5, 10, 25, 50])
        a.set_xticklabels(["5", "10", "25", "50"])
        a.set_xlabel("$k$")
    ax[0].set(ylabel="Median error (%)", title="(a) Median COUNT error", ylim=(-1.5, 36))
    ax[1].set(ylabel="Queries (%)", title="(b) Queries with error >10%")
    ax[0].legend(frameon=False, fontsize=6, loc="upper left")
    fig.tight_layout(w_pad=0.6)
    fig.savefig(FIG / "utility.pdf")
    plt.close(fig)


if __name__ == "__main__":
    for f in (fig_state, fig_attack, fig_utility):
        f()
    if (RES / "e2_wan.json").exists():
        fig_wan()
    print("figures written to", FIG)

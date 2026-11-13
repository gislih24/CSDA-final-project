#!/usr/bin/env python3
"""Regenerate the three report figures from archived data, without network access."""

from pathlib import Path
import json
import collections
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "analysis"
(REPORT / "figures").mkdir(exist_ok=True)
targets = json.loads((ROOT / "data/baseline_summary.json").read_text())[
    "targets"
]
bench = json.loads((ROOT / "data/benchmark_summary.json").read_text())
bm = json.loads((ROOT / "data/benchmark_metadata.json").read_text())
categories = []
label = {
    "financial": "Finance",
    "municipalities": "Municipalities",
    "healthcare": "Healthcare",
    "infrastructure": "Infrastructure",
}
for c in sorted(
    {t["category"] for t in targets},
    key=lambda c: -sum(
        t["category"] == c and t["hybrid_observation"] == "supported"
        for t in targets
    ),
):
    cc = collections.Counter(
        t["hybrid_observation"] for t in targets if t["category"] == c
    )
    categories.append(
        [
            label.get(c, c.title()),
            cc["supported"],
            cc["not_observed"],
            cc["inconclusive"],
        ]
    )

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "pdf.fonttype": 42,
        "figure.dpi": 160,
    }
)
pink = "#C81868"
teal = "#087F82"
grey = "#B3BDC7"
ink = "#172534"
amber = "#B77717"
fig, ax = plt.subplots(figsize=(7.1, 3.8), layout="constrained")
y = np.arange(len(categories))
left = np.zeros(len(y))
for col, color, name in [
    (1, teal, "Hybrid confirmed"),
    (2, grey, "Controlled negative"),
    (3, amber, "Inconclusive"),
]:
    vals = np.array([r[col] for r in categories])
    ax.barh(y, vals, left=left, color=color, label=name, height=0.68)
    for i, v in enumerate(vals):
        if v:
            ax.text(
                left[i] + v / 2,
                i,
                str(v),
                ha="center",
                va="center",
                color="white" if color != grey else ink,
                fontsize=9,
            )
    left += vals
ax.set_yticks(y, [r[0] for r in categories])
ax.invert_yaxis()
ax.set_xlim(0, 10)
ax.set_xticks(range(11))
ax.set_xlabel("Starting hostnames (10 per category)")
ax.legend(
    ncols=3,
    loc="upper center",
    bbox_to_anchor=(0.42, 1.16),
    frameon=False,
    fontsize=8.5,
)
ax.spines[["left", "bottom"]].set_visible(False)
ax.tick_params(length=0)
ax.set_axisbelow(True)
ax.xaxis.grid(True, color="#E8ECF0")
for ext in ["pdf", "png"]:
    fig.savefig(
        REPORT / "figures" / f"survey_by_sector.{ext}", bbox_inches="tight"
    )
plt.close(fig)

fig, ax = plt.subplots(figsize=(7.1, 3.4), layout="constrained")
profiles = ["C", "E", "F"]
xs = np.arange(3)
vals = [
    bench["profiles"][p]["effects"]["tls_ns"]["difference_ms"]
    for p in profiles
]
cis = [bench["profiles"][p]["effects"]["tls_ns"]["ci95_ms"] for p in profiles]
ax.bar(xs, vals, color=[teal, pink, amber], width=0.55)
ax.errorbar(
    xs,
    vals,
    yerr=[
        [v - c[0] for v, c in zip(vals, cis)],
        [c[1] - v for v, c in zip(vals, cis)],
    ],
    fmt="none",
    ecolor=ink,
    capsize=5,
)
for x, v in zip(xs, vals):
    ax.text(
        x, v + 0.5, f"{v:.2f} ms", ha="center", fontweight="bold", color=ink
    )
ax.set_xticks(xs, ["100 Mbit/s", "10 Mbit/s", "1 Mbit/s"])
ax.set_ylim(0, 22)
ax.set_ylabel("Added TLS handshake time (ms)")
ax.set_xlabel("Emulated link rate; added RTT fixed at 50 ms")
ax.spines[["left", "bottom"]].set_visible(False)
ax.tick_params(length=0)
ax.set_axisbelow(True)
ax.yaxis.grid(True, color="#E8ECF0")
for ext in ["pdf", "png"]:
    fig.savefig(
        REPORT / "figures" / f"benchmark_bandwidth.{ext}", bbox_inches="tight"
    )
plt.close(fig)

fig, ax = plt.subplots(figsize=(7.1, 2.5), layout="constrained")
groups = ["X25519", "X25519MLKEM768"]
a = [263, 1439]
b = [1375, 2473]
ax.barh(groups, a, color=pink, label="Client to server")
ax.barh(groups, b, left=a, color=teal, label="Server to client")
for i, (u, v) in enumerate(zip(a, b)):
    ax.text(u / 2, i, f"{u:,}", ha="center", va="center", color="white")
    ax.text(u + v / 2, i, f"{v:,}", ha="center", va="center", color="white")
    ax.text(u + v + 60, i, f"{u+v:,} B", va="center", fontsize=9)
ax.set_xlim(0, 4700)
ax.invert_yaxis()
ax.set_xlabel("TLS bytes through client handshake completion")
ax.legend(
    ncols=2, loc="upper center", bbox_to_anchor=(0.5, 1.3), frameon=False
)
ax.spines[["left", "bottom"]].set_visible(False)
ax.tick_params(length=0)
for ext in ["pdf", "png"]:
    fig.savefig(
        REPORT / "figures" / f"handshake_bytes.{ext}", bbox_inches="tight"
    )
plt.close(fig)

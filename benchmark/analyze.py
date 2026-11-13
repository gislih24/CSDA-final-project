#!/usr/bin/env python3
"""Analyze one run; never merge pilot/capture/main datasets implicitly.
pip/apt dependencies: numpy matplotlib. Bootstrap resamples round/profile blocks.
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

GROUPS = ["X25519", "X25519MLKEM768"]
COLORS = ["#355c9a", "#df287d"]
METRICS = ["tls_ns", "response_ns", "client_cpu_ns"]

TLS_DEF_SENT_SIZE = 1184 - 8
TLS_EXTRA_RCVD_BYTES = 1088 + 10


def estimate(pairs, metric, rng, replicates):
    blocks = defaultdict(list)
    for (rnd, _), ab in pairs.items():
        if all(g in ab and ab[g]["status"] == "ok" for g in GROUPS):
            blocks[rnd].append([ab[g][metric] / 1e6 for g in GROUPS])
    if not blocks:
        return {"complete_pairs": 0, "blocks": 0}
    means = np.array([np.mean(v, axis=0) for _, v in sorted(blocks.items())])
    a, b = means.mean(axis=0)
    difference = b - a
    result = {
        "complete_pairs": sum(map(len, blocks.values())),
        "blocks": len(means),
        "classical_block_mean_ms": float(a),
        "hybrid_block_mean_ms": float(b),
        "difference_ms": float(difference),
        "relative_percent": float(100 * difference / a),
        "ci95_ms": None,
        "ci95_relative_percent": None,
    }
    if len(means) >= 10:
        # Whole blocks, including both groups, are sampled together.
        boot = means[
            rng.integers(0, len(means), size=(replicates, len(means)))
        ].mean(axis=1)
        diff = boot[:, 1] - boot[:, 0]
        result["ci95_ms"] = np.quantile(diff, [0.025, 0.975]).tolist()
        result["ci95_relative_percent"] = np.quantile(
            100 * diff / boot[:, 0], [0.025, 0.975]
        ).tolist()
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("--bootstrap", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=73401)
    args = ap.parse_args()
    folder = args.run.resolve()
    rows = [
        json.loads(x)
        for x in (folder / "trials.jsonl").read_text().splitlines()
        if x.strip()
    ]
    status = json.loads((folder / "status.json").read_text())
    rows = [r for r in rows if not r["warmup"]]
    if not rows:
        raise SystemExit("No measured rows to analyze.")
    profiles = sorted({r["profile"] for r in rows})
    rng = np.random.default_rng(args.seed)
    summary = {
        "run_status": status,
        "bootstrap_replicates": args.bootstrap,
        "bootstrap_seed": args.seed,
        "estimand": "mean of within-round/profile complete-pair means; failures reported separately",
        "profiles": {},
        "warnings": [],
    }
    if not status["complete"]:
        summary["warnings"].append(
            "INCOMPLETE RUN: do not present as the planned final experiment."
        )
    if status["mode"] != "main":
        summary["warnings"].append(
            "Validation/pilot data: not the final main experiment."
        )
    lines = [
        "# Benchmark results",
        "",
        "All latency values are milliseconds. Descriptive statistics use fully successful trials.",
        "Effect estimates use complete pairs and equally weighted round/profile blocks.",
        "Confidence intervals are percentile block bootstrap intervals; no interval is given with fewer than 10 blocks.",
        "",
        "|Profile|Group|Attempts|Successes|Timeouts|Other failures|TLS median|TLS p95|",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    byprofile = {}
    for profile in profiles:
        subset = [r for r in rows if r["profile"] == profile]
        byprofile[profile] = subset
        pairs = defaultdict(dict)
        entry = {"groups": {}, "effects": {}}
        for r in subset:
            key = (r["round"], r["pair"])
            if r["offered_group"] in pairs[key]:
                raise ValueError("duplicate group in a pair")
            pairs[key][r["offered_group"]] = r
        for group in GROUPS:
            allrows = [r for r in subset if r["offered_group"] == group]
            ok = [r for r in allrows if r["status"] == "ok"]
            x = {
                "attempts": len(allrows),
                "successes": len(ok),
                "timeouts": sum(r["status"] == "timeout" for r in allrows),
                "failures": sum(r["status"] == "error" for r in allrows),
                "metrics": {},
            }
            for metric in METRICS:
                values = [r[metric] / 1e6 for r in ok]
                if values:
                    x["metrics"][metric] = {
                        "mean_ms": float(np.mean(values)),
                        "median_ms": float(np.median(values)),
                        "p95_ms": float(np.quantile(values, 0.95)),
                    }
            for direction in ("tls_sent_bytes", "tls_received_bytes"):
                x[direction] = sorted({r[direction] for r in ok})
            entry["groups"][group] = x
            v = x["metrics"].get("tls_ns", {})
            lines.append(
                f'|{profile}|{group}|{x["attempts"]}|{x["successes"]}|{x["timeouts"]}|{x["failures"]}|'
                f'{v.get("median_ms",float("nan")):.4f}|{v.get("p95_ms",float("nan")):.4f}|'
            )
        for metric in METRICS:
            entry["effects"][metric] = estimate(
                pairs, metric, rng, args.bootstrap
            )
        deltas = []
        for ab in pairs.values():
            if all(g in ab and ab[g]["status"] == "ok" for g in GROUPS):
                deltas.append(
                    [
                        ab[GROUPS[1]][k] - ab[GROUPS[0]][k]
                        for k in ("tls_sent_bytes", "tls_received_bytes")
                    ]
                )
        entry["byte_differences"] = sorted(
            map(list, {tuple(d) for d in deltas})
        )
        # OpenSSL 3.5: key-share growth plus -8/+10 bytes of TLS extensions
        # with the fixed X25519:X25519MLKEM768 server group order.
        if entry["byte_differences"] != [[1184 - 8, 1088 + 10]]:
            summary["warnings"].append(
                f'{profile}: investigate unexpected TLS byte differences {entry["byte_differences"]}'
            )
        if any(r["status"] != "ok" for r in subset):
            summary["warnings"].append(
                f"{profile}: failures present; successful-pair latency estimates may be selective."
            )
        summary["profiles"][profile] = entry
    lines += [
        "",
        "|Profile|Complete pairs|Blocks|Mean TLS difference|95% block CI|Relative overhead|",
        "|---|---:|---:|---:|---|---:|",
    ]
    for profile, e in summary["profiles"].items():
        x = e["effects"]["tls_ns"]
        ci = x.get("ci95_ms")
        lines.append(
            f'|{profile}|{x["complete_pairs"]}|{x["blocks"]}|{x.get("difference_ms",float("nan")):.4f}|'
            f'{f"[{ci[0]:.4f}, {ci[1]:.4f}]" if ci else "not estimated"}|{x.get("relative_percent",float("nan")):.3f}%|'
        )
    lines += [
        "",
        "## Interpretation and checks",
        "",
        "- Inspect latency/CPU drift, paired differences by round, failures, and qdisc logs before interpreting intervals.",
        "- The bootstrap assumes round blocks are sufficiently independent. Longer drift can make intervals too narrow.",
        "- Response time includes TCP, TLS, and a one-byte request/response; it is not browser page load time.",
        "- TLS bytes are unique bytes passed through the socket BIO through client handshake completion, including record framing. They exclude TCP/IP headers and retransmissions.",
        "- Relative overhead can be large in a very short local handshake; report absolute milliseconds alongside percentages.",
        "- A confidence interval containing zero means this run did not resolve a clear difference under that condition.",
        "",
        *[f"WARNING: {w}" for w in summary["warnings"]],
    ]
    (folder / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (folder / "summary.md").write_text("\n".join(lines) + "\n")
    plt.rcParams.update(
        {
            "font.size": 10,
            "figure.dpi": 140,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    # Separate axes keep baseline variation visible despite the large RTT range.
    fig, axs = plt.subplots(2, 3, figsize=(12, 7), squeeze=False)
    for ax, profile in zip(axs.flat, profiles):
        vals = [
            [
                r["tls_ns"] / 1e6
                for r in byprofile[profile]
                if r["offered_group"] == g and r["status"] == "ok"
            ]
            for g in GROUPS
        ]
        bp = ax.boxplot(
            vals,
            tick_labels=["X25519", "Hybrid"],
            showfliers=True,
            patch_artist=True,
        )
        for box, color in zip(bp["boxes"], COLORS):
            box.set_facecolor(color)
            box.set_alpha(0.65)
        ax.set_title("Profile " + profile)
        ax.set_ylabel("TLS handshake (ms)")
    for ax in list(axs.flat)[len(profiles) :]:
        ax.set_visible(False)
    fig.suptitle("Successful full TLS 1.3 handshakes — axis scales differ")
    fig.tight_layout()
    fig.savefig(folder / "handshake-distributions.pdf")
    fig.savefig(folder / "handshake-distributions.png")
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(8, 4))
    for i, profile in enumerate(profiles):
        e = summary["profiles"][profile]["effects"]["tls_ns"]
        if "difference_ms" not in e:
            continue
        ax.plot(i, e["difference_ms"], "o", color=COLORS[1])
        if e["ci95_ms"]:
            ax.vlines(i, *e["ci95_ms"], color=COLORS[1], linewidth=2)
    ax.axhline(0, color="gray", lw=0.8)
    ax.set_xticks(range(len(profiles)), profiles)
    ax.set_xlabel("Network profile")
    ax.set_ylabel("Hybrid − X25519 (ms)")
    ax.set_title("Mean paired TLS overhead; 95% block bootstrap intervals")
    fig.tight_layout()
    fig.savefig(folder / "overhead.pdf")
    fig.savefig(folder / "overhead.png")
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(7, 4))
    for j, g in enumerate(GROUPS):
        ok = [
            r for r in rows if r["status"] == "ok" and r["offered_group"] == g
        ]
        vals = [
            float(np.median([r[k] for r in ok])) if ok else 0
            for k in ("tls_sent_bytes", "tls_received_bytes")
        ]
        bars = ax.bar(
            np.arange(2) + (j - 0.5) * 0.35,
            vals,
            width=0.35,
            label=g,
            color=COLORS[j],
        )
        ax.bar_label(bars, fmt="%.0f")
    ax.set_xticks([0, 1], ["Client → server", "Server → client"])
    ax.set_ylabel("TLS stream bytes")
    ax.legend()
    ax.set_title("Median handshake bytes through client Finished")
    fig.tight_layout()
    fig.savefig(folder / "handshake-bytes.pdf")
    fig.savefig(folder / "handshake-bytes.png")
    plt.close(fig)
    fig, axs = plt.subplots(
        len(profiles), 2, figsize=(11, 2.4 * len(profiles)), squeeze=False
    )
    for i, p in enumerate(profiles):
        for j, metric in enumerate(["tls_ns", "client_cpu_ns"]):
            for g, color in zip(GROUPS, COLORS):
                ok = [
                    r
                    for r in byprofile[p]
                    if r["status"] == "ok" and r["offered_group"] == g
                ]
                axs[i, j].scatter(
                    [r["sequence"] for r in ok],
                    [r[metric] / 1e6 for r in ok],
                    s=5,
                    label=g,
                    color=color,
                    alpha=0.6,
                )
            axs[i, j].set_title(p + ": " + metric.replace("_ns", ""))
            axs[i, j].set_ylabel("ms")
            axs[i, j].set_xlabel("Trial sequence")
    axs[0, 0].legend()
    fig.tight_layout()
    fig.savefig(folder / "drift.png")
    plt.close(fig)
    print("\n".join(lines))
    print(f"Wrote summaries and figures to {folder}")


if __name__ == "__main__":
    main()

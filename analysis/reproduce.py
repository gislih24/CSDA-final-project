#!/usr/bin/env python3
"""Recompute report observations offline from archived measurement exports.

Run from any directory: python submission/analysis/reproduce.py
Dependencies: numpy and matplotlib (the archived benchmark estimator imports both).
This script makes no network connections and performs no new measurements.
"""

from pathlib import Path
from collections import Counter, defaultdict
from urllib.parse import urlparse
import gzip
import hashlib
import importlib.util
import json
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


def read(name):
    return json.loads((DATA / name).read_text())


def rows(name):
    with gzip.open(DATA / name, "rt") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    baseline = read("baseline_summary.json")
    targets = baseline["targets"]
    counts = Counter(t["hybrid_observation"] for t in targets)
    require(
        len({t["hostname"] for t in targets}) == 100,
        "Baseline must have 100 unique hostnames",
    )
    require(
        dict(counts) == baseline["hybrid_observations"],
        "Baseline classification totals disagree",
    )
    addresses = read("address_summary.json")
    attempts = rows("advanced_attempts.jsonl.gz")
    require(
        len(attempts) == len({a["job_id"] for a in attempts}) == 4200,
        "Unexpected or duplicate advanced jobs",
    )
    indexed = defaultdict(list)
    for a in attempts:
        indexed[(a["hostname"], a["port"], a["ip"], a["family"])].append(a)
    profiles = read("advanced_manifest.json")["config"]["profiles"]
    for a in addresses:
        records = indexed[(a["hostname"], a["port"], a["ip"], a["family"])]
        require(
            len(records) == a["recorded_attempts"] == 15,
            "Incomplete address group",
        )
        for profile in profiles:
            outcomes = Counter(
                x["negotiated_group"] if x["status"] == "ok" else x["status"]
                for x in records
                if x["profile"] == profile
            )
            require(
                dict(outcomes) == a[profile + "_outcomes"],
                "Address summary disagrees with attempt rows",
            )
    positives = {
        a["hostname"]
        for a in addresses
        if a["family"] == 4 and a["observation"] == "supported"
    }
    redirects = [
        json.loads(line)
        for line in (DATA / "redirects.jsonl").read_text().splitlines()
        if line.strip()
    ]
    terminal = [
        r
        for r in redirects
        if r["stop"] == "terminal_response"
        and urlparse(r["terminal_url"]).scheme == "https"
    ]
    terminal_positive = [
        r
        for r in terminal
        if urlparse(r["terminal_url"]).hostname in positives
    ]
    chain_positive = [
        r
        for r in terminal
        if all(h["hostname"] in positives for h in r["hops"])
    ]
    positive_pairs = [
        a
        for a in addresses
        if a["family"] == 4 and a["observation"] == "supported"
    ]
    order_sensitive = [
        a
        for a in positive_pairs
        if a["dual_classical_first_outcomes"].get("X25519")
    ]

    trials = rows("benchmark_trials.jsonl.gz")
    measured = [r for r in trials if not r["warmup"]]
    require(len(measured) == 7200, "Unexpected measured benchmark trial count")
    for r in measured:
        require(
            r["status"] == "ok" and r["verify_result"] == 0,
            "Failed or unverified benchmark trial",
        )
        require(
            r["negotiated_group"].lower() == r["offered_group"].lower(),
            "Wrong negotiated group",
        )
        require(r["reused"] == r["hrr"] == 0, "Resumption or HRR in benchmark")
        require(
            r["client_finished"] == r["server_finished"] == 1,
            "Missing Finished evidence",
        )
    spec = importlib.util.spec_from_file_location(
        "benchmark_analysis", ROOT / "benchmark/analyze.py"
    )
    analysis = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analysis)
    summary = read("benchmark_summary.json")
    rng = np.random.default_rng(summary["bootstrap_seed"])
    differences = {}
    for profile in sorted(summary["profiles"]):
        pairs = defaultdict(dict)
        for r in measured:
            if r["profile"] == profile:
                require(
                    r["offered_group"] not in pairs[(r["round"], r["pair"])],
                    "Duplicate benchmark pair member",
                )
                pairs[(r["round"], r["pair"])][r["offered_group"]] = r
        for metric in analysis.METRICS:
            actual = analysis.estimate(
                pairs, metric, rng, summary["bootstrap_replicates"]
            )
            expected = summary["profiles"][profile]["effects"][metric]
            for key, value in actual.items():
                require(
                    np.allclose(value, expected[key], rtol=1e-12, atol=1e-12),
                    f"Benchmark estimate mismatch: {profile}/{metric}/{key}",
                )
            if metric == "tls_ns":
                differences[profile] = {
                    "difference_ms": actual["difference_ms"],
                    "ci95_ms": actual["ci95_ms"],
                }

    checked = 0
    for manifest_name, key, folder in [
        ("baseline_manifest.json", "source_sha256", "survey"),
        ("advanced_manifest.json", None, "survey"),
        ("benchmark_metadata.json", "sha256", "benchmark"),
    ]:
        manifest = read(manifest_name)
        hashes = manifest[key] if key else manifest["config"]["source_sha256"]
        for name, expected in hashes.items():
            path = ROOT / folder / name
            if path.exists():
                require(
                    hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                    f"Source hash mismatch: {folder}/{name}",
                )
                checked += 1

    result = {
        "baseline": dict(counts),
        "advanced_attempts": len(attempts),
        "address_pairs": len(addresses),
        "terminal_https_chains": len(terminal),
        "starts_with_hybrid_terminal": len(terminal_positive),
        "starts_with_all_discovered_hosts_hybrid_capable": len(chain_positive),
        "unique_hybrid_terminal_hostnames": len(
            {urlparse(r["terminal_url"]).hostname for r in terminal_positive}
        ),
        "positive_ipv4_pairs": len(positive_pairs),
        "order_sensitive_pairs": [
            {"hostname": a["hostname"], "ip": a["ip"]} for a in order_sensitive
        ],
        "ipv6_outcomes": dict(
            Counter(a["status"] for a in attempts if a["family"] == 6)
        ),
        "tls10_baseline": sum(t["tls_1_0_observed"] is True for t in targets),
        "tls11_baseline": sum(t["tls_1_1_observed"] is True for t in targets),
        "measured_benchmark_connections": len(measured),
        "warmup_benchmark_connections": len(trials) - len(measured),
        "benchmark_summary_reproduced": True,
        "matched_source_hashes": checked,
        "handshake_differences": differences,
    }
    output = ROOT / "analysis/reproduced_results.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

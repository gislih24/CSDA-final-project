"""Explain saved survey results without scanning sites or modifying evidence."""

import argparse
from collections import Counter
import csv
import json
from pathlib import Path

from collect_pqc_tls import summarize


def diagnose(folder: Path) -> dict:
    with (folder / "sample.csv").open(
        encoding="utf-8-sig", newline=""
    ) as stream:
        targets = list(csv.DictReader(stream))
    for target in targets:
        target["sample_index"] = int(target["sample_index"])
        target["port"] = int(target["port"])
    with (folder / "attempts.jsonl").open(encoding="utf-8") as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    summaries = [summarize(target, events) for target in targets]
    inconclusive = [
        row for row in summaries if row["hybrid_observation"] == "inconclusive"
    ]
    return {
        "endpoints": len(summaries),
        "observations": dict(
            Counter(row["hybrid_observation"] for row in summaries)
        ),
        "inconclusive_reasons": dict(
            Counter(row["hybrid_observation_reason"] for row in inconclusive)
        ),
        "inconclusive_endpoints": [
            {
                "hostname": row["hostname"],
                "ip_address": row["ip_address"],
                "reason": row["hybrid_observation_reason"],
                "tls13_inventory_observed": row.get("tls_1_3_observed"),
            }
            for row in inconclusive
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "survey", type=Path, help="Saved survey directory (read only)"
    )
    args = parser.parse_args()
    try:
        report = diagnose(args.survey)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, f"Cannot analyze survey: {error}\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

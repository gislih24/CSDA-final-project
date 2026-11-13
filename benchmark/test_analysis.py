#!/usr/bin/env python3
"""Deterministic tests of pairing, block estimates, failure handling and plots."""

import json
from pathlib import Path
import subprocess as sp
import sys
import tempfile
from typing import Any
import numpy as np
from analyze import estimate, GROUPS, TLS_DEF_SENT_SIZE, TLS_EXTRA_RCVD_BYTES

pairs = {}
for block in range(30):
    for pair in range(4):
        a: float = 10 + block / 10 + pair / 100
        pairs[(block, pair)] = {
            GROUPS[0]: {"status": "ok", "tls_ns": a * 1e6},
            GROUPS[1]: {"status": "ok", "tls_ns": (a + 2) * 1e6},
        }
e: dict[str, int] | dict[str, int | float | None] = estimate(
    pairs, metric="tls_ns", rng=np.random.default_rng(1), replicates=1000
)
assert e["blocks"] == 30 and e["complete_pairs"] == 120
assert abs(e["difference_ms"] - 2) < 1e-12 and np.allclose(
    e["ci95_ms"], [2, 2]
)
pairs[(0, 0)][GROUPS[1]]["status"] = "timeout"
e = estimate(
    pairs, metric="tls_ns", rng=np.random.default_rng(1), replicates=1000
)
assert e["complete_pairs"] == 119 and abs(e["difference_ms"] - 2) < 1e-12
with tempfile.TemporaryDirectory(prefix="pqc-analysis-test-") as tmp:
    folder = Path(tmp)
    (folder / "status.json").write_text(
        json.dumps({"complete": True, "mode": "pilot"})
    )
    rows: list[Any] = []
    for profile in "ABCDEF":
        for (block, pair), ab in pairs.items():
            for order, g in enumerate(GROUPS):
                r = ab[g]
                rows.append(
                    dict(
                        r,
                        profile=profile,
                        round=block,
                        pair=pair,
                        order=order,
                        warmup=False,
                        sequence=len(rows),
                        offered_group=g,
                        response_ns=r["tls_ns"] + 1e6,
                        client_cpu_ns=r["tls_ns"] / 100,
                        tls_sent_bytes=200
                        + (TLS_DEF_SENT_SIZE if order else 0),
                        tls_received_bytes=1500
                        + (TLS_EXTRA_RCVD_BYTES if order else 0),
                    )
                )
    # One unexpected byte count must still trigger the analysis warning.
    changed = next(
        r
        for r in rows
        if r["profile"] == "B"
        and r["offered_group"] == GROUPS[1]
        and r["status"] == "ok"
    )
    changed["tls_sent_bytes"] += 1
    # Warm-up outlier must not enter descriptive statistics or effects.
    rows.append(dict(rows[-1], warmup=True, tls_ns=1e18))
    (folder / "trials.jsonl").write_text(
        data="".join(json.dumps(r) + "\n" for r in rows)
    )
    sp.run(
        args=[
            sys.executable,
            str(Path(__file__).with_name("analyze.py")),
            str(folder),
            "--bootstrap",
            "1000",
        ],
        check=True,
        stdout=sp.DEVNULL,
    )
    s = json.loads((folder / "summary.json").read_text())
    assert (
        abs(s["profiles"]["A"]["effects"]["tls_ns"]["difference_ms"] - 2)
        < 1e-12
    )
    assert s["profiles"]["A"]["groups"][GROUPS[1]]["timeouts"] == 1
    assert s["profiles"]["A"]["byte_differences"] == [
        [TLS_DEF_SENT_SIZE, TLS_EXTRA_RCVD_BYTES]
    ]

    assert s["profiles"]["B"]["byte_differences"] == [
        [TLS_DEF_SENT_SIZE, TLS_EXTRA_RCVD_BYTES],
        [TLS_DEF_SENT_SIZE + 1, TLS_EXTRA_RCVD_BYTES],
    ]
    byte_warnings: list[Any] = [
        w for w in s["warnings"] if "unexpected TLS byte differences" in w
    ]
    assert len(byte_warnings) == 1 and byte_warnings[0].startswith(
        "B:"
    ), byte_warnings
    assert (folder / "overhead.pdf").read_bytes().startswith(b"%PDF")
    assert (folder / "drift.png").stat().st_size > 1000
print(
    "PASS: known paired effect, block bootstrap, incomplete-pair exclusion, warm-up exclusion, failure counts and figure generation"
)

# CSDA report evidence and reproducibility

This directory adds the measurement code and compact data needed for the final
report. It preserves the existing collector and surveys in the repository root.
It is a research artifact, not a completed report or a claim about all Icelandic
organisations.

## Archived runs

- `survey/`: actual source snapshots for `survey_3` and `survey_3_advanced`,
  measured 5 November 2026, plus the associated documentation and local tests.
- `benchmark/`: actual source snapshot from completed `main-01`, measured
  4 November 2026, 17:16-17:38 UTC. C++ client/server; Python orchestration.
- `data/`: baseline summary, manifests and sample; advanced address outcomes,
  redirects and all 4,200 attempt records; all 9,000 benchmark trial records
  (7,200 measured and 1,800 warm-up), metadata and original summary.
- `analysis/reproduce.py`: added on 13 November 2026 to independently check the
  report numbers from these exports. It does not run new network measurements.

The original per-handshake command/stdout/stderr traces and full SSLyze inventory
remain in the separate `survey_3.zip` measurement archive. This compact directory
does not reproduce that complete raw archive. Do not describe the compact exports
as an independent reparse of every TLS packet or raw SSLyze result.

## Reproduce report numbers offline

Install Python, NumPy and Matplotlib, then run:

```sh
python submission/analysis/reproduce.py
```

The script verifies source hashes, reconciles 4,200 advanced attempts with all
280 address-summary rows, recalculates redirect counts, checks benchmark protocol
fields and reproduces timing effects and block-bootstrap confidence intervals.
It writes `submission/analysis/reproduced_results.json`.

The archived benchmark analysis uses 10,000 bootstrap replicates, seed 73401,
and whole round/profile blocks. The 600 pairs within each profile are grouped
into 30 blocks, not treated as 600 independent bootstrap units.

## Re-run measurements

Follow `survey/README.md` and `benchmark/README.md`. Those procedures contact
public endpoints or create local network namespaces and need the documented
environment and permissions. Do not mistake an offline reproduction of saved
data for a fresh measurement. OpenSSL 3.5.5, Python 3.14.4 and SSLyze 6.3.1 are
recorded for the survey; the benchmark metadata records its actual machine and
software configuration. Read the manifests for complete settings.

No existing binary, session secrets or private certificate key is included here.
The benchmark's `certs.sh` generates local test certificates; their exact encoded
sizes can differ from the original certificate, so a fresh run need not reproduce
the same absolute byte counts. The archived trial data preserve the measured
counts. Do not use local test certificates for production.

## Interpretation

The baseline result is 48 confirmed, 33 controlled negative and 19 inconclusive
starting hostnames out of 100. Redirect and address-pair counts have different
denominators. All IPv6 attempts failed at the network level and cannot establish
IPv6 support. The survey times are subprocess durations; only the controlled
benchmark has a dedicated TLS-handshake timer.

Source snapshots are preserved without changes. Some original READMEs contain
recommendations or planned validation; their presence is not evidence that every
suggested step was performed. The final report must describe the author's actual
contribution, assistance and performed validation accurately.

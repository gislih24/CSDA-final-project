import csv
import json
from pathlib import Path
import tempfile
import unittest

from survey_diagnostics import diagnose


class SavedSurveyTest(unittest.TestCase):
    def test_historical_empty_exit_explained_without_changing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            sample = folder / "sample.csv"
            with sample.open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(
                    stream, fieldnames=["hostname", "port", "sample_index"]
                )
                writer.writeheader()
                writer.writerow(
                    dict(hostname="example.test", port=443, sample_index=1)
                )
            events = [
                dict(
                    sample_index=1,
                    profile="dns",
                    kind="dns",
                    status="ok",
                    terminal=True,
                )
            ]
            for profile in (
                "tls13_classical",
                "tls13_hybrid_only",
                "tls13_mixed",
            ):
                events.append(
                    dict(
                        sample_index=1,
                        profile=profile,
                        kind="tls",
                        status="tls_error",
                        returncode=0,
                        handshake_completed=False,
                        terminal=True,
                    )
                )
            evidence = folder / "attempts.jsonl"
            evidence.write_text(
                "".join(json.dumps(row) + "\n" for row in events),
                encoding="utf-8",
            )
            original = {
                path.name: path.read_bytes() for path in folder.iterdir()
            }
            report = diagnose(folder)
            self.assertEqual(report["observations"], {"inconclusive": 1})
            self.assertEqual(
                report["inconclusive_reasons"],
                {"missing_handshake_evidence": 1},
            )
            self.assertEqual(
                {path.name: path.read_bytes() for path in folder.iterdir()},
                original,
            )

    def test_corrupt_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "sample.csv").write_text(
                "hostname,port,sample_index\nexample.test,443,1\n"
            )
            (folder / "attempts.jsonl").write_text("{broken")
            with self.assertRaises(ValueError):
                diagnose(folder)


if __name__ == "__main__":
    unittest.main()

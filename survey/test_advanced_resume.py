import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import advanced_survey as a


class ResumeTest(unittest.TestCase):
    def test_interruption_resume_keeps_plan_and_no_duplicate_successes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "baseline"
            base.mkdir()
            out = Path(tmp) / "out"
            (base / "manifest.json").write_text(
                json.dumps({"state": "complete"})
            )
            (base / "sample.csv").write_text(
                "sample_index,hostname,port,category\n1,example.org,443,test\n"
            )
            chain = {
                "hops": [{"hostname": "example.org", "port": 443}],
                "dns": {"example.org": {"selected": ["1.1.1.1"]}},
                "stop": "terminal_response",
            }
            argv = [
                "advanced_survey.py",
                str(base),
                "--out",
                str(out),
                "--delay",
                "0",
                "--repeats",
                "1",
            ]
            calls = []

            def probe(binary, job, timeout, cafile):
                calls.append(job["job_id"])
                if len(calls) == 2:
                    raise KeyboardInterrupt
                return (
                    {"status": "ok", "negotiated_group": "X25519MLKEM768"},
                    {
                        "interrupted": False,
                        "stdout": "",
                        "stderr": "",
                        "process_elapsed_ms": 1,
                        "returncode": 0,
                        "timed_out": False,
                    },
                    ["openssl"],
                )

            with patch.object(
                a.p,
                "inspect_openssl",
                return_value=("openssl", {"version": "fixture"}),
            ), patch.object(a, "discover", return_value=chain), patch.object(
                a, "probe", side_effect=probe
            ):
                with patch.object(a.sys, "argv", argv):
                    self.assertEqual(a.main(), 130)
                first_plan = (out / "plan.json").read_bytes()
                with patch.object(a.sys, "argv", argv + ["--resume"]):
                    self.assertEqual(a.main(), 0)
            events = a.read_events(out / "attempts.jsonl")
            self.assertEqual(len(events), 5)
            self.assertEqual(len({e["job_id"] for e in events}), 5)
            self.assertEqual(first_plan, (out / "plan.json").read_bytes())
            self.assertEqual(calls.count(events[0]["job_id"]), 1)
            self.assertEqual(
                json.loads((out / "manifest.json").read_text())["state"],
                "complete",
            )
            with patch.object(
                a.p,
                "inspect_openssl",
                return_value=("openssl", {"version": "changed"}),
            ), patch.object(a.sys, "argv", argv + ["--resume"]):
                with self.assertRaisesRegex(ValueError, "changed"):
                    a.main()


if __name__ == "__main__":
    unittest.main()

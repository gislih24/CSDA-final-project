import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import advanced_survey as a


class AdvancedTest(unittest.TestCase):
    def test_ipv6_pinned_with_sni(self):
        c = a.command(
            "openssl",
            "example.org",
            443,
            "2606:4700::1111",
            "dual_classical_first",
            None,
        )
        self.assertIn("-6", c)
        self.assertEqual(c[c.index("-connect") + 1], "[2606:4700::1111]:443")
        self.assertEqual(c[c.index("-servername") + 1], "example.org")
        self.assertEqual(c[c.index("-groups") + 1], "*X25519:*X25519MLKEM768")
        self.assertIn("-verify_return_error", c)

    def test_address_caps_and_exclusions(self):
        selected = a.select_addresses(
            [
                "127.0.0.1",
                "10.0.0.1",
                "::1",
                "169.254.169.254",
                "8.8.8.8",
                "1.1.1.1",
                "2606:4700::1111",
            ],
            1,
        )
        self.assertEqual(selected, ["1.1.1.1", "2606:4700::1111"])
        self.assertEqual(len(a.select_addresses(["8.8.8.8", "1.1.1.1"], 0)), 2)

    def test_urls(self):
        self.assertEqual(
            a.normalize_url("https://EXAMPLE.org/a?q=1#f"),
            "https://example.org/a?q=1",
        )
        for url in [
            "file:///etc/passwd",
            "https://user:pass@example.org/",
            "https://127.0.0.1/",
            "https://example.org:22/",
        ]:
            with self.assertRaises(ValueError):
                a.normalize_url(url)

    def test_hrr_unknown(self):
        self.assertIsNone(a.trace_hrr("no handshake"))

    def test_hrr_marker(self):
        def message(random):
            payload = b"\x02\x00\x00\x50\x03\x03" + random
            return (
                "<<< TLS 1.3, Handshake [length 0054], ServerHello\n    "
                + payload.hex(" ")
                + "\n"
            )

        self.assertTrue(a.trace_hrr(message(a.HRR)))
        self.assertFalse(a.trace_hrr(message(bytes(32))))

    def test_reproducible_complete_jobs(self):
        chain = {
            "hops": [{"hostname": "example.org", "port": 443}] * 2,
            "dns": {
                "example.org": {"selected": ["1.1.1.1", "2606:4700::1111"]}
            },
        }
        jobs = a.make_jobs([chain, chain], 3, 123)
        self.assertEqual(len(jobs), 30)
        self.assertEqual(len({j["job_id"] for j in jobs}), 30)
        self.assertEqual(jobs, a.make_jobs([chain], 3, 123))
        self.assertEqual(
            [j["repetition"] for j in jobs],
            sorted(j["repetition"] for j in jobs),
        )

    def test_redirect_chain_and_downgrade(self):
        def fake(req, timeout):
            if req["kind"] == "dns":
                return {"addresses": ["1.1.1.1"]}
            return {
                "http_status": 302,
                "location": (
                    "https://www.example.org/login"
                    if req["url"] == "https://example.org/"
                    else "http://example.org/"
                ),
            }

        with patch.object(a, "bounded_worker", side_effect=fake):
            c = a.discover("https://example.org/", 2, 5, 2, None, 0)
        self.assertEqual(len(c["hops"]), 2)
        self.assertEqual(c["stop"], "http_downgrade")
        self.assertEqual(len(a.make_jobs([c], 1, 1)), 10)

    def test_redirect_loop(self):
        with patch.object(
            a,
            "bounded_worker",
            side_effect=lambda r, t: (
                {"addresses": ["1.1.1.1"]}
                if r["kind"] == "dns"
                else {"http_status": 301, "location": "/"}
            ),
        ):
            c = a.discover("https://example.org/", 2, 5, 2, None, 0)
        self.assertEqual(c["stop"], "redirect_loop")

    def test_failure_still_plans_tls(self):
        with patch.object(
            a,
            "bounded_worker",
            side_effect=lambda r, t: (
                {"addresses": ["1.1.1.1"]}
                if r["kind"] == "dns"
                else {"error": "certificate failure"}
            ),
        ):
            c = a.discover("https://example.org/", 2, 5, 2, None, 0)
        self.assertEqual(c["stop"], "http_or_certificate_failure")
        self.assertEqual(len(a.make_jobs([c], 1, 1)), 5)

    def test_deadline(self):
        with patch.object(
            a.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("worker", 1),
        ):
            self.assertEqual(
                a.bounded_worker({}, 1)["error"], "worker_deadline_exceeded"
            )

    def test_journal_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "events.jsonl"
            p.write_bytes(b'{"a":1}\n{"broken"')
            self.assertEqual(a.read_events(p), [{"a": 1}])
            a.append(p, {"a": 2})
            self.assertEqual(len(a.read_events(p)), 2)

    def test_no_newline_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "events.jsonl"
            p.write_text('{"a":1}')
            a.read_events(p)
            a.append(p, {"a": 2})
            self.assertEqual(len(a.read_events(p)), 2)

    def test_missing_and_failed_repetitions_not_negative(self):
        chain = {
            "hops": [{"hostname": "example.org", "port": 443}],
            "dns": {"example.org": {"selected": ["1.1.1.1"]}},
        }
        jobs = a.make_jobs([chain], 2, 1)
        events = [
            dict(
                j,
                status="ok" if j["profile"] == "classical" else "tls_alert",
                negotiated_group=(
                    "X25519" if j["profile"] == "classical" else None
                ),
            )
            for j in jobs
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            a.export(out, jobs, events[:-1])
            self.assertEqual(
                json.loads((out / "address_summary.json").read_text())[0][
                    "observation"
                ],
                "inconclusive",
            )
            a.export(out, jobs, events)
            self.assertEqual(
                json.loads((out / "address_summary.json").read_text())[0][
                    "observation"
                ],
                "not_observed_controlled_alert",
            )
            for e in events:
                if e["profile"] == "hybrid_only":
                    e.update(status="ok", negotiated_group="X25519MLKEM768")
                    break
            a.export(out, jobs, events)
            self.assertEqual(
                json.loads((out / "address_summary.json").read_text())[0][
                    "hybrid_successes"
                ],
                1,
            )


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL not installed")
class LocalTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temp.name)
        a.p.make_test_certificates("openssl", cls.folder)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_classical_handshake_and_hrr(self):
        for group, expected in [("X25519", False), ("P-256", True)]:
            with a.p.local_server(
                "openssl", self.folder, group, a.p.TLS_V1_3
            ) as port:
                result, raw, cmd = a.probe(
                    "openssl",
                    dict(
                        hostname="localhost",
                        port=port,
                        ip="127.0.0.1",
                        profile="classical",
                    ),
                    5,
                    str(self.folder / "ca.pem"),
                )
                self.assertEqual(result["status"], "ok", raw)
                self.assertIs(
                    result["hello_retry_request_observed"], expected, raw
                )
                self.assertEqual(
                    result["initial_keyshare_group_ids"], [29], raw
                )

    def test_real_hostname_error(self):
        with a.p.local_server(
            "openssl", self.folder, "X25519", a.p.TLS_V1_3
        ) as port:
            result, _, _ = a.probe(
                "openssl",
                dict(
                    hostname="wrong.test",
                    port=port,
                    ip="127.0.0.1",
                    profile="classical",
                ),
                5,
                str(self.folder / "ca.pem"),
            )
            self.assertEqual(result["status"], "certificate_error")

    def test_real_verified_https_discovery_worker(self):
        with a.p.local_server(
            "openssl", self.folder, "X25519", a.p.TLS_V1_3
        ) as port:
            request = {
                "kind": "http",
                "url": f"https://localhost:{port}/",
                "ip": "127.0.0.1",
                "timeout": 3,
                "cafile": str(self.folder / "ca.pem"),
            }
            result = a.bounded_worker(request, 4)
            self.assertEqual(result.get("http_status"), 200, result)
            request["cafile"] = None
            result = a.bounded_worker(request, 4)
            self.assertIn("error", result)

    def test_real_dual_keyshares(self):
        binary = shutil.which("openssl")
        try:
            a.p.inspect_openssl(binary)
        except (ValueError, RuntimeError):
            self.skipTest("OpenSSL 3.5+ with ML-KEM is required")
        with a.p.local_server(
            binary, self.folder, "X25519MLKEM768:X25519", a.p.TLS_V1_3
        ) as port:
            for profile in ("dual_hybrid_first", "dual_classical_first"):
                result, raw, _ = a.probe(
                    binary,
                    dict(
                        hostname="localhost",
                        port=port,
                        ip="127.0.0.1",
                        profile=profile,
                    ),
                    5,
                    str(self.folder / "ca.pem"),
                )
                self.assertEqual(result["status"], "ok", raw)
                self.assertIn(
                    result["negotiated_group"], ("X25519", "X25519MLKEM768")
                )
                self.assertFalse(result["hello_retry_request_observed"])
                self.assertEqual(
                    set(result["initial_keyshare_group_ids"]), {29, 4588}, raw
                )


if __name__ == "__main__":
    unittest.main()

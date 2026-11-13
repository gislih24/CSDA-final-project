import unittest
import pqc_probe as p
from collect_pqc_tls import summarize


def process(text="", **overrides):
    return dict(
        stdout="",
        stderr=text,
        returncode=0,
        timed_out=False,
        interrupted=False,
        process_elapsed_ms=1,
        **overrides
    )


SUCCESS = """CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
Verification: OK
Peer Temp Key: X25519MLKEM768, 1216 bits
"""


class ProbeEvidenceTest(unittest.TestCase):
    def test_empty_successful_process_is_retryable_not_tls_success(self):
        result = p.parse_tls(
            process("Connecting to 192.0.2.1"), p.TLS13_HYBRID_ONLY
        )
        self.assertEqual(result["status"], "no_handshake")
        self.assertIn(result["status"], p.RETRYABLE)

    def test_verified_hybrid_survives_shutdown_timeout(self):
        raw = process(SUCCESS)
        raw.update(timed_out=True, returncode=-9)
        result = p.parse_tls(raw, p.TLS13_HYBRID_ONLY)
        self.assertEqual(result["status"], "ok")

    def test_cipher_name_alone_cannot_prove_pqc(self):
        self.assertEqual(
            p.parse_tls(
                process("Ciphersuite: TLS_AES_256_GCM_SHA384"),
                p.TLS13_HYBRID_ONLY,
            )["status"],
            "no_handshake",
        )

    def test_incomplete_summary_is_parser_error(self):
        self.assertEqual(
            p.parse_tls(
                process(SUCCESS.replace("Verification: OK", "")),
                p.TLS13_HYBRID_ONLY,
            )["status"],
            "parse_error",
        )

    def test_wrong_group_is_parser_error(self):
        self.assertEqual(
            p.parse_tls(
                process(SUCCESS.replace("X25519MLKEM768", "X25519")),
                p.TLS13_HYBRID_ONLY,
            )["status"],
            "parse_error",
        )

    def test_certificate_error_overrides_hybrid_evidence(self):
        self.assertEqual(
            p.parse_tls(
                process(SUCCESS + "certificate verify failed"),
                p.TLS13_HYBRID_ONLY,
            )["status"],
            "certificate_error",
        )

    def test_explicit_alert_is_not_reclassified(self):
        self.assertEqual(
            p.parse_tls(
                process("tlsv1 alert protocol version"), p.TLS13_HYBRID_ONLY
            )["status"],
            "tls_alert",
        )


class SummaryEvidenceTest(unittest.TestCase):
    def summary(
        self, classical="ok", hybrid="no_handshake", mixed="ok", **fields
    ):
        events = [
            dict(
                sample_index=1,
                profile="dns",
                kind="dns",
                status="ok",
                terminal=True,
            )
        ]
        for profile, status in (
            (p.TLS13_CLASSICAL, classical),
            (p.TLS13_HYBRID_ONLY, hybrid),
            (p.TLS13_MIXED, mixed),
        ):
            events.append(
                dict(
                    sample_index=1,
                    kind="tls",
                    profile=profile,
                    status=status,
                    terminal=True,
                    **fields
                )
            )
        return summarize(
            dict(sample_index=1, hostname="localhost", port=443), events
        )

    def test_no_handshake_stays_inconclusive(self):
        row = self.summary()
        self.assertEqual(row["hybrid_observation"], "inconclusive")
        self.assertEqual(
            row["hybrid_observation_reason"], "missing_handshake_evidence"
        )

    def test_alert_with_control_is_not_observed(self):
        self.assertEqual(
            self.summary(hybrid="tls_alert")["hybrid_observation"],
            "not_observed",
        )

    def test_alert_without_control_is_inconclusive(self):
        self.assertEqual(
            self.summary(classical="tls_alert", hybrid="tls_alert")[
                "hybrid_observation"
            ],
            "inconclusive",
        )

    def test_verified_hybrid_wins_over_classical_failure(self):
        row = self.summary(
            classical="network_error", hybrid="ok", negotiated_group=p.HYBRID
        )
        self.assertEqual(row["hybrid_observation"], "supported")


if __name__ == "__main__":
    unittest.main()

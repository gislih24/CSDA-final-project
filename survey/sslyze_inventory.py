"""SSLyze inventory and report tables; keep the library's native JSON intact.

Running this module directly is an internal worker operation. One Scanner is
isolated in a subprocess so a slow endpoint cannot block the entire survey.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import ssl
import sys
from typing import Any, TypeAlias, TypedDict


class ScanConfig(TypedDict):
    """Required worker settings; nullable fields must still be present.

    ``ip_address=None`` lets SSLyze resolve the hostname, and ``cafile=None``
    uses its bundled trust stores without adding a custom CA file.
    """

    hostname: str
    port: int
    ip_address: str | None
    network_timeout: int
    network_retries: int
    commands: list[str]
    cafile: str | None
    resumption_attempts: int
    connections: int


class ObservationCounts(TypedDict):
    """Counts of true, false, and unknown outcomes for one inventory metric."""

    observed_true: int
    observed_false: int
    unknown_or_not_tested: int


class EndpointCounts(TypedDict):
    """Endpoint denominators and observation counts for a group."""

    endpoints: int
    completed_endpoints: int
    hybrid_observations: dict[str, int]
    inventory_metrics: dict[str, ObservationCounts]


class CategoryCounts(EndpointCounts):
    """Observation counts for a named sample category."""

    category: str


class InventoryOverview(TypedDict):
    """Aggregate observations across the sample and within each category."""

    all_endpoints: EndpointCounts
    by_category: list[CategoryCounts]


SummaryValue: TypeAlias = str | int | float | bool | list[str] | None


BASE_COMMANDS: tuple[str, ...] = (
    "certificate_info",
    "tls_1_0_cipher_suites",
    "tls_1_1_cipher_suites",
    "tls_1_2_cipher_suites",
    "tls_1_3_cipher_suites",
    "elliptic_curves",
    "session_resumption",
    "tls_1_3_early_data",
    "tls_compression",
    "tls_fallback_scsv",
    "tls_extended_master_secret",
)
PROTOCOLS: tuple[str, ...] = (
    "ssl_2_0",
    "ssl_3_0",
    "tls_1_0",
    "tls_1_1",
    "tls_1_2",
    "tls_1_3",
)
PACKAGES: tuple[str, ...] = (
    "sslyze",
    "nassl",
    "cryptography",
    "pydantic",
    "pydantic-core",
    "tls-parser",
    "cffi",
    "pycparser",
    "typing-extensions",
    "typing-inspection",
    "annotated-types",
)
TABLE_COLUMNS: dict[str, list[str]] = {
    "certificates": "sni_mode deployment_index leaf_sha256 spki_sha256_base64 subject issuer public_key_algorithm public_key_bits ec_curve certificate_signature certificate_signature_oid certificate_signature_hash not_before_utc not_after_utc days_until_expiry_at_scan validity_days expired_at_scan not_yet_valid_at_scan san_dns_names san_dns_count received_chain_length leaf_der_bytes received_chain_der_bytes chain_order_valid ocsp_stapled ocsp_trusted sct_count must_staple trust_by_store trusted_by_any_tested_store trust_store_versions validation_errors".split(),
    "cipher_suites": "tls_version outcome cipher_suite openssl_name sslyze_key_size_bits is_anonymous ephemeral_key error_message".split(),
    "curves": "curve openssl_nid outcome tls_version".split(),
    "scan_status": "scan_command status error_reason error_trace".split(),
}


def selected_commands(
    http_headers: bool = False, obsolete_ssl: bool = False
) -> list[str]:
    """Return the base SSLyze commands plus any explicitly enabled scans.

    Args:
        http_headers (bool, optional): Whether to include the HTTP headers scan
            command. Defaults to False.
        obsolete_ssl (bool, optional): Whether to include the obsolete SSL 2.0
            and SSL 3.0 cipher suites scan commands. Defaults to False.

    Returns:
        list[str]: A new list of command names, with optional scans appended
            after the base commands.
    """
    return (
        list(BASE_COMMANDS)
        + (["http_headers"] if http_headers else [])
        + (
            ["ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites"]
            if obsolete_ssl
            else []
        )
    )


def environment() -> dict[str, dict[str, str]]:
    """Record dependency versions and bundled trust-store file hashes.

    Verify the required SSLyze 6.3.1 / nassl 5.4.0 versions without modifying
    the environment. Other package versions are recorded without comparison.

    Raises:
        ValueError: If SSLyze cannot be imported, package metadata is missing,
            or the SSLyze/nassl versions do not match the required versions.
        OSError: If the trust-store directory or its files cannot be read.

    Returns:
        dict[str, dict[str, str]]: Package versions under ``packages`` and
            SHA-256 hashes keyed by PEM/YAML filename under
            ``trust_store_files_sha256``.
    """
    try:
        import sslyze

        packages: dict[str, str] = {name: version(name) for name in PACKAGES}
    except ImportError as error:
        raise ValueError(
            "Install dependencies in this Python environment: python -m pip install -r requirements.txt"
        ) from error
    if packages["sslyze"] != "6.3.1" or packages["nassl"] != "5.4.0":
        raise ValueError(
            "This collector targets SSLyze 6.3.1 / nassl 5.4.0. Install requirements.txt in a virtual environment."
        )
    stores: Path = (
        Path(sslyze.__file__).parent
        / "plugins/certificate_info/trust_stores/pem_files"
    )
    return {
        "packages": packages,
        "trust_store_files_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(stores.iterdir())
            if path.suffix in {".pem", ".yaml"}
        },
    }


def scan(config: ScanConfig) -> dict[str, Any]:
    """Scan one server and return SSLyze's native JSON-compatible result.

    SSLyze owns discovery, probe scheduling, and result serialization. Network
    and command outcomes remain in the native result, including failed scans.

    Args:
        config (ScanConfig): Configuration dictionary with required keys:
            - hostname (str): The server's hostname.
            - port (int): The server's port.
            - ip_address (str | None): The server's IP address, or None to
              let SSLyze resolve the hostname.
            - network_timeout (int): Per-connection network timeout in seconds.
            - network_retries (int): Number of network retries.
            - commands (list[str]): List of SSLyze scan commands to execute.
            - cafile (str | None): Optional custom CA file for certificate
              validation, in addition to the bundled trust stores.
            - resumption_attempts (int): Attempts per pre-TLS-1.3 session
              resumption mechanism.
            - connections (int): Maximum concurrent connections for scanning.

    Returns:
        dict[str, Any]: SSLyze's serialized server result. Nested fields vary
            by command and are retained without normalization.
    """
    from sslyze import (
        Scanner,
        ServerScanRequest,
        ServerNetworkLocation,
        ServerNetworkConfiguration,
        ScanCommand,
        ScanCommandsExtraArguments,
        CertificateInfoExtraArgument,
        SessionResumptionSupportExtraArgument,
    )
    from sslyze.json.json_output import ServerScanResultAsJson

    request = ServerScanRequest(
        server_location=ServerNetworkLocation(
            hostname=config["hostname"],
            port=config["port"],
            ip_address=config["ip_address"],
        ),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=config["hostname"],
            network_timeout=config["network_timeout"],
            network_max_retries=config["network_retries"],
            http_user_agent="PQC-TLS-Academic-Survey/2.0 (SSLyze/6.3.1)",
        ),
        scan_commands={ScanCommand(command) for command in config["commands"]},
        scan_commands_extra_arguments=ScanCommandsExtraArguments(
            certificate_info=(
                CertificateInfoExtraArgument(
                    custom_ca_file=Path(config["cafile"])
                )
                if config["cafile"]
                else None
            ),
            session_resumption=SessionResumptionSupportExtraArgument(
                number_of_resumptions_to_attempt=config["resumption_attempts"]
            ),
        ),
    )
    scanner = Scanner(
        per_server_concurrent_connections_limit=config["connections"],
        concurrent_server_scans_limit=1,
    )
    scanner.queue_scans([request])
    return ServerScanResultAsJson.model_validate(
        next(scanner.get_results())
    ).model_dump(mode="json")


def completed(
    native: Mapping[str, Any], command: str
) -> dict[str, Any] | None:
    """Return a command's result only when its status is COMPLETED.

    Args:
        native (Mapping[str, Any]): The native SSLyze scan result dictionary.
        command (str): The SSLyze scan command to check for completion.

    Returns:
        dict[str, Any] | None: The original command result dictionary, or None
            if the scan, command, or result is missing or not completed. A
            completed result containing false observations is returned intact.
    """
    attempt = (native.get("scan_result") or {}).get(command) or {}
    return (
        attempt.get("result") if attempt.get("status") == "COMPLETED" else None
    )


def is_timeout_rejection(item: Mapping[str, Any]) -> bool:
    """Check a rejected suite's error message for case-insensitive timeout text.

    A missing, null, or empty error message is not classified as a timeout.
    """
    message: str = (item.get("error_message") or "").lower()
    return "timed out" in message or "timeout" in message


def parse_date(value: str) -> datetime:
    """Parse an ISO 8601 timestamp and return a timezone-aware UTC datetime.

    A trailing ``Z`` denotes UTC. A timestamp without an offset is interpreted
    in the local timezone by ``astimezone()``.

    Args:
        value (str): An ISO 8601 timestamp from SSLyze or the collector.

    Raises:
        ValueError: If the timestamp cannot be parsed.

    Returns:
        datetime: The parsed instant normalized to UTC.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def certificate_rows(
    native: Mapping[str, Any], measured_at: str
) -> list[dict[str, Any]]:
    """Describe each nonempty certificate deployment, with and without SNI.

    Fingerprints and byte counts use DER-encoded certificates. Validity and
    expiry metrics are evaluated at the supplied scan time, and trust outcomes
    retain the individual stores' results.

    Args:
        native (Mapping[str, Any]): The native SSLyze scan result dictionary.
        measured_at (str): ISO 8601 timestamp at which to evaluate validity.

    Returns:
        list[dict[str, Any]]: One row per deployment with a received chain.
            Returns an empty list when certificate_info did not complete.
            Store-specific mappings and DNS-name lists remain nested values.
    """
    certinfo: dict[str, Any] | None = completed(
        native, command="certificate_info"
    )
    if certinfo is None:
        return []
    deployments: list[tuple[str, int, dict[str, Any]]] = [
        ("with_sni", i + 1, item)
        for i, item in enumerate(certinfo["certificate_deployments"])
    ]
    if certinfo.get("certificate_deployment_with_sni_disabled"):
        deployments.append(
            (
                "without_sni",
                1,
                certinfo["certificate_deployment_with_sni_disabled"],
            )
        )
    rows: list[dict[str, Any]] = []
    for mode, index, deployment in deployments:
        chain = deployment["received_certificate_chain"]
        if not chain:
            continue
        leaf = chain[0]
        der = [ssl.PEM_cert_to_DER_cert(cert["as_pem"]) for cert in chain]
        not_before, not_after = parse_date(
            leaf["not_valid_before"]
        ), parse_date(leaf["not_valid_after"])
        valid_at = parse_date(measured_at)
        paths = deployment.get("path_validation_results") or []
        trust: dict[str, bool] = {
            item["trust_store"]["name"]: item["was_validation_successful"]
            for item in paths
        }
        key = leaf["public_key"]
        rows.append(
            {
                "sni_mode": mode,
                "deployment_index": index,
                "leaf_sha256": hashlib.sha256(der[0]).hexdigest(),
                "spki_sha256_base64": leaf["hpkp_pin"],
                "subject": (leaf.get("subject") or {}).get("rfc4514_string"),
                "issuer": (leaf.get("issuer") or {}).get("rfc4514_string"),
                "public_key_algorithm": key["algorithm"],
                "public_key_bits": key.get("key_size"),
                "ec_curve": key.get("ec_curve_name"),
                "certificate_signature": leaf["signature_algorithm_oid"][
                    "name"
                ],
                "certificate_signature_oid": leaf["signature_algorithm_oid"][
                    "dotted_string"
                ],
                "certificate_signature_hash": (
                    leaf.get("signature_hash_algorithm") or {}
                ).get("name"),
                "not_before_utc": leaf["not_valid_before"],
                "not_after_utc": leaf["not_valid_after"],
                "days_until_expiry_at_scan": round(
                    (not_after - valid_at).total_seconds() / 86400, 3
                ),
                "validity_days": round(
                    (not_after - not_before).total_seconds() / 86400, 3
                ),
                "expired_at_scan": valid_at > not_after,
                "not_yet_valid_at_scan": valid_at < not_before,
                "san_dns_names": leaf["subject_alternative_name"]["dns_names"],
                "san_dns_count": len(
                    leaf["subject_alternative_name"]["dns_names"]
                ),
                "received_chain_length": len(chain),
                "leaf_der_bytes": len(der[0]),
                "received_chain_der_bytes": sum(map(len, der)),
                "chain_order_valid": deployment.get(
                    "received_chain_has_valid_order"
                ),
                "ocsp_stapled": deployment.get("ocsp_response") is not None,
                "ocsp_trusted": deployment.get("ocsp_response_is_trusted"),
                "sct_count": deployment.get(
                    "leaf_certificate_signed_certificate_timestamps_count"
                ),
                "must_staple": deployment.get(
                    "leaf_certificate_has_must_staple_extension"
                ),
                "trust_by_store": trust,
                "trusted_by_any_tested_store": (
                    any(trust.values()) if trust else None
                ),
                "trust_store_versions": {
                    item["trust_store"]["name"]: item["trust_store"]["version"]
                    for item in paths
                },
                "validation_errors": {
                    item["trust_store"]["name"]: item.get("validation_error")
                    for item in paths
                },
            }
        )
    return rows


def summarize(
    native: Mapping[str, Any], measured_at: str
) -> dict[str, SummaryValue]:
    """Summarize observed TLS, certificate, resumption, and HTTP properties.

    Unknown or untested observations remain None. Timeout-only protocol and
    static-RSA negatives remain unknown, as does SSLyze's TLS 1.3 EMS shortcut.
    Certificate summary metrics use only deployments observed with SNI.

    Args:
        native (Mapping[str, Any]): The native SSLyze scan result dictionary.
        measured_at (str): ISO 8601 timestamp used for certificate validity.

    Returns:
        dict[str, SummaryValue]: Exportable observations, counts, durations,
            names, and fingerprints. No security score or PQC support is
            inferred.
    """
    connectivity = native.get("connectivity_result") or {}
    summary: dict[str, SummaryValue] = {
        "sslyze_connectivity_status": native.get("connectivity_status"),
        "sslyze_scan_status": native.get("scan_status"),
        "sslyze_highest_tls_observed": connectivity.get(
            "highest_tls_version_supported"
        ),
        "client_auth_requirement": connectivity.get("client_auth_requirement"),
    }
    for protocol in PROTOCOLS:
        result: dict[str, Any] | None = completed(
            native, protocol + "_cipher_suites"
        )
        timeouts: int | None = (
            sum(
                is_timeout_rejection(item)
                for item in result["rejected_cipher_suites"]
            )
            if result
            else None
        )
        # SSLyze can put timeout outcomes in its rejected-suite list. Do not
        # turn an all-negative scan containing timeouts into a protocol negative.
        observed: bool | None = (
            result["is_tls_version_supported"] if result is not None else None
        )
        summary[protocol + "_observed"] = (
            None if observed is False and timeouts else observed
        )
        summary[protocol + "_cipher_count"] = (
            len(result["accepted_cipher_suites"])
            if result is not None
            else None
        )
        summary[protocol + "_cipher_timeout_count"] = timeouts
    for command, flag in (
        ("tls_1_3_early_data", "supports_early_data"),
        ("tls_compression", "supports_compression"),
        ("tls_fallback_scsv", "supports_fallback_scsv"),
        ("tls_extended_master_secret", "supports_ems_extension"),
    ):
        result = completed(native, command)
        summary[flag] = result.get(flag) if result is not None else None
    summary["sslyze_fallback_scsv_result"] = summary.pop(
        "supports_fallback_scsv"
    )
    # SSLyze 6 returns True without testing EMS when its best connection is
    # TLS 1.3. EMS is a pre-TLS-1.3 extension; that shortcut is not an observation.
    ems: dict[str, Any] | None = completed(
        native, "tls_extended_master_secret"
    )
    summary["ems_result_scope"] = (
        "not_tested"
        if ems is None
        else (
            "not_tested_tls13_shortcut"
            if connectivity.get("highest_tls_version_supported") == "TLS_1_3"
            else "tested_pre_tls13"
        )
    )
    if summary["ems_result_scope"] != "tested_pre_tls13":
        summary["supports_ems_extension"] = None
    curves: dict[str, Any] | None = completed(native, "elliptic_curves")
    summary["classical_curves_observed"] = (
        [c["name"] for c in curves.get("supported_curves") or []]
        if curves is not None
        else None
    )
    summary["curve_scan_tls_version"] = (
        connectivity.get("highest_tls_version_supported")
        if curves is not None
        else None
    )
    resum: dict[str, Any] | None = completed(native, "session_resumption")
    for key in (
        "session_id_resumption_result",
        "session_id_attempted_resumptions_count",
        "session_id_successful_resumptions_count",
        "tls_ticket_resumption_result",
        "tls_ticket_attempted_resumptions_count",
        "tls_ticket_successful_resumptions_count",
    ):
        summary["pre_tls13_" + key] = (
            resum.get(key) if resum is not None else None
        )
    highest: str | None = connectivity.get("highest_tls_version_supported")
    summary["resumption_test_tls_version"] = (
        ("TLS_1_2" if highest == "TLS_1_3" else highest) if resum else None
    )
    tls12: dict[str, Any] | None = completed(native, "tls_1_2_cipher_suites")
    rsa_observed: bool | None = (
        any(
            item["cipher_suite"]["name"].startswith("TLS_RSA_WITH_")
            for item in tls12["accepted_cipher_suites"]
        )
        if tls12 is not None
        else None
    )
    rsa_timeouts: bool = (
        any(
            is_timeout_rejection(item)
            and item["cipher_suite"]["name"].startswith("TLS_RSA_WITH_")
            for item in tls12["rejected_cipher_suites"]
        )
        if tls12 is not None
        else False
    )
    summary["tls12_static_rsa_observed"] = (
        None if rsa_observed is False and rsa_timeouts else rsa_observed
    )
    certs: list[dict[str, Any]] = [
        row
        for row in certificate_rows(native, measured_at)
        if row["sni_mode"] == "with_sni"
    ]
    cert_complete: bool = completed(native, "certificate_info") is not None
    summary["certificate_deployment_count"] = (
        len(certs) if cert_complete else None
    )
    for key, source in (
        ("certificate_key_algorithms", "public_key_algorithm"),
        ("certificate_issuers", "issuer"),
        ("leaf_sha256s", "leaf_sha256"),
    ):
        summary[key] = (
            sorted({row[source] for row in certs if row[source]})
            if cert_complete
            else None
        )
    summary["minimum_certificate_days_remaining"] = min(
        (r["days_until_expiry_at_scan"] for r in certs), default=None
    )
    summary["maximum_received_chain_der_bytes"] = max(
        (r["received_chain_der_bytes"] for r in certs), default=None
    )
    # Only count a trust negative when each discovered deployment has an evaluated outcome.
    trusted: list[bool | None] = [
        r["trusted_by_any_tested_store"] for r in certs
    ]
    summary["any_sni_certificate_trusted"] = (
        True
        if True in trusted
        else False if trusted and all(x is False for x in trusted) else None
    )
    http: dict[str, Any] | None = completed(native, "http_headers")
    hsts = http.get("strict_transport_security_header") if http else None
    http_ok: bool = http is not None and not http.get("http_error_trace")
    summary.update(
        hsts_header_observed=hsts is not None if http_ok else None,
        hsts_max_age=hsts.get("max_age") if hsts else None,
        hsts_include_subdomains=(
            hsts.get("include_subdomains") if hsts else None
        ),
        hsts_preload_directive=hsts.get("preload") if hsts else None,
    )
    return summary


def tables(
    native: Mapping[str, Any], measured_at: str
) -> dict[str, list[dict[str, Any]]]:
    """Build long-form certificate, cipher-suite, curve, and scan-status tables.

    Preserve every certificate deployment, suite-level error, and available
    command status. Rejected suites with timeout messages receive a separate
    ``timeout`` outcome; curve rejections retain SSLyze's broader
    classification.

    Args:
        native (Mapping[str, Any]): The native SSLyze scan result dictionary.
        measured_at (str): ISO 8601 timestamp used for certificate validity.

    Returns:
        dict[str, list[dict[str, Any]]]: Rows keyed by TABLE_COLUMNS names.
            Incomplete commands contribute status rows but no result rows.
            Certificate mappings/lists and ephemeral-key objects stay nested.
    """
    output: dict[str, list[dict[str, Any]]] = {
        "certificates": certificate_rows(native, measured_at),
        "cipher_suites": [],
        "curves": [],
        "scan_status": [],
    }
    for name, attempt in (native.get("scan_result") or {}).items():
        output["scan_status"].append(
            {
                "scan_command": name,
                "status": attempt["status"],
                "error_reason": attempt.get("error_reason"),
                "error_trace": attempt.get("error_trace"),
            }
        )
        result = completed(native, name)
        if result is None or not name.endswith("_cipher_suites"):
            continue
        for key, outcome in (
            ("accepted_cipher_suites", "accepted"),
            ("rejected_cipher_suites", "rejected"),
        ):
            for item in result[key]:
                suite = item["cipher_suite"]
                output["cipher_suites"].append(
                    {
                        "tls_version": result["tls_version_used"],
                        "outcome": (
                            "timeout"
                            if outcome == "rejected"
                            and is_timeout_rejection(item)
                            else outcome
                        ),
                        "cipher_suite": suite["name"],
                        "openssl_name": suite["openssl_name"],
                        "sslyze_key_size_bits": suite["key_size"],
                        "is_anonymous": suite["is_anonymous"],
                        "ephemeral_key": item.get("ephemeral_key"),
                        "error_message": item.get("error_message"),
                    }
                )
    curves = completed(native, "elliptic_curves")
    if curves:
        for field, outcome in (
            ("supported_curves", "accepted"),
            ("rejected_curves", "rejected_by_sslyze"),
        ):
            output["curves"].extend(
                {
                    "curve": item["name"],
                    "openssl_nid": item["openssl_nid"],
                    "outcome": outcome,
                    "tls_version": (
                        native.get("connectivity_result") or {}
                    ).get("highest_tls_version_supported"),
                }
                for item in curves.get(field) or []
            )
    return output


def overview(summaries: Sequence[Mapping[str, Any]]) -> InventoryOverview:
    """Count endpoint outcomes for the full sample and each sorted category.

    Args:
        summaries (Sequence[Mapping[str, Any]]): Combined collector summaries.
            Each row requires ``category``, ``complete``, and
            ``hybrid_observation``; missing inventory metrics count as unknown.

    Returns:
        InventoryOverview: Total and completed endpoint counts, hybrid outcome
            counts, and true/false/unknown counts for inventory metrics.
            Categories are sorted by name. An empty sample has zero total counts
            and no category groups.
    """
    metrics = [p + "_observed" for p in PROTOCOLS] + [
        "supports_early_data",
        "supports_compression",
        "supports_ems_extension",
        "tls12_static_rsa_observed",
        "any_sni_certificate_trusted",
        "hsts_header_observed",
    ]

    def count(rows: Sequence[Mapping[str, Any]]) -> EndpointCounts:
        """Count group outcomes with all supplied endpoints as the denominator."""
        return {
            "endpoints": len(rows),
            "completed_endpoints": sum(bool(row["complete"]) for row in rows),
            "hybrid_observations": {
                label: sum(row["hybrid_observation"] == label for row in rows)
                for label in ("supported", "not_observed", "inconclusive")
            },
            "inventory_metrics": {
                key: {
                    "observed_true": sum(row.get(key) is True for row in rows),
                    "observed_false": sum(
                        row.get(key) is False for row in rows
                    ),
                    "unknown_or_not_tested": sum(
                        row.get(key) is None for row in rows
                    ),
                }
                for key in metrics
            },
        }

    categories = sorted({row["category"] for row in summaries})
    return {
        "all_endpoints": count(summaries),
        "by_category": [
            {
                "category": category,
                **count(
                    [row for row in summaries if row["category"] == category]
                ),
            }
            for category in categories
        ],
    }


if __name__ == "__main__":
    print(json.dumps(scan(json.loads(sys.argv[1])), ensure_ascii=False))

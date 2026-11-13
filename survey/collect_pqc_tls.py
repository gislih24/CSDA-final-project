#!/usr/bin/env python3
"""Collect an IPv4 TLS survey using SSLyze 6.3.1 plus explicit PQC probes.

Quick start:
  python3 collect_pqc_tls.py --self-test
  python3 collect_pqc_tls.py websites.txt --out survey_1 --location Iceland
  python3 collect_pqc_tls.py websites.txt --out survey_1 --location Iceland --resume

Input: one hostname/HTTPS URL per line; # comments and [category] headings
are allowed. Alternatively use tab-separated hostname, category, organisation.
SSLyze inventories protocols, suites, curves, certificates and TLS features.
The OpenSSL 3.5+ adapter performs verified classical/hybrid TLS 1.3 comparisons.
This is a deployment survey, NOT a controlled latency/byte benchmark.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sys
import time
from types import FrameType
from typing import Any, Final, Literal, NoReturn, TypeAlias, TypedDict
from urllib.parse import urlsplit
import uuid

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text

import pqc_probe
import sslyze_inventory as sslyze_inventory

logger: logging.Logger = logging.getLogger(__name__)


def _iso_utc_log_time(value: datetime) -> Text:
    """Render a Rich log timestamp as ISO 8601 UTC with milliseconds."""
    timestamp = value.astimezone(timezone.utc).isoformat(
        timespec="milliseconds"
    )
    return Text(timestamp.replace("+00:00", "Z"))


def configure_logging(level: str = "INFO") -> None:
    """Configure Rich console logging for the CLI without changing root handlers.

    Send messages to stderr and treat bracketed input as literal text. Reuse
    the handler on repeated calls while applying the requested log level.
    Importing this module leaves logging configuration to the caller.

    Args:
        level (str): Standard logging level name, validated by the CLI.
    """
    logger.setLevel(level)
    logger.propagate = False
    if not any(
        isinstance(handler, RichHandler) for handler in logger.handlers
    ):
        handler = RichHandler(
            console=Console(stderr=True),
            show_path=False,
            omit_repeated_times=False,
            log_time_format=_iso_utc_log_time,
            markup=False,
            rich_tracebacks=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)


class _SampleMetadata(pqc_probe.Endpoint):
    """Required input metadata shared by unique and duplicate sample rows."""

    category: str
    organisation: str
    input_line: int
    input_value: str


class SampleRow(_SampleMetadata, total=False):
    """Normalized endpoint and its input metadata.

    Unique targets receive a one-based sample_index after deduplication.
    Duplicate rows retain their input metadata without a sample_index.
    """

    sample_index: int


class InventoryConfig(TypedDict):
    """Shared SSLyze worker settings, including the whole-worker deadline."""

    commands: list[str]
    network_timeout: int
    network_retries: int
    connections: int
    deadline_s: float
    resumption_attempts: int
    cafile: str | None


class _DNSDetails(TypedDict, total=False):
    """Optional DNS fields populated according to the worker's outcome."""

    error: str
    resolved_ipv4: list[str]
    ip_address: str
    dns_duration_ms: float


class DNSResult(_DNSDetails):
    """DNS worker outcome, with address/timing fields when available."""

    status: Literal["ok", "dns_error", "timeout", "interrupted", "tool_error"]


InventoryStatus: TypeAlias = Literal[
    "ok",
    "inventory_connectivity_error",
    "inventory_partial",
    "interrupted",
    "inventory_timeout",
    "tool_error",
    "parse_error",
]


class _InventoryPayload(TypedDict, total=False):
    """Optional native SSLyze payload, absent when the worker has no result."""

    sslyze_result: dict[str, Any]


class InventoryResult(_InventoryPayload):
    """Worker classification and any parsed native SSLyze result."""

    status: InventoryStatus
    error: str | None


VERSION: Final = "2.1.0"
PQC_PROFILES: tuple[str, ...] = tuple(
    name for name in pqc_probe.PROFILES if name.startswith("tls13")
)
SOURCE_FILES: tuple[str, ...] = (
    "collect_pqc_tls.py",
    "pqc_probe.py",
    "sslyze_inventory.py",
)


def utc_now() -> str:
    """Return the current UTC timestamp in ISO 8601 format with milliseconds."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of the supplied bytes."""
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, data: Any) -> None:
    """Write indented UTF-8 JSON through a flushed, synced sibling temp file.

    Replace the destination only after serialization and syncing succeed.
    The parent directory must already exist.

    Args:
        path (Path): Destination file, replaced if it already exists.
        data (Any): JSON-serializable value to write.

    Raises:
        TypeError: If data contains values the JSON encoder cannot serialize.
        OSError: If writing, syncing, or replacing the file fails.
    """
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def normalize_endpoint(value: str, default_port: int) -> tuple[str, int]:
    """Validate an input endpoint and normalize its DNS hostname and port.

    Accept bare hostnames or HTTP(S) URLs, discard URL paths, and normalize
    hostnames to lowercase IDNA without a trailing dot. IP literals and
    credentials are rejected; localhost is allowed for test fixtures.

    Args:
        value (str): Hostname or URL, optionally including a port.
        default_port (int): Port used when the input does not specify one,
            regardless of the URL scheme.

    Raises:
        ValueError: If the URL, hostname, scheme, or port is invalid, or
            credentials are present.
        UnicodeError: If the hostname cannot be encoded as IDNA.

    Returns:
        tuple[str, int]: Normalized ASCII hostname and validated port.
    """
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("only bare hostnames and HTTP(S) URLs are accepted")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials are not allowed in the input")
    if not parsed.hostname:
        raise ValueError("missing hostname")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    port = parsed.port if parsed.port is not None else default_port
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError(
            "use a hostname, not an IP address, so SNI and hostname verification are meaningful"
        )
    labels = host.split(".")
    if (
        len(host) > 253
        or (len(labels) < 2 and host != pqc_probe.LOCALHOST)
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise ValueError("invalid DNS hostname")
    return host, port


def read_sample(
    path: Path, default_port: int, limit: int | None
) -> tuple[list[SampleRow], list[SampleRow]]:
    """Read, validate, and deduplicate the complete endpoint sample.

    Accept UTF-8 input with an optional BOM, comments, category headings, and
    up to three tab-separated fields: hostname, category, organisation. Retain
    input line numbers and values. Matching endpoints must also have matching
    category/organisation metadata.

    Args:
        path (Path): Input sample file.
        default_port (int): Port used when an endpoint does not specify one.
        limit (int | None): Optional positive cap on returned unique targets.
            All input rows are validated and deduplicated before applying it.

    Raises:
        ValueError: If any endpoint is invalid, duplicate metadata conflicts,
            or no usable hostnames remain. Row errors include line numbers.
        OSError: If the input cannot be read.
        UnicodeError: If the file is not valid UTF-8.

    Returns:
        tuple[list[SampleRow], list[SampleRow]]: Unique targets in input order,
            each with a one-based sample_index, and all duplicate input rows
            without sample indices. The limit applies only to unique targets.
    """
    targets: list[SampleRow] = []
    duplicates: list[SampleRow] = []
    seen: dict[tuple[str, int], SampleRow] = {}
    errors: list[str] = []
    category = ""
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), 1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            category = line[1:-1].strip()
            continue
        fields = [field.strip() for field in line.split("\t")]
        if (
            fields[0].lower() == "hostname"
            and len(fields) > 1
            and fields[1].lower() == "category"
        ):
            continue
        try:
            if len(fields) > 3:
                raise ValueError("expected at most three tab-separated fields")
            host, port = normalize_endpoint(fields[0], default_port)
            target: SampleRow = {
                "hostname": host,
                "port": port,
                "category": fields[1] if len(fields) > 1 else category,
                "organisation": fields[2] if len(fields) > 2 else "",
                "input_line": line_number,
                "input_value": fields[0],
            }
            key = (host, port)
            if key in seen:
                previous = seen[key]
                if (previous["category"], previous["organisation"]) != (
                    target["category"],
                    target["organisation"],
                ):
                    raise ValueError(
                        "duplicate endpoint has conflicting category/organisation metadata"
                    )
                duplicates.append(target)
                continue
            target["sample_index"] = len(targets) + 1
            seen[key] = target
            targets.append(target)
        except (ValueError, UnicodeError) as error:
            errors.append(f"Line {line_number}: {error}: {line!r}")
    if errors:
        raise ValueError(
            "Fix the input before collecting:\n" + "\n".join(errors)
        )
    if not targets:
        raise ValueError("The input has no usable hostnames.")
    return targets[:limit] if limit else targets, duplicates


# A child process lets the parent enforce a deadline on getaddrinfo, including
# platforms where socket.setdefaulttimeout does not bound DNS resolution.
DNS_WORKER: Final = r"""
import ipaddress, json, socket, sys, time
start = time.perf_counter()
try:
    answers = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), socket.AF_INET, socket.SOCK_STREAM)
    ips = sorted({a[4][0] for a in answers}, key=ipaddress.IPv4Address)
    print(json.dumps({'status': 'ok', 'resolved_ipv4': ips,
                      'ip_address': ips[0], 'dns_duration_ms': (time.perf_counter()-start)*1000}))
except Exception as error:
    print(json.dumps({'status': 'dns_error', 'error': str(error),
                      'dns_duration_ms': (time.perf_counter()-start)*1000}))
"""


def resolve_target(
    target: pqc_probe.Endpoint, timeout: float
) -> tuple[DNSResult, pqc_probe.ProcessResult, list[str]]:
    """Resolve IPv4 addresses in a child process under a parent-set deadline.

    The worker sorts distinct addresses numerically and selects the lowest one
    for all later connections. Timeout, interruption, and unusable worker JSON
    are returned as outcomes rather than raised as DNS failures.

    Args:
        target (pqc_probe.Endpoint): Hostname and port passed to getaddrinfo().
        timeout (float): DNS worker communication deadline in seconds.

    Returns:
        tuple[DNSResult, pqc_probe.ProcessResult, list[str]]: DNS outcome,
            captured process evidence, and exact worker command arguments.
    """
    command = [
        sys.executable,
        "-c",
        DNS_WORKER,
        target["hostname"],
        str(target["port"]),
    ]
    result = pqc_probe.run_process(command, timeout)
    if result["interrupted"]:
        data: DNSResult = {
            "status": "interrupted",
            "error": "Interrupted during DNS lookup",
        }
    elif result["timed_out"]:
        data = {
            "status": "timeout",
            "error": "DNS lookup exceeded its deadline",
        }
    else:
        try:
            data = json.loads(result["stdout"])
        except (ValueError, TypeError):
            data = {
                "status": "tool_error",
                "error": "DNS worker failed: " + result["stderr"],
            }
    return data, result, command


def run_inventory(
    target: pqc_probe.Endpoint, ip: str, config: InventoryConfig
) -> tuple[InventoryResult, pqc_probe.ProcessResult, list[str]]:
    """Run the SSLyze worker and classify its native output without changing it.

    A successful worker may still report connectivity or individual command
    failures. Distinguish those outcomes from a whole-worker timeout, process
    failure, interruption, or malformed JSON.

    Args:
        target (pqc_probe.Endpoint): Hostname for SNI and the endpoint port.
        ip (str): Selected IPv4 address to scan.
        config (InventoryConfig): Scan settings and whole-worker deadline.

    Returns:
        tuple[InventoryResult, pqc_probe.ProcessResult, list[str]]: Classified
            outcome, captured process evidence, and exact worker arguments.
            Parsed native results are retained under sslyze_result.
    """
    request: dict[str, Any] = {
        **config,
        "hostname": target["hostname"],
        "port": target["port"],
        "ip_address": ip,
    }
    command = [
        sys.executable,
        str(Path(__file__).with_name("sslyze_inventory.py")),
        json.dumps(request),
    ]
    result = pqc_probe.run_process(command, config["deadline_s"])
    if result["interrupted"]:
        data: InventoryResult = {
            "status": "interrupted",
            "error": "Interrupted SSLyze inventory; rerun on resume",
        }
    elif result["timed_out"]:
        data = {
            "status": "inventory_timeout",
            "error": "SSLyze exceeded its per-endpoint deadline; inventory is unknown",
        }
    elif result["returncode"] != 0:
        data = {
            "status": "tool_error",
            "error": "SSLyze worker failed: " + result["stderr"][-2500:],
        }
    else:
        try:
            native = json.loads(result["stdout"])
            if native["connectivity_status"] != "COMPLETED":
                status: InventoryStatus = "inventory_connectivity_error"
            elif all(
                (native.get("scan_result") or {}).get(cmd, {}).get("status")
                == "COMPLETED"
                for cmd in config["commands"]
            ):
                status = "ok"
            else:
                status = "inventory_partial"
            data = {
                "status": status,
                "sslyze_result": native,
                "error": native.get("connectivity_error_trace"),
            }
        except (ValueError, TypeError, KeyError) as error:
            data = {
                "status": "parse_error",
                "error": "Unrecognized SSLyze output: " + str(error),
            }
    return data, result, command


@contextmanager
def output_lock(directory: Path) -> Iterator[None]:
    """Hold a nonblocking, exclusive run lock while the context is active.

    Use a one-byte lock on Windows and flock() elsewhere. Closing the file on
    context exit releases the lock; the run.lock file remains in the directory.

    Args:
        directory (Path): Existing output directory containing the run.

    Raises:
        ValueError: If acquiring the lock raises OSError, usually because
            another collector holds it.
        OSError: If the lock file cannot be opened.

    Yields:
        None: Control while the output directory is locked.
    """
    with (directory / "run.lock").open("a+b") as stream:
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                stream.write(b"0")
                stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError(
                "Another collector is using this output folder."
            ) from error
        yield


def read_events(path: Path) -> list[dict[str, Any]]:
    """Load committed JSONL events, preserving and removing an unfinished tail.

    A trailing record without a newline is treated as uncommitted. Save its
    bytes to a uniquely named uncommitted_tail_*.bin beside the journal, then
    truncate the journal to its last newline before parsing committed records.

    Args:
        path (Path): Append-only attempts journal.

    Raises:
        ValueError: If a committed line is not valid JSON.
        OSError: If reading or recovering the journal fails.

    Returns:
        list[dict[str, Any]]: Parsed events in journal order, or an empty list
            when the journal does not exist. Phase-specific fields stay intact.
    """
    if not path.exists():
        return []
    raw = path.read_bytes()
    # A killed process can leave an uncommitted final line. Keep it as evidence.
    if raw and not raw.endswith(b"\n"):
        cut = raw.rfind(b"\n") + 1
        path.with_name(f"uncommitted_tail_{uuid.uuid4().hex}.bin").write_bytes(
            raw[cut:]
        )
        with path.open("r+b") as stream:
            stream.truncate(cut)
        raw = raw[:cut]
        logger.warning(
            "Recovered an incomplete final record; its bytes were preserved."
        )
    try:
        return [json.loads(line) for line in raw.splitlines()]
    except ValueError as error:
        raise ValueError(
            "A committed JSONL record is damaged; preserve this folder and start a new run."
        ) from error


def save_event(
    out: Path,
    events: list[dict[str, Any]],
    event: dict[str, Any],
    result: Mapping[str, Any],
    command: list[str],
) -> None:
    """Persist raw evidence before committing an event to the attempts journal.

    Add finish time, process metadata, command arguments, and evidence paths to
    event in place. Write any native SSLyze JSON and the raw log first, then
    append and sync the JSONL record before adding event to the in-memory list.

    Args:
        out (Path): Existing run directory with raw/ and sslyze/ subdirectories.
        events (list[dict[str, Any]]): Journal list to append to on success.
        event (dict[str, Any]): Phase outcome with sample_index, profile, and
            attempt_id; enriched in place with persistence metadata.
        result (Mapping[str, Any]): ProcessResult fields from the worker/probe.
        command (list[str]): Exact executable and arguments used by the attempt.

    Raises:
        OSError: If evidence or the journal cannot be written or synced,
            including when the raw-log filename already exists.
        TypeError: If event data cannot be serialized as JSON.
    """
    event["finished_utc"] = utc_now()
    event.update(
        {
            key: result[key]
            for key in (
                "returncode",
                "timed_out",
                "interrupted",
                "process_elapsed_ms",
            )
        }
    )
    event["command"] = command
    event["raw_log"] = (
        f"raw/{event['sample_index']:03d}_{event['profile']}_{event['attempt_id']}.txt"
    )
    if "sslyze_result" in event:
        event["sslyze_json"] = (
            f"sslyze/{event['sample_index']:03d}_{event['attempt_id']}.json"
        )
        write_json(out / event["sslyze_json"], event["sslyze_result"])
    with (out / event["raw_log"]).open(
        "x", encoding="utf-8", newline="\n"
    ) as stream:
        stream.write(
            "COMMAND (JSON argv)\n" + json.dumps(command) + "\n\nSTDOUT\n"
        )
        stream.write(result["stdout"] + "\n\nSTDERR\n" + result["stderr"])
        stream.flush()
        os.fsync(stream.fileno())
    with (out / "attempts.jsonl").open(
        "a", encoding="utf-8", newline="\n"
    ) as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    events.append(event)


def write_csv(
    path: Path, rows: Iterable[Mapping[str, Any]], fields: Sequence[str]
) -> None:
    """Replace a CSV export after writing its header and rows to a sibling file.

    Use UTF-8 with a BOM and encode nested dictionaries/lists as JSON cells.
    Ignore keys outside fields and preserve the supplied column order.

    Args:
        path (Path): Destination file in an existing directory.
        rows (Iterable[Mapping[str, Any]]): Export rows, consumed once.
        fields (Sequence[str]): Column names in output order.

    Raises:
        OSError: If writing or replacing the export fails.
        TypeError: If a nested value cannot be serialized as JSON.
    """
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fields, extrasaction="ignore"
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: (
                        json.dumps(value, ensure_ascii=False)
                        if isinstance(value, (dict, list))
                        else value
                    )
                    for key, value in row.items()
                }
            )
    temp.replace(path)


def summarize(
    target: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Combine one endpoint's DNS, PQC, and SSLyze observations into a summary.

    For each PQC profile, prefer its latest successful attempt; otherwise use
    its latest attempt. Verified hybrid evidence establishes support. Classical
    success plus a hybrid-only TLS alert records not_observed; other cases stay
    inconclusive. Inventory and DNS fields use their latest attempts.

    Args:
        target (Mapping[str, Any]): Endpoint metadata including sample_index.
        events (Sequence[Mapping[str, Any]]): Attempt records for all endpoints.

    Returns:
        dict[str, Any]: Metadata, profile observations, and inventory metrics.
            complete means DNS terminated and either failed or all later phases
            terminated; it does not require every scan to have succeeded.
    """
    rows = [
        event
        for event in events
        if event["sample_index"] == target["sample_index"]
    ]
    dns = [row for row in rows if row["profile"] == "dns"]
    row: dict[str, Any] = {
        **target,
        "ip_address": dns[-1].get("ip_address") if dns else None,
        "dns_status": dns[-1]["status"] if dns else "pending",
        "hybrid_observation": "inconclusive",
        "complete": False,
    }
    selected: dict[str, Mapping[str, Any]] = {}
    for profile in PQC_PROFILES:
        attempts = [item for item in rows if item["profile"] == profile]
        selected[profile] = next(
            (item for item in reversed(attempts) if item["status"] == "ok"),
            attempts[-1] if attempts else {},
        )
        item = selected[profile]
        row[profile + "_status"] = item.get("status", "not_attempted")
        row[profile + "_group"] = item.get("negotiated_group")
        row[profile + "_cipher"] = item.get("cipher_suite")
    if any(
        item.get("status") == "ok"
        and item.get("negotiated_group") == pqc_probe.HYBRID
        for item in selected.values()
    ):
        row["hybrid_observation"] = "supported"
    elif (
        selected[pqc_probe.TLS13_CLASSICAL].get("status") == "ok"
        and selected[pqc_probe.TLS13_HYBRID_ONLY].get("status") == "tls_alert"
    ):
        row["hybrid_observation"] = "not_observed"
    inventory_attempts = [item for item in rows if item["profile"] == "sslyze"]
    last_inventory = inventory_attempts[-1] if inventory_attempts else {}
    row["inventory_status"] = last_inventory.get("status", "not_attempted")
    row.update(
        sslyze_inventory.summarize(
            last_inventory.get("sslyze_result") or {},
            last_inventory.get("started_utc", utc_now()),
        )
    )
    row["complete"] = bool(
        dns
        and dns[-1].get("terminal")
        and (
            dns[-1]["status"] != "ok"
            or (
                all(item.get("terminal") for item in selected.values())
                and last_inventory.get("terminal")
            )
        )
    )
    row["hybrid_observation_reason"] = hybrid_reason(row, selected)
    row["pqc_attempt_count"] = len(
        [item for item in rows if item["kind"] == "tls"]
    )
    return row


def hybrid_reason(
    row: Mapping[str, Any], selected: Mapping[str, Mapping[str, Any]]
) -> str:
    """Explain uncertainty without turning transport failures into negatives."""
    if row["hybrid_observation"] == "supported":
        return "verified_hybrid_handshake"
    if row["hybrid_observation"] == "not_observed":
        return "hybrid_alert_with_successful_classical_control"
    if row["dns_status"] != "ok":
        return "dns_" + row["dns_status"]
    statuses = {item.get("status") for item in selected.values()}
    if "certificate_error" in statuses:
        return "certificate_validation_failed"
    if "timeout" in statuses:
        return "probe_timeout"
    if "network_error" in statuses:
        return "network_failure"
    if any(
        item.get("status") == "no_handshake"
        or (
            item.get("status") == "tls_error"
            and item.get("returncode") == 0
            and not item.get("handshake_completed")
        )
        for item in selected.values()
    ):
        return "missing_handshake_evidence"
    if row.get("tls_1_3_observed") is False:
        return "tls13_not_observed_by_inventory"
    if any(not item for item in selected.values()):
        return "probes_pending"
    return "no_decisive_hybrid_evidence"


def export_results(
    out: Path,
    targets: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
) -> None:
    """Regenerate survey summaries and long-form tables from saved events.

    Export all TLS/DNS attempts, one summary per target, aggregate counts, and
    certificate/cipher/curve/status tables from each target's latest inventory.
    Include a worker-status row even when no native command results exist.

    Args:
        out (Path): Existing run directory receiving CSV and JSON exports.
        targets (Sequence[Mapping[str, Any]]): Nonempty sample in output order.
        events (Sequence[Mapping[str, Any]]): Saved attempts for that sample.

    Raises:
        OSError: If an export cannot be written or replaced.
        ValueError: If certificate timestamps in native results are invalid.
    """
    attempt_fields = [
        "sample_index",
        "hostname",
        "port",
        "category",
        "organisation",
        "ip_address",
        "profile",
        "attempt_number",
        "started_utc",
        "finished_utc",
        "status",
        "terminal",
        "tls_version",
        "cipher_suite",
        "negotiated_group",
        "group_raw",
        "certificate_verified",
        "verified_peername",
        "peer_certificate",
        "peer_signature_type",
        "handshake_completed",
        "tls_alert",
        "process_elapsed_ms",
        "returncode",
        "timed_out",
        "interrupted",
        "error",
        "raw_log",
    ]
    write_csv(
        out / "attempts.csv",
        [row for row in events if row["kind"] == "tls"],
        attempt_fields,
    )
    write_csv(
        out / "dns.csv",
        [row for row in events if row["kind"] == "dns"],
        [
            "sample_index",
            "hostname",
            "port",
            "attempt_number",
            "started_utc",
            "status",
            "ip_address",
            "resolved_ipv4",
            "dns_duration_ms",
            "error",
            "raw_log",
        ],
    )
    summaries = [summarize(target, events) for target in targets]
    write_csv(out / "summary.csv", summaries, list(summaries[0]))
    counts = {
        key: sum(row["hybrid_observation"] == key for row in summaries)
        for key in ("supported", "not_observed", "inconclusive")
    }
    write_json(
        out / "summary.json",
        {
            "updated_utc": utc_now(),
            "sample_size": len(targets),
            "completed_targets": sum(row["complete"] for row in summaries),
            "hybrid_observations": counts,
            "targets": summaries,
        },
    )
    write_json(
        out / "report_overview.json", sslyze_inventory.overview(summaries)
    )
    table_rows: dict[str, list[dict[str, Any]]] = {
        name: []
        for name in ("certificates", "cipher_suites", "curves", "scan_status")
    }
    for target in targets:
        scans = [
            row
            for row in events
            if row["sample_index"] == target["sample_index"]
            and row["kind"] == "sslyze"
        ]
        if not scans:
            continue
        latest = scans[-1]
        base = {
            key: latest.get(key)
            for key in (
                "sample_index",
                "hostname",
                "port",
                "category",
                "organisation",
                "ip_address",
                "started_utc",
                "sslyze_json",
            )
        }
        base["inventory_status"] = latest["status"]
        native = latest.get("sslyze_result") or {}
        for name, rows in sslyze_inventory.tables(
            native, latest["started_utc"]
        ).items():
            table_rows[name].extend({**base, **row} for row in rows)
        # Connectivity/worker failure also appears in the status table, even without plugin results.
        table_rows["scan_status"].append(
            {
                **base,
                "scan_command": "__inventory__",
                "status": latest["status"],
                "error_reason": latest.get("error"),
                "error_trace": native.get("connectivity_error_trace"),
            }
        )
    for name, rows in table_rows.items():
        columns = [
            "sample_index",
            "hostname",
            "port",
            "category",
            "organisation",
            "ip_address",
            "started_utc",
            "sslyze_json",
            "inventory_status",
        ] + sslyze_inventory.TABLE_COLUMNS[name]
        write_csv(out / (name + ".csv"), rows, columns)


def collect(
    args: argparse.Namespace,
    binary: str,
    openssl_info: pqc_probe.OpenSSLInfo,
    sslyze_info: Mapping[str, Mapping[str, str]],
) -> int:
    """Create or resume a fingerprinted survey and checkpoint each attempt.

    Process one endpoint at a time: bounded DNS, a deterministically rotating
    order of TLS 1.3 profiles, then SSLyze inventory. Reuse completed phases on
    resume and retry transient DNS/TLS failures within the configured budget.
    Refresh exports and manifest state on completion or interruption.

    Args:
        args (argparse.Namespace): Parsed, validated main() options for input,
            output, resume, pacing, deadlines, retries, and scanner settings.
        binary (str): Resolved OpenSSL executable path.
        openssl_info (pqc_probe.OpenSSLInfo): Recorded executable capabilities.
        sslyze_info (Mapping[str, Mapping[str, str]]): Recorded package versions
            and trust-store hashes from sslyze_inventory.environment().

    Raises:
        ValueError: If the sample is invalid, the output is locked, resume
            metadata is missing, or the run fingerprint has changed.
        RuntimeError: If a worker reports a tool or output-parsing problem.
        OSError: If input, checkpoint, or export files cannot be accessed.

    Returns:
        int: Zero on completion or 130 on interruption during collection.
            Other failures propagate after finalizing exports and manifest state
            when the attempt loop has started.
    """
    input_path: Path = Path(args.input).resolve()
    targets, duplicates = read_sample(input_path, args.port, args.limit)
    cafile: str | None = (
        str(Path(args.cafile).resolve()) if args.cafile else None
    )
    inventory_config: InventoryConfig = {
        "commands": sslyze_inventory.selected_commands(
            args.http_headers, args.obsolete_ssl
        ),
        "network_timeout": args.sslyze_network_timeout,
        "network_retries": args.sslyze_network_retries,
        "connections": args.connections,
        "deadline_s": args.inventory_timeout,
        "resumption_attempts": args.resumption_attempts,
        "cafile": cafile,
    }
    settings: dict[str, Any] = {
        "timeout_s": args.timeout,
        "dns_timeout_s": args.dns_timeout,
        "delay_s": args.delay,
        "retries": args.retries,
        "default_port": args.port,
        "location": args.location,
        "limit": args.limit,
        "cafile": cafile,
        "cafile_sha256": sha256(Path(cafile).read_bytes()) if cafile else None,
        "sslyze": inventory_config,
    }
    fingerprint_data: dict[str, Any] = {
        "source_sha256": {
            name: sha256(Path(__file__).with_name(name).read_bytes())
            for name in SOURCE_FILES
        },
        "input_sha256": sha256(input_path.read_bytes()),
        "targets": targets,
        "openssl": openssl_info,
        "sslyze": sslyze_info,
        "settings": settings,
        "profiles": {name: pqc_probe.PROFILES[name] for name in PQC_PROFILES},
        "tls13_ciphers": pqc_probe.TLS13_CIPHERS,
        "tls12_ciphers": pqc_probe.TLS12_CIPHERS,
        "python_version": sys.version,
        "platform": platform.platform(),
    }
    fingerprint: str = sha256(
        json.dumps(fingerprint_data, sort_keys=True).encode()
    )
    out: Path = Path(args.out).resolve()
    if args.resume:
        if not (out / "manifest.json").is_file():
            raise ValueError(
                "--resume requires an existing run folder containing manifest.json"
            )
    else:
        out.mkdir(parents=True, exist_ok=False)
    with output_lock(out):
        manifest: dict[str, Any]
        if args.resume:
            manifest = json.loads(
                (out / "manifest.json").read_text(encoding="utf-8")
            )
            if manifest["fingerprint"] != fingerprint:
                raise ValueError(
                    "Input, script, settings or software differ from the original run. Use the original values or a NEW output folder."
                )
        else:
            (out / "raw").mkdir()
            (out / "sslyze").mkdir()
            (out / "source").mkdir()
            (out / "input_original.txt").write_bytes(input_path.read_bytes())
            for name in SOURCE_FILES:
                shutil.copyfile(
                    Path(__file__).with_name(name), out / "source" / name
                )
            write_csv(out / "sample.csv", targets, list(targets[0]))
            manifest = {
                "schema_version": 2,
                "collector_version": VERSION,
                "run_id": uuid.uuid4().hex,
                "created_utc": utc_now(),
                "fingerprint": fingerprint,
                **fingerprint_data,
                "duplicates_removed": duplicates,
                "method": {
                    "address_selection": "numerically lowest returned IPv4; fixed across profiles and resume",
                    "profile_order": "DNS, rotating three TLS 1.3 PQC profiles, then SSLyze inventory",
                    "pqc_alpn_offer": "h2,http/1.1",
                    "pqc_certificate_verification": True,
                    "pqc_resumption": "fresh s_client process each attempt; no session/PSK input; received tickets never reused",
                    "sslyze_certificate_verification": "inventory probes can complete with untrusted certificates; CERTIFICATE_INFO evaluates trust separately",
                    "sslyze_resumption": "explicit session-ID and ticket tests at TLS 1.2 or below; TLS 1.3 early-data tested separately",
                    "sslyze_sni": "hostname sent, except the library's explicit no-SNI certificate comparison",
                    "http_headers_enabled": args.http_headers,
                    "http_redirects": "SSLyze HTTP_HEADERS may follow same-host/same-port redirects; PQC adapter sends no HTTP",
                    "timing": "process_elapsed_ms includes process startup, TCP, TLS and shutdown; NOT handshake-only",
                    "trust_store": "PQC: OpenSSL defaults plus --cafile; SSLyze: bundled stores plus --cafile as an additional store",
                },
                "invocations": [],
            }
        manifest["invocations"].append(
            {"utc": utc_now(), "argv": sys.argv, "resume": args.resume}
        )
        manifest["state"] = "running"
        write_json(out / "manifest.json", manifest)
        events = read_events(out / "attempts.jsonl")
        logger.info(
            "%d unique endpoints; %d duplicate lines removed. Output: %s",
            len(targets),
            len(duplicates),
            out,
        )
        interrupted = False
        fatal_error: str | None = None
        try:
            for target in targets:
                ip = None
                names = list(PQC_PROFILES)
                offset = (target["sample_index"] - 1) % len(names)
                for profile in (
                    ["dns"] + names[offset:] + names[:offset] + ["sslyze"]
                ):
                    previous = [
                        event
                        for event in events
                        if event["sample_index"] == target["sample_index"]
                        and event["profile"] == profile
                    ]
                    if previous and previous[-1]["terminal"]:
                        last = previous[-1]
                    else:
                        while True:
                            if events:
                                time.sleep(args.delay)
                            event: dict[str, Any] = {
                                **target,
                                "run_id": manifest["run_id"],
                                "attempt_id": uuid.uuid4().hex,
                                "kind": (
                                    profile
                                    if profile in {"dns", "sslyze"}
                                    else "tls"
                                ),
                                "profile": profile,
                                "attempt_number": len(previous) + 1,
                                "started_utc": utc_now(),
                            }
                            data: (
                                DNSResult
                                | InventoryResult
                                | pqc_probe.TLSResult
                            )
                            if profile == "dns":
                                data, result, command = resolve_target(
                                    target, args.dns_timeout
                                )
                            elif profile == "sslyze":
                                event["ip_address"] = ip
                                logger.info(
                                    "[%3d/%d] %s SSLyze inventory running...",
                                    target["sample_index"],
                                    len(targets),
                                    target["hostname"],
                                )
                                data, result, command = run_inventory(
                                    target, ip, inventory_config
                                )
                            else:
                                event["ip_address"] = ip
                                data, result, command = pqc_probe.probe(
                                    binary,
                                    target,
                                    ip,
                                    profile,
                                    args.timeout,
                                    cafile,
                                )
                            event.update(data)
                            failed_before = sum(
                                item["status"] in pqc_probe.RETRYABLE
                                for item in previous
                            )
                            event["terminal"] = data["status"] not in {
                                "interrupted",
                                "tool_error",
                                "parse_error",
                            } and (
                                data["status"] not in pqc_probe.RETRYABLE
                                or failed_before >= args.retries
                            )
                            save_event(out, events, event, result, command)
                            previous.append(event)
                            last = event
                            level = logging.INFO
                            if data["status"] in {"tool_error", "parse_error"}:
                                level = logging.ERROR
                            elif data["status"] not in {"ok", "tls_alert"}:
                                level = logging.WARNING
                            logger.log(
                                level,
                                "[%3d/%d] %s %s: %s %s",
                                target["sample_index"],
                                len(targets),
                                target["hostname"],
                                profile,
                                data["status"],
                                data.get("negotiated_group") or "",
                            )
                            if result["interrupted"]:
                                raise KeyboardInterrupt
                            if data["status"] in {"tool_error", "parse_error"}:
                                raise RuntimeError(
                                    f"Collector/tool problem; collection stopped. Inspect {event['raw_log']}: {data.get('error')}"
                                )
                            if event["terminal"]:
                                break
                    if profile == "dns":
                        if last["status"] != "ok":
                            break
                        ip = last["ip_address"]
                export_results(out, targets, events)
        except KeyboardInterrupt:
            interrupted = True
            logger.warning(
                "Interrupted. Saved attempts are safe; "
                "use the same command with --resume."
            )
        except Exception as error:
            fatal_error = str(error)
            raise
        finally:
            try:
                export_results(out, targets, events)
            except Exception as error:
                fatal_error = str(error)
                raise
            finally:
                manifest.update(
                    state=(
                        "error"
                        if fatal_error
                        else "interrupted" if interrupted else "complete"
                    ),
                    updated_utc=utc_now(),
                    last_error=fatal_error,
                )
                write_json(out / "manifest.json", manifest)
        logger.info(
            "Saved %s and raw evidence in %s", out / "summary.csv", out / "raw"
        )
    return 130 if interrupted else 0


def inventory_self_test(binary: str) -> int:
    """Validate SSLyze inventory against three temporary loopback scenarios.

    Check TLS 1.2 and TLS 1.3 protocol/certificate exports and confirm that a
    hybrid-only server can yield verified OpenSSL evidence even when SSLyze
    cannot connect. Temporary certificates and servers are cleaned up.

    Args:
        binary (str): OpenSSL 3.5+ executable with X25519MLKEM768 support.

    Raises:
        RuntimeError: If a fixture fails or an expected observation is missing.
        OSError: If a fixture process, socket, or file cannot be created.

    Returns:
        int: Zero after all three scenarios pass; failures raise an exception.
    """
    import tempfile
    from pqc_probe import make_test_certificates, local_server

    with tempfile.TemporaryDirectory(prefix="sslyze_selftest_") as tmp:
        folder = Path(tmp)
        make_test_certificates(binary, folder)
        config: InventoryConfig = {
            "commands": sslyze_inventory.selected_commands(True),
            "network_timeout": 2,
            "network_retries": 0,
            "connections": 2,
            "deadline_s": 60,
            "resumption_attempts": 2,
            "cafile": str(folder / "ca.pem"),
        }
        for protocol in (pqc_probe.TLS_V1_2, pqc_probe.TLS_V1_3):
            with local_server(
                binary, folder, pqc_probe.X25519, protocol
            ) as port:
                data, result, _ = run_inventory(
                    {"hostname": pqc_probe.LOCALHOST, "port": port},
                    "127.0.0.1",
                    config,
                )
            native = data.get("sslyze_result") or {}
            summary = sslyze_inventory.summarize(native, utc_now())
            protocol_field = (
                "tls_1_2_observed"
                if protocol == pqc_probe.TLS_V1_2
                else "tls_1_3_observed"
            )
            certificates = sslyze_inventory.certificate_rows(native, utc_now())
            if not (
                summary.get(protocol_field) is True
                and certificates
                and summary["any_sni_certificate_trusted"] is True
            ):
                raise RuntimeError(
                    f"SSLyze self-test failed for {protocol}: {summary}\n{result['stderr']}"
                )
            if not (
                certificates[0]["public_key_bits"] == 256
                and certificates[0]["leaf_der_bytes"] > 0
            ):
                raise RuntimeError(
                    "SSLyze certificate export self-test failed"
                )
            logger.info(
                "PASS SSLyze %s: protocol, cipher, certificate "
                "trust/key/DER-size and feature inventory",
                protocol,
            )
        with local_server(
            binary, folder, pqc_probe.HYBRID, pqc_probe.TLS_V1_3
        ) as port:
            data, _, _ = run_inventory(
                {"hostname": pqc_probe.LOCALHOST, "port": port},
                "127.0.0.1",
                config,
            )
            pqc, _, _ = pqc_probe.probe(
                binary,
                {"hostname": pqc_probe.LOCALHOST, "port": port},
                "127.0.0.1",
                pqc_probe.TLS13_HYBRID_ONLY,
                5,
                config["cafile"],
            )
        if (
            data["status"] != "inventory_connectivity_error"
            or pqc["status"] != "ok"
        ):
            raise RuntimeError(
                "Hybrid-only endpoint self-test failed: SSLyze failure must not erase PQC evidence"
            )
        logger.info(
            "PASS hybrid-only endpoint: SSLyze connectivity limitation is separate from verified PQC success"
        )
    logger.info("All 3 SSLyze integration scenarios passed.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Validate CLI options and run environment checks, self-tests, or a survey.

    Inspect SSLyze dependencies and OpenSSL capabilities before dispatching the
    requested operation. Collection options are validated before any run starts.
    Configure Rich logging at the requested level for console messages on stderr.

    Args:
        argv (Sequence[str] | None): Arguments excluding the executable name,
            or None to read sys.argv[1:].

    Raises:
        SystemExit: For help or invalid command-line usage, via argparse.

    Returns:
        int: Zero on success, one for handled setup/collection errors, or 130
            on interruption. Handled errors are also written to stderr.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="UTF-8 .txt sample file with one hostname per line",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="New output folder; reuse only with --resume",
    )
    parser.add_argument(
        "--openssl",
        default="openssl",
        help="OpenSSL 3.5+ executable/path (default: openssl)",
    )
    parser.add_argument(
        "--log-level",
        type=str.upper,
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
        help="Console logging threshold (default: INFO); logs go to stderr",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Default TCP port for endpoints (default: 443)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=12,
        help="Whole TLS subprocess deadline, seconds (default: 12)",
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=10,
        help="DNS resolution timeout, seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1,
        help="Pause between collection phases/PQC attempts; not between internal SSLyze handshakes (default: 1)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Extra attempts for transient network/DNS errors only (default: 1)",
    )
    parser.add_argument(
        "--inventory-timeout",
        type=float,
        default=300,
        help="Whole SSLyze inventory deadline per endpoint, seconds (default: 300)",
    )
    parser.add_argument(
        "--sslyze-network-timeout",
        type=int,
        default=5,
        help="SSLyze per-connection timeout, seconds (default: 5)",
    )
    parser.add_argument(
        "--sslyze-network-retries",
        type=int,
        default=1,
        help="Internal SSLyze connection retries (default: 1)",
    )
    parser.add_argument(
        "--connections",
        type=int,
        default=2,
        help="Maximum concurrent SSLyze connections per endpoint (default: 2)",
    )
    parser.add_argument(
        "--resumption-attempts",
        type=int,
        default=3,
        help="SSLyze attempts per pre-TLS-1.3 resumption mechanism (default: 3)",
    )
    parser.add_argument(
        "--http-headers",
        action="store_true",
        help="Also collect HSTS using SSLyze HTTP requests",
    )
    parser.add_argument(
        "--obsolete-ssl",
        action="store_true",
        help="Also inventory SSL 2.0 and SSL 3.0",
    )
    parser.add_argument(
        "--cafile", help="Additional trusted CA certificates in PEM format"
    )
    parser.add_argument(
        "--location",
        default="not_recorded",
        type=str,
        help="Measurement location, e.g. 'Reykjavik, Iceland'",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="First N unique endpoints, for a separate pilot run",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Continue an interrupted run with identical inputs/settings",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check SSLyze dependencies and local OpenSSL capabilities, then exit",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate with real local positive/negative TLS fixtures, then exit",
    )
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    if (
        not 1 <= args.port <= 65535
        or args.retries < 0
        or (args.limit is not None and args.limit < 1)
    ):
        parser.error("invalid port, retries or limit")
    if (
        min(
            args.sslyze_network_timeout,
            args.connections,
            args.resumption_attempts,
        )
        < 1
        or args.sslyze_network_retries < 0
    ):
        parser.error(
            "SSLyze timeout/connections/resumption-attempts must be positive; network-retries must be nonnegative"
        )
    for name in ("timeout", "dns_timeout", "delay", "inventory_timeout"):
        value = getattr(args, name)
        if (
            not math.isfinite(value)
            or value < 0
            or (name != "delay" and value == 0)
        ):
            parser.error(
                f"--{name.replace('_', '-')} must be finite and {'nonnegative' if name == 'delay' else 'positive'}"
            )
    if not (args.check or args.self_test) and not args.input:
        parser.error("provide websites.txt, or use --check / --self-test")
    if args.resume and not args.out:
        parser.error("--resume requires --out pointing to the original run")
    args.out = args.out or datetime.now(timezone.utc).strftime(
        "survey_%Y%m%dT%H%M%SZ"
    )
    try:
        sslyze_info = sslyze_inventory.environment()
        logger.info(
            "SSLyze %s / nassl %s",
            sslyze_info["packages"]["sslyze"],
            sslyze_info["packages"]["nassl"],
        )
        binary, info = pqc_probe.inspect_openssl(args.openssl)
        logger.info("%s", info["version"].splitlines()[0])
        if args.self_test:
            pqc_probe.self_test(binary)
            return inventory_self_test(binary)
        if args.check:
            logger.info(
                "Ready: %s is available. Next run --self-test.",
                pqc_probe.HYBRID,
            )
            return 0
        return collect(args, binary, info, sslyze_info)
    except KeyboardInterrupt:
        logger.warning("Interrupted.")
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        logger.error("%s", error)
        return 1


if __name__ == "__main__":
    if hasattr(signal, "SIGTERM"):

        def stop(signum: int, frame: FrameType | None) -> NoReturn:
            """Translate SIGTERM to KeyboardInterrupt for collection cleanup."""
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop)
    sys.exit(main())

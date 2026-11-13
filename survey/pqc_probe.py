"""Small, explicit OpenSSL adapter for the PQC comparisons SSLyze 6 cannot perform.

The survey invokes only the three TLS 1.3 profiles. The TLS 1.2 profile is
retained solely for local regression checks. Total process time is diagnostic.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Final, Literal, TypeAlias, TypedDict


class Endpoint(TypedDict):
    """Hostname used for SNI/verification and port used for the connection."""

    hostname: str
    port: int


class TLSProfile(TypedDict):
    """TLS version and colon-separated key-exchange groups offered by a probe."""

    tls: Literal["TLSv1.2", "TLSv1.3"]
    groups: str


class ProcessResult(TypedDict):
    """Captured subprocess output, exit state, and total elapsed time.

    Output is decoded as UTF-8 with replacement for invalid bytes. The return
    code retains Popen's nullable type; elapsed time includes process startup
    and cleanup, rather than measuring only the TLS handshake.
    """

    stdout: str
    stderr: str
    returncode: int | None
    timed_out: bool
    interrupted: bool
    process_elapsed_ms: float


class OpenSSLInfo(TypedDict):
    """Executable identity, capabilities, and relevant environment variables."""

    binary: str
    binary_sha256: str
    version: str
    tls13_groups: str
    providers: str
    environment: dict[str, str | None]


ProbeStatus: TypeAlias = Literal[
    "ok",
    "tls_error",
    "certificate_error",
    "tool_error",
    "parse_error",
    "interrupted",
    "timeout",
    "tls_alert",
    "network_error",
    "no_handshake",
]


class TLSResult(TypedDict):
    """Parsed connection evidence and its classification.

    Missing text fields remain None. Handshake completion and certificate
    verification are recorded separately from the final status.
    """

    tls_version: str | None
    cipher_suite: str | None
    negotiated_group: str | None
    group_raw: str | None
    certificate_verified: bool
    verified_peername: str | None
    peer_certificate: str | None
    peer_signature_type: str | None
    tls_alert: str | None
    handshake_completed: bool
    status: ProbeStatus
    error: str | None


def sha256(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of the supplied bytes."""
    return hashlib.sha256(data).hexdigest()


TLS_V1_2: Final = "TLSv1.2"
TLS_V1_3: Final = "TLSv1.3"
TLS12_CLASSICAL: Final = "tls12_classical"
TLS13_HYBRID_ONLY: Final = "tls13_hybrid_only"
TLS13_CLASSICAL: Final = "tls13_classical"
TLS13_MIXED: Final = "tls13_mixed"
HYBRID: Final = "X25519MLKEM768"
LOCALHOST: Final = "localhost"
X25519: Final = "X25519"
PROFILES: dict[str, TLSProfile] = {
    TLS12_CLASSICAL: {"tls": TLS_V1_2, "groups": "X25519:P-256:P-384"},
    TLS13_CLASSICAL: {"tls": TLS_V1_3, "groups": "X25519:P-256:P-384"},
    TLS13_HYBRID_ONLY: {"tls": TLS_V1_3, "groups": HYBRID},
    TLS13_MIXED: {
        "tls": TLS_V1_3,
        "groups": f"{HYBRID}:X25519:P-256:P-384",
    },
}
TLS13_CIPHERS: Final = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
)
TLS12_CIPHERS: Final = "ECDHE+AESGCM:ECDHE+CHACHA20"
RETRYABLE: set[str] = {"timeout", "network_error", "dns_error", "no_handshake"}
CONFIG_ERRORS: tuple[str, ...] = (
    "unknown option",
    "unknown group",
    "error setting",
    "call to ssl_conf_cmd",
    "no protocols available",
    "no ciphers available",
    "no cipher match",
    "unable to load",
    "error loading",
    "invalid command",
    "library has no ciphers",
)


def run_process(command: Sequence[str], timeout: float) -> ProcessResult:
    """Run a command with a deadline and preserve output on timeout or Ctrl+C.

    Use the C locale and close stdin. On timeout or interruption, kill and reap
    the child, then return its captured output and flags without re-raising
    that timeout or interruption.

    Args:
        command (Sequence[str]): Executable and arguments, without a shell.
        timeout (float): Seconds allowed by communicate() after the child starts.

    Raises:
        OSError: If the child process cannot be started.

    Returns:
        ProcessResult: Decoded output, return code, timeout/interruption flags,
            and elapsed milliseconds including startup and cleanup.
    """
    start = time.perf_counter()
    timed_out = interrupted = False
    with subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            timed_out = isinstance(error, subprocess.TimeoutExpired)
            interrupted = isinstance(error, KeyboardInterrupt)
            process.kill()
            stdout, stderr = process.communicate()
    return {
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "returncode": process.returncode,
        "timed_out": timed_out,
        "interrupted": interrupted,
        "process_elapsed_ms": round((time.perf_counter() - start) * 1000, 3),
    }


def checked_command(command: Sequence[str]) -> str:
    """Run a setup command with a 20-second deadline and require success.

    Args:
        command (Sequence[str]): Executable and arguments, without a shell.

    Raises:
        KeyboardInterrupt: If the command was interrupted.
        RuntimeError: If the command times out or exits with a nonzero code.
        OSError: If the child process cannot be started.

    Returns:
        str: The command's decoded standard output.
    """
    result = run_process(command, 20)
    if result["interrupted"]:
        raise KeyboardInterrupt
    if result["returncode"] != 0 or result["timed_out"]:
        raise RuntimeError(f"Command failed: {command!r}\n{result['stderr']}")
    return result["stdout"]


def inspect_openssl(executable: str) -> tuple[str, OpenSSLInfo]:
    """Find OpenSSL 3.5+ and verify that X25519MLKEM768 is advertised.

    Record the executable hash, version, TLS 1.3 groups, providers, and relevant
    environment variables for reproducibility. This checks local capabilities;
    it does not perform a TLS handshake.

    Args:
        executable (str): Executable name on PATH or path to an OpenSSL binary.

    Raises:
        ValueError: If the executable is missing, its version is unsupported,
            or its advertised groups do not include X25519MLKEM768.
        RuntimeError: If an inspection command fails or times out.
        OSError: If the executable cannot be read or started.

    Returns:
        tuple[str, OpenSSLInfo]: Resolved binary path and environment details.
    """
    found = shutil.which(executable)
    if not found:
        raise ValueError(
            "OpenSSL was not found. Install OpenSSL 3.5+ or pass --openssl /path/to/openssl."
        )
    binary = str(Path(found).resolve())
    version: str = checked_command([binary, "version", "-a"])
    match: re.Match[str] | None = re.match(
        r"OpenSSL (\d+)\.(\d+)\.(\d+)", version
    )
    if not match or tuple(map(int, match.groups())) < (3, 5, 0):
        raise ValueError(
            f"This survey requires OpenSSL 3.5+ with {HYBRID}. Found:\n{version.splitlines()[0]}\n"
            "Installing a Python package will not upgrade the openssl command. "
            "Select a newer binary with --openssl /path/to/openssl."
        )
    groups: str = checked_command([binary, "list", "-tls-groups", "-tls1_3"])
    if not re.search(r"\bX25519MLKEM768\b", groups, re.IGNORECASE):
        raise ValueError(
            f"This OpenSSL configuration does not provide {HYBRID}.\n{groups}"
        )
    return binary, {
        "binary": binary,
        "binary_sha256": sha256(Path(binary).read_bytes()),
        "version": version,
        "tls13_groups": groups,
        "providers": checked_command([binary, "list", "-providers"]),
        "environment": {
            name: os.environ.get(name)
            for name in (
                "OPENSSL_CONF",
                "OPENSSL_CONF_INCLUDE",
                "OPENSSL_MODULES",
                "OPENSSL_ENGINES",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
            )
        },
    }


def client_command(
    binary: str, target: Endpoint, ip: str, profile: str, cafile: str | None
) -> list[str]:
    """Build a fresh, certificate-verifying IPv4 s_client invocation.

    Connect to the supplied address while using the target hostname for SNI
    and certificate verification. The profile fixes the TLS version and group
    offer; no saved session is supplied and no application request is sent.

    Args:
        binary (str): OpenSSL executable path.
        target (Endpoint): Hostname and port of the endpoint.
        ip (str): IPv4 address selected for the connection.
        profile (str): Name of the offer in PROFILES.
        cafile (str | None): Optional PEM CA file passed with -CAfile.

    Raises:
        KeyError: If the profile is unknown or a required target key is missing.

    Returns:
        list[str]: Executable and arguments ready for run_process().
    """
    config: TLSProfile = PROFILES[profile]
    command = [
        binary,
        "s_client",
        "-4",
        "-connect",
        f"{ip}:{target['port']}",
        "-servername",
        target["hostname"],
        "-verify_hostname",
        target["hostname"],
        "-verify_return_error",
        "-brief",
        "-no_ign_eof",
        "-no_ticket",
        "-alpn",
        "h2,http/1.1",
        "-groups",
        config["groups"],
        "-tls1_3" if config["tls"] == TLS_V1_3 else "-tls1_2",
        "-ciphersuites",
        TLS13_CIPHERS,
        "-cipher",
        TLS12_CIPHERS,
    ]
    if cafile:
        command.extend(["-CAfile", cafile])
    return command


def canonical_group(value: str | None) -> str | None:
    """Normalize an OpenSSL group name or temporary-key description.

    Strip ECDH/bit-count decorations and map known aliases to the names used
    by the collector, including P-256 and P-384. Unknown names retain their
    spelling after decorations are removed; None remains None.

    Args:
        value (str | None): Group text extracted from an OpenSSL summary.

    Returns:
        str | None: The normalized group name, or None when value is None.
    """
    if value is None:
        return None
    value = value.strip()
    if value.upper().startswith("ECDH, "):
        value = value.split(",", 2)[1].strip()
    else:
        value = value.split(",", 1)[0].strip()

    aliases: dict[str, str] = {
        "x25519": X25519,
        "x25519mlkem768": HYBRID,
        "prime256v1": "P-256",
        "secp256r1": "P-256",
        "p-256": "P-256",
        "secp384r1": "P-384",
        "p-384": "P-384",
    }
    return aliases.get(value.lower(), value)


def parse_tls(result: ProcessResult, profile: str) -> TLSResult:
    """Classify an s_client result from explicit handshake evidence.

    Success requires a completed, verified handshake with a reported protocol,
    cipher, and group consistent with the configured offer. Certificate and
    local configuration errors take precedence. Otherwise, verified handshake
    evidence survives later shutdown errors, timeouts, or interruption.
    Never infer the group from the cipher suite or process exit status.

    Args:
        result (ProcessResult): Captured process output and outcome flags.
        profile (str): Name of the configured offer in PROFILES.

    Returns:
        TLSResult: Parsed fields, status, and an error excerpt for failures.
            Missing text fields remain None; raw output stays in result.
    """
    text = result["stdout"] + "\n" + result["stderr"]
    lower = text.lower()

    def field(pattern: str) -> str | None:
        """Return the first capture of a matching output field, stripped."""
        found = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        return found.group(1).strip() if found else None

    group_raw = field(
        r"^(?:Negotiated TLS1\.3 group|(?:Server|Peer) Temp Key):\s*(.+)$"
    )
    group = canonical_group(group_raw)
    data: TLSResult = {
        "tls_version": field(r"^Protocol version:\s*(\S+)"),
        "cipher_suite": field(r"^Ciphersuite:\s*(\S+)"),
        "negotiated_group": group,
        "group_raw": group_raw,
        "certificate_verified": bool(
            re.search(r"^Verification: OK\s*$", text, re.MULTILINE)
        ),
        "verified_peername": field(r"^Verified peername:\s*(.+)$"),
        "peer_certificate": field(r"^Peer certificate:\s*(.+)$"),
        "peer_signature_type": field(r"^Signature type:\s*(.+)$"),
        "tls_alert": field(
            r"(\b(?:tlsv\d+(?:\.\d+)?|sslv\d+|ssl/tls|tls) alert [^:\n]+)"
        ),
        "handshake_completed": bool(
            re.search(r"^CONNECTION ESTABLISHED\s*$", text, re.MULTILINE)
        ),
        "status": "tls_error",
        "error": None,
    }
    cert_error = (
        "certificate verify failed" in lower
        or "verification error:" in lower
        or "verify error:" in lower
    )
    if cert_error:
        data.update(status="certificate_error", certificate_verified=False)
    elif any(token in lower for token in CONFIG_ERRORS):
        data["status"] = "tool_error"
    elif data["handshake_completed"]:
        # s_client can fail during shutdown AFTER a successful handshake.
        # Retain returncode/timeouts separately; require full verified evidence.
        offered = {
            canonical_group(g) for g in PROFILES[profile]["groups"].split(":")
        }
        if not (
            data["certificate_verified"]
            and data["tls_version"]
            and data["cipher_suite"]
            and group
        ):
            data.update(
                status="parse_error",
                error="Incomplete connection summary; inspect raw output",
            )
        elif (
            data["tls_version"] != PROFILES[profile]["tls"]
            or group not in offered
        ):
            data.update(
                status="parse_error",
                error="Negotiated protocol/group contradicts the configured offer",
            )
        else:
            data["status"] = "ok"
    elif result["interrupted"]:
        data["status"] = "interrupted"
    elif result["timed_out"]:
        data["status"] = "timeout"
    elif data["tls_alert"]:
        data["status"] = "tls_alert"
    elif any(
        token in lower
        for token in (
            "connection refused",
            "connection reset",
            "network is unreachable",
            "no route to host",
            "connect:errno",
            "bio_connect",
            "unexpected eof",
            "errno=",
        )
    ):
        data["status"] = "network_error"
    # Exit code zero is not evidence of a negotiated TLS session. Some peers
    # close without an alert; preserve the uncertainty and allow a bounded retry.
    elif result["returncode"] == 0:
        data["status"] = "no_handshake"
    if data["status"] != "ok" and data["error"] is None:
        lines = [line for line in text.splitlines() if line.strip()]
        data["error"] = "\n".join(lines[-6:])[-2500:] or data["status"]
    return data


def probe(
    binary: str,
    target: Endpoint,
    ip: str,
    profile: str,
    timeout: float,
    cafile: str | None,
) -> tuple[TLSResult, ProcessResult, list[str]]:
    """Execute and classify one fresh TLS connection using the selected profile.

    Args:
        binary (str): OpenSSL executable path.
        target (Endpoint): Hostname for SNI/verification and connection port.
        ip (str): IPv4 address selected for the connection.
        profile (str): Name of the offer in PROFILES.
        timeout (float): Process communication deadline in seconds.
        cafile (str | None): Optional PEM CA file passed with -CAfile.

    Returns:
        tuple[TLSResult, ProcessResult, list[str]]: Parsed observations, captured
            process evidence, and the exact command arguments. TLS failures,
            timeouts, and interruptions are represented in these results.
    """
    command = client_command(binary, target, ip, profile, cafile)
    result = run_process(command, timeout)
    return parse_tls(result, profile), result, command


@contextmanager
def local_server(
    binary: str, folder: Path, group: str, protocol: str
) -> Iterator[int]:
    """Run an OpenSSL fixture on an ephemeral IPv4 loopback port.

    Wait up to five seconds for the listener, then yield its port. On leaving
    the context, terminate and reap the server, killing it if termination takes
    longer than three seconds.

    Args:
        binary (str): OpenSSL executable path.
        folder (Path): Existing directory containing cert.pem and key.pem.
        group (str): Group or colon-separated groups offered by the server.
        protocol (str): TLS_V1_3 selects TLS 1.3; other values select TLS 1.2.

    Raises:
        RuntimeError: If the server exits early or does not become reachable.
        OSError: If process creation or socket setup fails.

    Yields:
        int: Port number of the running local server.
    """
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    command = [
        binary,
        "s_server",
        "-accept",
        f"127.0.0.1:{port}",
        "-cert",
        str(folder / "cert.pem"),
        "-key",
        str(folder / "key.pem"),
        "-groups",
        group,
        "-tls1_3" if protocol == TLS_V1_3 else "-tls1_2",
        "-www",
        "-quiet",
    ]
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=log
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None or time.monotonic() > deadline:
                    log.seek(0)
                    raise RuntimeError(
                        "Local server failed to start: "
                        + log.read().decode(errors="replace")
                    )
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=0.1
                    ):
                        break
                except OSError:
                    time.sleep(0.05)
            yield port
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def make_test_certificates(binary: str, folder: Path) -> None:
    """Write a test CA and signed localhost certificate into an existing folder.

    Create P-256 private keys, ca.pem, cert.pem, a signing request, extensions,
    and a CA serial file. The CA is valid for two days and the server
    certificate for one day. No certificate is installed in the system trust
    store.

    Args:
        binary (str): OpenSSL executable path.
        folder (Path): Existing directory in which to write the test fixtures.

    Raises:
        RuntimeError: If a certificate-generation command fails or times out.
        OSError: If a command cannot start or a fixture cannot be written.
    """
    checked_command(
        [
            binary,
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-days",
            "2",
            "-subj",
            "/CN=Collector Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(folder / "ca.key"),
            "-out",
            str(folder / "ca.pem"),
        ]
    )
    checked_command(
        [
            binary,
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(folder / "key.pem"),
            "-out",
            str(folder / "request.csr"),
        ]
    )
    (folder / "extensions.cnf").write_text(
        "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
        encoding="ascii",
    )
    checked_command(
        [
            binary,
            "x509",
            "-req",
            "-in",
            str(folder / "request.csr"),
            "-CA",
            str(folder / "ca.pem"),
            "-CAkey",
            str(folder / "ca.key"),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            str(folder / "extensions.cnf"),
            "-out",
            str(folder / "cert.pem"),
        ]
    )


def self_test(binary: str) -> int:
    """Check twelve local TLS scenarios using temporary fixtures.

    Cover hybrid/classical success and rejection, protocol mismatch, P-256
    fallback, hostname mismatch, untrusted certificates, and a silent listener.
    Fixture files and servers are cleaned up without changing system trust or
    connecting to public endpoints.

    Args:
        binary (str): OpenSSL 3.5+ executable with X25519MLKEM768 support.

    Raises:
        RuntimeError: If an observed result differs from the expected result,
            or a fixture command or server fails.
        OSError: If local fixture files, processes, or sockets cannot be created.

    Returns:
        int: Zero after all twelve scenarios pass; failures raise an exception.
    """

    with tempfile.TemporaryDirectory(prefix="pqc_tls_selftest_") as temporary:
        folder = Path(temporary)
        make_test_certificates(binary, folder)
        cafile = str(folder / "ca.pem")

        TLS_ALERT: Final = "tls_alert"
        cases: list[tuple[str, str, str, str, str, str | None]] = [
            (
                HYBRID,
                TLS_V1_3,
                TLS13_HYBRID_ONLY,
                LOCALHOST,
                "ok",
                HYBRID,
            ),
            (HYBRID, TLS_V1_3, TLS13_MIXED, LOCALHOST, "ok", HYBRID),
            (
                HYBRID,
                TLS_V1_3,
                TLS13_CLASSICAL,
                LOCALHOST,
                TLS_ALERT,
                None,
            ),
            (
                X25519,
                TLS_V1_3,
                TLS13_HYBRID_ONLY,
                LOCALHOST,
                TLS_ALERT,
                None,
            ),
            (
                X25519,
                TLS_V1_3,
                TLS13_CLASSICAL,
                LOCALHOST,
                "ok",
                X25519,
            ),
            (X25519, TLS_V1_3, TLS13_MIXED, LOCALHOST, "ok", X25519),
            (
                "P-256",
                TLS_V1_3,
                TLS13_CLASSICAL,
                LOCALHOST,
                "ok",
                "P-256",
            ),
            (
                X25519,
                TLS_V1_2,
                TLS12_CLASSICAL,
                LOCALHOST,
                "ok",
                X25519,
            ),
            (
                X25519,
                TLS_V1_2,
                TLS13_HYBRID_ONLY,
                LOCALHOST,
                TLS_ALERT,
                None,
            ),
            (
                HYBRID,
                TLS_V1_3,
                TLS13_HYBRID_ONLY,
                "wrong.example",
                "certificate_error",
                None,
            ),
        ]
        for (
            group,
            protocol,
            profile,
            hostname,
            expected,
            expected_group,
        ) in cases:
            with local_server(binary, folder, group, protocol) as port:
                data, result, _ = probe(
                    binary,
                    {"hostname": hostname, "port": port},
                    "127.0.0.1",
                    profile,
                    5,
                    cafile,
                )
            if data["status"] != expected or (
                expected_group and data["negotiated_group"] != expected_group
            ):
                raise RuntimeError(
                    f"Self-test failed: {group}/{profile}: expected {expected}/{expected_group}\n{data}\n{result['stderr']}"
                )
            print(
                f"PASS server={group}/{protocol} client={profile} => {expected} {expected_group or ''}"
            )
        with local_server(binary, folder, HYBRID, TLS_V1_3) as port:
            data, _, _ = probe(
                binary,
                {"hostname": LOCALHOST, "port": port},
                "127.0.0.1",
                TLS13_HYBRID_ONLY,
                5,
                None,
            )
            if data["status"] != "certificate_error":
                raise RuntimeError(
                    f"Untrusted-certificate self-test failed: {data}"
                )
        print("PASS untrusted certificate => certificate_error")
        # A listening socket that never speaks TLS must be a timeout, not a negative result.
        with socket.socket() as silent:
            silent.bind(("127.0.0.1", 0))
            silent.listen()
            data, _, _ = probe(
                binary,
                {"hostname": LOCALHOST, "port": silent.getsockname()[1]},
                "127.0.0.1",
                TLS13_HYBRID_ONLY,
                0.4,
                cafile,
            )
            if data["status"] != "timeout":
                raise RuntimeError(f"Timeout self-test failed: {data}")
        print("PASS silent server => timeout")
    print("All 12 local integration checks passed.")
    return 0

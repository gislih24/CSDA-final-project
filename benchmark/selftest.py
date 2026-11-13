#!/usr/bin/env python3
"""Local correctness checks; these are NOT benchmark results. No root needed."""

import json
from pathlib import Path
import socket
import subprocess as sp
import threading
import time
from run import readline, stop
from analyze import TLS_DEF_SENT_SIZE, TLS_EXTRA_RCVD_BYTES

ROOT = Path(__file__).resolve().parent


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def server(groups):
    p = port()
    proc = sp.Popen(
        [
            str(ROOT / "tlsbench"),
            "server",
            "127.0.0.1",
            str(p),
            str(ROOT / "certs/server.pem"),
            str(ROOT / "certs/server.key"),
            groups,
        ],
        text=True,
        stdout=sp.PIPE,
        stderr=sp.DEVNULL,
    )
    assert readline(proc).startswith("READY ")
    return p, proc


def client(p, ca="ca.pem", timeout=1000):
    proc = sp.Popen(
        [
            str(ROOT / "tlsbench"),
            "client",
            "127.0.0.1",
            str(p),
            str(ROOT / "certs" / ca),
            str(timeout),
        ],
        text=True,
        stdin=sp.PIPE,
        stdout=sp.PIPE,
        stderr=sp.PIPE,
        bufsize=1,
    )
    assert readline(proc).startswith("READY ")
    return proc


def trial(proc, group):
    proc.stdin.write(group + "\n")
    proc.stdin.flush()
    return json.loads(readline(proc))


def main():
    p, s = server("X25519")
    c = None
    try:
        c = client(p)
        results = [trial(c, "X25519") for _ in range(100)]
        assert all(
            r["status"] == "ok"
            and r["hrr"] == 0
            and r["reused"] == 0
            and r["verify_result"] == 0
            for r in results
        )
        assert all(
            r["response_ns"] >= r["tls_ns"] > 0 and r["client_cpu_ns"] > 0
            for r in results
        )
        assert (
            len(
                {
                    (r["tls_sent_bytes"], r["tls_received_bytes"])
                    for r in results
                }
            )
            == 1
        )
        r = trial(c, "NotARealGroup")
        assert r["status"] == "error" and r["phase"] == "setup"
        assert (
            trial(c, "X25519")["status"] == "ok"
        )  # errors do not poison subsequent trials
        stop(c)
        c = client(p, ca="server.pem")
        r = trial(c, "X25519")
        assert r["status"] == "error" and r["phase"] == "tls", r
        print(
            "PASS: 100 fresh verified TLS 1.3 handshakes; stable bytes; unsupported-group and trust failures"
        )
    finally:
        stop(c)
        stop(s)
    p, s = server("P-256")
    c = None
    try:
        c = client(p)
        r = trial(c, "X25519:P-256")
        assert (
            r["status"] == "error"
            and r["phase"] == "validation"
            and r["hrr"] == 1
        ), r
        print("PASS: deliberately triggered HelloRetryRequest detected")
    finally:
        stop(c)
        stop(s)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def stall():
        sock, _ = listener.accept()
        with sock:
            time.sleep(0.3)

    t = threading.Thread(target=stall)
    t.start()
    c = client(listener.getsockname()[1], timeout=100)
    try:
        r = trial(c, "X25519")
        assert r["status"] == "timeout" and r["phase"] == "tls", r
        print("PASS: stalled TLS handshake reaches absolute deadline")
    finally:
        stop(c)
        t.join()
        listener.close()
    # When installed OpenSSL supports hybrid, test the actual comparison as well.
    probe = sp.run(
        ["openssl", "list", "-tls1_3", "-tls-groups"],
        capture_output=True,
        text=True,
    )
    if "X25519MLKEM768" not in probe.stdout:
        print(
            "SKIP: hybrid path unavailable in this OpenSSL; must test on target machine"
        )
        return
    p, s = server("X25519:X25519MLKEM768")
    c = None
    try:
        c = client(p)
        pairs = []
        for _ in range(10):
            a = trial(c, "X25519")
            b = trial(c, "X25519MLKEM768")
            assert a["status"] == b["status"] == "ok", (a, b)
            pairs.append(
                (
                    b["tls_sent_bytes"] - a["tls_sent_bytes"],
                    b["tls_received_bytes"] - a["tls_received_bytes"],
                )
            )
        # OpenSSL 3.5 omits the 8-byte ec_point_formats ClientHello extension
        # for the hybrid group. Since it is second in the server's group list,
        # its EncryptedExtensions also adds 10 bytes of supported_groups.
        # The key-share increases alone are 1184/1088 bytes.
        assert set(pairs) == {(TLS_DEF_SENT_SIZE, TLS_EXTRA_RCVD_BYTES)}, pairs
        print(
            f"PASS: hybrid negotiation, full handshakes, +{TLS_DEF_SENT_SIZE}/+{TLS_EXTRA_RCVD_BYTES} TLS bytes"
        )
    finally:
        stop(c)
        stop(s)


if __name__ == "__main__":
    main()

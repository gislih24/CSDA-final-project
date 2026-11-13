"""Supplement a baseline survey with repeated, address-specific TLS experiments.
Only Python stdlib and the supplied pqc_probe module are needed for this stage.
"""

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urljoin, urlsplit, urlunsplit
import pqc_probe as p

PROFILES = {
    "classical": "X25519:P-256:P-384",
    "hybrid_only": "X25519MLKEM768",
    "mixed_original": "X25519MLKEM768:X25519:P-256:P-384",
    "dual_hybrid_first": "*X25519MLKEM768:*X25519",
    "dual_classical_first": "*X25519:*X25519MLKEM768",
}
HRR = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, obj):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    temp.replace(path)


def append(path, obj):
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_events(path):
    if not path.exists():
        return []
    # A crash can leave only the final record truncated. Preserve its bytes.
    data = path.read_bytes()
    lines = data.splitlines(keepends=True)
    rows = []
    valid = 0
    for index, line in enumerate(lines):
        try:
            rows.append(json.loads(line))
        except (ValueError, UnicodeDecodeError):
            if index != len(lines) - 1:
                raise ValueError("Corrupt journal before final record")
            path.with_name(
                path.name + ".truncated-" + str(time.time_ns())
            ).write_bytes(line)
            with path.open("r+b") as f:
                f.truncate(valid)
            break
        valid += len(line)
    if rows and path.read_bytes() and not path.read_bytes().endswith(b"\n"):
        with path.open("ab") as f:
            f.write(b"\n")
    return rows


def normalize_url(url):
    u = urlsplit(url)
    if (
        u.scheme not in ("https", "http")
        or not u.hostname
        or u.username
        or u.password
    ):
        raise ValueError("Only HTTP(S) URLs without credentials are accepted")
    host = u.hostname.encode("idna").decode("ascii").lower()
    port = u.port or (443 if u.scheme == "https" else 80)
    if port not in (80, 443):
        raise ValueError("Redirect ports restricted to 80/443")
    # Numeric URLs are recorded as stopped redirects, never treated as DNS names.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Numeric URL hostname excluded")
    authority = host + (
        f":{port}" if port != (443 if u.scheme == "https" else 80) else ""
    )
    return urlunsplit((u.scheme, authority, u.path or "/", u.query, ""))


def select_addresses(addresses, cap):
    public = sorted(
        {
            str(ipaddress.ip_address(x))
            for x in addresses
            if ipaddress.ip_address(x).is_global
        },
        key=lambda x: (
            ipaddress.ip_address(x).version,
            int(ipaddress.ip_address(x)),
        ),
    )
    selected = []
    for version in (4, 6):
        family = [
            x for x in public if ipaddress.ip_address(x).version == version
        ]
        selected.extend(family if cap == 0 else family[:cap])
    return selected


def worker(request):
    if request["kind"] == "dns":
        addresses = sorted(
            {
                r[4][0]
                for r in socket.getaddrinfo(
                    request["host"], 443, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
            }
        )
        return {"addresses": addresses}
    u = urlsplit(request["url"])
    context = ssl.create_default_context(cafile=request.get("cafile"))
    context.set_alpn_protocols(["http/1.1"])
    conn = http.client.HTTPSConnection(
        u.hostname, u.port or 443, timeout=request["timeout"], context=context
    )
    sock = socket.create_connection(
        (request["ip"], u.port or 443), timeout=request["timeout"]
    )
    try:
        conn.sock = context.wrap_socket(sock, server_hostname=u.hostname)
        conn.request(
            "GET",
            urlunsplit(("", "", u.path or "/", u.query, "")),
            headers={
                "User-Agent": "Academic-PQC-Survey/3.0",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        return {
            "http_status": response.status,
            "location": response.getheader("Location"),
            "server": response.getheader("Server"),
            "http_tls_version": conn.sock.version() if conn.sock else None,
        }
    finally:
        conn.close()
        sock.close()


def bounded_worker(request, timeout):
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--worker"],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        if result.returncode:
            return {"error": result.stderr[-1500:] or "worker failed"}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "worker_deadline_exceeded"}


def discover(start_url, cap, max_hops, timeout, cafile, delay):
    hops = []
    dns = {}
    url = normalize_url(start_url)
    visited = set()
    for index in range(max_hops + 1):
        if url in visited:
            return {"hops": hops, "dns": dns, "stop": "redirect_loop"}
        visited.add(url)
        u = urlsplit(url)
        if u.scheme != "https":
            return {
                "hops": hops,
                "dns": dns,
                "stop": "http_downgrade",
                "next_url": url,
            }
        host = u.hostname
        if host not in dns:
            dns[host] = {
                "measured_utc": now(),
                **bounded_worker({"kind": "dns", "host": host}, timeout),
            }
            dns[host]["selected"] = select_addresses(
                dns[host].get("addresses", []), cap
            )
        addresses = dns[host]["selected"]
        hop = {
            "url": url,
            "hostname": host,
            "port": u.port or 443,
            "started_utc": now(),
            "requests": [],
        }
        hops.append(hop)
        if not addresses:
            return {
                "hops": hops,
                "dns": dns,
                "stop": "no_public_address_or_dns_failure",
            }
        response = {}
        # Try selected addresses in order until one HTTP response is obtained.
        for ip in addresses:
            time.sleep(delay)
            response = bounded_worker(
                {
                    "kind": "http",
                    "url": url,
                    "ip": ip,
                    "timeout": timeout,
                    "cafile": cafile,
                },
                timeout,
            )
            hop["requests"].append({"ip": ip, **response})
            if "http_status" in response:
                break
        if "http_status" not in response:
            return {
                "hops": hops,
                "dns": dns,
                "stop": "http_or_certificate_failure",
            }
        if response["http_status"] not in (301, 302, 303, 307, 308):
            return {
                "hops": hops,
                "dns": dns,
                "stop": "terminal_response",
                "terminal_url": url,
            }
        if not response.get("location"):
            return {
                "hops": hops,
                "dns": dns,
                "stop": "redirect_without_location",
            }
        try:
            url = normalize_url(urljoin(url, response["location"]))
        except ValueError as error:
            return {
                "hops": hops,
                "dns": dns,
                "stop": "excluded_redirect",
                "detail": str(error),
            }
    return {"hops": hops, "dns": dns, "stop": "hop_limit", "next_url": url}


def trace_hrr(text):
    messages = re.findall(
        r"<<<[^\n]*Handshake[^\n]*ServerHello[^\n]*\n((?:[ \t]+[0-9a-fA-F ]+\n)+)",
        text,
    )
    if not messages:
        return None
    payloads = [bytes.fromhex(m) for m in messages]
    return any(len(b) >= 38 and b[6:38] == HRR for b in payloads)


def client_keyshares(text):
    """Decode first outgoing ClientHello key_share IDs from OpenSSL -msg hex."""
    messages = re.findall(
        r">>>[^\n]*Handshake[^\n]*ClientHello[^\n]*\n((?:[ \t]+[0-9a-fA-F ]+\n)+)",
        text,
    )
    if not messages:
        return None
    try:
        data = bytes.fromhex(messages[0])
        pos = 38
        pos += 1 + data[pos]  # legacy session ID
        pos += 2 + int.from_bytes(data[pos : pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]  # compression
        end = pos + 2 + int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        if end > len(data):
            return None
        while pos < end:
            kind = int.from_bytes(data[pos : pos + 2], "big")
            size = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if pos + size > end:
                return None
            if kind == 51:
                stop = pos + size
                pos += 2
                groups = []
                while pos < stop:
                    if pos + 4 > stop:
                        return None
                    groups.append(int.from_bytes(data[pos : pos + 2], "big"))
                    pos += 4 + int.from_bytes(data[pos + 2 : pos + 4], "big")
                return groups if pos == stop else None
            pos += size
    except (ValueError, IndexError):
        return None
    return []


def command(binary, host, port, ip, profile, cafile):
    base = p.client_command(
        binary, {"hostname": host, "port": port}, ip, p.TLS13_MIXED, cafile
    )
    version = ipaddress.ip_address(ip).version
    base[base.index("-4")] = "-6" if version == 6 else "-4"
    base[base.index("-connect") + 1] = (
        f"[{ip}]:{port}" if version == 6 else f"{ip}:{port}"
    )
    base[base.index("-groups") + 1] = PROFILES[profile]
    return base + ["-msg"]


def probe(binary, job, timeout, cafile):
    cmd = command(
        binary, job["hostname"], job["port"], job["ip"], job["profile"], cafile
    )
    raw = p.run_process(cmd, timeout)
    result = p.parse_tls(raw, p.TLS13_MIXED)
    allowed = {
        p.canonical_group(g.lstrip("*"))
        for g in PROFILES[job["profile"]].split(":")
    }
    if result["status"] == "ok" and result["negotiated_group"] not in allowed:
        result.update(
            status="parse_error",
            error="Negotiated group not in explicit offer",
        )
    result["hello_retry_request_observed"] = trace_hrr(
        raw["stdout"] + "\n" + raw["stderr"]
    )
    result["initial_keyshare_group_ids"] = client_keyshares(
        raw["stdout"] + "\n" + raw["stderr"]
    )
    return result, raw, cmd


def make_jobs(chains, repeats, seed):
    endpoints = set()
    for chain in chains:
        for hop in chain["hops"]:
            for ip in (
                chain["dns"].get(hop["hostname"], {}).get("selected", [])
            ):
                endpoints.add((hop["hostname"], hop["port"], ip))
    jobs = []
    rng = random.Random(seed)
    for repetition in range(1, repeats + 1):
        round_jobs = [
            {
                "hostname": host,
                "port": port,
                "ip": ip,
                "family": ipaddress.ip_address(ip).version,
                "profile": profile,
                "repetition": repetition,
            }
            for host, port, ip in sorted(endpoints)
            for profile in PROFILES
        ]
        rng.shuffle(round_jobs)
        for job in round_jobs:
            job["job_id"] = digest(json.dumps(job, sort_keys=True).encode())[
                :24
            ]
        jobs.extend(round_jobs)
    return jobs


def export(out, jobs, events):
    rows = []
    for host, port, ip in sorted(
        {(j["hostname"], j["port"], j["ip"]) for j in jobs}
    ):
        ee = [
            e
            for e in events
            if (e["hostname"], e["port"], e["ip"]) == (host, port, ip)
        ]
        planned = [
            j
            for j in jobs
            if (j["hostname"], j["port"], j["ip"]) == (host, port, ip)
        ]
        hybrid = [
            e
            for e in ee
            if e["status"] == "ok" and e.get("negotiated_group") == p.HYBRID
        ]
        controls = [e for e in ee if e["profile"] == "classical"]
        only = [e for e in ee if e["profile"] == "hybrid_only"]
        label = "supported" if hybrid else "inconclusive"
        if (
            not hybrid
            and len(ee) == len(planned)
            and controls
            and only
            and all(e["status"] == "ok" for e in controls)
            and all(e["status"] == "tls_alert" for e in only)
        ):
            label = "not_observed_controlled_alert"
        row = {
            "hostname": host,
            "port": port,
            "ip": ip,
            "family": ipaddress.ip_address(ip).version,
            "observation": label,
            "planned_attempts": len(planned),
            "recorded_attempts": len(ee),
            "hybrid_successes": len(hybrid),
            "complete": len(ee) == len(planned),
        }
        for profile in PROFILES:
            pp = [e for e in ee if e["profile"] == profile]
            row[profile + "_outcomes"] = dict(
                Counter(
                    (
                        e.get("negotiated_group")
                        if e["status"] == "ok"
                        else e["status"]
                    )
                    for e in pp
                )
            )
        rows.append(row)
    save(out / "address_summary.json", rows)
    if rows:
        with (out / "address_summary.csv").open(
            "w", newline="", encoding="utf-8"
        ) as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(
                {
                    k: json.dumps(v) if isinstance(v, dict) else v
                    for k, v in r.items()
                }
                for r in rows
            )
    with (out / "attempts.csv").open("w", newline="", encoding="utf-8") as f:
        fields = [
            "job_id",
            "hostname",
            "port",
            "ip",
            "family",
            "profile",
            "repetition",
            "started_utc",
            "finished_utc",
            "status",
            "negotiated_group",
            "certificate_verified",
            "hello_retry_request_observed",
            "process_elapsed_ms",
            "raw_log",
        ]
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(events)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "baseline", type=Path, help="Completed original survey directory"
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--max-per-family",
        type=int,
        default=2,
        help="Selected addresses per family; 0 means all returned public addresses",
    )
    parser.add_argument("--max-hops", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=12)
    parser.add_argument("--delay", type=float, default=1)
    parser.add_argument("--seed", type=int, default=20261104)
    parser.add_argument("--max-jobs", type=int, default=10000)
    parser.add_argument("--cafile")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Discover DNS/HTTPS redirects and save the exact job plan; no OpenSSL probes",
    )
    args = parser.parse_args()
    if (
        args.repeats < 1
        or args.max_per_family < 0
        or args.max_hops < 0
        or args.timeout <= 0
        or args.delay < 0
        or args.max_jobs < 1
    ):
        parser.error("Invalid numeric limit")
    binary, info = p.inspect_openssl(args.openssl)
    baseline_manifest = json.loads(
        (args.baseline / "manifest.json").read_text()
    )
    if baseline_manifest.get("state") != "complete":
        parser.error("Finish the baseline survey first")
    baseline_ca = baseline_manifest.get("settings", {}).get("cafile_sha256")
    if baseline_ca and not args.cafile:
        parser.error("Baseline used a custom CA file: supply --cafile")
    config = {
        k: v
        for k, v in vars(args).items()
        if k not in ("resume", "out", "plan_only", "baseline", "openssl")
    }
    if args.cafile:
        config["cafile"] = str(Path(args.cafile).resolve())
    config.update(
        openssl=info,
        python=sys.version,
        profiles=PROFILES,
        cafile_sha256=(
            digest(Path(args.cafile).read_bytes()) if args.cafile else None
        ),
        baseline_manifest_sha256=digest(
            (args.baseline / "manifest.json").read_bytes()
        ),
        sample_sha256=digest((args.baseline / "sample.csv").read_bytes()),
        source_sha256={
            name: digest(Path(__file__).with_name(name).read_bytes())
            for name in ("advanced_survey.py", "pqc_probe.py")
        },
    )
    fingerprint = digest(json.dumps(config, sort_keys=True).encode())
    out = args.out
    if not args.resume:
        out.mkdir(parents=True, exist_ok=False)
    elif not (out / "manifest.json").exists():
        parser.error("No advanced run to resume")
    with (out / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.resume:
            manifest = json.loads((out / "manifest.json").read_text())
            if manifest["fingerprint"] != fingerprint:
                raise ValueError(
                    "Inputs, settings or toolchain changed; use a new output directory"
                )
        else:
            manifest = {
                "version": "3.0-supplement",
                "created_utc": now(),
                "fingerprint": fingerprint,
                "config": config,
                "state": "discovery",
            }
            save(out / "manifest.json", manifest)
            (out / "raw").mkdir()
            (out / "source").mkdir()
            for name in config["source_sha256"]:
                shutil.copyfile(
                    Path(__file__).with_name(name), out / "source" / name
                )
            for name in ("sample.csv", "manifest.json"):
                shutil.copyfile(
                    args.baseline / name, out / ("baseline_" + name)
                )
        if (args.baseline / "summary.json").exists():
            baseline_rows = json.loads(
                (args.baseline / "summary.json").read_text()
            )["targets"]
            diagnostics = []
            for row in baseline_rows:
                tls13 = (
                    any(
                        row.get(k + "_status") == "ok"
                        for k in (
                            "tls13_classical",
                            "tls13_mixed",
                            "tls13_hybrid_only",
                        )
                    )
                    or row.get("tls_1_3_observed") is True
                    or row.get("sslyze_highest_tls_observed") == "TLS_1_3"
                )
                subgroup = row["hybrid_observation"]
                if subgroup == "inconclusive":
                    if tls13:
                        subgroup = "tls13_observed_hybrid_unresolved"
                    elif (
                        row.get("tls_1_3_observed") is False
                        and row.get("tls_1_2_observed") is True
                    ):
                        subgroup = "tls12_observed_tls13_not_observed"
                diagnostics.append(
                    {
                        "hostname": row["hostname"],
                        "original_classification": row["hybrid_observation"],
                        "tls13_observed_combined": tls13,
                        "analytical_subgroup": subgroup,
                    }
                )
            save(out / "baseline_diagnostics.json", diagnostics)
        chains = read_events(out / "redirects.jsonl")
        with (args.baseline / "sample.csv").open(encoding="utf-8-sig") as f:
            samples = list(csv.DictReader(f))
        for sample in samples:
            key = sample["sample_index"]
            if any(c["sample_index"] == key for c in chains):
                continue
            if int(sample["port"]) != 443:
                raise ValueError(
                    "Supplement currently supports baseline port 443 only"
                )
            print("Discovering", sample["hostname"], flush=True)
            chain = {
                "sample_index": key,
                "seed_hostname": sample["hostname"],
                "category": sample.get("category"),
                **discover(
                    "https://" + sample["hostname"] + "/",
                    args.max_per_family,
                    args.max_hops,
                    args.timeout,
                    args.cafile,
                    args.delay,
                ),
            }
            append(out / "redirects.jsonl", chain)
            chains.append(chain)
        if (out / "plan.json").exists():
            jobs = json.loads((out / "plan.json").read_text())
        else:
            jobs = make_jobs(chains, args.repeats, args.seed)
            save(out / "plan.json", jobs)
        print(
            f"{len(jobs)} TLS probes planned; pacing alone is {len(jobs)*args.delay/60:.1f} minutes.",
            flush=True,
        )
        if len(jobs) > args.max_jobs:
            raise ValueError(
                "Job budget exceeded. Start a new run with a higher budget or lower address/repetition limits."
            )
        events = read_events(out / "attempts.jsonl")
        done = {e["job_id"] for e in events}
        if any(e["status"] in ("tool_error", "parse_error") for e in events):
            raise ValueError(
                "Saved tool/parser error requires investigation and a new run after correction"
            )
        if args.plan_only:
            manifest["state"] = "planned"
            save(out / "manifest.json", manifest)
            export(out, jobs, events)
            return 0
        manifest["state"] = "running"
        save(out / "manifest.json", manifest)
        try:
            for job in jobs:
                if job["job_id"] in done:
                    continue
                time.sleep(args.delay)
                started = now()
                result, raw, cmd = probe(
                    binary, job, args.timeout, args.cafile
                )
                if raw["interrupted"]:
                    raise KeyboardInterrupt
                name = "raw/" + job["job_id"] + ".json"
                save(out / name, {"command": cmd, **raw})
                event = {
                    **job,
                    **result,
                    "started_utc": started,
                    "finished_utc": now(),
                    "process_elapsed_ms": raw["process_elapsed_ms"],
                    "returncode": raw["returncode"],
                    "timed_out": raw["timed_out"],
                    "raw_log": name,
                }
                append(out / "attempts.jsonl", event)
                events.append(event)
                done.add(job["job_id"])
                print(
                    f"{len(done)}/{len(jobs)} {job['hostname']} {job['ip']} {job['profile']}: {result['status']}",
                    flush=True,
                )
                if result["status"] in ("parse_error", "tool_error"):
                    raise RuntimeError(
                        "Tool/parser failure; inspect saved raw log before continuing"
                    )
            manifest["state"] = "complete"
        except KeyboardInterrupt:
            manifest["state"] = "interrupted"
            return 130
        except Exception:
            manifest["state"] = "error"
            raise
        finally:
            export(out, jobs, events)
            manifest["updated_utc"] = now()
            save(out / "manifest.json", manifest)
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        try:
            print(json.dumps(worker(json.load(sys.stdin))))
        except Exception as error:
            print(json.dumps({"error": f"{type(error).__name__}: {error}"}))
    else:
        try:
            sys.exit(main())
        except KeyboardInterrupt:
            sys.exit(130)
        except (ValueError, OSError, RuntimeError) as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)

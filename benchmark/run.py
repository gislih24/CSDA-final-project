#!/usr/bin/env python3
"""Serial randomized paired experiment. Python standard library only.
Privileged orchestration is confined to dedicated namespaces; TLS children drop
to the sudo caller's UID/GID. Both TLS processes persist for an entire run.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import random
import re
import select
import shutil
import signal
import subprocess as sp
import sys
import time

ROOT = Path(__file__).resolve().parent
os.environ["LC_ALL"] = "C"
PROFILES = {
    "A": (0, None),
    "B": (20, 100),
    "C": (50, 100),
    "D": (100, 100),
    "E": (50, 10),
    "F": (50, 1),
}
GROUPS = ["X25519", "X25519MLKEM768"]


def command(args, **kw):
    return sp.run(
        list(map(str, args)), check=True, text=True, capture_output=True, **kw
    ).stdout


def ns(name, *args):
    return ["ip", "netns", "exec", name, *map(str, args)]


def readline(process, seconds=25):
    # One request -> one response, no pipelining; TextIO cannot hide queued lines.
    if not select.select([process.stdout], [], [], seconds)[0]:
        raise RuntimeError("child did not respond before watchdog deadline")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("child exited; inspect client/server stderr logs")
    return line.rstrip("\n")


def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=4)
        except sp.TimeoutExpired:
            p.kill()
            p.wait()


def telemetry():
    paths = [Path("/sys/firmware/acpi/platform_profile")]
    paths += list(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
    paths += list(
        Path("/sys/devices/system/cpu").glob(
            "cpu[0-9]*/cpufreq/scaling_governor"
        )
    )
    paths += list(
        Path("/sys/devices/system/cpu").glob(
            "cpu[0-9]*/cpufreq/energy_performance_preference"
        )
    )
    paths += list(
        Path("/sys/devices/system/cpu").glob(
            "cpu[0-9]*/cpufreq/scaling_cur_freq"
        )
    )
    result = {}
    for path in paths:
        try:
            result[str(path)] = path.read_text().strip()
        except OSError:
            pass
    result["utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    return result


def qdiscs():
    return {
        dev: json.loads(
            command(ns("pqb-r", "tc", "-j", "-s", "qdisc", "show", "dev", dev))
        )
        for dev in ("rc", "rs")
    }


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


def metadata(out, args):
    info = {
        "arguments": vars(args),
        "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profiles": PROFILES,
        "groups": GROUPS,
        "telemetry": telemetry(),
        "commands": {},
        "sha256": {},
    }
    cmds = [
        ["uname", "-a"],
        ["lscpu"],
        ["lscpu", "-e=CPU,CORE,SOCKET,ONLINE,MAXMHZ"],
        ["openssl", "version", "-a"],
        [ROOT / "tlsbench", "version"],
        ["ldd", ROOT / "tlsbench"],
        ["tc", "-V"],
        ["g++", "--version"],
        ["powerprofilesctl", "get"],
        [ROOT / "net.sh", "show"],
    ]
    for cmd in cmds:
        try:
            info["commands"][" ".join(map(str, cmd))] = command(cmd)
        except (OSError, sp.CalledProcessError) as e:
            info["commands"][" ".join(map(str, cmd))] = str(e)
    # Keep an exact snapshot of the scripts, binary and public certificates.
    snap = out / "snapshot"
    snap.mkdir()
    for p in sorted(ROOT.iterdir()):
        if p.is_file() and (
            p.suffix in (".cpp", ".py", ".sh", ".md")
            or p.name in ("Makefile", "tlsbench")
        ):
            if not p.is_file():
                continue
            shutil.copy2(p, snap / p.name)
            info["sha256"][p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    for name in ("ca.pem", "server.pem"):
        p = ROOT / "certs" / name
        shutil.copy2(p, snap / name)
        info["sha256"][name] = hashlib.sha256(p.read_bytes()).hexdigest()
    for namespace in ("pqb-c", "pqb-r", "pqb-s"):
        for cmd in (["sysctl", "-a"], ["ip", "-details", "link", "show"]):
            try:
                info["commands"][namespace + " " + " ".join(cmd)] = command(
                    ns(namespace, *cmd)
                )
            except sp.CalledProcessError as e:
                info["commands"][namespace + " " + " ".join(cmd)] = e.stdout
    save(out / "metadata.json", info)


def validate_network(out):
    report = {}
    server = None
    try:
        server = sp.Popen(
            ns("pqb-s", "iperf3", "-s", "-B", "10.203.2.2"),
            stdout=sp.DEVNULL,
            stderr=sp.PIPE,
        )
        time.sleep(0.3)
        if server.poll() is not None:
            raise RuntimeError("iperf3 server failed")
        for profile, (rtt, rate) in PROFILES.items():
            command([ROOT / "net.sh", "profile", profile])
            # Populate neighbor entries before recording RTTs.
            command(ns("pqb-c", "ping", "-n", "-c", 1, "-W", 2, "10.203.2.2"))
            ping = command(
                ns(
                    "pqb-c",
                    "ping",
                    "-n",
                    "-c",
                    8,
                    "-i",
                    "0.2",
                    "-W",
                    2,
                    "10.203.2.2",
                )
            )
            match = re.search(
                r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", ping
            )
            if not match:
                raise RuntimeError("cannot parse ping output")
            avg = float(match[2])
            baseline = report.get("A", {}).get("ping_avg_ms", avg)
            item = {
                "ping": ping,
                "ping_avg_ms": avg,
                "added_rtt_ms": avg - baseline,
                "rtt_pass": abs(avg - baseline - rtt) <= max(3, rtt * 0.10),
                "directions": {},
            }
            if rate is not None:
                for direction, flags in [("forward", []), ("reverse", ["-R"])]:
                    raw = json.loads(
                        command(
                            ns(
                                "pqb-c",
                                "iperf3",
                                "-c",
                                "10.203.2.2",
                                "-t",
                                10,
                                "-O",
                                2,
                                "-J",
                                *flags,
                            ),
                            timeout=25,
                        )
                    )
                    if "error" in raw:
                        raise RuntimeError(raw["error"])
                    save(out / f"iperf-{profile}-{direction}.json", raw)
                    mbps = raw["end"]["sum_received"]["bits_per_second"] / 1e6
                    item["directions"][direction] = {
                        "mbit_s": mbps,
                        "broad_sanity_pass": rate * 0.65
                        <= mbps
                        <= rate * 1.20,
                    }
            report[profile] = item
            save(out / "network-validation.json", report)
            print(
                f'{profile}: ping average {avg:.3f} ms; bandwidth {item["directions"]}',
                flush=True,
            )
        passed = all(
            x["rtt_pass"]
            and all(d["broad_sanity_pass"] for d in x["directions"].values())
            for x in report.values()
        )
        if not passed:
            raise RuntimeError(
                "network sanity check failed; inspect network-validation.json"
            )
        print(
            "Broad network checks passed. Inspect achieved rates before freezing the protocol."
        )
    finally:
        stop(server)


def endpoint(namespace, cpu, uid, gid, *args):
    return ns(
        namespace,
        "taskset",
        "-c",
        cpu,
        "setpriv",
        "--reuid",
        uid,
        "--regid",
        gid,
        "--clear-groups",
        ROOT / "tlsbench",
        *args,
    )


def experiment(out, args):
    uid, gid = int(os.environ.get("SUDO_UID", os.getuid())), int(
        os.environ.get("SUDO_GID", os.getgid())
    )
    rng = random.Random(args.seed)
    client = server = capture = None
    logs = []
    total = bad = 0
    try:
        child_env = os.environ.copy()
        child_env.pop("TLSBENCH_KEYLOG", None)
        if args.mode == "capture":
            keylog = out / "tls.keys"
            keylog.touch(mode=0o600)
            os.chown(keylog, uid, gid)
            child_env["TLSBENCH_KEYLOG"] = str(keylog)
        for name in ("server", "client"):
            logs.append((out / f"{name}.log").open("w"))
        server = sp.Popen(
            endpoint(
                "pqb-s",
                args.server_cpu,
                uid,
                gid,
                "server",
                "10.203.2.2",
                4433,
                ROOT / "certs/server.pem",
                ROOT / "certs/server.key",
                ":".join(GROUPS),
            ),
            text=True,
            stdout=sp.PIPE,
            stderr=logs[0],
            bufsize=1,
            env=child_env,
        )
        if not readline(server).startswith("READY "):
            raise RuntimeError("server readiness failed")
        client = sp.Popen(
            endpoint(
                "pqb-c",
                args.client_cpu,
                uid,
                gid,
                "client",
                "10.203.2.2",
                4433,
                ROOT / "certs/ca.pem",
                5000,
            ),
            text=True,
            stdin=sp.PIPE,
            stdout=sp.PIPE,
            stderr=logs[1],
            bufsize=1,
            env=child_env,
        )
        if not readline(client).startswith("READY "):
            raise RuntimeError("client readiness failed")
        if args.mode == "capture":
            caplog = (out / "tcpdump.log").open("w")
            logs.append(caplog)
            capture = sp.Popen(
                ns(
                    "pqb-s",
                    "tcpdump",
                    "-Z",
                    "root",
                    "-i",
                    "s0",
                    "-nn",
                    "-s",
                    0,
                    "-U",
                    "-w",
                    out / "validation.pcap",
                    "tcp port 4433",
                ),
                stdout=sp.DEVNULL,
                stderr=caplog,
            )
            time.sleep(0.4)
            if capture.poll() is not None:
                raise RuntimeError("tcpdump failed")
        with (out / "trials.jsonl").open("w", buffering=1) as raw, (
            out / "blocks.jsonl"
        ).open("w", buffering=1) as blocks:

            def trial(group, round_id, profile, pair, order, warmup):
                nonlocal total, bad
                client.stdin.write(group + "\n")
                client.stdin.flush()
                rec = json.loads(readline(client))
                rec.update(
                    round=round_id,
                    profile=profile,
                    pair=pair,
                    order=order,
                    warmup=warmup,
                    utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                    sequence=total,
                )
                raw.write(json.dumps(rec) + "\n")
                total += 1
                if rec["status"] != "ok":
                    bad += 1
                    print(
                        f"FAILED {profile} {group}: {rec}",
                        file=sys.stderr,
                        flush=True,
                    )
                    # Fail closed on setup/control failures. Ordinary network failures
                    # remain in the dataset and do not get retried or replaced.
                    if warmup or rec["phase"] in ("setup", "validation"):
                        raise RuntimeError(
                            "warm-up/control failure; result retained, run stopped"
                        )
                return rec

            for round_id in range(args.rounds):
                profiles = args.profiles.copy()
                rng.shuffle(profiles)
                for profile in profiles:
                    command([ROOT / "net.sh", "profile", profile])
                    # All previous application + close_notify exchanges have completed.
                    # Fixed settling pause is outside all timing windows.
                    time.sleep(0.2)
                    before = qdiscs()
                    before_meta = telemetry()
                    for pair in range(args.warmup):
                        order = GROUPS.copy()
                        rng.shuffle(order)
                        for pos, group in enumerate(order):
                            trial(group, round_id, profile, pair, pos, True)
                    for pair in range(args.pairs):
                        order = GROUPS.copy()
                        rng.shuffle(order)
                        for pos, group in enumerate(order):
                            trial(group, round_id, profile, pair, pos, False)
                    after = qdiscs()
                    block = {
                        "round": round_id,
                        "profile": profile,
                        "qdisc_before": before,
                        "qdisc_after": after,
                        "telemetry_before": before_meta,
                        "telemetry_after": telemetry(),
                    }
                    blocks.write(json.dumps(block) + "\n")
                    for dev in ("rc", "rs"):
                        b = sum(q.get("drops", 0) for q in before[dev])
                        a = sum(q.get("drops", 0) for q in after[dev])
                        if a > b:
                            raise RuntimeError(
                                f"unexpected qdisc drops in {profile}/{dev}; inspect retained data"
                            )
                    print(
                        f"round {round_id+1}/{args.rounds}, profile {profile}: {total} trials including warm-ups, {bad} failures",
                        flush=True,
                    )
            client.stdin.write("QUIT\n")
            client.stdin.flush()
            client.wait(timeout=5)
    finally:
        if capture and capture.poll() is None:
            capture.send_signal(signal.SIGINT)
            try:
                capture.wait(timeout=5)
            except sp.TimeoutExpired:
                stop(capture)
        stop(client)
        stop(server)
        for log in logs:
            log.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--mode",
        choices=["validate", "pilot", "main", "capture"],
        required=True,
    )
    ap.add_argument("--client-cpu", type=int, default=0)
    ap.add_argument("--server-cpu", type=int, default=2)
    ap.add_argument("--rounds", type=int)
    ap.add_argument("--pairs", type=int)
    ap.add_argument(
        "--warmup", type=int, default=5, help="warm-up PAIRS per profile/block"
    )
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--profiles", nargs="+", choices=list(PROFILES))
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    if os.geteuid() != 0:
        ap.error("run with sudo; namespaces require root")
    if args.client_cpu == args.server_cpu:
        ap.error("client and server CPU must differ")
    for cpu in (args.client_cpu, args.server_cpu):
        if cpu not in os.sched_getaffinity(0):
            ap.error(f"CPU {cpu} is unavailable")

    def core(cpu):
        return (
            Path(
                f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
            )
            .read_text()
            .strip()
        )

    if core(args.client_cpu) == core(args.server_cpu):
        ap.error("selected CPUs are SMT siblings")
    for name in [
        "ip",
        "tc",
        "ethtool",
        "taskset",
        "setpriv",
        "openssl",
        "ping",
    ]:
        if not shutil.which(name):
            ap.error(f"missing {name}")
    if args.mode == "validate" and not shutil.which("iperf3"):
        ap.error("install iperf3 for validation")
    if args.mode == "capture" and not shutil.which("tcpdump"):
        ap.error("install tcpdump")
    groups = command(["openssl", "list", "-tls1_3", "-tls-groups"])
    if "X25519MLKEM768" not in groups:
        ap.error("native X25519MLKEM768 support required")
    args.rounds = (
        args.rounds
        if args.rounds is not None
        else (30 if args.mode == "main" else 1)
    )
    args.pairs = (
        args.pairs
        if args.pairs is not None
        else (20 if args.mode == "main" else 50 if args.mode == "pilot" else 5)
    )
    args.profiles = args.profiles or (
        list(PROFILES)
        if args.mode == "main"
        else ["A", "F"] if args.mode == "pilot" else ["A", "C", "F"]
    )
    if min(args.rounds, args.pairs, args.warmup) < 1:
        ap.error("rounds, pairs and warm-up pairs must be positive")
    if len(set(args.profiles)) != len(args.profiles):
        ap.error("duplicate profiles")
    out = (
        args.out
        or ROOT
        / "results"
        / f"{args.mode}-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}"
    ).resolve()
    out.mkdir(parents=True, exist_ok=False)
    args.out = str(out)
    state = {
        "complete": False,
        "mode": args.mode,
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    save(out / "status.json", state)
    try:
        metadata(out, args)
        if args.mode == "validate":
            validate_network(out)
        else:
            experiment(out, args)
        state["complete"] = True
    except BaseException as e:
        state["error"] = str(e)
        raise
    finally:
        state["ended_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        save(out / "status.json", state)
        uid = int(os.environ.get("SUDO_UID", os.getuid()))
        gid = int(os.environ.get("SUDO_GID", os.getgid()))
        for p in [out, *out.rglob("*")]:
            if not p.is_symlink():
                os.chown(p, uid, gid)
        print(f"Results: {out}", flush=True)


if __name__ == "__main__":
    main()

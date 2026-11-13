# 🔬 Controlled benchmark: X25519 vs. X25519MLKEM768

This project compares classical X25519 key establishment with the hybrid
X25519MLKEM768 group. It includes:

- 💻 a C++17 TLS client and server;
- ⏱️ OpenSSL-based measurements;
- 🌐 an emulated network built with Linux namespaces and `netem`; and
- 📊 Python scripts for running and analysing the experiment.

It was prepared for Ubuntu on an Intel Core Ultra 5 235U with OpenSSL 3.5.5.
Everything runs locally. The benchmark does not connect to public websites.

🚀 **Start by building the project and running `selftest.py`. Before collecting
the main results, validate the network and complete a pilot run.**

The code was compiled and tested with OpenSSL 3.0.13 in the development
environment. However, that environment could not create network namespaces
and did not provide a native ML-KEM group. You must therefore validate the
hybrid handshake and namespace setup on the target laptop. Until those checks
pass, do not describe the package as validated on your hardware.

## 🛠️ 1. Build and check locally (no sudo)

Extract the archive into a local directory, open a terminal in that directory,
and run:

```bash
sudo apt update
sudo apt install g++ make pkg-config libssl-dev iproute2 ethtool tcpdump tshark iperf3 python3-numpy python3-matplotlib
chmod +x net.sh certs.sh
make
./tlsbench version
./certs.sh
python3 selftest.py
python3 test_analysis.py
```

Most of these dependencies are already installed on the supplied machine. The
most likely additions are `iperf3`, the C++ compiler, and the Python analysis
packages. If your usual Python installation cannot find packages installed by
`apt`, use the system interpreter at `/usr/bin/python3`. You do not need to run
`iperf3` as a system service.

`pkg-config --modversion openssl` reported OpenSSL 3.5.5 on the target machine.
Building the project and running `tlsbench version` confirm which development
headers and runtime library are actually being used. Seeing a group in an
OpenSSL list is not enough; a real handshake must also succeed.

The local tests cover:

- 100 new classical connections;
- an invalid certificate trust path;
- an unavailable group;
- HelloRetryRequest (HRR) detection; and
- a timeout.

With OpenSSL 3.5, the tests also run ten hybrid/classical pairs. They expect the
hybrid TLS stream to contain 1,176 more client-to-server bytes and 1,098 more
server-to-client bytes than the classical stream.

The key shares themselves grow by 1,184/1,088 bytes, but the counters include
other TLS fields too. In OpenSSL 3.5, the hybrid ClientHello omits the 8-byte
`ec_point_formats` extension sent for X25519. With the fixed server group order
`X25519:X25519MLKEM768`, the hybrid handshake also adds a 10-byte
`supported_groups` extension to EncryptedExtensions, because the negotiated
group is not first in the server's list. Thus the stream differences are
`1184 - 8 = 1176` and `1088 + 10 = 1098`. Changing the OpenSSL build or server
group order requires rechecking these expectations.

⚠️ If any assertion fails, save the output and investigate it before running the
main experiment. Do not weaken a check simply to make the test pass.

`certs.sh` creates a local RSA-2048 certificate authority and an RSA-2048 server certificate for `bench.test`. It does not add either certificate to the operating system's trust store. Reuse the same certificates for every run, including the independent repeat the following day. They are valid for 30 days.

The benchmark uses a fixed-length RSA-PSS `CertificateVerify` signature so that ECDSA's variable signature length does not affect the byte counts. Server authentication is still classical. This experiment measures hybrid key establishment; it is not a fully post-quantum authentication system.

## 🔌 2. Fix the machine conditions

- 🔌 Connect the laptop to AC power. Use the same power profile for the pilot and
  main run, and record the profile's name.
- 💤 Pause CPU-heavy tasks such as virtual machines, builds, and transcription.
  Keep the laptop awake and reasonably cool.
- 📌 Pin the client to logical CPU **0** and the server to logical CPU **2**.
  According to the target machine's `lscpu` output, these are different 4.9 GHz
  physical cores. CPUs 0 and 1 share one physical core, while CPUs 2 and 3
  share another. Do not treat CPUs 0 and 1 as separate cores.
- ⚠️ CPU affinity does not reserve a core exclusively. Other processes, SMT
  siblings, interrupts, clock-speed changes, and temperature can still affect
  the measurements. Randomized pairing reduces some noise, but cannot remove
  it completely.
- 🔒 During collection, do not change the CPU governor, disable turbo, isolate
  cores, change the MTU, or update OpenSSL. Any of these changes would create a
  different experiment.

The runner records the CPU topology, kernel and OpenSSL versions, linked
libraries, power policy when available, CPU frequency, available temperature
readings, network settings, source hashes, and a source/binary snapshot.
Frequency and temperature are sampled between blocks, not during every
handshake.

## 🌐 3. Create and validate the emulated network

```bash
sudo ./net.sh up
sudo python3 run.py --mode validate --out results/network-check
```

The script creates three isolated network namespaces:

| Namespace | Interface/address                        | Role            |
| --------- | ---------------------------------------- | --------------- |
| `pqb-c`   | `c0`, 10.203.1.2/30                      | C++ client      |
| `pqb-r`   | `rc`, 10.203.1.1/30; `rs`, 10.203.2.1/30 | Router/emulator |
| `pqb-s`   | `s0`, 10.203.2.2/30                      | C++ server      |

The setup does not change host routes, host firewall rules, physical
interfaces, or system-wide forwarding. It also refuses to overwrite existing
namespaces with the same names.

The scripts use an MTU of 1500 and disable TSO, GSO, and GRO on all four
virtual Ethernet endpoints. TCP route-metric saving is disabled inside the
namespaces. Delay and rate limits are applied to the router's outgoing traffic
toward each receiver. This keeps the impairment away from the sender endpoint's
TCP Small Queues.

| Profile | Added RTT | Rate each direction |
| ------- | --------: | ------------------: |
| A       |      none |        unrestricted |
| B       |     20 ms |          100 Mbit/s |
| C       |     50 ms |          100 Mbit/s |
| D       |    100 ms |          100 Mbit/s |
| E       |     50 ms |           10 Mbit/s |
| F       |     50 ms |            1 Mbit/s |

Each router egress has one `netem` queue discipline that combines fixed delay
with rate serialization. Half of the added round-trip time is applied in each
direction. Profile A uses the same topology and still has a `netem` qdisc, but
adds no delay or rate limit. No packet loss is configured, and each queue can
hold up to 10,000 packets.

This setup emulates a packet rate; it does not reproduce physical Ethernet
wire-rate accounting. Record the exact `tc` version and qdisc configuration.
Kernel timers may also release packets in bursts, especially at high configured
rates. For that reason, report the measured RTT and achieved throughput as well
as the requested settings.

⏳ Network validation takes about 2–4 minutes. It measures ping RTT and runs a
10-second TCP throughput test in each direction, after omitting the first two
seconds. The acceptance ranges are deliberately broad:

- added RTT must be within the larger of 3 ms or 10% of the target; and
- throughput must reach 65–120% of the configured cap.

These checks catch major configuration mistakes. Passing them does not prove
that the emulation is perfect or that the configured cap equals the exact link
speed. Review `network-validation.json` and the `iperf` JSON files for
retransmissions or unexpected rate limits. If a check fails, fix the network
before continuing. Do not mix network-validation data with TLS timing data.

## 🧪 4. Pilot and packet validation

```bash
sudo python3 run.py --mode pilot --out results/pilot-01
python3 analyze.py results/pilot-01
sudo python3 run.py --mode capture --out results/capture-01
```

By default, the pilot uses profiles A and F. For each profile, it runs 5
warm-up pairs followed by 50 measured pairs. Capture mode uses profiles A, C,
and F, with 5 warm-up pairs and 5 measured pairs per profile.

Every pair contains one handshake with each group. A seeded random choice
decides which group runs first. Keep pilot and capture data out of the final
analysis of the main run.

Capture mode creates `validation.pcap` and a local `tls.keys` file. To decrypt
the capture in Wireshark, set the TLS preference **(Pre)-Master-Secret log
filename** to the generated key file. You can instead create a text version
with `tshark`; use the real absolute path on your machine:

```bash
tshark -r results/capture-01/validation.pcap \
  -o "tls.keylog_file:$(pwd)/results/capture-01/tls.keys" \
  -Y 'tls.handshake' -V > results/capture-01/decoded-handshakes.txt
```

🔍 Inspect at least one classical and one hybrid connection for every captured
profile. The `local_port` field in `trials.jsonl` identifies the corresponding
TCP stream. Remember that the capture also contains the warm-up connections.

For each connection, confirm that:

- TLS 1.3 is used;
- only the intended group is offered and that same group is negotiated;
- there is one ClientHello and one ServerHello, with no HelloRetryRequest;
- the certificate flight and both Finished messages are present;
- there is no PSK resumption and no NewSessionTicket;
- both groups use the same one-byte Q/A application exchange;
- the X25519 key shares are 32/32 bytes;
- the hybrid key shares are 1,216/1,120 bytes;
- in this fixed setup, the hybrid TLS streams contain 1,176 more
  client-to-server bytes and 1,098 more server-to-client bytes; and
- the zero-loss experiment has no unexplained retransmissions, resets, or queue
  drops.

The generated TLS keys can decrypt only these deliberately created local test
sessions. Key logging is enabled in capture mode only, because writing keys to
disk could disturb the timing measurements. Pilot and main modes explicitly
remove the key-log setting from child-process environments.

Packets are captured on the server's `s0` interface, which records each packet
once. The capture does not use the `any` interface. A captured frame's length
is not its physical wire length, because a virtual-interface capture omits
physical-medium overhead. Checksum offload can also make Wireshark display TCP
checksum warnings; a warning alone does not mean that a packet is corrupt.

✅ Accept the pilot only if all correctness checks pass, there are no
unexplained failures or byte-count changes, RTT and throughput look reasonable,
and there is no strong unexplained drift. The analysis does not calculate an
interval from a single pilot block.

Use the pilot to estimate how long the main run will take. Before starting the
main run, freeze the protocol. If you plan to change the trial count, network
conditions, timeout, or any other setting, write down both the change and its
reason in your lab notes.

## ⏱️ 5. Collect the main experiment

```bash
sudo python3 run.py --mode main --out results/main-01 --client-cpu 0 --server-cpu 2 --seed 20261101
python3 analyze.py results/main-01
```

The default main experiment uses:

- 30 rounds;
- all six profiles in every round, in a seeded random order;
- 5 warm-up pairs for each profile; and
- 20 measured pairs for each profile.

🧮 In total, this gives **600 measured trials per group per profile**, or **7,200
measured handshakes**, plus 1,800 warm-up handshakes.

The client and server processes stay alive for the entire experiment, but each
trial gets a new kernel socket, SSL connection, and set of ephemeral keys. Only
one trial runs at a time. The runner prints one progress line after each
profile/block finishes.

Expect collection to take tens of minutes. Use the pilot to estimate the time
more accurately for your laptop. A complete TLS `close_notify` exchange happens
after each trial, but its time is outside the measurement windows.

You can override the defaults with `--rounds`, `--pairs`, `--profiles`, and
`--warmup`. All overrides are saved in the metadata. Decide on them before
collecting the main data; do not change the design because a confidence
interval looks more or less favourable.

📁 Always use a new output directory. The runner refuses to overwrite an
existing one. If a run is interrupted, its completed rows remain on disk and
the run is marked `complete: false`. Do not quietly continue it in the same
dataset or report it as a complete run.

## 📏 Measurement boundaries and controls

| Field                                                     | Definition                                                                                 |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `tcp_ns`                                                  | From immediately before nonblocking TCP connect to established connection                  |
| `tls_ns`                                                  | Monotonic wall time around the SSL_connect/retry/poll loop, after TCP connects             |
| `client_cpu_ns`                                           | Thread CPU time around that handshake loop; includes verification and harness overhead     |
| `response_ns`                                             | From before TCP connect through receiving the one-byte application response                |
| `tls_sent_bytes`                                          | Successful socket BIO writes through client handshake completion, before application write |
| `tls_received_bytes`                                      | Successful socket BIO reads through client handshake completion, before application read   |
| `status`, `phase`, `error`                                | Outcome and where failure occurred; failed measurements may be -1                          |
| `hrr`, Finished counts, `reused`, `verify_result`         | Per-trial protocol checks                                                                  |
| `round`, `profile`, `pair`, `order`, `warmup`, `sequence` | Experimental design and ordering identifiers                                               |

⏱️ All time values are stored as integer nanoseconds. That storage precision
does not imply nanosecond measurement accuracy. C++ reads the monotonic and
thread CPU clocks; Python does not time the TLS operations.

The connect and handshake timings exclude configuration work such as setting up
the SSL context and trust store, creating the SSL object, selecting the group,
setting SNI, and applying socket options. They do include ephemeral key
generation performed inside the TLS handshake. Certificate-chain and hostname
verification happen during `SSL_connect`, so they are also included. There is
no DNS lookup: the client connects to a fixed IP address while using
`bench.test` for SNI and hostname verification.

Nonblocking sockets allow the runner to enforce an absolute deadline. `tls_ns`
includes the small amount of retry/poll-loop and tracing-callback overhead, as
well as time spent in OpenSSL, scheduling, and network waits. It is therefore a
full handshake measurement, not a standalone cryptographic algorithm benchmark.

Client CPU time excludes sleeping, but includes certificate verification and
client-side I/O work. It does not measure server CPU time, combined endpoint
CPU time, energy use, or cryptography in isolation.

`response_ns` includes a small amount of harness work between phases, such as
reading timers and BIO counters. It represents a fixed, minimal application
transaction—not an HTTP request or a browser page load. A successful
`SSL_connect` does not by itself prove that the server processed the client's
Finished message. Receiving the fixed application response confirms that it
did.

The byte counters include TLS records, authentication tags, and any
compatibility ChangeCipherSpec message. They exclude TCP/IP headers, duplicate
retransmitted bytes, acknowledgements, shutdown messages, and application data.
The server sends neither tickets nor unsolicited application data, so BIO
read-ahead does not add those bytes. The counters do include all incoming
server handshake bytes and the outgoing client Finished message.

The expected total difference of 2,274 bytes is a useful check for this exact
configuration. It is not a universal estimate of TCP or wire overhead.

The following controls stay fixed throughout the experiment:

- TLS 1.3 only;
- `TLS_AES_128_GCM_SHA256`;
- an RSA-PSS-SHA256 handshake signature;
- one static RSA-2048 server certificate and trust root;
- no early data, session cache, or ticket issuance;
- one offered group per trial;
- no client certificate or ALPN;
- `TCP_NODELAY` at both endpoints;
- IPv4 and an MTU of 1500; and
- fixed CPU affinities.

Within each network profile, the selected key-establishment group is the
intended independent variable.

Each trial has a 5-second deadline covering the TCP connection, TLS handshake,
and application exchange. Shutdown has a separate 5-second deadline outside the
latency measurement. The server allows up to 10 seconds to handle a connection.

A timed-out trial remains in the data and is never replaced by a successful
retry. A shutdown failure also makes the trial unsuccessful, even if earlier
timing fields were recorded. If failures occur, analyse them by phase.

The runner stops collection—but preserves existing data—after a warm-up
failure, a setup/negotiation/control failure, or an unexpected qdisc drop. It
keeps other connection failures and continues collecting. A watchdog aborts the
run if the client stops responding.

## 📊 6. Analysis and interpretation

`analyze.py` creates the following files:

- 📄 `summary.md` and `summary.json` — attempts, successes, timeouts, errors,
  group means, medians, p95 values, paired effects, and byte differences;
- 📈 `handshake-distributions.pdf` and `.png` — a separate distribution for each
  profile, with outliers retained;
- 📊 `overhead.pdf` and `.png` — mean hybrid-minus-classical latency with block
  bootstrap intervals;
- 📏 `handshake-bytes.pdf` and `.png` — handshake byte counts in each direction;
  and
- 🔎 `drift.png` — TLS latency and client CPU time in trial order for every
  profile.

The analysis keeps only complete, successful pairs when calculating timing
effects. Within each round/profile block, it averages the measurements for each
group. It then gives every block equal weight and subtracts the classical mean
from the hybrid mean. Relative overhead is this difference divided by the
equally weighted classical mean.

When there are no missing trials, this produces the same difference as simply
subtracting the two trial means. Missing pairs can change exactly what is being
estimated, so their counts are always reported.

For the confidence interval, the script resamples complete round/profile blocks
10,000 times using a recorded seed. Both groups stay together during
resampling. The 2.5th and 97.5th percentiles form the reported 95% interval.

The script requires at least 10 blocks before it reports an interval; the main
design plans 30. This minimum is only a reporting safeguard, not proof that the
sample is statistically adequate.

The analysis does not remove outliers and does not stop collection based on
statistical significance. The p95 is descriptive and has no precision claim.
Bootstrap intervals also depend on the blocks being sufficiently independent.
Long-lasting thermal drift or autocorrelation can make an interval look too
narrow.

🔍 Inspect the drift plots and block telemetry. If they reveal a problem,
investigate and document it. Do not delete slow measurements merely because
they make an interval wider.

Latency summaries describe successful trials only. Missing or failed pairs can
introduce selection bias, so always report failures alongside timing results.
The controlled zero-loss experiment should normally have no failures.

If a confidence interval crosses zero, the experiment did not find a clear
difference for that profile. Report absolute milliseconds as well as percentage
overhead, especially for the near-zero-RTT baseline. TLS wall time is the
primary outcome; response time and client CPU time are secondary outcomes.

Do not search across conditions for whichever result happens to be
statistically significant. Treat packet-loss experiments or tests of other
groups as separate exploratory work.

## 📦 7. Archive and clean up

```bash
sudo ./net.sh down
tar -czf pqc-benchmark-completed.tar.gz README.md bench.cpp Makefile certs.sh net.sh run.py analyze.py selftest.py test_analysis.py certs results
```

🔐 Keep the archive locally and make a backup. It contains private keys for the
generated local CA and server, plus the capture session keys. Never reuse these
keys for a real service.

Each run's snapshot intentionally includes the code, binary, and public
certificates, but not private keys. To reproduce the experiment fully, you must
also preserve the original `certs` directory.

`net.sh down` refuses to remove a namespace while it still contains running
processes; it will not kill unrelated work automatically. Pressing Ctrl+C in
the runner normally stops the child processes it created. If cleanup still
fails, inspect the remaining processes with:

```bash
sudo ip netns pids pqb-c
sudo ip netns pids pqb-s
```

🔁 For the independent repeat on the following day, reuse the same software,
certificates, and settings. Use a new output directory and a new recorded seed.
Report the repeat separately before considering any combined analysis. Do not
merge results from different days without accounting for run/day effects.

## 📚 Sources and scope

- [OpenSSL groups and prediction/HRR behaviour](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/)
- [Negotiated group name](https://docs.openssl.org/3.5/man3/SSL_group_to_name/)
- [`SSL_connect` semantics](https://docs.openssl.org/3.5/man3/SSL_connect/)
- [Disabling TLS 1.3 tickets](https://docs.openssl.org/3.5/man3/SSL_CTX_set_num_tickets/)
- [Message tracing](https://docs.openssl.org/3.5/man3/SSL_CTX_set_msg_callback/)
- [OpenSSL 3.5.5 ClientHello extension construction](https://github.com/openssl/openssl/blob/openssl-3.5.5/ssl/statem/extensions_clnt.c)
- [OpenSSL 3.5.5 server supported-groups extension](https://github.com/openssl/openssl/blob/openssl-3.5.5/ssl/statem/extensions_srvr.c)
- [`netem` behaviour and limitations](https://man7.org/linux/man-pages/man8/tc-netem.8.html)

The conclusions apply only to this OpenSSL build, computer, authentication
setup, and set of emulated network conditions. Because one laptop hosts the
client, server, and network emulator, CPU scheduling and shared package power
remain limitations.

This experiment complements the public-site deployment survey. It does not
directly measure browser performance or the overhead of any particular website
in that survey.

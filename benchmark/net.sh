#!/usr/bin/env bash
# Only touches these three dedicated namespaces. No host firewall/routing edits.
set -euo pipefail
[[ $EUID == 0 ]] || {
  echo 'Run with sudo.' >&2
  exit 1
}
exists() { ip netns list |
  awk '{print $1}' |
  grep --fixed-strings -line-regexp --quiet "$1"; }
case "${1:-}" in
up)
  for ns in pqb-c pqb-r pqb-s; do
    if exists "$ns"; then
      echo "$ns already exists. Inspect it; do not overwrite." >&2
      exit 1
    fi
  done
  created=()
  trap 'for ns in "${created[@]}"; do ip netns del "$ns"; done' ERR
  for ns in pqb-c pqb-r pqb-s; do
    ip netns add "$ns"
    created+=("$ns")
  done
  ip -netns pqb-c link add c0 type veth peer name rc netns pqb-r
  ip -netns pqb-s link add s0 type veth peer name rs netns pqb-r
  ip -netns pqb-c addr add 10.203.1.2/30 dev c0
  ip -netns pqb-r addr add 10.203.1.1/30 dev rc
  ip -netns pqb-r addr add 10.203.2.1/30 dev rs
  ip -netns pqb-s addr add 10.203.2.2/30 dev s0
  for ns in pqb-c pqb-r pqb-s; do
    ip -netns "$ns" link set lo up
    ip netns exec "$ns" sysctl --quiet --write net.ipv4.tcp_no_metrics_save=1
  done
  for item in 'pqb-c c0' 'pqb-r rc' 'pqb-r rs' 'pqb-s s0'; do
    read -r ns dev <<<"$item"
    ip -netns "$ns" link set "$dev" mtu 1500 txqueuelen 10000 up
    for feature in tso gso gro; do
      ip netns exec "$ns" ethtool --features "$dev" "$feature" off
    done
  done
  ip netns exec pqb-r sysctl --quiet --write net.ipv4.ip_forward=1
  ip -netns pqb-c route add 10.203.2.0/30 via 10.203.1.1
  ip -netns pqb-s route add 10.203.1.0/30 via 10.203.2.1
  trap - ERR
  "$0" profile A
  ;;
profile)
  case "${2:-}" in
  A) args=() ;;
  B) args=(delay 10ms rate 100mbit) ;;
  C) args=(delay 25ms rate 100mbit) ;;
  D) args=(delay 50ms rate 100mbit) ;;
  E) args=(delay 25ms rate 10mbit) ;;
  F) args=(delay 25ms rate 1mbit) ;;
  *)
    echo 'Profile must be A, B, C, D, E or F.' >&2
    exit 2
    ;;
  esac
  for dev in rc rs; do
    ip netns exec pqb-r tc qdisc replace dev "$dev" root netem limit 10000 "${args[@]}"
  done
  ;;
show)
  for ns in pqb-c pqb-r pqb-s; do
    ip -netns "$ns" -details addr show
    ip -netns "$ns" route show
  done
  for dev in rc rs; do
    ip netns exec pqb-r tc -stats -details qdisc show dev "$dev"
  done
  ;;
down)
  # Refuse to remove a namespace that still contains a running process.
  for ns in pqb-c pqb-r pqb-s; do
    if exists "$ns" && [[ -n $(ip netns pids "$ns") ]]; then
      echo "$ns has running processes. Stop the benchmark/capture first." >&2
      exit 1
    fi
  done
  for ns in pqb-c pqb-r pqb-s; do
    if exists "$ns"; then
      ip netns del "$ns"
    fi
  done
  ;;
*)
  echo 'Usage: sudo ./net.sh up|profile A-F|show|down' >&2
  exit 2
  ;;
esac

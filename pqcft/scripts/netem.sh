#!/usr/bin/env bash
# Validate the userspace channel emulator against real kernel-level netem.
#
# The Python relay in pqcft/channel.py is portable and gives exact control over
# disruption timing, which is what makes baseline and proposed runs comparable.
# But it is a userspace approximation. This script applies the *same* nominal
# impairments with tc/netem on the loopback interface so you can check that the
# emulator's numbers track the kernel's. Reviewers will ask; have the answer.
#
# Requires root (CAP_NET_ADMIN). Will NOT work in most containers.
#
#   sudo ./scripts/netem.sh setup   --latency 4 --jitter 1.5 --loss 0.1 --rate 200mbit
#   sudo ./scripts/netem.sh blockage --duration 0.5     # one outage
#   sudo ./scripts/netem.sh teardown
#
# Then run the transfer against a plain receiver (no SimulatedChannel):
#   python3 -m pqcft.cli recv --port 9000 --out ./received &
#   python3 -m pqcft.cli send payload.bin --port 9000

set -euo pipefail

IFACE="${IFACE:-lo}"
LATENCY_MS=4
JITTER_MS=1.5
LOSS_PCT=0
RATE="200mbit"
DURATION=0.5

die() { echo "error: $*" >&2; exit 1; }

need_root() {
  [[ $EUID -eq 0 ]] || die "must run as root (tc needs CAP_NET_ADMIN)"
  command -v tc >/dev/null || die "tc not found; install iproute2"
}

parse() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --latency)  LATENCY_MS="$2"; shift 2 ;;
      --jitter)   JITTER_MS="$2";  shift 2 ;;
      --loss)     LOSS_PCT="$2";   shift 2 ;;
      --rate)     RATE="$2";       shift 2 ;;
      --duration) DURATION="$2";   shift 2 ;;
      --iface)    IFACE="$2";      shift 2 ;;
      *) die "unknown option: $1" ;;
    esac
  done
}

cmd_setup() {
  need_root
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  # netem delay applies per-direction; on loopback both directions traverse the
  # same qdisc, so a packet sees the delay twice -- halve it to get the intended
  # one-way latency and match ChannelProfile.latency_ms semantics.
  local one_way
  one_way=$(python3 -c "print(f'{$LATENCY_MS/2}ms')")
  local jit
  jit=$(python3 -c "print(f'{$JITTER_MS/2}ms')")

  tc qdisc add dev "$IFACE" root handle 1: netem \
      delay "$one_way" "$jit" distribution normal \
      loss "${LOSS_PCT}%"
  tc qdisc add dev "$IFACE" parent 1: handle 2: tbf \
      rate "$RATE" burst 32kbit latency 50ms

  echo "netem active on $IFACE: ${LATENCY_MS}ms±${JITTER_MS}ms, ${LOSS_PCT}% loss, $RATE"
  tc qdisc show dev "$IFACE"
}

cmd_blockage() {
  need_root
  echo "blockage: dropping all traffic on $IFACE for ${DURATION}s"
  tc qdisc change dev "$IFACE" root handle 1: netem loss 100%
  sleep "$DURATION"
  tc qdisc change dev "$IFACE" root handle 1: netem \
      delay "$(python3 -c "print(f'{$LATENCY_MS/2}ms')")" \
      "$(python3 -c "print(f'{$JITTER_MS/2}ms')")" distribution normal \
      loss "${LOSS_PCT}%"
  echo "link restored"
}

cmd_teardown() {
  need_root
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  echo "netem removed from $IFACE"
}

[[ $# -ge 1 ]] || die "usage: $0 {setup|blockage|teardown} [options]"
sub="$1"; shift
parse "$@"

case "$sub" in
  setup)    cmd_setup ;;
  blockage) cmd_blockage ;;
  teardown) cmd_teardown ;;
  *) die "unknown command: $sub" ;;
esac

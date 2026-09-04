# Results summary

Total runs: 168  |  delivered: 168  |  did not finish in budget: 0  |  **corrupted deliveries: 0**

Performance means below are over *delivered* runs only. A run that exhausted its retry budget is a censored observation -- its goodput describes an aborted prefix, not a transfer -- so it is reported as a completion rate instead of averaged in.

## Steady state (no disruptions)

| Arm | Goodput (Mbps) | Handshake (ms) | KEX wire (B) |
|---|---|---|---|
| Baseline (X25519, no ckpt) | 47.80 | 13.6 | 64 |
| ML-KEM, no ckpt | 47.08 | 26.7 | 2272 |
| X25519 + checkpoint | 47.66 | 12.4 | 64 |
| Proposed (ML-KEM + ckpt) | 46.88 | 25.6 | 2272 |

## Under disruption

| Arm | Goodput (Mbps) | Retransmission overhead | Mean recovery (s) | Wasted MB |
|---|---|---|---|---|
| Baseline (X25519, no ckpt) | 21.59 | 68.3% | 0.77 | 7.35 |
| ML-KEM, no ckpt | 21.46 | 66.1% | 0.78 | 7.16 |
| X25519 + checkpoint | 27.47 | 10.8% | 0.77 | 0.83 |
| Proposed (ML-KEM + ckpt) | 27.12 | 9.4% | 0.78 | 0.79 |

## Completion rate under disruption

| Arm | Completed | Rate |
|---|---|---|
| Baseline (X25519, no ckpt) | 36/36 | 100% |
| ML-KEM, no ckpt | 36/36 | 100% |
| X25519 + checkpoint | 36/36 | 100% |
| Proposed (ML-KEM + ckpt) | 36/36 | 100% |

## Headline

- Retransmission overhead: 68.3% -> 9.4% (86% reduction)
- Goodput under disruption: 21.59 -> 27.12 Mbps (+26%)
- ML-KEM handshake cost: 2272 B vs 64 B (35.5x wire), 5.98 ms vs 0.15 ms CPU
- Steady-state goodput impact of ML-KEM: 47.73 -> 46.98 Mbps (-1.6%)

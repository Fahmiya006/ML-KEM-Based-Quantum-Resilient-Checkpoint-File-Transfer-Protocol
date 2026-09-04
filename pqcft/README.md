# ML-KEM-Based Quantum-Resilient Checkpoint File Transfer Protocol for Simulated 6G Networks

A working implementation and evaluation harness for a file-transfer protocol that
combines **ML-KEM-768** (NIST FIPS 203) post-quantum key establishment,
**AES-256-GCM** authenticated bulk encryption, and a **checkpoint/resume**
mechanism that continues an interrupted transfer from the last verified chunk
instead of restarting — all measured over a configurable simulated 6G channel.

| Register No. | Name |
|---|---|
| 2024503003 | Fathima Fahmiya S |
| 2024503005 | Nivriti Muthuvairavan |
| 2024503577 | Mounika K M |
| 2024503579 | Tharun P |

---

## Quick start

```bash
pip install kyber-py cryptography matplotlib pytest

# self-contained demo: receiver + simulated 6G channel + sender, one process
python3 -m pqcft.cli demo --size 12 --disruptions 3 --duration 0.6

# test suite (19 tests: RFC 5869 vectors, FIPS 203 sizes, resume correctness)
python3 -m pytest tests/ -v

# full evaluation + figures
python3 experiments/run_experiments.py --repeats 3 --out results/results.csv
python3 experiments/plot_results.py --csv results/results.csv --outdir results/figs
```

Real two-host use:

```bash
python3 -m pqcft.cli recv --port 9000 --out ./received     # receiver
python3 -m pqcft.cli send bigfile.iso --host <rx> --port 9000
```

---

## What's here

```
pqcft/
  crypto.py       ML-KEM-768 + X25519 behind one KEM interface; HKDF; chunk AEAD
  protocol.py     wire format and framing
  client.py       sender: chunk, encrypt, transmit, detect outage, resume
  server.py       receiver: decapsulate, verify, reassemble, checkpoint
  checkpoint.py   atomic, self-authenticating checkpoint records
  channel.py      simulated 6G channel (latency, jitter, bandwidth, disruptions)
  metrics.py      metric collection and derived statistics
  cli.py          recv / send / demo
experiments/
  run_experiments.py   2x2 factorial evaluation harness
  plot_results.py      figures + summary.md for the report
scripts/netem.sh       validate the emulator against real kernel netem
tests/test_protocol.py
```

---

## Design decisions worth defending in the viva

**The evaluation is a 2×2 factorial, not baseline-vs-proposed.** The plan asks
you to compare "traditional key exchange vs ML-KEM" *and* "no-checkpoint vs
checkpoint-based recovery." If you only run those two arms, every measured
difference is confounded — you cannot tell whether a goodput gain came from the
KEM or from the checkpointing. So four arms run over identical channel seeds:

| Arm | KEM | Checkpointing | Isolates |
|---|---|---|---|
| `baseline-tls` | X25519 ECDHE | no | Week 4 baseline |
| `pq-nockpt` | ML-KEM-768 | no | cost of the KEM alone |
| `classical-ckpt` | X25519 ECDHE | yes | gain from checkpointing alone |
| `proposed` | ML-KEM-768 | yes | the full system |

**Nonces are derived, not transmitted.** The GCM nonce is `salt ‖ counter(index)`.
Chunk index is unique per session, so uniqueness holds without spending 12 bytes
per chunk, and — the part that matters here — a *resumed* transfer reconstructs
the exact nonce for chunk N from the index alone. Random nonces would have forced
the checkpoint to persist a nonce table.

**The session key is bound to the handshake transcript**, not just the shared
secret: `key = HKDF(ss, salt=SHA256(HELLO ‖ ek ‖ ct))`. A tampered HELLO (a
downgraded `scheme`, an altered `chunk_size`) yields a different key on each side
and the first chunk fails to authenticate. `test_session_key_binds_to_transcript`
asserts this.

**AAD binds index *and* total chunk count.** Binding the index stops chunk
reordering/replay; binding the total stops a truncation attack where an attacker
drops trailing chunks and the receiver accepts a short file. Both are asserted in
`test_chunk_cipher_roundtrip_and_aad_binding`.

**Checkpoints are self-authenticating and atomically written.** Each record
carries a SHA-256 over its canonical JSON body and is written tmp-then-`os.replace`.
A torn or edited checkpoint loads as `None` and the transfer restarts — degrading
to baseline behaviour rather than resuming from a resume point an attacker chose.
This is the "safeguards against corrupted/partial checkpoints" item in Week 7.

**The receiver's checkpoint is authoritative, and only counts *verified* chunks.**
A chunk is checkpointed only after it decrypts, authenticates, and lands on disk.
The resume point is therefore never optimistic — no ambiguity about whether the
last chunk before an outage half-arrived.

### Why a userspace channel emulator instead of `tc`/netem

The plan lists Mininet/NS-3/netem. All three need `CAP_NET_ADMIN` and a real
interface, which makes the experiment un-runnable in a container, in CI, or on a
teammate's laptop — and, more importantly, none of them let you guarantee that
the baseline run and the proposed run see *byte-for-byte identical outage
timing*. Without that guarantee the comparison isn't controlled.

`channel.py` is a TCP relay that applies one-way latency with Gaussian jitter, a
bandwidth ceiling, and disruption events at exact seeded timestamps. `scripts/netem.sh`
applies the same nominal impairments via real kernel netem so you can show the
emulator's numbers track the kernel's — the honest answer when a reviewer asks
"why not netem?"

**Two caveats to state in the report rather than hide:**

1. *Packet loss is not injected at the byte level.* The relay is TCP-to-TCP, so
   kernel retransmission already hides sub-connection loss; corrupting the stream
   would be physically meaningless above TCP. Loss is modelled through its two
   observable effects at the file-transfer layer — reduced goodput (bandwidth
   cap) and connection death (disruption). Use `netem.sh` for true loss.
2. *Socket buffers are capped near the bandwidth-delay product* (128 KB). Left
   at loopback defaults, the sender parks megabytes in its own send buffer and
   calls them "transmitted"; a disruption then appears to destroy far more bytes
   than a real radio link ever would, which inflates the baseline's measured
   waste and flatters the proposed protocol. The cap keeps in-flight loss physical.
   This was found and fixed during development — the uncapped run reported ~42%
   retransmission overhead where the capped run reports ~13%.

---

## Results

From `results/figs/summary.md` — **168 runs, 168 delivered, 0 corrupted, 0 that
failed to finish** (3 repeats x 2 file sizes x 4 disruption counts x 2 outage
durations x 4 arms; 200 Mbps / 4 ms +/-1.5 ms):

**Steady state (no disruptions) — the KEM is essentially free.**
ML-KEM-768 costs ~2272 B of handshake wire vs 64 B for X25519 (≈35×) and a few
ms of CPU, but that is a one-time per-session cost. Goodput impact is ≈1%,
inside run-to-run noise.

**Under disruption — checkpointing is where everything is won.**
Retransmission overhead drops from **68.3% to 9.4% (an 86% reduction)**, goodput
under disruption rises **21.6 -> 27.1 Mbps (+26%)**, and bytes wasted per
transfer fall from **7.35 MB to 0.79 MB (-89%)**. `pq-nockpt` tracks `baseline-tls`, and `proposed`
tracks `classical-ckpt` — which is exactly the point of the factorial design:
**the post-quantum upgrade is not what costs you, and the checkpointing is not
made worse by it.** That is the paper's thesis in one sentence.

**Recovery time floors at the outage duration, and is identical across arms
(~0.78 s for both).** This is not a null result, it is the control: recovery time
measures *how fast the link comes back*, which the channel dictates, not the
protocol. The proposed protocol resumes within ~0.03-0.05 s of the link
returning, regardless of how much of the file was already sent. The baseline
also "recovers" that quickly but recovers *to chunk zero* —
which is why its recovery time looks similar while its goodput and waste do not.
Report recovery *and* waste together or the baseline looks better than it is.

**Which disruptions benefit most** (Week 9–10 question): checkpointing's
advantage grows with (a) file size and (b) how late the outage lands. An outage
at 90% completion costs the baseline the entire 90%; it costs the proposed
protocol at most `checkpoint_interval + in-flight window`. The retransmission
overhead of the proposed protocol is *bounded by a constant*; the baseline's
grows with bytes already sent.

Figures in `results/figs/`:
- `fig1_retransmission.png` — overhead vs disruption count, all four arms
- `fig2_goodput.png` — goodput vs disruption count
- `fig3_recovery.png` — recovery time against the outage-duration floor
- `fig4_kem_cost.png` — ML-KEM vs X25519 handshake wire bytes and CPU
- `fig5_completion.png` — completion rate under disruption (100% for all arms)
- `summary.md` — the numbers to paste into the report

**The headline number scales with severity.** At the harshest condition
(16 MB, 4 x 1.0 s outages) the gap is not subtle: baseline burns **138%**
retransmission overhead at 12.3 Mbps, while the proposed protocol spends
**7.9%** at 21.3 Mbps. The baseline's waste grows with bytes already sent; the
proposed protocol's is bounded by the checkpoint interval. Report the harsh
condition alongside the mean, or the design's whole point is averaged away.

### A bug this evaluation caught (worth telling the examiner)

The first full run reported 6 "integrity failures", all at the harshest
condition. Two distinct causes hid behind that one label:

1. **A measurement artifact, not a protocol fault.** The sender retried a fixed
   40 times with 0.1 s backoff — a ~4 s budget against 4 x 1.0 s of outage. The
   runs were cut off by the *client's configuration*, not by the protocol. A
   fixed attempt count is a disguised time limit; the retry budget is now
   wall-clock (`retry_budget_s`) with capped exponential backoff.
2. **A real protocol bug.** The receiver had written and verified the complete
   file, but the DONE frame died in the outage it was racing. The sender
   concluded failure and restarted the session — *destroying a finished
   transfer.* Completion is now idempotent: the receiver remembers verified
   sessions and re-announces DONE on reconnect instead of starting over. Locked
   down by `test_completion_is_idempotent_when_done_frame_is_lost`.

The harness now separates **corrupted delivery** (a bug) from **did not finish
in budget** (a result), and verifies the output hash against the source
independently of what the sender believes. Performance means are computed over
delivered runs only — a run that exhausts its budget is a censored observation
whose goodput describes an aborted prefix, and averaging it in would flatter
whichever arm failed most.

---

## Tuning the checkpoint interval (Week 7)

`--interval N` writes a checkpoint every N verified chunks. The trade-off:

- **Small N**: less data re-sent after an outage, more fsync calls. At N=1 with
  64 KB chunks you fsync every 64 KB.
- **Large N**: cheaper, but up to `N × chunk_size` of verified data is re-sent.

Worst-case re-sent bytes ≈ `(N × chunk_size) + in-flight window`. With the
defaults (N=8, 64 KB chunks) that's ~512 KB + ~256 KB regardless of file size —
which is why proposed-arm overhead *falls* as a percentage as files grow, while
baseline overhead does not.

## Security note on `--resume-mode cached`

`cached` persists session key material in the checkpoint so a resume skips the
KEM handshake. It is implemented so you can *measure* the handshake's share of
recovery time — but it writes a live AES key to disk in plaintext, so the default
is `rekey` (fresh ML-KEM handshake on every reconnect). Don't ship `cached`
without wrapping the checkpoint in an OS keystore or a password-derived KEK, and
say so in the report rather than letting a reviewer find it.

## Known limitations (state these; don't wait to be asked)

- **No forward secrecy across resumes in `cached` mode**, per above.
- **The receiver is not authenticated.** This is a KEM + AEAD study, not a full
  TLS replacement: an active attacker could stand in as the receiver. Real
  deployment needs the KEM public key bound to a certificate or a signature
  (ML-DSA / FIPS 204) over the transcript. The transcript binding already gives
  the hook to attach that.
- **Single-stream TCP.** Real 6G edge work would want QUIC (connection migration
  across a handover would remove most reconnection cost outright — arguably the
  strongest "Future Work" item).
- **`kyber-py` is a pure-Python ML-KEM**, correct against FIPS 203 vectors but
  not constant-time and not fast. Absolute KEM CPU numbers are pessimistic;
  liboqs would be ~100× faster. The *relative* conclusion (KEM cost is dwarfed by
  checkpoint gains) only gets stronger with liboqs.
- Loss and buffer caveats, above.

## References

1. NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard," FIPS 203, Aug. 2024.
2. Krawczyk & Eronen, "HKDF," RFC 5869, 2010.
3. Bernstein & Lange, "Post-quantum cryptography," *Nature* 549, 2017.
4. Sosnowski et al., "The Performance of Post-Quantum TLS 1.3," CoNEXT Companion '23.
5. Serghiou et al., "Terahertz Channel Propagation Phenomena... for 6G," *IEEE COMST* 24(4), 2022.

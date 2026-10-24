# PQ6G Transfer: Secure Checkpoint/Resume File Transfer over a Simulated 6G Link

A working model of a post-quantum file transfer that survives link blockages. A file is sent from a sender to a receiver through an emulated 6G link. The key exchange uses ML-KEM-768, each chunk is encrypted with AES-256-GCM, and the receiver saves signed checkpoints, so after a blockage the transfer resumes from the last checkpoint instead of starting over.

A live dashboard shows the beam, the blockages, the checkpoints and the resume. A built-in simulated quantum attacker shows why ML-KEM is used instead of RSA.

## What is real and what is simulated

| Part | Status |
|---|---|
| ML-KEM-768 key exchange (FIPS 203) | Real |
| AES-256-GCM chunk encryption, SHA-256 hash chain, HMAC-signed 84-byte checkpoints | Real |
| Checkpoint saving, resume and whole-file verification | Real (data is flushed to disk, TCP connections really break) |
| 6G radio link | Simulated: a relay applies rate, delay and random beam blockages using the 6G terahertz parameters from the paper's Table I. There is no real radio. |
| Quantum computer | Simulated: Shor's algorithm runs on a classical state-vector simulator against a toy 11-bit RSA key. There is no quantum hardware. |

The security and recovery protocol is real. The environment around it (the link and the quantum attacker) is simulated.

## Features

- **Key exchange:** ML-KEM-768. Only a public key (1184 B) and a ciphertext (1088 B) cross the link. A pure-Python ML-KEM is included as a fallback.
- **Encrypted chunks:** 64 KB chunks, AES-256-GCM, a hash chain linking the chunks, and deterministic re-sealing so a re-sent chunk is byte-identical.
- **Signed checkpoints:** the receiver saves an 84-byte HMAC-signed record every N chunks, written atomically.
- **Resume:** after a cut, the sender checks the checkpoint's signature and hash chain, skips the key exchange and re-sends only the chunks after it.
- **Attack handling:** tampered chunks are rejected, a forged checkpoint is refused, and a replayed old checkpoint only costs extra re-sending.
- **Link emulator:** rate, delay, Poisson-timed blockages (detect time, then reconnect time), manual cut button, and an eavesdropper recording.
- **Quantum attacker:** records the transfer, then attacks it. The ML-KEM transfer holds, and the same file sent with a toy RSA key exchange is recovered.
- **Dashboard:** choose the file in the page, then step through the transfer with Presenter buttons, or run everything at once. A phone page shows "File received".

## Requirements

- Python 3.10 or newer
- The `cryptography` package (`python3 -m pip install cryptography`). If your version has no native ML-KEM, the bundled pure-Python version is used (slower).
- A browser. Nothing else to install.

## Quick start

From this folder:

```bash
python3 -m pq6g selftest        # 17 checks, should all pass
python3 -m pq6g demo
```

Open `http://localhost:8080`, choose the file to send, and use the Presenter buttons:

1. **Start**: key exchange
2. **Send the data**
3. **Cut the link**: the beam is blocked and the connection breaks
4. **Resume from the checkpoint**
5. **Finish the transfer**: the whole file is verified
6. **Quantum attack on this transfer**: fails (ML-KEM)
7. **Quantum attack on old RSA**: succeeds, for comparison (a toy 11-bit key)

**Run everything at once** does all of it with one click.

To open the dashboard on a phone, use the `/phone` address printed in the terminal (same Wi-Fi). It shows the status, progress and "File received", and offers a Save button for the verified file. That last download is an ordinary Wi-Fi download from the laptop, outside the simulated link.

If `python3 -m pq6g` says "No module named pq6g", you are not in the folder that contains `pq6g/`. The single file `pq6g.pyz` also works from anywhere: `python3 pq6g.pyz demo`.

## Laptop to phone (if Termux is available)

On the phone:
```bash
pkg install python python-cryptography
python pq6g.pyz receive --listen 0.0.0.0:9000 --dashboard 8080
```
On the laptop:
```bash
python3 -m pq6g send FILE --to PHONE_IP:9000 --link 6g-demo --dashboard 8081
```
The received file is saved in `received/` in Termux. Add `--persist` on the receiver so it survives being killed.

## Commands

| Command | What it does |
|---|---|
| `demo [FILE]` | Everything on one machine with the dashboard. Leave out FILE to choose it in the page. |
| `send FILE --to HOST:PORT` | Send a file through the simulated link to a receiver |
| `receive` | Run the receiver |
| `attack CAPTURE --original FILE` | Run the simulated quantum attacker on a recording |
| `makefile PATH --mb N` | Create a test file |
| `selftest` | Crypto and protocol checks |

Useful options: `--link {5g-mmwave,b5g,6g-thz,6g-demo,6g-slow,ideal}`, `--n` (checkpoint every N chunks), `--cut-after 1000` (cut the link after chunk 1000), `--attack tamper:300 | forge | replay`, `--kem {mlkem768,mlkem768-pure,rsa-toy}`, `--mode restart` (the baseline without checkpoints), `--ckpt-delay-ms` (emulate slow phone storage).

## Results

All measured on one machine over loopback with the emulated link (see `evidence/` and `report.html`).

- **Clean transfer:** 100 MiB in 4.5 s, SHA-256 identical.
- **Cut after chunk 1000, checkpoint every 64:** resumed from chunk 959 and redid 41 chunks, with no second key exchange.
- **Random blockages, 100 MiB:** with checkpoints 5 of 5 runs finished (median 11.5 s). Without checkpoints only 2 of 5 finished within 60 s.
- **Receiver killed with `kill -9`:** restarted from its saved checkpoint and the file arrived intact.
- **Attacks:** a tampered chunk, a forged checkpoint and a replayed checkpoint all ended with an identical file.
- **Quantum attacker:** the toy RSA recording was fully recovered. The ML-KEM recording stayed encrypted.
- **Checkpoint interval:** N between 1 and 32 performed about equally. Larger values re-sent more data.

Five seeds per comparison is a small sample, so read the pattern rather than the exact medians.

## Project layout

```
pq6g/            sender, receiver, link emulator, crypto, quantum attacker, dashboard, presenter
pq6g/web/        dashboard.html (laptop) and phone.html (phone)
pq6g.pyz         the whole program as a single file (for the phone)
scenarios.py     re-runs every scenario and rewrites evidence/
evidence/        event logs and results from the real runs
replays/         recorded runs you can replay in a browser
report.html      summary report of the evidence
```

## Limitations

- The 6G link and the quantum computer are simulations. The RSA key in the attack demo is a tiny toy key, so a normal laptop could break it. It demonstrates the harvest-now-decrypt-later attack, not that real RSA-2048 can be broken today.
- ML-KEM's security rests on the hardness of the Module-LWE problem. No known quantum attack breaks it, which is not a proof that none exists.
- Checkpoint cost includes flushing the received data to disk (about 4 ms per checkpoint here), not only writing the 84-byte record.
- The receiver chooses the session id and the sender speaks first. With `--persist` the receiver stores session keys on disk, which the original design kept in memory only.
- The phone steps are written for Android with Termux and are untested. iPhone is not covered.

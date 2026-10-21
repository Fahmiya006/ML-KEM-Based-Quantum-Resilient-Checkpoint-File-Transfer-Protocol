# PQ6G Transfer: secure checkpoint/resume file transfer over a simulated 6G link

Real: ML-KEM-768 key exchange, AES-256-GCM chunks, SHA-256 hash chain, HMAC-signed 84-byte checkpoints, resume after a cut.
Simulated: the 6G radio (rate, delay, random blockages, done by a relay) and the quantum computer (Shor's algorithm on a state-vector simulator against a toy 11-bit RSA key).
Needs Python 3.10+ and the `cryptography` package (>= 47 for native ML-KEM; otherwise a bundled pure-Python ML-KEM is used, slower).

## Easiest: everything from the dashboard
    python3 -m pq6g demo
Open http://localhost:8080, choose the file to send in the page, then use the Presenter buttons (or "Run everything at once").
Open the `/phone` address it prints on a phone on the same Wi-Fi to see "file received" there.

## Quick start on one machine (laptop only)
    python -m pq6g selftest
    python -m pq6g makefile test.bin --mb 100
    python -m pq6g demo test.bin --link 6g-demo --seed 1
Open http://localhost:8080 (press Enter in the terminal to start). Use the "cut link" button to cut the beam by hand.
`--cut-after 1000 --n 64 --no-random-blockage` reproduces the worked example (resume from chunk 959).

## Laptop to phone (Android with Termux; not tested here, iPhone not covered)
Both devices on the same Wi-Fi.
Phone (Termux):
    pkg install python python-cryptography
    # copy pq6g.pyz to the phone (e.g. laptop: `python -m http.server 8000`, phone: `curl -O http://LAPTOP_IP:8000/pq6g.pyz`)
    python pq6g.pyz receive --listen 0.0.0.0:9000 --dashboard 8080
Laptop:
    python pq6g.pyz send FILE --to PHONE_IP:9000 --link 6g-demo --dashboard 8081
Watch the laptop dashboard at http://localhost:8081 and the phone's at http://PHONE_IP:8080.
The received file is in `received/` on the phone. Add `--persist` on the receiver so it survives being killed.
No-install alternative: run `demo` on the laptop and open `http://LAPTOP_IP:8080` in the phone's browser to watch (the transfer then stays on the laptop).

## Other commands
- `--attack tamper:300 | forge | replay | drop:30` with `--cut-after` to test an active attacker.
- `--capture rec.cap --kem rsa-toy` records what an eavesdropper hears; `python -m pq6g attack rec.cap --original FILE` runs the simulated quantum attack. Repeat with `--kem mlkem768`.
- `--mode restart` is the no-checkpoint baseline. `--ckpt-delay-ms 20` emulates slow phone flash.
- `python scenarios.py all` re-runs every scenario and rewrites `evidence/`. `report.html` summarises it; `replays/*.html` replay recorded runs (open directly in a browser).

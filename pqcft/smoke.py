import os, tempfile, shutil
from pqcft import *
from pqcft.crypto import file_sha256

d = tempfile.mkdtemp()
src = os.path.join(d, "payload.bin")
with open(src, "wb") as f: f.write(os.urandom(8*1024*1024))
h = file_sha256(src)

rx = Receiver(out_dir=os.path.join(d,"out"), state_dir=os.path.join(d,"rxstate")).start()
prof = ChannelProfile.with_disruptions(count=2, duration_s=0.5, first_at_s=0.4, spacing_s=1.2)
ch = SimulatedChannel(("127.0.0.1", rx.port), prof).start()

s = Sender(src, ("127.0.0.1", ch.port), scheme="mlkem", checkpointing=True,
           state_dir=os.path.join(d,"txstate"))
m = s.run()
print("completed", m.completed, "integrity", m.integrity_ok, "attempts", m.attempts)
print("resumed_from", m.resumed_from_chunks, "recovery", m.recovery_times_s)
print("overhead%%", round(m.retransmission_overhead_pct,2), "goodput", round(m.goodput_mbps,2))
print("kex bytes", m.kex_wire_bytes, "kex cpu ms", round(m.kex_cpu_ms,2))
print("hash match", file_sha256(os.path.join(d,"out","payload.bin")) == h)
ch.stop(); rx.stop(); shutil.rmtree(d)

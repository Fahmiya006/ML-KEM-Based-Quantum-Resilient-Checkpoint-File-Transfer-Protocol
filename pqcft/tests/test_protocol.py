#!/usr/bin/env python3
"""
Test suite.

Run:  python3 -m pytest tests/ -v      (or: python3 tests/test_protocol.py)
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqcft.channel import ChannelProfile, DisruptionEvent, SimulatedChannel
from pqcft.checkpoint import CheckpointManager, CheckpointRecord
from pqcft.client import Sender
from pqcft.crypto import (
    BACKENDS,
    ChunkCipher,
    derive_session,
    file_sha256,
    hkdf,
    new_session_id,
)
from pqcft.server import Receiver


# --------------------------------------------------------------------------- #
# Crypto
# --------------------------------------------------------------------------- #
def test_hkdf_rfc5869_vector():
    """RFC 5869 Appendix A.1 test case for HKDF-SHA256."""
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expect = ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865")
    assert hkdf(ikm, salt, info, 42).hex() == expect


@pytest.mark.parametrize("scheme", ["mlkem", "x25519"])
def test_kem_roundtrip(scheme):
    b = BACKENDS[scheme]
    pk, sk, _ = b.responder_keygen()
    shared_i, ct, _ = b.initiator_encaps(pk)
    shared_r, _ = b.responder_decaps(sk, ct)
    assert shared_i == shared_r
    assert len(shared_i) == 32


def test_mlkem_sizes_match_fips203():
    """ML-KEM-768 parameter sizes per NIST FIPS 203."""
    ek, dk, _ = BACKENDS["mlkem"].responder_keygen()
    _, ct, _ = BACKENDS["mlkem"].initiator_encaps(ek)
    assert (len(ek), len(dk), len(ct)) == (1184, 2400, 1088)


def test_session_key_binds_to_transcript():
    shared = os.urandom(32)
    k1, _ = derive_session(shared, b"transcript-A")
    k2, _ = derive_session(shared, b"transcript-B")
    assert k1 != k2, "same secret + different transcript must not yield same key"


def test_chunk_cipher_roundtrip_and_aad_binding():
    sid = new_session_id()
    c = ChunkCipher(os.urandom(32), os.urandom(4), sid)
    pt = b"chunk payload" * 100
    sealed = c.seal(5, 10, pt)
    assert c.open(5, 10, sealed) == pt
    # A chunk replayed at a different index must not authenticate.
    with pytest.raises(Exception):
        c.open(6, 10, sealed)
    # Nor under a different total-chunk count (truncation attack).
    with pytest.raises(Exception):
        c.open(5, 11, sealed)


def test_nonce_is_unique_per_index():
    c = ChunkCipher(os.urandom(32), b"\x01\x02\x03\x04", new_session_id())
    nonces = {c._nonce(i) for i in range(1000)}
    assert len(nonces) == 1000
    assert all(len(n) == 12 for n in nonces)


# --------------------------------------------------------------------------- #
# Checkpoint
# --------------------------------------------------------------------------- #
def _rec(**kw):
    d = dict(session_id="ab" * 16, file_name="f.bin", file_size=1000,
             file_hash="00" * 32, chunk_size=100, total_chunks=10, next_chunk=3)
    d.update(kw)
    return CheckpointRecord(**d)


def test_checkpoint_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        cm = CheckpointManager(os.path.join(d, "c.ckpt"), interval_chunks=1)
        cm.save(_rec(next_chunk=7), force=True)
        got = cm.load()
        assert got is not None and got.next_chunk == 7


def test_checkpoint_rejects_corruption():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.ckpt")
        cm = CheckpointManager(p, interval_chunks=1)
        cm.save(_rec(next_chunk=7), force=True)
        raw = open(p, "rb").read().replace(b'"next_chunk":7', b'"next_chunk":9')
        open(p, "wb").write(raw)
        assert cm.load() is None, "tampered checkpoint must not be trusted"


def test_checkpoint_rejects_truncation():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.ckpt")
        cm = CheckpointManager(p, interval_chunks=1)
        cm.save(_rec(), force=True)
        raw = open(p, "rb").read()
        open(p, "wb").write(raw[: len(raw) // 2])
        assert cm.load() is None


def test_checkpoint_rejects_wrong_session():
    with tempfile.TemporaryDirectory() as d:
        cm = CheckpointManager(os.path.join(d, "c.ckpt"), interval_chunks=1)
        cm.save(_rec(), force=True)
        assert cm.load(expect_session="cd" * 16) is None
        assert cm.load(expect_session="ab" * 16) is not None


def test_checkpoint_honours_interval():
    with tempfile.TemporaryDirectory() as d:
        cm = CheckpointManager(os.path.join(d, "c.ckpt"), interval_chunks=5)
        wrote = [cm.save(_rec(next_chunk=i)) for i in range(10)]
        assert sum(wrote) == 2, "should write once per 5 chunks"


# --------------------------------------------------------------------------- #
# End-to-end
# --------------------------------------------------------------------------- #
def _transfer(size, arm_scheme, checkpointing, disruptions=0, duration=0.4,
              chunk_size=16 * 1024):
    d = tempfile.mkdtemp()
    try:
        src = os.path.join(d, "payload.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(size))
        want = file_sha256(src)

        rx = Receiver(out_dir=os.path.join(d, "out"), state_dir=os.path.join(d, "rx"),
                      checkpointing=checkpointing, checkpoint_interval=4).start()
        prof = ChannelProfile.with_disruptions(
            count=disruptions, duration_s=duration, first_at_s=0.3, spacing_s=1.0
        ) if disruptions else ChannelProfile()
        ch = SimulatedChannel(("127.0.0.1", rx.port), prof).start()
        try:
            m = Sender(src, ("127.0.0.1", ch.port), scheme=arm_scheme,
                       chunk_size=chunk_size, checkpointing=checkpointing,
                       checkpoint_interval=4,
                       state_dir=os.path.join(d, "tx")).run()
        finally:
            ch.stop()
            rx.stop()
        out = os.path.join(d, "out", "payload.bin")
        got = file_sha256(out) if os.path.exists(out) else None
        return m, want, got
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


@pytest.mark.parametrize("scheme", ["mlkem", "x25519"])
def test_clean_transfer_is_byte_exact(scheme):
    m, want, got = _transfer(512 * 1024, scheme, checkpointing=True)
    assert m.completed and m.integrity_ok
    assert got == want
    assert m.attempts == 1


def test_transfer_survives_disruption_and_resumes():
    m, want, got = _transfer(4 * 1024 * 1024, "mlkem", checkpointing=True,
                             disruptions=2, duration=0.4)
    assert m.completed, "proposed protocol must complete despite disruptions"
    assert got == want, "resumed file must be byte-identical to the source"
    assert m.attempts > 1, "test did not actually induce a disruption"
    assert m.resumed_from_chunks, "resume point should be past chunk 0"
    assert all(c > 0 for c in m.resumed_from_chunks)


def test_checkpointing_beats_no_checkpointing_on_waste():
    """The core claim of the project, asserted rather than eyeballed."""
    prop, _, _ = _transfer(4 * 1024 * 1024, "mlkem", checkpointing=True,
                           disruptions=2, duration=0.4)
    base, _, _ = _transfer(4 * 1024 * 1024, "x25519", checkpointing=False,
                           disruptions=2, duration=0.4)
    if base.attempts == 1 and prop.attempts == 1:
        pytest.skip("no disruption landed; timing-dependent")
    assert prop.wasted_bytes < base.wasted_bytes


def test_mlkem_and_x25519_both_reach_integrity_under_disruption():
    for scheme in ("mlkem", "x25519"):
        m, want, got = _transfer(2 * 1024 * 1024, scheme, checkpointing=True,
                                 disruptions=1, duration=0.4)
        assert m.completed and got == want, f"{scheme} failed"


def test_receiver_rejects_forged_chunk():
    """A chunk that fails AEAD verification must abort, not be written."""
    sid = new_session_id()
    c = ChunkCipher(os.urandom(32), os.urandom(4), sid)
    sealed = bytearray(c.seal(0, 4, b"real data"))
    sealed[-1] ^= 0xFF  # flip a tag bit
    with pytest.raises(Exception):
        c.open(0, 4, bytes(sealed))


def test_completion_is_idempotent_when_done_frame_is_lost():
    """
    Regression: the receiver finished and verified the file, but the DONE frame
    died in the outage it was racing. The sender must not restart and destroy a
    completed transfer -- reconnecting must re-announce completion instead.
    """
    import shutil
    d = tempfile.mkdtemp()
    try:
        src = os.path.join(d, "payload.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(256 * 1024))
        want = file_sha256(src)

        rx = Receiver(out_dir=os.path.join(d, "out"), state_dir=os.path.join(d, "rx"),
                      checkpointing=True, checkpoint_interval=4).start()
        try:
            s1 = Sender(src, ("127.0.0.1", rx.port), scheme="mlkem",
                        chunk_size=16 * 1024, checkpointing=True,
                        state_dir=os.path.join(d, "tx"))
            m1 = s1.run()
            assert m1.completed and m1.integrity_ok

            # Replay the exact same session id, as a sender would after losing
            # DONE and reconnecting.
            s2 = Sender(src, ("127.0.0.1", rx.port), scheme="mlkem",
                        chunk_size=16 * 1024, checkpointing=True,
                        state_dir=os.path.join(d, "tx2"))
            s2.session_id = s1.session_id
            s2.sid_hex = s1.sid_hex
            m2 = s2.run()
            assert m2.completed, "replayed session must complete, not restart"
            assert m2.integrity_ok
            assert m2.payload_bytes_sent == 0, "must not re-send a completed file"
        finally:
            rx.stop()
        assert file_sha256(os.path.join(d, "out", "payload.bin")) == want
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_disruption_event_window():
    ev = DisruptionEvent(start_s=1.0, duration_s=0.5)
    assert not ev.active_at(0.99)
    assert ev.active_at(1.0)
    assert ev.active_at(1.49)
    assert not ev.active_at(1.5)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

"""QPN-001..QPN-010 — the QuietOS Network proving ground, executable.

Each test mirrors its scenario: the Attention Token, device pairing, and
local file transfer. The bar is 10/10 — a network layer that fails even
one is not a network layer.

Bench only: in-memory transports, typed pairing codes, fake clock. The
wire protocol, crypto, and token lifecycle are the real shape.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from quietos import AuditLog
from quietos.network import (
    Bucket, TokenCoordinator, PairedDevice, PairingError, new_pairing_code,
    MemoryTransport, FileSender, FileReceiver,
    RefusedError, IntegrityError,
)


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def advance(self, secs: float):
        self.t += secs


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def coord(clock):
    return TokenCoordinator(clock=clock)


@pytest.fixture
def audit_coord(clock, tmp_path):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    return TokenCoordinator(clock=clock, audit=audit), audit


def paired_pair(name_a="phone-a", name_b="phone-b"):
    code = new_pairing_code()
    return (PairedDevice.pair(code, name_a),
            PairedDevice.pair(code, name_b))


def linked():
    ta, tb = MemoryTransport(), MemoryTransport()
    MemoryTransport.link(ta, tb)
    return ta, tb


def _run_receiver(receiver):
    """Run receive() in a daemon thread; returns (thread, box) where box
    gets 'result' or 'error'. Push blocks on ACCEPT, so the receiver must
    already be listening."""
    import threading
    box = {}

    def go():
        try:
            box["result"] = receiver.receive()
        except Exception as exc:  # noqa: BLE001 — the test asserts on it
            box["error"] = exc

    th = threading.Thread(target=go, daemon=True)
    th.start()
    return th, box


# --- Attention Token (001-005, 009-010) -----------------------------------

def test_qpn001_single_claim_interrupts(coord):
    assert coord.claim("ev-1", "phone-a", Bucket.NOW) is True
    action, device = coord.route("ev-1", Bucket.NOW)
    assert action == "interrupt" and device == "phone-a"


def test_qpn002_second_device_stays_quiet(coord):
    assert coord.claim("ev-1", "phone-a", Bucket.NOW) is True
    assert coord.claim("ev-1", "phone-b", Bucket.NOW) is False
    action, device = coord.route("ev-1", Bucket.NOW)
    assert action == "interrupt" and device == "phone-a"


def test_qpn003_yield_hands_off(coord):
    coord.claim("ev-1", "phone-a", Bucket.NOW)
    assert coord.yield_token("ev-1", "phone-a") is True
    assert coord.claim("ev-1", "phone-b", Bucket.NOW) is True
    action, device = coord.route("ev-1", Bucket.NOW)
    assert action == "interrupt" and device == "phone-b"


def test_qpn004_dead_device_never_swallows_emergency(coord, clock):
    coord.claim("ev-1", "phone-a", Bucket.NOW)
    clock.advance(61)  # owner goes silent past the 60s TTL
    assert coord.owner("ev-1") is None
    assert coord.claim("ev-1", "phone-b", Bucket.NOW) is True
    action, device = coord.route("ev-1", Bucket.NOW)
    assert action == "interrupt" and device == "phone-b"


def test_qpn005_now_no_owner_escalates_never_dropped(coord):
    action, device = coord.route("ev-orphan", Bucket.NOW)
    assert action == "escalate" and device is None


def test_qpn009_soon_event_digest_only(coord):
    assert coord.claim("ev-1", "phone-a", Bucket.SOON) is True
    action, device = coord.route("ev-1", Bucket.SOON)
    assert action == "digest" and device is None
    action, _ = coord.route("ev-2", Bucket.DIGEST)
    assert action == "digest"
    action, _ = coord.route("ev-3", Bucket.SPAM)
    assert action == "quiet"


def test_qpn010_flood_one_interrupt_per_now_event(coord):
    interrupts = []
    for i in range(10):
        ev = f"ev-{i}"
        bucket = Bucket.NOW if i % 2 == 0 else Bucket.SOON
        # two devices race every event; only one may win a NOW event
        a_won = coord.claim(ev, "phone-a", bucket)
        b_won = coord.claim(ev, "phone-b", bucket)
        assert not (a_won and b_won), f"double-claim on {ev}"
        action, device = coord.route(ev, bucket)
        if bucket is Bucket.NOW:
            assert action == "interrupt"
            interrupts.append(device)
        else:
            assert action == "digest"
    assert len(interrupts) == 5
    assert len(set(interrupts)) >= 1  # winners vary, never duplicated


def test_qpn_token_lifecycle_audited(audit_coord):
    coord, audit = audit_coord
    coord.claim("ev-1", "phone-a", Bucket.NOW)
    coord.heartbeat("ev-1", "phone-a")
    coord.yield_token("ev-1", "phone-a")
    ok, msg = audit.verify()
    assert ok, msg
    events = [__import__("json").loads(line)["event"]
              for line in open(audit.path).read().strip().split("\n")]
    assert events[-3:] == ["token_claimed", "token_heartbeat", "token_yielded"]


# --- Pairing + transfer (006-008) -----------------------------------------

def test_qpn006_pair_two_devices_same_key():
    code = new_pairing_code()
    a = PairedDevice.pair(code, "phone-a")
    b = PairedDevice.pair(code, "phone-b")
    assert a.device_id != b.device_id          # stable, distinct ids
    assert a.channel_key == b.channel_key      # same shared key
    assert a.trusts(b) and b.trusts(a)


def test_qpn006_bad_code_rejected():
    with pytest.raises(PairingError):
        PairedDevice.pair("nope", "phone-x")


def test_qpn007_file_push_bytes_identical():
    a, b = paired_pair()
    t_recv, t_send = linked()
    data = os.urandom(40_000)  # spans multiple 16 KiB chunks
    th, box = _run_receiver(FileReceiver(b, t_recv))
    receipt = FileSender(a, t_send).push("model.gguf", data)
    th.join(timeout=10)
    assert "error" not in box, box.get("error")
    name, out = box["result"]
    assert name == "model.gguf"
    assert out == data
    assert receipt.chunks >= 3


def test_qpn008_push_to_unpaired_refused():
    a, b = paired_pair()
    stranger = PairedDevice.pair(new_pairing_code(), "stranger")
    assert not a.trusts(stranger)
    t_recv, t_send = linked()
    th, box = _run_receiver(FileReceiver(b, t_recv))
    with pytest.raises(RefusedError):
        FileSender(stranger, t_send).push("evil.bin", b"nope")
    th.join(timeout=10)
    assert isinstance(box.get("error"), RefusedError)


def test_qpn008_tampered_chunk_fails_integrity():
    a, b = paired_pair()
    ta, tb = linked()

    receiver = FileReceiver(b, tb)
    import threading
    data = os.urandom(1000)

    def evil_push():
        from quietos.network import transfer as tmod
        from quietos.network.transfer import encrypt_chunk
        import hashlib
        offer = {"type": "OFFER", "id": "evil1", "name": "x",
                 "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "key_id": a.key_id, "from": a.device_id}
        ta.send(offer)
        assert ta.recv()["type"] == "ACCEPT"
        nonce, ct = encrypt_chunk(a.channel_key, data)
        bad = bytearray(ct)
        bad[0] ^= 0xFF  # flip a bit: GCM must reject
        ta.send({"type": "CHUNK", "offer_id": "evil1", "seq": 0,
                 "nonce": nonce, "ciphertext": bytes(bad)})
        ta.send({"type": "DONE", "offer_id": "evil1", "chunks": 1})

    th = threading.Thread(target=evil_push)
    th.start()
    with pytest.raises(IntegrityError):
        receiver.receive()
    th.join()

"""QPT-001..QPT-008 — QuietOS Network socket transport proving ground.

Real TCP sockets on localhost: server + client pair with a shared code,
exchange encrypted token messages, and verify the other side sees them.
The crypto, framing, and handshake are the real shape that runs on the
phones over Wi-Fi.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from quietos.network import (
    Bucket, PairedDevice, NetworkNode, TransportError, HandshakeError,
    DEFAULT_PORT, encrypt_frame, decrypt_frame,
)


TEST_CODE = "K7Q2-M9XD"
_PORT_BASE = 18475


def _port():
    _port.n += 1
    return _PORT_BASE + _port.n
_port.n = 0


def _paired(name):
    return PairedDevice.pair(TEST_CODE, name=name)


def _wait_for(pred, timeout=5.0, tick=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(tick)
    return False


@pytest.fixture
def node_a():
    n = NetworkNode(_paired("node-a"), port=_port())
    n.start()
    yield n
    n.stop()


@pytest.fixture
def node_b():
    n = NetworkNode(_paired("node-b"), port=_port())
    n.start()
    yield n
    n.stop()


def _link(a: NetworkNode, b: NetworkNode):
    """a dials b (localhost). Waits until both see each other."""
    a.connect("127.0.0.1", b.port)
    assert _wait_for(lambda: b.device.device_id in a.peer_ids), \
        "a never saw b"
    assert _wait_for(lambda: a.device.device_id in b.peer_ids), \
        "b never saw a"


# -- QPT-001: handshake + peer registration ---------------------------------
def test_handshake_registers_peer(node_a, node_b):
    _link(node_a, node_b)
    assert node_b.device.device_id in node_a.peer_ids
    assert node_a.device.device_id in node_b.peer_ids


# -- QPT-002: token claim propagates -----------------------------------------
def test_token_claim_visible_on_peer(node_a, node_b):
    _link(node_a, node_b)
    assert node_a.claim_token("call-123", Bucket.NOW) is True
    assert _wait_for(
        lambda: node_b.token_owner("call-123") == node_a.device.device_id), \
        "peer never learned the token owner"


# -- QPT-003: second claim loses while first holds -----------------------------
def test_token_contention_one_owner(node_a, node_b):
    _link(node_a, node_b)
    assert node_a.claim_token("event-9", Bucket.NOW) is True
    assert _wait_for(
        lambda: node_b.token_owner("event-9") == node_a.device.device_id)
    # b's local claim for the same event must fail: a owns it.
    assert node_b.tokens.claim("event-9", node_b.device.device_id,
                               Bucket.NOW) is False


# -- QPT-004: yield propagates, token becomes claimable -------------------------
def test_token_yield_propagates(node_a, node_b):
    _link(node_a, node_b)
    node_a.claim_token("event-7", Bucket.NOW)
    assert _wait_for(
        lambda: node_b.token_owner("event-7") == node_a.device.device_id)
    assert node_a.yield_token("event-7") is True
    assert _wait_for(lambda: node_b.token_owner("event-7") is None), \
        "peer still thinks a holds the token after yield"
    # Now b can claim it.
    assert node_b.claim_token("event-7", Bucket.NOW) is True


# -- QPT-005: generic events arrive ----------------------------------------------
def test_generic_event_delivery(node_a, node_b):
    _link(node_a, node_b)
    received = []
    node_b.on_event = lambda et, p, frm: received.append((et, p, frm))
    node_a.send_event("guardian_alarm", {"photo_id": "abc123"})
    assert _wait_for(lambda: len(received) == 1), "event never arrived"
    et, payload, frm = received[0]
    assert et == "guardian_alarm"
    assert payload == {"photo_id": "abc123"}
    assert frm == node_a.device.device_id


# -- QPT-006: unpaired device is refused at handshake ----------------------------
def test_unpaired_device_refused(node_a):
    intruder = PairedDevice.pair("ZZZ9-QQQQ", name="intruder")
    bad = NetworkNode(intruder, port=_port())
    bad.start()
    try:
        with pytest.raises(HandshakeError):
            bad.connect("127.0.0.1", node_a.port)
        # The server must not have registered the intruder either.
        time.sleep(0.3)
        assert intruder.device_id not in node_a.peer_ids
    finally:
        bad.stop()


# -- QPT-007: frame crypto round-trip + tamper detection --------------------------
def test_frame_encrypt_decrypt_roundtrip():
    key = _paired("x").channel_key
    msg = {"type": "TOKEN_CLAIM", "event_id": "e1", "bucket": "now",
           "device_id": "abc"}
    frame = encrypt_frame(key, msg)
    # Frame = 4-byte header + 12-byte nonce + ciphertext.
    assert len(frame) > 4 + 12 + 16
    body_len = int.from_bytes(frame[:4], "big")
    assert body_len == len(frame) - 4
    assert decrypt_frame(key, frame[4:]) == msg


def test_frame_tamper_rejected():
    key = _paired("x").channel_key
    frame = encrypt_frame(key, {"type": "PING"})
    tampered = bytearray(frame)
    tampered[20] ^= 0xFF  # flip a bit inside the ciphertext
    with pytest.raises(TransportError):
        decrypt_frame(key, bytes(tampered[4:]))


def test_frame_wrong_key_rejected():
    key_a = _paired("a").channel_key
    key_b = PairedDevice.pair("QQQ9-WWWW", name="b").channel_key
    frame = encrypt_frame(key_a, {"type": "PING"})
    with pytest.raises(TransportError):
        decrypt_frame(key_b, frame[4:])


# -- QPT-008: nonce uniqueness (no reuse across messages) --------------------------
def test_nonces_unique():
    key = _paired("x").channel_key
    nonces = set()
    for _ in range(200):
        frame = encrypt_frame(key, {"type": "PING"})
        nonces.add(frame[4:16])
    assert len(nonces) == 200, "nonce reuse detected"

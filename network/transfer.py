"""Local file transfer between paired devices — encrypted, chunked, verified.

Bench transport is in-memory (two queues standing in for the local
socket the phones will use). The wire protocol is the same either way:

    sender                          receiver
      |--- OFFER {name,size,sha256,key_id} --->|
      |<-- ACCEPT / DECLINE ------------------|
      |--- CHUNK {seq, nonce, ciphertext} --->|  (repeat)
      |--- DONE ----------------------------->|
      |                              verify SHA-256 over plaintext

Encryption: AES-256-GCM with the pairing channel key, fresh 96-bit nonce
per chunk. A tampered or replayed chunk fails authentication and aborts
the transfer. The receiver's SHA-256 check over the reassembled plaintext
is the final integrity gate.

Refusal is explicit: a receiver only accepts offers whose key_id matches
its own paired channel key. An unpaired sender gets DECLINE, and its bytes
never touch disk.
"""
import hashlib
import os
import queue
import uuid
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .pairing import PairedDevice

CHUNK_SIZE = 16 * 1024  # 16 KiB per chunk


class TransferError(Exception):
    pass


class RefusedError(TransferError):
    """Receiver declined the offer (unpaired sender, bad key, policy)."""


class IntegrityError(TransferError):
    """SHA-256 mismatch or chunk authentication failure."""


# -- bench transport ----------------------------------------------------
class MemoryTransport:
    """Two in-memory queues standing in for the local socket.

    Device A writes to its outbox; device B reads from the same queue as
    its inbox, and vice versa. `link(a, b)` wires a pair cross-wise.
    """

    def __init__(self):
        self.inbox: queue.Queue = queue.Queue()
        self._peer_outbox: queue.Queue | None = None

    @staticmethod
    def link(a: "MemoryTransport", b: "MemoryTransport"):
        a._peer_outbox = b.inbox
        b._peer_outbox = a.inbox

    def send(self, message: dict):
        if self._peer_outbox is None:
            raise TransferError("transport not linked to a peer")
        self._peer_outbox.put(message)

    def recv(self, timeout: float = 5.0) -> dict:
        return self.inbox.get(timeout=timeout)


# -- crypto ---------------------------------------------------------------
def _aead(key: bytes) -> AESGCM:
    if len(key) != 32:
        raise TransferError("channel key must be 32 bytes")
    return AESGCM(key)


def encrypt_chunk(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, _aead(key).encrypt(nonce, plaintext, None)


def decrypt_chunk(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    try:
        return _aead(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise IntegrityError(f"chunk authentication failed: {exc}") from exc


# -- session --------------------------------------------------------------
@dataclass
class TransferReceipt:
    name: str
    size: int
    sha256: str
    chunks: int


class FileSender:
    """Push side. Owned by a PairedDevice; speaks only to its transport."""

    def __init__(self, device: PairedDevice, transport: MemoryTransport):
        self.device = device
        self.transport = transport

    def push(self, name: str, data: bytes) -> TransferReceipt:
        digest = hashlib.sha256(data).hexdigest()
        offer = {"type": "OFFER", "id": uuid.uuid4().hex[:12], "name": name,
                 "size": len(data), "sha256": digest,
                 "key_id": self.device.key_id,
                 "from": self.device.device_id}
        self.transport.send(offer)
        reply = self.transport.recv()
        if reply.get("type") != "ACCEPT" or reply.get("offer_id") != offer["id"]:
            raise RefusedError(f"offer declined: {reply.get('reason', reply)}")

        chunks = 0
        for seq in range(0, len(data), CHUNK_SIZE):
            piece = data[seq:seq + CHUNK_SIZE]
            nonce, ct = encrypt_chunk(self.device.channel_key, piece)
            self.transport.send({"type": "CHUNK", "offer_id": offer["id"],
                                 "seq": seq // CHUNK_SIZE,
                                 "nonce": nonce, "ciphertext": ct})
            chunks += 1
        self.transport.send({"type": "DONE", "offer_id": offer["id"],
                             "chunks": chunks})
        return TransferReceipt(name=name, size=len(data),
                               sha256=digest, chunks=chunks)


class FileReceiver:
    """Receive side. Accept policy: paired key_id only, then verify."""

    def __init__(self, device: PairedDevice, transport: MemoryTransport):
        self.device = device
        self.transport = transport

    def _decline(self, offer: dict, reason: str):
        self.transport.send({"type": "DECLINE", "offer_id": offer.get("id"),
                             "reason": reason})

    def receive(self) -> tuple[str, bytes]:
        """Block for one incoming file. Returns (name, plaintext bytes).

        Raises RefusedError for unpaired senders, IntegrityError for
        tampered or corrupted transfers.
        """
        offer = self.transport.recv()
        if offer.get("type") != "OFFER":
            raise TransferError(f"expected OFFER, got {offer.get('type')}")
        if offer.get("key_id") != self.device.key_id:
            self._decline(offer, "unpaired sender: key_id mismatch")
            raise RefusedError("unpaired sender refused")

        self.transport.send({"type": "ACCEPT", "offer_id": offer["id"]})
        pieces: dict[int, bytes] = {}
        expected = offer["size"]
        while True:
            msg = self.transport.recv()
            if msg.get("type") == "DONE":
                break
            if msg.get("type") != "CHUNK":
                raise TransferError(f"unexpected message {msg.get('type')}")
            pieces[msg["seq"]] = decrypt_chunk(
                self.device.channel_key, msg["nonce"], msg["ciphertext"])

        data = b"".join(pieces[i] for i in sorted(pieces))
        if len(data) != expected:
            raise IntegrityError(
                f"size mismatch: got {len(data)}, expected {expected}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != offer["sha256"]:
            raise IntegrityError("SHA-256 mismatch: transfer corrupted")
        return offer["name"], data

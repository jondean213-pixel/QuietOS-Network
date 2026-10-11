"""Wi-Fi socket transport for the QuietOS Network.

Real TCP sockets between paired devices on the same local network.
Every message after the handshake is AES-256-GCM encrypted with the
pairing channel key; framing is a 4-byte big-endian length prefix.

Wire protocol:
    client -> server : HELLO  {device_id, key_id}          (plaintext)
    server -> client : WELCOME {device_id, key_id}         (plaintext)
    either way       : FRAME   {len(12 + ct)} + nonce + ct (encrypted)
                       where ct = AES-GCM(key, nonce, json_message)

Message types inside the encrypted frame:
    TOKEN_CLAIM      {event_id, bucket, device_id}
    TOKEN_YIELD      {event_id, device_id}
    TOKEN_HEARTBEAT  {event_id, device_id}
    PING / PONG      {}                          (keepalive)
    EVENT            {event_type, payload}       (generic, e.g. Guardian)

Stdlib + cryptography only. Runs on Termux/Android.

Integration: NetworkNode owns a TokenCoordinator. claim_token() claims
locally AND broadcasts to all connected peers; incoming TOKEN_CLAIMs are
applied to the local coordinator so both sides agree on who owns what.
The in-memory MemoryTransport in transfer.py is untouched — this is a
new, parallel transport for live sockets.
"""
import json
import os
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .pairing import PairedDevice
from .token import Bucket, TokenCoordinator

DEFAULT_PORT = 8475
_FRAME_HDR = struct.Struct(">I")  # 4-byte big-endian length
_NONCE_BYTES = 12
_HANDSHAKE_TIMEOUT = 10.0


class TransportError(Exception):
    pass


class HandshakeError(TransportError):
    """Peer failed the pairing handshake (wrong key, bad HELLO)."""


# -- crypto ---------------------------------------------------------------
def _aead(key: bytes) -> AESGCM:
    if len(key) != 32:
        raise TransportError("channel key must be 32 bytes")
    return AESGCM(key)


def encrypt_frame(key: bytes, message: dict) -> bytes:
    """Serialize + encrypt one message. Returns the full wire frame."""
    plaintext = json.dumps(message, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(_NONCE_BYTES)
    ct = _aead(key).encrypt(nonce, plaintext, None)
    return _FRAME_HDR.pack(len(nonce) + len(ct)) + nonce + ct


def decrypt_frame(key: bytes, blob: bytes) -> dict:
    """Decrypt one frame body (nonce + ciphertext). Returns the message."""
    if len(blob) < _NONCE_BYTES + 16:  # nonce + minimum GCM tag
        raise TransportError("frame too short")
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        plaintext = _aead(key).decrypt(nonce, ct, None)
    except Exception as exc:
        raise TransportError(f"frame authentication failed: {exc}") from exc
    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise TransportError(f"bad frame payload: {exc}") from exc


# -- low-level socket helpers ---------------------------------------------
def _send_all(sock: socket.socket, data: bytes):
    sock.sendall(data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise TransportError on EOF/timeout."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout as exc:
            raise TransportError(f"read timeout: {exc}") from exc
        if not chunk:
            raise TransportError("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def _send_plain(sock: socket.socket, message: dict):
    """Length-prefixed plaintext JSON (handshake only)."""
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    _send_all(sock, _FRAME_HDR.pack(len(payload)) + payload)


def _recv_plain(sock: socket.socket, timeout: float = _HANDSHAKE_TIMEOUT) -> dict:
    """Read one length-prefixed plaintext JSON message."""
    sock.settimeout(timeout)
    try:
        (length,) = _FRAME_HDR.unpack(_recv_exact(sock, _FRAME_HDR.size))
        if length > 64 * 1024:
            raise HandshakeError("handshake message too large")
        payload = _recv_exact(sock, length)
        return json.loads(payload.decode("utf-8"))
    finally:
        sock.settimeout(None)


# -- the node ---------------------------------------------------------------
class NetworkNode:
    """One device on the QuietOS Network.

    Runs a TCP server (background thread), connects out to peers, and
    keeps a TokenCoordinator in sync across the fleet via encrypted
    TOKEN_* broadcasts.

    Usage:
        device = PairedDevice.pair("K7Q2-M9XD", name="phone-a")
        node = NetworkNode(device, port=8475)
        node.start()                          # listen for peers
        node.connect("192.168.1.42", 8475)    # dial a peer
        node.claim_token("call-123", Bucket.NOW)
        ...
        node.stop()
    """

    def __init__(self, device: PairedDevice, port: int = DEFAULT_PORT,
                 token_coordinator: TokenCoordinator | None = None):
        self.device = device
        self.port = port
        self.tokens = token_coordinator or TokenCoordinator()
        self._server: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._peers: dict[str, socket.socket] = {}  # device_id -> socket
        self._peers_lock = threading.Lock()
        self._running = threading.Event()
        self.on_event = None  # callback(event_type: str, payload: dict,
                              #           from_device: str)
        self.on_peer = None   # callback(device_id: str, connected: bool)

    # -- lifecycle --------------------------------------------------------
    def start(self):
        """Start listening for peers. Idempotent."""
        if self._running.is_set():
            return
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("0.0.0.0", self.port))
        self._server.listen(8)
        self._server.settimeout(1.0)
        self._running.set()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True,
            name=f"quietos-accept-{self.port}")
        self._accept_thread.start()

    def stop(self):
        """Shut down the server and all peer connections."""
        self._running.clear()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        with self._peers_lock:
            peers = list(self._peers.values())
            self._peers.clear()
        for sock in peers:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=3.0)
            self._accept_thread = None

    @property
    def peer_ids(self) -> list[str]:
        with self._peers_lock:
            return list(self._peers.keys())

    # -- outbound -----------------------------------------------------------
    def connect(self, host: str, port: int = DEFAULT_PORT,
                timeout: float = _HANDSHAKE_TIMEOUT):
        """Dial a peer, handshake, and register it. Raises on failure."""
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            peer_id = self._client_handshake(sock, timeout)
        except HandshakeError:
            try:
                sock.close()
            except OSError:
                pass
            raise
        except TransportError as exc:
            # Server closed the connection mid-handshake (e.g. unpaired
            # key_id refused): that IS a handshake failure.
            try:
                sock.close()
            except OSError:
                pass
            raise HandshakeError(f"handshake failed: {exc}") from exc
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise
        self._register_peer(peer_id, sock)

    def _client_handshake(self, sock: socket.socket,
                          timeout: float) -> str:
        """Returns the peer's device id on success."""
        _send_plain(sock, {"type": "HELLO",
                           "device_id": self.device.device_id,
                           "key_id": self.device.key_id})
        reply = _recv_plain(sock, timeout)
        if reply.get("type") != "WELCOME":
            raise HandshakeError(f"expected WELCOME, got {reply.get('type')}")
        if reply.get("key_id") != self.device.key_id:
            raise HandshakeError("peer key_id mismatch: not paired")
        return reply.get("device_id", "unknown")

    # -- inbound ------------------------------------------------------------
    def _accept_loop(self):
        while self._running.is_set():
            try:
                conn, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._server_handshake,
                                 args=(conn,), daemon=True,
                                 name="quietos-handshake")
            t.start()

    def _server_handshake(self, conn: socket.socket):
        try:
            hello = _recv_plain(conn)
            if hello.get("type") != "HELLO":
                raise HandshakeError("expected HELLO")
            if hello.get("key_id") != self.device.key_id:
                # Unpaired device: refuse silently, close.
                try:
                    conn.close()
                except OSError:
                    pass
                return
            _send_plain(conn, {"type": "WELCOME",
                               "device_id": self.device.device_id,
                               "key_id": self.device.key_id})
            peer_id = hello.get("device_id", "unknown")
            self._register_peer(peer_id, conn)
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    def _register_peer(self, peer_id: str, sock: socket.socket):
        # If we already have this peer (both dialed each other), keep
        # the existing connection and drop the duplicate.
        with self._peers_lock:
            if peer_id in self._peers:
                try:
                    sock.close()
                except OSError:
                    pass
                return
            self._peers[peer_id] = sock
        if self.on_peer:
            try:
                self.on_peer(peer_id, True)
            except Exception:
                pass
        t = threading.Thread(target=self._peer_loop, args=(peer_id, sock),
                             daemon=True, name=f"quietos-peer-{peer_id[:8]}")
        t.start()

    def _drop_peer(self, peer_id: str):
        with self._peers_lock:
            sock = self._peers.pop(peer_id, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self.on_peer:
            try:
                self.on_peer(peer_id, False)
            except Exception:
                pass

    def _peer_loop(self, peer_id: str, sock: socket.socket):
        """Read frames from one peer until it goes away."""
        try:
            while self._running.is_set():
                (length,) = _FRAME_HDR.unpack(
                    _recv_exact(sock, _FRAME_HDR.size))
                if length > 4 * 1024 * 1024:
                    raise TransportError("frame too large")
                blob = _recv_exact(sock, length)
                msg = decrypt_frame(self.device.channel_key, blob)
                self._handle_message(msg, peer_id)
        except Exception:
            pass
        finally:
            self._drop_peer(peer_id)

    # -- messaging ------------------------------------------------------------
    def _send_to(self, peer_id: str, message: dict):
        with self._peers_lock:
            sock = self._peers.get(peer_id)
        if sock is None:
            raise TransportError(f"no such peer: {peer_id}")
        frame = encrypt_frame(self.device.channel_key, message)
        try:
            _send_all(sock, frame)
        except OSError as exc:
            self._drop_peer(peer_id)
            raise TransportError(f"send failed: {exc}") from exc

    def _broadcast(self, message: dict):
        for peer_id in self.peer_ids:
            try:
                self._send_to(peer_id, message)
            except TransportError:
                pass  # dead peer already dropped

    def _handle_message(self, msg: dict, peer_id: str):
        mtype = msg.get("type")
        if mtype == "TOKEN_CLAIM":
            try:
                bucket = Bucket(msg["bucket"])
            except ValueError:
                return
            self.tokens.claim(msg["event_id"], msg["device_id"], bucket)
        elif mtype == "TOKEN_YIELD":
            self.tokens.yield_token(msg["event_id"], msg["device_id"])
        elif mtype == "TOKEN_HEARTBEAT":
            self.tokens.heartbeat(msg["event_id"], msg["device_id"])
        elif mtype == "PING":
            try:
                self._send_to(peer_id, {"type": "PONG"})
            except TransportError:
                pass
        elif mtype == "PONG":
            pass
        elif mtype == "EVENT":
            if self.on_event:
                try:
                    self.on_event(msg.get("event_type", ""),
                                  msg.get("payload", {}),
                                  msg.get("device_id", peer_id))
                except Exception:
                    pass
        # Unknown types are ignored — forward-compatible.

    # -- token API (local claim + fleet broadcast) ------------------------------
    def claim_token(self, event_id: str, bucket: Bucket) -> bool:
        """Claim the token locally and tell the fleet. True = granted."""
        granted = self.tokens.claim(event_id, self.device.device_id, bucket)
        if granted:
            self._broadcast({"type": "TOKEN_CLAIM", "event_id": event_id,
                             "bucket": bucket.value,
                             "device_id": self.device.device_id})
        return granted

    def yield_token(self, event_id: str) -> bool:
        """Yield the token locally and tell the fleet."""
        yielded = self.tokens.yield_token(event_id, self.device.device_id)
        if yielded:
            self._broadcast({"type": "TOKEN_YIELD", "event_id": event_id,
                             "device_id": self.device.device_id})
        return yielded

    def heartbeat_token(self, event_id: str) -> bool:
        """Renew the lease locally and tell the fleet."""
        renewed = self.tokens.heartbeat(event_id, self.device.device_id)
        if renewed:
            self._broadcast({"type": "TOKEN_HEARTBEAT", "event_id": event_id,
                             "device_id": self.device.device_id})
        return renewed

    def token_owner(self, event_id: str):
        """Who holds the token for this event (local view, fleet-synced)."""
        return self.tokens.owner(event_id)

    # -- generic events ---------------------------------------------------------
    def send_event(self, event_type: str, payload: dict | None = None):
        """Broadcast a generic event (e.g. Guardian) to all peers."""
        self._broadcast({"type": "EVENT", "event_type": event_type,
                         "payload": payload or {},
                         "device_id": self.device.device_id})

    def ping(self):
        """Keepalive to all peers."""
        self._broadcast({"type": "PING"})

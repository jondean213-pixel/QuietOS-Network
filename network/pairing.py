"""Device pairing — one shared secret, two paired devices.

Bench model (real QR + ECDH comes on the phone): Jon shows a pairing
code on device A and types it into device B — the same ritual as a
Wi-Fi password. The code IS the shared secret. Both sides run it through
HKDF and land on the same 32-byte channel key; each side keeps its own
stable device id.

Nothing here ever sends the secret anywhere. On the phone the code will
travel by QR (camera, local only); on the bench the two "devices" just
both receive the same code string.
"""
import hashlib
import hmac
import secrets
import string
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_SALT = b"quietos-network-v1"
HKDF_INFO = b"local-channel-key"
KEY_BYTES = 32

# Short, typable, unambiguous: no 0/O, 1/I/l.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def new_pairing_code(length: int = 8) -> str:
    """Generate a fresh pairing code, e.g. 'K7Q2-M9XD'. Shown on device A."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(length))
    return "-".join(raw[i:i + 4] for i in range(0, length, 4))


def _canon(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


def derive_channel_key(pairing_code: str) -> bytes:
    """Both devices, same code in -> same 32-byte key out. Deterministic."""
    secret = _canon(pairing_code).encode("ascii")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES,
                salt=HKDF_SALT, info=HKDF_INFO)
    return hkdf.derive(secret)


def key_fingerprint(key: bytes) -> str:
    """Short public fingerprint of a channel key (safe to display / compare)."""
    return hashlib.sha256(b"quietos-key-id" + key).hexdigest()[:16]


class PairingError(Exception):
    pass


class PairedDevice:
    """One side of a pairing. Holds its stable id and the shared channel key."""

    def __init__(self, device_id: str, channel_key: bytes, name: str = ""):
        self.device_id = device_id
        self.channel_key = channel_key
        self.name = name or device_id[:8]

    @property
    def key_id(self) -> str:
        return key_fingerprint(self.channel_key)

    @classmethod
    def pair(cls, pairing_code: str, name: str = "") -> "PairedDevice":
        """Enter the code shown on the other device. Returns this side."""
        code = _canon(pairing_code)
        if len(code) < 6 or any(c not in _CODE_ALPHABET for c in code):
            raise PairingError("pairing code rejected: bad format")
        return cls(device_id=uuid.uuid4().hex[:12],
                   channel_key=derive_channel_key(code), name=name)

    def trusts(self, other: "PairedDevice") -> bool:
        """True when both sides derived the same channel key."""
        return hmac.compare_digest(self.key_id, other.key_id)

    def __repr__(self):
        return f"PairedDevice(name={self.name!r}, id={self.device_id[:8]}…)"

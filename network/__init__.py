"""QuietOS Network core — cross-device coordination for the $8.99/mo tier.

Three capabilities (Jon's locked v2 decisions, 2026-10-08):
    token    — the Attention Token: exactly one device interrupts per event
    pairing  — pair two devices once via a shared pairing code
    transfer — encrypted, chunked, integrity-checked local file push

Bench note: the MemoryTransport is in-memory and the pairing code is
typed, not scanned. transport.py is the real Wi-Fi socket layer — two
phones on the same LAN talk TCP, handshake with their paired key_id,
then exchange AES-256-GCM frames. Real QR + ECDH arrive with the phone
build. The wire protocol and the crypto are the real shape.
"""
from .token import Bucket, TokenCoordinator, DEFAULT_LEASE_SECONDS
from .pairing import (PairedDevice, PairingError, new_pairing_code,
                      derive_channel_key, key_fingerprint)
from .transfer import (MemoryTransport, FileSender, FileReceiver,
                       TransferReceipt, TransferError, RefusedError,
                       IntegrityError, CHUNK_SIZE)
from .transport import (NetworkNode, TransportError, HandshakeError,
                        DEFAULT_PORT, encrypt_frame, decrypt_frame)
from .spamshield import (Verdict, RelayDecision, CallContext, MessageContext,
                         Classification, SpamShield, normalize_number,
                         shielded_send, CALL_EVENT, MESSAGE_EVENT, VIP_NAMES)
from .relay import (RelayEvent, RelayRouter, EnvelopeError, OutboxEntry,
                    MISSED_CALL, SMS, EMAIL_ALERT, ENVELOPE_VERSION,
                    missed_call_event, sms_event, email_alert_event,
                    seal_envelope, open_envelope)

__all__ = [
    "Bucket", "TokenCoordinator", "DEFAULT_LEASE_SECONDS",
    "PairedDevice", "PairingError", "new_pairing_code",
    "derive_channel_key", "key_fingerprint",
    "MemoryTransport", "FileSender", "FileReceiver",
    "TransferReceipt", "TransferError", "RefusedError",
    "IntegrityError", "CHUNK_SIZE",
    "NetworkNode", "TransportError", "HandshakeError",
    "DEFAULT_PORT", "encrypt_frame", "decrypt_frame",
    "Verdict", "RelayDecision", "CallContext", "MessageContext",
    "Classification", "SpamShield", "normalize_number",
    "shielded_send", "CALL_EVENT", "MESSAGE_EVENT", "VIP_NAMES",
    "RelayEvent", "RelayRouter", "EnvelopeError", "OutboxEntry",
    "MISSED_CALL", "SMS", "EMAIL_ALERT", "ENVELOPE_VERSION",
    "missed_call_event", "sms_event", "email_alert_event",
    "seal_envelope", "open_envelope",
]

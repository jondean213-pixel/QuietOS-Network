"""Cloud relay — the forgotten-phone case.

Phone B sits at home on the house Wi-Fi taking Jon's calls. Jon is out
with the Motorola. When Phone B gets a missed call or text, SPAM SHIELD
filters it:

    CLEAN   -> relay to the Motorola now
    SUSPECT -> relay, flagged so Jon decides
    SPAM    -> NEVER leaves the home phone

RelayRouter picks the path: if the peer is reachable over the local
Wi-Fi socket transport, the event goes direct; otherwise it is sealed
into a signed cloud envelope and queued in the outbox for push delivery.

Cloud envelope format (v1) — JSON, exactly these fields:
    {
      "v": 1,
      "msg_id": "<uuid4 hex>",          # dedup key across local+cloud
      "from": "<sender device_id>",
      "to": "<recipient device_id>",
      "key_id": "<channel key fingerprint>",  # receiver rejects mismatch
      "event": "missed_call" | "sms" | "email_alert",
      "payload_enc": "<base64 AES-256-GCM(nonce||ct)>",
      "ts": 1728660000.0,               # unix time, sender clock
      "sig": "<HMAC-SHA256 hex>"        # over canonical JSON of the rest
    }

The payload is AES-256-GCM encrypted with the pairing channel key
(bare nonce||ciphertext body, 12-byte nonce, base64-encoded). "sig" is HMAC-SHA256 over the canonical JSON
(sort_keys, no whitespace) of every field except "sig" itself, keyed by
a relay subkey derived from the channel key. Tampered envelopes fail
HMAC; wrong-key envelopes fail on key_id and HMAC both.

Firebase/push delivery itself is future work — RelayRouter queues
sealed envelopes in its outbox and hands them to a push_send hook when
one is configured. The wire format above is what the push payload must
carry, so the phone side can be built against it now.

Termux-safe: stdlib + cryptography only.
"""
import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .pairing import PairedDevice, key_fingerprint
from .spamshield import (Verdict, RelayDecision, SpamShield, CallContext,
                         MessageContext, CALL_EVENT, MESSAGE_EVENT)

# -- relay event types ------------------------------------------------
MISSED_CALL = CALL_EVENT          # "missed_call"
SMS = MESSAGE_EVENT               # "sms"
EMAIL_ALERT = "email_alert"

ENVELOPE_VERSION = 1

# Retry backoff for the cloud outbox (seconds): 1m, 5m, 15m, 1h, capped.
_RETRY_BACKOFF = (60.0, 300.0, 900.0, 3600.0)

# How long the dedup window remembers a delivered msg_id (seconds).
_DEDUP_WINDOW = 24 * 3600.0


def _relay_hmac_key(channel_key: bytes) -> bytes:
    """Derive the relay signing subkey from the pairing channel key."""
    return hmac.new(channel_key, b"quietos-relay/hmac-v1",
                    hashlib.sha256).digest()


def _canonical(env: Dict[str, Any]) -> bytes:
    """Canonical JSON bytes of an envelope (everything except 'sig')."""
    return json.dumps(env, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


# -- relay events -----------------------------------------------------

@dataclass
class RelayEvent:
    """One filtered event ready to relay to the carried phone."""
    event_id: str
    event_type: str          # MISSED_CALL / SMS / EMAIL_ALERT
    payload: Dict[str, Any]
    verdict: Verdict
    reasons: List[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    @property
    def flagged(self) -> bool:
        return self.verdict == Verdict.SUSPECT


def missed_call_event(number: str, verdict: Verdict,
                      reasons: Optional[List[str]] = None,
                      called_at: Optional[float] = None) -> RelayEvent:
    return RelayEvent(event_id=uuid.uuid4().hex, event_type=MISSED_CALL,
                      payload={"number": number,
                               "called_at": called_at or time.time()},
                      verdict=verdict, reasons=list(reasons or []))


def sms_event(sender: str, body: str, verdict: Verdict,
              reasons: Optional[List[str]] = None,
              received_at: Optional[float] = None) -> RelayEvent:
    return RelayEvent(event_id=uuid.uuid4().hex, event_type=SMS,
                      payload={"sender": sender, "body": body,
                               "received_at": received_at or time.time()},
                      verdict=verdict, reasons=list(reasons or []))


def email_alert_event(sender: str, subject: str, snippet: str,
                      verdict: Verdict = Verdict.CLEAN,
                      reasons: Optional[List[str]] = None) -> RelayEvent:
    """Email alerts have no spam classifier yet; the caller assigns the
    verdict (default CLEAN)."""
    return RelayEvent(event_id=uuid.uuid4().hex, event_type=EMAIL_ALERT,
                      payload={"sender": sender, "subject": subject,
                               "snippet": snippet},
                      verdict=verdict, reasons=list(reasons or []))


# -- payload crypto ---------------------------------------------------
# AES-256-GCM with a fresh nonce per envelope. Note: transport
# encrypt_frame() adds a 4-byte socket length header, so the relay
# encrypts the bare nonce||ciphertext body itself instead.

_NONCE_BYTES = 12


def _encrypt_payload(key: bytes, payload: Dict[str, Any]) -> bytes:
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _decrypt_payload(key: bytes, blob: bytes) -> Dict[str, Any]:
    if len(blob) < _NONCE_BYTES + 16:
        raise EnvelopeError("payload too short")
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:
        raise EnvelopeError("payload decrypt failed: %s" % exc)
    return json.loads(plaintext.decode("utf-8"))


# -- cloud envelope ---------------------------------------------------

def seal_envelope(device: PairedDevice, to_device_id: str,
                  event: RelayEvent) -> Dict[str, Any]:
    """Seal a RelayEvent into a signed cloud envelope (v1 format).

    Payload is AES-256-GCM encrypted with the pairing channel key;
    the whole envelope (minus sig) is HMAC-SHA256 signed with the
    relay subkey.
    """
    env: Dict[str, Any] = {
        "v": ENVELOPE_VERSION,
        "msg_id": event.event_id,
        "from": device.device_id,
        "to": to_device_id,
        "key_id": device.key_id,
        "event": event.event_type,
        "payload_enc": base64.b64encode(
            _encrypt_payload(device.channel_key, {
                **event.payload,
                "spamshield_verdict": event.verdict.value,
                "spamshield_reasons": event.reasons,
                "spamshield_flag": event.flagged,
                "event_ts": event.ts,
            })).decode("ascii"),
        "ts": event.ts,
    }
    env["sig"] = hmac.new(_relay_hmac_key(device.channel_key),
                          _canonical(env),
                          hashlib.sha256).hexdigest()
    return env


class EnvelopeError(Exception):
    """A cloud envelope failed verification."""


def open_envelope(device: PairedDevice,
                  envelope: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Verify and decrypt a cloud envelope.

    Returns (event_type, payload). Raises EnvelopeError on bad version,
    key_id mismatch, bad signature, or undecryptable payload.
    """
    if not isinstance(envelope, dict) or envelope.get("v") != ENVELOPE_VERSION:
        raise EnvelopeError("unsupported envelope version")
    if envelope.get("key_id") != device.key_id:
        raise EnvelopeError("key_id mismatch: not paired with sender")
    sig = envelope.get("sig", "")
    env = {k: v for k, v in envelope.items() if k != "sig"}
    expect = hmac.new(_relay_hmac_key(device.channel_key),
                      _canonical(env), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(sig), expect):
        raise EnvelopeError("bad signature: envelope tampered or wrong key")
    try:
        payload = _decrypt_payload(device.channel_key,
                                   base64.b64decode(envelope["payload_enc"]))
    except EnvelopeError:
        raise
    except Exception as exc:
        raise EnvelopeError("payload decode failed: %s" % exc)
    return envelope["event"], payload


# -- outbox -----------------------------------------------------------

@dataclass
class OutboxEntry:
    msg_id: str
    to_device_id: str
    envelope: Dict[str, Any]
    queued_at: float
    next_retry_at: float
    attempts: int = 0


# -- router -----------------------------------------------------------

class RelayRouter:
    """Decides local vs cloud for each filtered relay event.

    Phone B constructs one with its SpamShield and (optionally) its
    live NetworkNode. Inbound calls/texts are classified and routed:

        route_event() -> "local" | "cloud" | "held"

    SPAM is always "held" — it never leaves the home phone, local or
    cloud. Cloud-queued envelopes sit in the outbox until push_send
    accepts them or they are acked.
    """

    def __init__(self,
                 device: PairedDevice,
                 shield: SpamShield,
                 node=None,
                 push_send: Optional[Callable[[Dict[str, Any]], bool]] = None,
                 on_relay_event: Optional[Callable[[str, Dict[str, Any],
                                                   str], None]] = None):
        self.device = device
        self.shield = shield
        self.node = node
        self.push_send = push_send
        self.on_relay_event = on_relay_event
        self.outbox: Dict[str, OutboxEntry] = {}
        self._seen: Dict[str, float] = {}  # msg_id -> first-seen time

    # -- reachability -------------------------------------------------

    def local_reachable(self, device_id: str) -> bool:
        """True when the peer is on the local Wi-Fi socket transport."""
        if self.node is None:
            return False
        try:
            return device_id in self.node.peer_ids
        except Exception:
            return False

    # -- inbound (home phone side) ------------------------------------

    def handle_inbound_call(self, ctx: CallContext,
                            to_device_id: str) -> Tuple[RelayDecision, str]:
        """Classify an inbound call and route it. Returns (decision, route)."""
        cls = self.shield.classify_call(ctx)
        event = missed_call_event(ctx.number, cls.verdict, cls.reasons)
        return self.shield.relay_for(cls.verdict), self.route_event(
            event, to_device_id)

    def handle_inbound_sms(self, ctx: MessageContext,
                           to_device_id: str) -> Tuple[RelayDecision, str]:
        """Classify an inbound SMS and route it. Returns (decision, route)."""
        cls = self.shield.classify_message(ctx)
        event = sms_event(ctx.sender, ctx.body, cls.verdict, cls.reasons)
        return self.shield.relay_for(cls.verdict), self.route_event(
            event, to_device_id)

    def handle_inbound_email(self, sender: str, subject: str, snippet: str,
                             to_device_id: str,
                             verdict: Verdict = Verdict.CLEAN,
                             reasons: Optional[List[str]] = None
                             ) -> Tuple[RelayDecision, str]:
        """Route an email alert with a caller-assigned verdict."""
        event = email_alert_event(sender, subject, snippet, verdict, reasons)
        return self.shield.relay_for(verdict), self.route_event(
            event, to_device_id)

    # -- routing ------------------------------------------------------

    def route_event(self, event: RelayEvent, to_device_id: str) -> str:
        """Route one filtered event. Returns 'local', 'cloud', or 'held'."""
        if event.verdict == Verdict.SPAM:
            return "held"
        if self.local_reachable(to_device_id):
            self._send_local(event, to_device_id)
            self._mark_seen(event.event_id)
            return "local"
        self._queue_cloud(event, to_device_id)
        return "cloud"

    def _send_local(self, event: RelayEvent, to_device_id: str) -> None:
        payload = dict(event.payload)
        payload["relay_msg_id"] = event.event_id
        payload["spamshield_verdict"] = event.verdict.value
        payload["spamshield_reasons"] = event.reasons
        payload["spamshield_flag"] = event.flagged
        # The socket transport broadcasts; the paired key handshake means
        # only the paired peer can read it. to_device_id is recorded for
        # the cloud path and for logging.
        self.node.send_event(event.event_type, payload)

    def _queue_cloud(self, event: RelayEvent, to_device_id: str) -> str:
        envelope = seal_envelope(self.device, to_device_id, event)
        now = time.time()
        self.outbox[event.event_id] = OutboxEntry(
            msg_id=event.event_id, to_device_id=to_device_id,
            envelope=envelope, queued_at=now, next_retry_at=now)
        self._flush_outbox()
        self._mark_seen(event.event_id)
        return event.event_id

    # -- outbox -------------------------------------------------------

    def _flush_outbox(self) -> None:
        """Try to push everything due. Hook returns True when the push
        service accepted the envelope."""
        if self.push_send is None:
            return
        now = time.time()
        for entry in list(self.outbox.values()):
            if entry.next_retry_at > now:
                continue
            entry.attempts += 1
            try:
                accepted = bool(self.push_send(entry.envelope))
            except Exception:
                accepted = False
            if accepted:
                del self.outbox[entry.msg_id]
            else:
                backoff = _RETRY_BACKOFF[min(entry.attempts - 1,
                                             len(_RETRY_BACKOFF) - 1)]
                entry.next_retry_at = now + backoff

    def retry_due(self, now: Optional[float] = None) -> List[OutboxEntry]:
        """Entries whose retry timer has fired (also triggers a flush)."""
        self._flush_outbox()
        at = now if now is not None else time.time()
        return [e for e in self.outbox.values() if e.next_retry_at <= at]

    def cloud_acked(self, msg_id: str) -> bool:
        """The push service confirmed delivery — drop from the outbox."""
        return self.outbox.pop(msg_id, None) is not None

    def outbox_pending(self) -> List[OutboxEntry]:
        return list(self.outbox.values())

    # -- receiving (carried phone side) -------------------------------

    def _mark_seen(self, msg_id: str) -> None:
        now = time.time()
        self._seen[msg_id] = now
        cutoff = now - _DEDUP_WINDOW
        for mid in [m for m, t in self._seen.items() if t < cutoff]:
            del self._seen[mid]

    def already_seen(self, msg_id: str) -> bool:
        return msg_id in self._seen

    def receive_local(self, event_type: str, payload: Dict[str, Any],
                      from_device: str) -> bool:
        """Handle an event arriving over the socket transport. Returns
        True if delivered (False when it was a duplicate)."""
        msg_id = payload.get("relay_msg_id") or payload.get("msg_id")
        if msg_id and self.already_seen(msg_id):
            return False
        if msg_id:
            self._mark_seen(msg_id)
        self._deliver(event_type, dict(payload), from_device)
        return True

    def receive_cloud_envelope(self, envelope: Dict[str, Any]) -> bool:
        """Verify, decrypt, and deliver a cloud envelope. Returns True
        if delivered; False when it was a duplicate. Raises
        EnvelopeError on verification failure."""
        event_type, payload = open_envelope(self.device, envelope)
        msg_id = envelope.get("msg_id")
        if msg_id and self.already_seen(msg_id):
            return False
        if msg_id:
            self._mark_seen(msg_id)
        self._deliver(event_type, payload, envelope.get("from", ""))
        return True

    def _deliver(self, event_type: str, payload: Dict[str, Any],
                 from_device: str) -> None:
        if self.on_relay_event is not None:
            self.on_relay_event(event_type, payload, from_device)

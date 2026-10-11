"""The Attention Token — cross-device interrupt coordination.

For any given event, exactly ONE device owns the right to interrupt Jon.
The rest digest quietly. Bucket decides urgency, token decides location.

Lifecycle (Jon's locked v2 decisions, 2026-10-08):
    CLAIM   — a device takes the token for an event (nobody live holds it)
    LEASE   — held with a TTL (default 60s), renewed by heartbeat
    YIELD   — device hands off voluntarily (Jon picked up his phone)
    EXPIRE  — owner silent past TTL; token becomes claimable again.
              A dead device can NEVER swallow an emergency.

Routing rule:
    NOW + live owner   -> interrupt on the owner, and ONLY the owner
    NOW + no live owner -> escalate per governor rules, NEVER silently drop
    SOON / DIGEST      -> digest quietly, no interrupt
    QUIET / SPAM       -> nothing leaves the device

The token is PER-EVENT (event id), not global — Jon's phone can be
ringing about the missed call while his computer digests the newsletter.
"""
import time
from dataclasses import dataclass, field
from enum import Enum


class Bucket(str, Enum):
    """Attention buckets. Same five Jon uses everywhere."""
    NOW = "now"          # interrupt-worthy
    SOON = "soon"        # digest quietly
    DIGEST = "digest"    # digest quietly
    QUIET = "quiet"      # stays on the device
    SPAM = "spam"        # never leaves the house


DEFAULT_LEASE_SECONDS = 60.0  # v1 starter's proposed starting point


@dataclass
class _Token:
    event_id: str
    owner: str
    bucket: Bucket
    expires_at: float
    lease_seconds: float = DEFAULT_LEASE_SECONDS
    claims: int = 1


class TokenCoordinator:
    """Owns token state for a fleet of paired devices.

    All time goes through the injected clock so the proving ground can
    fast-forward past TTLs without sleeping. Pass audit= to write every
    claim/heartbeat/yield/expire into the hash-chained audit log.
    """

    def __init__(self, lease_seconds: float = DEFAULT_LEASE_SECONDS,
                 clock=None, audit=None):
        self.lease_seconds = lease_seconds
        self.clock = clock or time.time
        self.audit = audit
        self._tokens: dict[str, _Token] = {}

    # -- internal ------------------------------------------------------
    def _now(self) -> float:
        return self.clock()

    def _log(self, event: str, **fields):
        if self.audit is not None:
            self.audit.append(event, **fields)

    def _live(self, event_id: str):
        """Return the token if it exists and has not expired, else None.

        Expiry is lazy: a token past its TTL is dropped the moment anyone
        looks at it, and the drop is audited as an expiry.
        """
        tok = self._tokens.get(event_id)
        if tok is None:
            return None
        if self._now() >= tok.expires_at:
            del self._tokens[event_id]
            self._log("token_expired", event_id=event_id,
                      owner=tok.owner, bucket=tok.bucket.value)
            return None
        return tok

    # -- lifecycle -----------------------------------------------------
    def claim(self, event_id: str, device_id: str, bucket: Bucket) -> bool:
        """Try to take the token for an event. True = granted."""
        tok = self._live(event_id)
        if tok is None:
            self._tokens[event_id] = _Token(
                event_id=event_id, owner=device_id, bucket=bucket,
                expires_at=self._now() + self.lease_seconds,
                lease_seconds=self.lease_seconds)
            self._log("token_claimed", event_id=event_id,
                      owner=device_id, bucket=bucket.value)
            return True
        if tok.owner == device_id:
            # Re-claim by the owner is a heartbeat, not a conflict.
            return self.heartbeat(event_id, device_id)
        return False

    def heartbeat(self, event_id: str, device_id: str) -> bool:
        """Renew the lease. False if this device doesn't hold the token."""
        tok = self._live(event_id)
        if tok is None or tok.owner != device_id:
            return False
        tok.expires_at = self._now() + tok.lease_seconds
        self._log("token_heartbeat", event_id=event_id, owner=device_id)
        return True

    def yield_token(self, event_id: str, device_id: str) -> bool:
        """Voluntary handoff. False if this device doesn't hold the token."""
        tok = self._live(event_id)
        if tok is None or tok.owner != device_id:
            return False
        del self._tokens[event_id]
        self._log("token_yielded", event_id=event_id, owner=device_id,
                  bucket=tok.bucket.value)
        return True

    def owner(self, event_id: str):
        """Current live owner device id, or None."""
        tok = self._live(event_id)
        return tok.owner if tok else None

    # -- routing -------------------------------------------------------
    def route(self, event_id: str, bucket: Bucket) -> tuple[str, str | None]:
        """Decide what happens for an event on the fleet.

        Returns (action, device_id):
            ("interrupt", owner) — NOW event, live owner: ring THERE only
            ("escalate", None)   — NOW event, nobody live: escalate, never drop
            ("digest", None)     — SOON/DIGEST: quiet digest, no interrupt
            ("quiet", None)      — QUIET/SPAM: stays put, relays nothing
        """
        if bucket is Bucket.NOW:
            live_owner = self.owner(event_id)
            if live_owner is not None:
                return ("interrupt", live_owner)
            self._log("token_no_owner_escalated", event_id=event_id,
                      bucket=bucket.value)
            return ("escalate", None)
        if bucket in (Bucket.SOON, Bucket.DIGEST):
            return ("digest", None)
        return ("quiet", None)

"""SPAM SHIELD — call/message spam classifier for the QuietOS Network.

Phone B sits at home taking the calls. SPAM SHIELD decides what is
worth relaying to the phone Jon is carrying and what stays home:

    CLEAN   -> RELAY          (contacts, VIPs, known-good numbers)
    SUSPECT -> RELAY_FLAGGED  (unknown, odd hour, one weak signal — Jon decides)
    SPAM    -> HOLD           (never leaves the home phone)

Rule-based v1: stdlib only, no models, no network lookups. Runs fine
in Termux on a cheap phone. Jon's VIPs (Noah Dean, Vanessa Brzeski,
his doctors) always come through — the shield never blocks them.

The shield plugs into the socket transport: Phone B classifies each
incoming call/text, then calls shielded_send(), which relays through
the NetworkNode only when the verdict warrants it.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Verdict(str, Enum):
    """What SPAM SHIELD thinks of an inbound call or message."""
    CLEAN = "clean"        # known-good: relay it
    SUSPECT = "suspect"    # uncertain: relay flagged so Jon decides
    SPAM = "spam"          # junk: hold it on the home phone


class RelayDecision(str, Enum):
    """What Phone B does with the event after classification."""
    RELAY = "relay"                 # send to the other phone now
    RELAY_FLAGGED = "relay_flagged"  # send, marked suspect
    HOLD = "hold"                   # stays on the home phone


# Jon's standing VIPs (call-pipeline v1, 2026-10-07): Noah Dean,
# Vanessa Brzeski, Jon's doctors. The shield takes their NUMBERS at
# construction; names live here so the config stays readable.
VIP_NAMES = ("Noah Dean", "Vanessa Brzeski", "Jon's doctors")

# US toll-free area codes — unknown toll-free callers are SUSPECT,
# never outright SPAM (banks, airlines, and doctors use them too).
TOLL_FREE_CODES = {"800", "888", "877", "866", "855", "844", "833", "822"}

# Business hours (local): unknown callers outside these are SUSPECT.
BUSINESS_START = 8
BUSINESS_END = 21  # 9 PM

# Message spam signals (matched case-insensitively against the body).
_SPAM_PHRASES = (
    "you've won", "you won", "you are a winner", "congratulations you",
    "claim your prize", "claim your reward", "lottery", "sweepstakes",
    "free cruise", "free vacation", "free money", "get rich",
    "act now", "urgent action required", "immediate action",
    "final notice", "last chance",
    "wire transfer", "western union", "gift card", "itunes card",
    "verify your account", "account suspended", "account locked",
    "update your payment", "payment failed",
    "social security", "arrest warrant", "irs",
    "click the link below", "click here to claim",
)

# Link shorteners / shady TLDs commonly abused in smishing.
_SHADY_LINK_BITS = (
    "bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", ".xyz", ".top", ".click", ".loan",
)

# Common TLDs — an unknown sender dropping any link at all is SUSPECT.
_LINK_TLDS = (
    ".com", ".net", ".org", ".io", ".co", ".info", ".biz", ".us",
    ".me", ".app", ".link",
)


def _has_link(body: str) -> bool:
    if "http" in body or "www." in body:
        return True
    return any(tld in body for tld in _LINK_TLDS)


def normalize_number(raw: str) -> str:
    """Strip a phone number down to digits, dropping a leading US '1'.

    Returns "" for anything that has no usable digits.
    """
    if not raw:
        return ""
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits


def _area_code(digits: str) -> str:
    return digits[:3] if len(digits) >= 10 else ""


def _looks_invalid(digits: str) -> bool:
    """Numbers that cannot be real callers."""
    if not digits or len(digits) < 7:
        return True
    if len(set(digits)) == 1:  # 0000000000, 1111111111, ...
        return True
    if digits.startswith("000") or digits.startswith("111"):
        return True
    return False


def _looks_fictional(digits: str) -> bool:
    """555-01xx numbers are reserved fictional — treat as suspicious."""
    return len(digits) == 10 and digits[3:6] == "555" and digits[6:8] == "01"


@dataclass
class CallContext:
    """Everything the shield knows about one inbound call."""
    number: str
    in_contacts: bool = False
    previously_called_by_jon: bool = False  # Jon dialed them before
    previously_received: bool = False       # they called before
    hour: int = 12                          # local hour, 0-23


@dataclass
class MessageContext:
    """Everything the shield knows about one inbound SMS."""
    sender: str
    body: str = ""
    in_contacts: bool = False
    is_service_number: bool = False  # bank alerts, carrier, 2FA, etc.


@dataclass
class Classification:
    verdict: Verdict
    reasons: List[str] = field(default_factory=list)


class SpamShield:
    """Rule-based call/message classifier. No models, no lookups.

    Configure once with Jon's numbers; classify every inbound event.
    """

    def __init__(self,
                 vip_numbers: Tuple[str, ...] = (),
                 blocked_prefixes: Tuple[str, ...] = ()):
        self.vip_numbers = {normalize_number(n) for n in vip_numbers
                            if normalize_number(n)}
        self.blocked_prefixes = tuple(blocked_prefixes)

    # -- calls ------------------------------------------------------

    def classify_call(self, ctx: CallContext) -> Classification:
        number = normalize_number(ctx.number)
        reasons: List[str] = []

        # VIPs always come through, any hour. The shield never blocks them.
        if number and number in self.vip_numbers:
            return Classification(Verdict.CLEAN, ["vip allowlist"])

        if ctx.in_contacts:
            return Classification(Verdict.CLEAN, ["in contacts"])

        if ctx.previously_called_by_jon:
            return Classification(Verdict.CLEAN, ["jon called them before"])

        if _looks_invalid(number):
            return Classification(Verdict.SPAM,
                                  ["invalid number: %r" % ctx.number])

        for prefix in self.blocked_prefixes:
            if number.startswith(normalize_number(prefix)):
                return Classification(Verdict.SPAM,
                                      ["blocked prefix %s" % prefix])

        if _area_code(number) in TOLL_FREE_CODES:
            return Classification(Verdict.SUSPECT,
                                  ["unknown toll-free caller"])

        if _looks_fictional(number):
            return Classification(Verdict.SUSPECT, ["fictional 555 number"])

        if not (BUSINESS_START <= ctx.hour < BUSINESS_END):
            return Classification(Verdict.SUSPECT,
                                  ["unknown caller outside business hours"])

        if ctx.previously_received:
            reasons.append("called before, not in contacts")
            return Classification(Verdict.SUSPECT, reasons)

        reasons.append("unknown number")
        return Classification(Verdict.SUSPECT, reasons)

    # -- messages ---------------------------------------------------

    def classify_message(self, ctx: MessageContext) -> Classification:
        sender = normalize_number(ctx.sender)
        reasons: List[str] = []

        if sender and sender in self.vip_numbers:
            return Classification(Verdict.CLEAN, ["vip allowlist"])
        if ctx.in_contacts:
            return Classification(Verdict.CLEAN, ["in contacts"])
        if ctx.is_service_number:
            return Classification(Verdict.CLEAN, ["known service number"])

        body = (ctx.body or "").lower()
        hits = [p for p in _SPAM_PHRASES if p in body]
        shady = [b for b in _SHADY_LINK_BITS if b in body]

        if len(hits) >= 2 or (hits and shady):
            reasons.append("spam phrases: %s" % ", ".join(hits[:3]))
            if shady:
                reasons.append("shady link: %s" % shady[0])
            return Classification(Verdict.SPAM, reasons)

        if hits or shady or _looks_invalid(sender):
            if hits:
                reasons.append("spam phrase: %s" % hits[0])
            if shady:
                reasons.append("shady link: %s" % shady[0])
            if _looks_invalid(sender):
                reasons.append("invalid sender")
            return Classification(Verdict.SUSPECT, reasons)

        if _has_link(body):
            return Classification(Verdict.SUSPECT,
                                  ["unknown sender with link"])

        return Classification(Verdict.CLEAN, ["no spam signals"])

    # -- relay ------------------------------------------------------

    @staticmethod
    def relay_for(verdict: Verdict) -> RelayDecision:
        """Map a verdict to what Phone B does with the event."""
        if verdict == Verdict.CLEAN:
            return RelayDecision.RELAY
        if verdict == Verdict.SUSPECT:
            return RelayDecision.RELAY_FLAGGED
        return RelayDecision.HOLD


# -- transport plug-in ---------------------------------------------

CALL_EVENT = "missed_call"
MESSAGE_EVENT = "sms"


def shielded_send(shield: SpamShield, node, kind: str,
                  ctx, event_type: Optional[str] = None,
                  payload: Optional[Dict] = None) -> RelayDecision:
    """Classify an inbound call/text and relay it only when warranted.

    kind is "call" or "message"; ctx is a CallContext or MessageContext.
    On RELAY / RELAY_FLAGGED the event goes out through the NetworkNode
    (SUSPECT payloads carry a spamshield flag); on HOLD nothing is sent.

    Returns the RelayDecision so the caller can log it.
    """
    if kind == "call":
        cls = shield.classify_call(ctx)
        etype = event_type or CALL_EVENT
        base = {"number": ctx.number, "hour": ctx.hour}
    elif kind == "message":
        cls = shield.classify_message(ctx)
        etype = event_type or MESSAGE_EVENT
        base = {"sender": ctx.sender, "body": ctx.body}
    else:
        raise ValueError("kind must be 'call' or 'message', got %r" % kind)

    decision = shield.relay_for(cls.verdict)
    if decision == RelayDecision.HOLD:
        return decision

    out = dict(base)
    out.update(payload or {})
    out["spamshield_verdict"] = cls.verdict.value
    out["spamshield_reasons"] = cls.reasons
    if decision == RelayDecision.RELAY_FLAGGED:
        out["spamshield_flag"] = True
    node.send_event(etype, out)
    return decision

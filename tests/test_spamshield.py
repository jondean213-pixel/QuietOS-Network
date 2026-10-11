"""QSS-001..QSS-012 — SPAM SHIELD proving ground.

Rule-based call/message classifier for the QuietOS Network: Phone B
filters inbound calls and texts, relays only what is worth relaying,
and never lets spam leave the home phone.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from quietos.network import (
    Verdict, RelayDecision, CallContext, MessageContext,
    SpamShield, normalize_number, shielded_send,
)


@pytest.fixture
def shield():
    # Noah Dean on the VIP list (one of Jon's standing VIPs).
    return SpamShield(vip_numbers=("812-555-0147",))


# -- number normalization -------------------------------------------

def test_qss_001_normalize_strips_formatting_and_country_code():
    assert normalize_number("(812) 555-0147") == "8125550147"
    assert normalize_number("+1 812-555-0147") == "8125550147"
    assert normalize_number("") == ""
    assert normalize_number("abc") == ""


# -- call classification --------------------------------------------

def test_qss_002_vip_always_clean_even_at_3am(shield):
    ctx = CallContext(number="812-555-0147", hour=3)
    cls = shield.classify_call(ctx)
    assert cls.verdict == Verdict.CLEAN
    assert "vip" in cls.reasons[0]


def test_qss_003_contact_is_clean(shield):
    ctx = CallContext(number="812-555-9999", in_contacts=True, hour=23)
    assert shield.classify_call(ctx).verdict == Verdict.CLEAN


def test_qss_004_number_jon_called_before_is_clean(shield):
    ctx = CallContext(number="812-555-2222", previously_called_by_jon=True)
    assert shield.classify_call(ctx).verdict == Verdict.CLEAN


def test_qss_005_invalid_numbers_are_spam(shield):
    for bad in ("", "123", "000-000-0000", "1111111111", "9999999"):
        ctx = CallContext(number=bad)
        assert shield.classify_call(ctx).verdict == Verdict.SPAM, bad


def test_qss_006_unknown_toll_free_is_suspect(shield):
    ctx = CallContext(number="800-555-0199", hour=12)
    assert shield.classify_call(ctx).verdict == Verdict.SUSPECT


def test_qss_007_unknown_caller_at_night_is_suspect(shield):
    ctx = CallContext(number="812-555-3333", hour=2)
    cls = shield.classify_call(ctx)
    assert cls.verdict == Verdict.SUSPECT
    assert any("hours" in r for r in cls.reasons)


def test_qss_008_blocked_prefix_is_spam():
    s = SpamShield(blocked_prefixes=("900",))
    ctx = CallContext(number="900-555-0100", hour=12)
    assert s.classify_call(ctx).verdict == Verdict.SPAM


# -- message classification ------------------------------------------

def test_qss_009_prize_text_is_spam(shield):
    ctx = MessageContext(sender="812-555-4444",
                         body="Congratulations! You've won a FREE CRUISE! "
                              "Click here to claim your prize: bit.ly/x9z")
    assert shield.classify_message(ctx).verdict == Verdict.SPAM


def test_qss_010_service_number_with_link_is_clean(shield):
    ctx = MessageContext(sender="872-265", is_service_number=True,
                         body="Chase: a $42.10 charge was made. "
                              "Reply STOP to opt out. chase.com/alerts")
    assert shield.classify_message(ctx).verdict == Verdict.CLEAN


def test_qss_011_unknown_sender_with_link_is_suspect(shield):
    ctx = MessageContext(sender="812-555-7777",
                         body="Hey, check out these photos: example.com/pic")
    assert shield.classify_message(ctx).verdict == Verdict.SUSPECT


# -- relay decisions --------------------------------------------------

def test_qss_012_relay_mapping():
    assert SpamShield.relay_for(Verdict.CLEAN) == RelayDecision.RELAY
    assert SpamShield.relay_for(Verdict.SUSPECT) == RelayDecision.RELAY_FLAGGED
    assert SpamShield.relay_for(Verdict.SPAM) == RelayDecision.HOLD


class _FakeNode:
    """Stands in for NetworkNode.send_event in relay tests."""
    def __init__(self):
        self.sent = []

    def send_event(self, event_type, payload):
        self.sent.append((event_type, payload))


def test_qss_013_shielded_send_relays_clean_call(shield):
    node = _FakeNode()
    ctx = CallContext(number="812-555-0147", hour=10)  # VIP
    d = shielded_send(shield, node, "call", ctx)
    assert d == RelayDecision.RELAY
    assert len(node.sent) == 1
    etype, payload = node.sent[0]
    assert etype == "missed_call"
    assert payload["spamshield_verdict"] == "clean"


def test_qss_014_shielded_send_flags_suspect_message(shield):
    node = _FakeNode()
    ctx = MessageContext(sender="812-555-7777",
                         body="Hey, check out these photos: example.com/pic")
    d = shielded_send(shield, node, "message", ctx)
    assert d == RelayDecision.RELAY_FLAGGED
    _, payload = node.sent[0]
    assert payload["spamshield_flag"] is True


def test_qss_015_shielded_send_holds_spam(shield):
    node = _FakeNode()
    ctx = MessageContext(sender="0000000000",
                         body="You've WON! Claim your prize now! Act now!")
    d = shielded_send(shield, node, "message", ctx)
    assert d == RelayDecision.HOLD
    assert node.sent == []


def test_qss_016_shielded_send_rejects_bad_kind(shield):
    node = _FakeNode()
    with pytest.raises(ValueError):
        shielded_send(shield, node, "fax", CallContext(number="1"))

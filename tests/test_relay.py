"""QRY-001..QRY-016 — cloud relay proving ground.

The forgotten-phone case: Phone B sits at home taking Jon's calls;
the Network relays FILTERED events to the phone Jon is carrying.
SPAM never leaves the home phone. Local Wi-Fi transport when the peer
is reachable, signed cloud envelopes queued in the outbox otherwise.
"""
import copy
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from quietos.network import (
    Verdict, RelayDecision, CallContext, MessageContext, SpamShield,
    PairedDevice, NetworkNode,
)
from quietos.network.relay import (
    MISSED_CALL, SMS, EMAIL_ALERT, ENVELOPE_VERSION,
    RelayEvent, RelayRouter, EnvelopeError,
    missed_call_event, sms_event, email_alert_event,
    seal_envelope, open_envelope,
)

PAIRING_CODE = "K7Q2-M9XD"


@pytest.fixture
def phone_b():
    return PairedDevice.pair(PAIRING_CODE, name="phone-b")


@pytest.fixture
def phone_a():
    return PairedDevice.pair(PAIRING_CODE, name="phone-a")


@pytest.fixture
def shield():
    return SpamShield(vip_numbers=("812-555-0147",))


class FakeNode:
    """Stand-in for NetworkNode: records sends, fakes peer reachability."""

    def __init__(self, peers=()):
        self._peers = list(peers)
        self.sent = []  # (event_type, payload)

    @property
    def peer_ids(self):
        return list(self._peers)

    def send_event(self, event_type, payload=None):
        self.sent.append((event_type, dict(payload or {})))


# -- event creation ---------------------------------------------------

def test_qry_001_missed_call_event_carries_number_and_verdict():
    ev = missed_call_event("8125550199", Verdict.CLEAN, ["in contacts"])
    assert ev.event_type == MISSED_CALL
    assert ev.payload["number"] == "8125550199"
    assert ev.verdict == Verdict.CLEAN
    assert ev.reasons == ["in contacts"]
    assert ev.event_id and not ev.flagged


def test_qry_002_sms_event_carries_sender_body_and_flag():
    ev = sms_event("8125550100", "running late, be there at 6",
                   Verdict.SUSPECT, ["unknown sender"])
    assert ev.event_type == SMS
    assert ev.payload["sender"] == "8125550100"
    assert ev.payload["body"] == "running late, be there at 6"
    assert ev.flagged is True  # SUSPECT -> flagged


def test_qry_003_email_alert_event_defaults_clean():
    ev = email_alert_event("cruisebrothers@example.com",
                           "Your group rates are ready",
                           "Star of the Seas, June 2027...")
    assert ev.event_type == EMAIL_ALERT
    assert ev.verdict == Verdict.CLEAN
    assert ev.payload["subject"] == "Your group rates are ready"


# -- spam filtering ---------------------------------------------------

def test_qry_004_spam_call_is_held_and_never_queued(shield, phone_b, phone_a):
    router = RelayRouter(phone_b, shield)
    ctx = CallContext(number="0000000000")  # invalid -> SPAM
    decision, route = router.handle_inbound_call(ctx, phone_a.device_id)
    assert decision == RelayDecision.HOLD
    assert route == "held"
    assert router.outbox_pending() == []


def test_qry_005_spam_sms_is_held_and_never_queued(shield, phone_b, phone_a):
    router = RelayRouter(phone_b, shield)
    ctx = MessageContext(
        sender="99999",
        body="You've won a FREE CRUISE! Claim your prize now at bit.ly/x")
    decision, route = router.handle_inbound_sms(ctx, phone_a.device_id)
    assert decision == RelayDecision.HOLD
    assert route == "held"
    assert router.outbox_pending() == []


def test_qry_006_suspect_relayed_with_flag(shield, phone_b, phone_a):
    node = FakeNode(peers=[phone_a.device_id])
    router = RelayRouter(phone_b, shield, node=node)
    ctx = CallContext(number="8125550199", hour=23)  # unknown + night
    decision, route = router.handle_inbound_call(ctx, phone_a.device_id)
    assert decision == RelayDecision.RELAY_FLAGGED
    assert route == "local"
    _, payload = node.sent[0]
    assert payload["spamshield_flag"] is True
    assert payload["spamshield_verdict"] == "suspect"


def test_qry_007_clean_call_relayed_without_flag(shield, phone_b, phone_a):
    node = FakeNode(peers=[phone_a.device_id])
    router = RelayRouter(phone_b, shield, node=node)
    ctx = CallContext(number="812-555-0147")  # VIP Noah Dean
    decision, route = router.handle_inbound_call(ctx, phone_a.device_id)
    assert decision == RelayDecision.RELAY
    assert route == "local"
    _, payload = node.sent[0]
    assert payload.get("spamshield_flag") is False
    assert payload["spamshield_verdict"] == "clean"


# -- envelope crypto --------------------------------------------------

def test_qry_008_envelope_sign_verify_round_trip(phone_b, phone_a):
    ev = missed_call_event("8125550199", Verdict.CLEAN, ["in contacts"])
    env = seal_envelope(phone_b, phone_a.device_id, ev)
    assert env["v"] == ENVELOPE_VERSION
    assert env["from"] == phone_b.device_id
    assert env["to"] == phone_a.device_id
    assert env["key_id"] == phone_b.key_id
    assert env["msg_id"] == ev.event_id
    assert "sig" in env and "payload_enc" in env
    event_type, payload = open_envelope(phone_a, env)
    assert event_type == MISSED_CALL
    assert payload["number"] == "8125550199"
    assert payload["spamshield_verdict"] == "clean"


def test_qry_009_tampered_payload_rejected(phone_b, phone_a):
    ev = sms_event("8125550100", "hello", Verdict.CLEAN, [])
    env = seal_envelope(phone_b, phone_a.device_id, ev)
    bad = copy.deepcopy(env)
    bad["payload_enc"] = bad["payload_enc"][:-4] + "AAAA"
    with pytest.raises(EnvelopeError):
        open_envelope(phone_a, bad)


def test_qry_010_tampered_signature_rejected(phone_b, phone_a):
    ev = sms_event("8125550100", "hello", Verdict.CLEAN, [])
    env = seal_envelope(phone_b, phone_a.device_id, ev)
    bad = copy.deepcopy(env)
    bad["sig"] = "0" * 64
    with pytest.raises(EnvelopeError):
        open_envelope(phone_a, bad)


def test_qry_011_wrong_key_envelope_rejected(phone_b):
    stranger = PairedDevice.pair("ZZZZ-9999", name="stranger")
    ev = missed_call_event("8125550199", Verdict.CLEAN, [])
    env = seal_envelope(phone_b, stranger.device_id, ev)
    with pytest.raises(EnvelopeError):
        open_envelope(stranger, env)


# -- routing ----------------------------------------------------------

def test_qry_012_local_routing_when_peer_reachable(shield, phone_b, phone_a):
    node = FakeNode(peers=[phone_a.device_id])
    router = RelayRouter(phone_b, shield, node=node)
    ev = missed_call_event("8125550147", Verdict.CLEAN, ["vip allowlist"])
    assert router.route_event(ev, phone_a.device_id) == "local"
    assert len(node.sent) == 1
    assert router.outbox_pending() == []


def test_qry_013_cloud_routing_queues_outbox_when_peer_unreachable(
        shield, phone_b, phone_a):
    node = FakeNode(peers=[])  # nobody on local Wi-Fi
    pushed = []
    router = RelayRouter(phone_b, shield, node=node,
                         push_send=lambda env: pushed.append(env) or True)
    ev = missed_call_event("8125550147", Verdict.CLEAN, ["vip allowlist"])
    assert router.route_event(ev, phone_a.device_id) == "cloud"
    assert node.sent == []
    assert len(pushed) == 1  # push hook accepted it -> outbox drained
    assert router.outbox_pending() == []


def test_qry_014_outbox_retains_and_retries_on_push_failure(
        shield, phone_b, phone_a):
    node = FakeNode(peers=[])
    router = RelayRouter(phone_b, shield, node=node,
                         push_send=lambda env: False)  # push keeps failing
    ev = sms_event("8125550100", "call me", Verdict.CLEAN, [])
    assert router.route_event(ev, phone_a.device_id) == "cloud"
    pending = router.outbox_pending()
    assert len(pending) == 1
    entry = pending[0]
    assert entry.attempts == 1
    # Retry timer armed with backoff; ack clears it.
    assert entry.next_retry_at > entry.queued_at
    assert router.cloud_acked(entry.msg_id) is True
    assert router.outbox_pending() == []


# -- dedup ------------------------------------------------------------

def test_qry_015_same_event_local_then_cloud_delivered_once(
        shield, phone_b, phone_a):
    received = []
    router = RelayRouter(phone_b, shield,
                         on_relay_event=lambda et, p, f: received.append(et))
    ev = missed_call_event("8125550147", Verdict.CLEAN, [])
    payload = dict(ev.payload)
    payload["relay_msg_id"] = ev.event_id
    assert router.receive_local(MISSED_CALL, payload,
                                phone_b.device_id) is True
    env = seal_envelope(phone_b, phone_a.device_id, ev)
    assert router.receive_cloud_envelope(env) is False  # duplicate
    assert received == [MISSED_CALL]


def test_qry_016_end_to_end_call_to_cloud_to_delivery(
        shield, phone_b, phone_a):
    """Phone B classifies, queues cloud, Phone A's router verifies and
    delivers exactly once."""
    pushed = []
    home = RelayRouter(phone_b, shield,
                       push_send=lambda env: pushed.append(env) or True)
    delivered = []
    carried = RelayRouter(phone_a, shield,
                          on_relay_event=lambda et, p, f: delivered.append(
                              (et, p, f)))

    ctx = CallContext(number="812-555-0147")  # VIP -> CLEAN
    decision, route = home.handle_inbound_call(ctx, phone_a.device_id)
    assert decision == RelayDecision.RELAY
    assert route == "cloud"
    assert len(pushed) == 1

    assert carried.receive_cloud_envelope(pushed[0]) is True
    assert len(delivered) == 1
    et, payload, frm = delivered[0]
    assert et == MISSED_CALL
    assert payload["number"] == "812-555-0147"
    assert frm == phone_b.device_id
    # Second copy (push retry) is a no-op.
    assert carried.receive_cloud_envelope(pushed[0]) is False
    assert len(delivered) == 1

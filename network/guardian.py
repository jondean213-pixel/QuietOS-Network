"""
Guardian module interface — sketch for Android integration.

DeanWay Guardian (theft protection) as a QuietOS Network module.
The Guardian stays a native Android app (Kotlin); this module defines
the contract between the Guardian app and the Network core.

Integration points:
  1. EVENT REPORTING — Guardian publishes theft events to the Network.
     The Network claims the Attention Token so Jon's OTHER devices
     alert (not just the stolen one).
  2. EVIDENCE SHARING — Alarm photos flow through the Network's
     encrypted file transfer, not just via Drive.
  3. REMOTE CONTROL — From a paired device, Jon can arm/disarm
     Guardian or trigger the alarm remotely.

This is the contract. The Android side implements GuardianBridge
(Kotlin); the Network side implements GuardianModule (Python).
They talk via the paired encrypted channel.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class GuardianEvent(Enum):
    """Events the Guardian app publishes to the Network."""
    ARMED = "armed"                       # Protection armed
    DISARMED = "disarmed"                 # Protection disarmed by owner
    PICKUP_DETECTED = "pickup_detected"   # Motion: possible snatch, grace period running
    CHALLENGE_SHOWN = "challenge_shown"   # Biometric challenge displayed
    CHALLENGE_PASSED = "challenge_passed" # Owner verified — stand down
    CHALLENGE_FAILED = "challenge_failed" # Non-owner failed — escalate
    ALARM_TRIGGERED = "alarm_triggered"   # Siren + photo capture active
    PHOTO_CAPTURED = "photo_captured"     # Evidence photo ready for transfer
    ALARM_STOPPED = "alarm_stopped"       # Alarm silenced (owner or timeout)


class GuardianCommand(Enum):
    """Commands the Network can send to the Guardian app."""
    ARM = "arm"                 # Arm protection remotely
    DISARM = "disarm"           # Disarm (requires owner auth on target)
    TRIGGER_ALARM = "trigger"   # Force alarm now (panic button from other device)
    LOCATE = "locate"           # Request current location
    STATUS = "status"           # Request status snapshot


@dataclass
class GuardianStatus:
    """Snapshot of Guardian state on a device."""
    device_id: str
    armed: bool = False
    alarm_active: bool = False
    battery_pct: Optional[int] = None
    last_event: Optional[GuardianEvent] = None


@dataclass
class GuardianModule:
    """
    Network-side Guardian module (Python).

    Subscribes to Guardian events from paired devices, claims the
    Attention Token for theft events, and routes evidence via
    the encrypted file transfer channel.
    """
    device_id: str
    token_coordinator: object = None   # TokenCoordinator from token.py
    transfer: object = None            # file transfer channel from transfer.py

    # --- Event intake (called when a Guardian event arrives) ---

    def on_event(self, event: GuardianEvent, from_device: str,
                 payload: dict = None) -> dict:
        """
        Handle a Guardian event from a paired device.
        Returns the Network action taken.
        """
        payload = payload or {}
        if event == GuardianEvent.PICKUP_DETECTED:
            # Possible theft — claim token so OTHER devices can alert.
            # The stolen phone's own alarm handles locally; the Network
            # ensures Jon's carried device also knows.
            return {"action": "token_claim",
                    "event_id": f"guardian-pickup-{from_device}",
                    "bucket": "NOW"}
        if event == GuardianEvent.ALARM_TRIGGERED:
            return {"action": "token_claim",
                    "event_id": f"guardian-alarm-{from_device}",
                    "bucket": "NOW"}
        if event == GuardianEvent.PHOTO_CAPTURED:
            # Evidence photo ready — pull via encrypted transfer.
            return {"action": "request_evidence",
                    "from_device": from_device,
                    "photo_id": payload.get("photo_id")}
        if event == GuardianEvent.CHALLENGE_PASSED:
            # Owner verified — yield any held token.
            return {"action": "token_yield",
                    "event_id": f"guardian-pickup-{from_device}"}
        return {"action": "log"}

    # --- Command dispatch (called to control a remote Guardian) ---

    def send_command(self, to_device: str, command: GuardianCommand,
                     payload: dict = None) -> dict:
        """
        Send a command to the Guardian app on a paired device.
        Returns the command envelope for the encrypted channel.
        """
        return {"type": "guardian_command",
                "to_device": to_device,
                "command": command.value,
                "payload": payload or {}}


# --- Android-side contract (for the Kotlin implementation) ---
#
# The Guardian app (Kotlin) implements:
#
#   interface GuardianBridge {
#       // Publish events to the Network (via paired encrypted channel)
#       fun publishEvent(event: GuardianEvent, payload: Map<String, String>)
#
#       // Receive commands from the Network
#       fun onCommand(command: GuardianCommand, payload: Map<String, String>)
#
#       // Provide evidence photos for Network transfer
#       fun getEvidencePhoto(photoId: String): ByteArray
#   }
#
# Event → Network → Token flow:
#   1. Snatch detected → Guardian publishes PICKUP_DETECTED
#   2. Network claims Attention Token (NOW bucket)
#   3. Jon's OTHER paired device interrupts: "Possible theft on your other phone"
#   4. Challenge fails → ALARM_TRIGGERED → token held, siren locally
#   5. PHOTO_CAPTURED → Network pulls photo via encrypted transfer
#   6. Owner verifies → CHALLENGE_PASSED → token yielded
#
# This keeps the Guardian's local theft response (siren, photo, Drive)
# intact while adding cross-device awareness via the Network.

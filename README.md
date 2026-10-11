# QuietOS Network

Cross-device coordination for QuietOS: Attention Token, encrypted pairing, file transfer, and Wi-Fi socket transport. Python.

## What it does

- **Attention Token** — Exactly one device interrupts for an event. Lifecycle: claim → lease → yield → expire. A dead device never swallows an emergency.
- **Encrypted pairing** — Devices pair with a typable code; HKDF-SHA256 derives a shared 32-byte channel key.
- **Encrypted file transfer** — Between paired devices. AES-256-GCM, offer → accept → chunks → integrity verification.
- **Wi-Fi socket transport** — Real TCP transport for phone-to-phone communication on a LAN. All traffic encrypted with the pairing key.
- **Guardian contract** — Event/command interface for the Guardian theft-protection module.

## Quick start (two phones on the same Wi-Fi)

On Phone A:
```
python3 net_demo.py listen
```

On Phone B (replace with A's IP):
```
python3 net_demo.py dial 192.168.1.X
```

Both phones must use the same pairing code (default `K7Q2-M9XD` in `net_demo.py`).

## Requirements

- Python 3.8+
- `cryptography` package (`pkg install python-cryptography` on Termux)

## Tests

```
python3 -m pytest tests/ -q
```

## Status

Bench-tested (223 passing). Live two-phone field test succeeded 2026-10-11.

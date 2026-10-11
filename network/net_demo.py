"""QuietOS Network live demo — run on both phones.

On PHONE A (the listener):
    python3 net_demo.py listen

On PHONE B (dials A — replace 192.168.1.X with A's Wi-Fi IP):
    python3 net_demo.py dial 192.168.1.X

Both phones must use the SAME pairing code (edit PAIRING_CODE below,
or pass it as the 3rd argument).

What happens:
  1. The two phones handshake (paired key_id check).
  2. Phone B claims the Attention Token for a test event.
  3. Phone A sees B as the token owner.
  4. Phone B yields; Phone A sees the token free.
  5. A Guardian-style event is sent B -> A.

Ctrl+C to stop.
"""
import sys
import time

sys.path.insert(0, ".")

from network import PairedDevice, NetworkNode, Bucket, DEFAULT_PORT

PAIRING_CODE = "K7Q2-M9XD"  # change me — both phones must match


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "listen"
    code = sys.argv[3] if len(sys.argv) > 3 else PAIRING_CODE
    port = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_PORT

    device = PairedDevice.pair(code, name="phone-" + mode)
    node = NetworkNode(device, port=port)
    node.on_peer = lambda pid, up: print(
        f"*** peer {'connected' if up else 'left'}: {pid[:8]}")
    node.on_event = lambda et, p, frm: print(
        f"*** EVENT from {frm[:8]}: {et} {p}")
    node.start()
    print(f"[{device.name}] listening on port {port}, "
          f"key_id={device.key_id}")

    if mode == "dial":
        host = sys.argv[2]
        print(f"[{device.name}] dialing {host}:{port} ...")
        node.connect(host, port)
        print(f"[{device.name}] connected. Peers: "
              f"{[p[:8] for p in node.peer_ids]}")
        time.sleep(1.0)

        # Claim the token — A should see us as owner.
        print(f"[{device.name}] claiming token for 'demo-call' ...")
        print("  granted:", node.claim_token("demo-call", Bucket.NOW))
        time.sleep(1.5)

        # Send a Guardian-style event.
        node.send_event("guardian_alarm",
                        {"photo_id": "demo-001", "note": "hello from B"})
        time.sleep(1.0)

        # Yield — A should see the token free.
        print(f"[{device.name}] yielding token ...")
        print("  yielded:", node.yield_token("demo-call"))
        time.sleep(1.0)
        print(f"[{device.name}] done. Ctrl+C to stop.")
    else:
        print(f"[{device.name}] waiting for a peer to dial in ...")
        print("  (on the other phone: python3 net_demo.py dial <this-ip>)")

    try:
        while True:
            # Show current token state every 5s so Jon can watch it.
            owner = node.token_owner("demo-call")
            print(f"[{device.name}] token 'demo-call' owner: "
                  f"{owner[:8] if owner else None} | "
                  f"peers: {[p[:8] for p in node.peer_ids]}")
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
        print("stopped.")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("listen", "dial"):
        print(__doc__)
        sys.exit(1)
    main()

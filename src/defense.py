import os
import time

from crypto_utils import verify_signature
from order_packet import build_signable_data, load_public_key

# Known customers: maps customer_id to the key owner's name
KNOWN_CUSTOMERS = {
    1: "customer_a",
    2: "customer_b",
}

TIMESTAMP_WINDOW_SECONDS = 30
RATE_LIMIT_MAX_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 5

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "verification_log.txt")

seen_orders = set()   # (customer_id, order_id) pairs already accepted -> replay protection
request_log = []      # timestamps of recent requests -> rate limiting


def verify_order_packet(order):
    """
    Run all Blue Team security checks on an incoming OrderPacket.
    Returns (accepted: bool, reason: str)
    """
    now = int(time.time())

    if order.customer_id not in KNOWN_CUSTOMERS:
        return False, f"REJECTED - unknown customer_id {order.customer_id} (identity binding failed)"

    customer_name = KNOWN_CUSTOMERS[order.customer_id]
    public_key = load_public_key(customer_name)

    data = build_signable_data(order.customer_id, order.order_id, order.item_id, order.quantity, order.timestamp)
    if not verify_signature(data, order.signature, public_key):
        return False, "REJECTED - invalid signature (tampering or spoofing detected)"

    age = abs(now - order.timestamp)
    if age > TIMESTAMP_WINDOW_SECONDS:
        return False, f"REJECTED - stale timestamp (age={age}s, max allowed={TIMESTAMP_WINDOW_SECONDS}s)"

    order_key = (order.customer_id, order.order_id)
    if order_key in seen_orders:
        return False, f"REJECTED - duplicate order detected (replay attack), order_id={order.order_id}"

    request_log.append(now)
    recent = [t for t in request_log if now - t <= RATE_LIMIT_WINDOW_SECONDS]
    request_log[:] = recent
    if len(recent) > RATE_LIMIT_MAX_REQUESTS:
        return False, f"REJECTED - rate limit exceeded ({len(recent)} requests in {RATE_LIMIT_WINDOW_SECONDS}s)"

    seen_orders.add(order_key)
    return True, "ACCEPTED - all checks passed"


def log(message):
    print(message)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(message + "\n")
from order_packet import create_signed_order, load_private_key
from defense import verify_order_packet, log

private_key_a = load_private_key("customer_a")

log("\n=== TEST 1: Legitimate order ===")
order = create_signed_order(customer_id=1, order_id=5001, item_id=10, quantity=2, private_key=private_key_a)
accepted, reason = verify_order_packet(order)
log(f"Result: {reason}")

log("\n=== TEST 2: Spoofed order (customer_id changed after signing) ===")
order2 = create_signed_order(customer_id=1, order_id=5002, item_id=10, quantity=2, private_key=private_key_a)
order2.customer_id = 999
accepted, reason = verify_order_packet(order2)
log(f"Result: {reason}")

log("\n=== TEST 3: Tampered order (item_id/quantity changed after signing) ===")
order3 = create_signed_order(customer_id=1, order_id=5003, item_id=10, quantity=2, private_key=private_key_a)
order3.item_id = 999
order3.quantity = 500
accepted, reason = verify_order_packet(order3)
log(f"Result: {reason}")

log("\n=== TEST 4: Replay attack (same order sent twice) ===")
order4 = create_signed_order(customer_id=1, order_id=5004, item_id=10, quantity=2, private_key=private_key_a)
accepted, reason = verify_order_packet(order4)
log(f"First send result: {reason}")
accepted, reason = verify_order_packet(order4)
log(f"Replay send result: {reason}")

log("\n=== TEST 5: Flooding (12 rapid requests) ===")
for i in range(12):
    flood_order = create_signed_order(customer_id=1, order_id=6000 + i, item_id=10, quantity=1, private_key=private_key_a)
    accepted, reason = verify_order_packet(flood_order)
    log(f"Request {i + 1}: {reason}")
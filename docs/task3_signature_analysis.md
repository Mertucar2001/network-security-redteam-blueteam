TASK 3 — Red Team: Analysis of Signature Misuse

Missing signature: If a packet is sent with an empty or missing signature field, verification must fail immediately and the packet should be rejected outright, since there is no way to confirm its authenticity.

Mismatched signature: If a signature was created with a different private key than the one whose public key is used for verification (or if the signed data was altered), verification returns False. This was demonstrated in our test by verifying Customer A's signature against Customer B's public key, which correctly failed.

Reused signature: A valid, correctly signed packet can be captured and resent unchanged by an attacker (replay attack). Since the content and signature are unmodified, verification alone will still return True, meaning signature verification by itself cannot detect a reused packet. This is why a timestamp freshness check is required in addition to signature verification (see Task 7).
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")


def generate_key_pair(name):
    """Generate an RSA key pair and save it to the keys/ folder."""
    key = RSA.generate(2048)

    private_key_path = os.path.join(KEYS_DIR, f"{name}_private.pem")
    public_key_path = os.path.join(KEYS_DIR, f"{name}_public.pem")

    with open(private_key_path, "wb") as f:
        f.write(key.export_key())

    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())

    print(f"Generated key pair for {name}")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key:  {public_key_path}")

    return key


def sign_data(data: bytes, private_key: RSA.RsaKey) -> bytes:
    """Sign data using the sender's RSA private key."""
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_signature(data: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    """Verify a signature using the sender's RSA public key."""
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    # Step 1: generate RSA key pairs for Customer A and Customer B
    key_a = generate_key_pair("customer_a")
    key_b = generate_key_pair("customer_b")

    # Step 2: test signing and verification
    test_message = b"order_id=1001;item_id=42;quantity=3"

    print("\nSigning test message with Customer A's private key...")
    signature = sign_data(test_message, key_a)
    print(f"Signature (first 20 bytes): {signature[:20].hex()}...")

    print("\nVerifying signature with Customer A's public key...")
    is_valid = verify_signature(test_message, signature, key_a.publickey())
    print(f"Verification result: {is_valid}")

    print("\nVerifying with a WRONG key (Customer B's public key) to confirm mismatch detection...")
    is_valid_wrong = verify_signature(test_message, signature, key_b.publickey())
    print(f"Verification result with wrong key: {is_valid_wrong}")
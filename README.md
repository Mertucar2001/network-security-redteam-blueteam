# Network Security — Red Team / Blue Team Simulation

A hands-on IT Security project implementing a custom encrypted network protocol, a set of attack simulations against it, and a defense system to detect and mitigate those attacks.

## Overview

This project simulates secure communication between two parties (`customer_a` and `customer_b`) using RSA-2048 encrypted packets sent over the network with Scapy. On top of the secure protocol, it includes offensive (red team) attack simulations and a defensive (blue team) detection/response system.

## Structure

```
├── src/
│   ├── crypto_utils.py     # RSA key handling, encryption/decryption helpers
│   ├── order_packet.py     # Custom packet format/protocol definition
│   ├── attacks.py          # Attack simulations
│   ├── defense.py          # Defense/detection system
│   ├── defense_test.py     # Tests for the defense system
│   └── test_scapy.py       # Scapy environment sanity checks
├── keys/                   # RSA public keys (private keys are gitignored)
├── docs/                   # Analysis write-ups
└── screenshots/            # Wireshark captures and terminal output evidence
```

## Key components

- **Secure protocol**: Custom packet format built with Scapy, encrypted using RSA-2048 key pairs generated per party
- **Attack simulations**: Multiple attack scenarios implemented against the protocol to test its resilience
- **Defense system**: Detects and responds to the simulated attacks, verified with dedicated tests
- **Signature analysis**: Documented in `docs/task3_signature_analysis.md`

## Tech stack

- Python, Scapy 2.7.0
- PyCryptodome 3.23.0 (RSA-2048)
- Wireshark / Npcap for packet capture and verification

## Running it

Raw packet sending requires elevated privileges:

```bash
# Run as Administrator (Windows) — required for raw packet operations
pip install -r requirements.txt
python src/test_scapy.py       # sanity check
python src/attacks.py          # run attack simulations
python src/defense.py          # run the defense system
python src/defense_test.py     # test the defense system
```

## Security note

Private RSA keys used in this project are excluded from version control (`.gitignore`). Only public keys are committed.

## Note

This was a course project built for an IT Security assignment, covering secure protocol design, offensive attack simulation, and defensive countermeasures.

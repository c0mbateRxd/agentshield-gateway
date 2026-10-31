"""Print a dev Ed25519 keypair for LEASE_SIGNING_KEY / LEASE_PUBLIC_KEY.

Run from services/gateway: python -m scripts.gen_keys
"""
from app.core.lease import generate_keypair

priv, pub = generate_keypair()
print(f"LEASE_SIGNING_KEY={priv}\nLEASE_PUBLIC_KEY={pub}")

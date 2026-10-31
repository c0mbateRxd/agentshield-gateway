import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from app.core.canonical import canonical


class LeaseInvalid(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def generate_keypair() -> tuple[str, str]:
    """Returns (private_seed_b64, public_b64) raw Ed25519 keys."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64e(seed), _b64e(pub)


class LeaseKeys:
    def __init__(self, kid: str, private_b64: str | None, public_b64: str | None):
        self.kid = kid
        self._priv = Ed25519PrivateKey.from_private_bytes(_b64d(private_b64)) if private_b64 else None
        if public_b64:
            self._pub = Ed25519PublicKey.from_public_bytes(_b64d(public_b64))
        elif self._priv:
            self._pub = self._priv.public_key()
        else:
            raise ValueError("need LEASE_SIGNING_KEY or LEASE_PUBLIC_KEY")

    def sign(self, payload: dict) -> str:
        if not self._priv:
            raise ValueError("no signing key")
        body = canonical({**payload, "kid": self.kid})
        return f"{_b64e(body)}.{_b64e(self._priv.sign(body))}"

    def verify(self, token: str) -> dict:
        try:
            body_b64, sig_b64 = token.split(".")
            body = _b64d(body_b64)
            self._pub.verify(_b64d(sig_b64), body)
            payload = json.loads(body)
        except (ValueError, InvalidSignature) as e:
            raise LeaseInvalid("bad signature or format") from e
        if payload.get("kid") != self.kid:
            raise LeaseInvalid("unknown kid")
        return payload

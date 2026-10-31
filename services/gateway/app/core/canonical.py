import hashlib
import json


def canonical(obj) -> bytes:
    """UTF-8, sorted keys, no whitespace (spec 8.1)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()

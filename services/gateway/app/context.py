import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.lease import LeaseKeys
from app.core.policy import Policy
from app.settings import Settings


@dataclass
class Ctx:
    settings: Settings
    session: object              # sessionmaker
    erp: object                  # ErpClient-compatible
    oracles: object              # OracleClient-compatible
    policy: Policy
    keys: LeaseKeys
    profile: str = "PROTECTED"   # PROTECTED | VULNERABLE (sandbox only)
    now: object = lambda: datetime.now(UTC)  # injectable clock for tests
    _locks: dict = field(default_factory=dict)
    _locks_guard: threading.Lock = field(default_factory=threading.Lock)

    def lock(self, key: str) -> threading.Lock:
        """Per-business-object lock: serialises check-then-execute for one invoice/supplier/PO."""
        with self._locks_guard:
            return self._locks.setdefault(key, threading.Lock())

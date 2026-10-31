import os
from dataclasses import dataclass, field
from pathlib import Path

from app.core.lease import generate_keypair

POLICY_DIR = Path(__file__).resolve().parent.parent / "policy"


@dataclass
class Settings:
    jwt_secret: str
    database_url: str = "sqlite:///./gateway.db"
    erp_url: str = "http://erp_sim:8001"
    oracles_url: str = "http://oracles:8002"
    agent_url: str = "http://agent:8003"
    erp_service_token: str = ""
    lease_signing_key: str | None = None
    lease_public_key: str | None = None
    lease_kid: str = "lease-key-2026-11"
    sandbox: bool = False
    policy_dir: Path = POLICY_DIR
    demo_passwords: dict[str, str] = field(default_factory=dict)  # env var name -> password
    test_inject_policy_error: bool = False  # test-only flag for DENY_POLICY_ERROR

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ
        s = cls(
            jwt_secret=e["JWT_SECRET"],
            database_url=e.get("DATABASE_URL", cls.database_url),
            erp_url=e.get("ERP_URL", cls.erp_url),
            oracles_url=e.get("ORACLES_URL", cls.oracles_url),
            agent_url=e.get("AGENT_URL", cls.agent_url),
            erp_service_token=e.get("ERP_SERVICE_TOKEN", ""),
            lease_signing_key=e.get("LEASE_SIGNING_KEY"),
            lease_public_key=e.get("LEASE_PUBLIC_KEY"),
            lease_kid=e.get("LEASE_KID", cls.lease_kid),
            sandbox=e.get("SANDBOX") == "1",
            demo_passwords={k: v for k, v in e.items() if k.startswith("DEMO_PASSWORD_")},
        )
        if not s.lease_signing_key:  # dev fallback: ephemeral key, leases die on restart
            s.lease_signing_key, s.lease_public_key = generate_keypair()
        return s

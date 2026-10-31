import hmac
import time

import jwt
import yaml
from fastapi import Depends, HTTPException, Request

ISSUER = "agentshield-demo"


def issue_token(secret: str, sub: str, roles: list[str], hours: int = 8) -> str:
    now = int(time.time())
    return jwt.encode({"sub": sub, "roles": roles, "iat": now, "exp": now + hours * 3600, "iss": ISSUER},
                      secret, algorithm="HS256")


def decode_token(secret: str, token: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"], issuer=ISSUER,
                      options={"require": ["sub", "roles", "iat", "exp", "iss"]})


def load_users(settings) -> dict:
    users = yaml.safe_load((settings.policy_dir / "users.yaml").read_text())["users"]
    return {u: v for u, v in users.items() if settings.sandbox or not v.get("sandbox_only")}


def check_login(settings, username: str, password: str) -> dict | None:
    user = load_users(settings).get(username)
    expected = settings.demo_passwords.get(user["password_env"]) if user else None
    if not expected or not hmac.compare_digest(expected.encode(), str(password).encode()):
        return None
    return user


def bearer(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    return h[7:] if h.lower().startswith("bearer ") else None


def claims_from_token(secret: str, token: str | None) -> dict:
    if not token:
        raise HTTPException(401, "missing bearer token")
    try:
        return decode_token(secret, token)
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid token") from None


def require_roles(*roles: str):
    """FastAPI dependency: valid JWT carrying at least one of `roles`."""
    def dep(request: Request) -> dict:
        claims = claims_from_token(request.app.state.ctx.settings.jwt_secret, bearer(request))
        if not set(claims["roles"]) & set(roles):
            raise HTTPException(403, "insufficient role")
        return claims
    return Depends(dep)

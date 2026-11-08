from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from collections.abc import Awaitable, Callable
from enum import IntEnum
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status
from nope_core.config import settings


class Role(IntEnum):
    ANONYMOUS = 0
    CI = 10
    AGENT = 20
    APPROVER = 30
    ADMIN = 40


class AuthIdentity(str):
    """Authenticated identity carrying subject, verified role, and tenant boundary.

    Inherits from str for complete backwards-compatibility with existing actor strings.
    """

    subject: str
    role: Role
    actor_id: str
    organization: str
    auth_type: str
    is_user_identity: bool

    def __new__(
        cls,
        subject: str,
        role: Role,
        actor_id: str | None = None,
        organization: str = "default",
        auth_type: str = "api_key",
        is_user_identity: bool = False,
    ) -> AuthIdentity:
        str_val = actor_id or subject
        instance = super().__new__(cls, str_val)
        instance.subject = subject
        instance.role = role
        instance.actor_id = str_val
        instance.organization = organization
        instance.auth_type = auth_type
        instance.is_user_identity = is_user_identity
        return instance

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Role):
            return self.role == other
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        if isinstance(other, Role):
            return self.role != other
        return super().__ne__(other)

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, Role):
            return self.role < other
        return super().__lt__(other)

    def __le__(self, other: Any) -> bool:
        if isinstance(other, Role):
            return self.role <= other
        return super().__le__(other)

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, Role):
            return self.role > other
        return super().__gt__(other)

    def __ge__(self, other: Any) -> bool:
        if isinstance(other, Role):
            return self.role >= other
        return super().__ge__(other)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "role": self.role.name.lower(),
            "actor_id": self.actor_id,
            "organization": self.organization,
            "auth_type": self.auth_type,
            "is_user_identity": self.is_user_identity,
        }


def _get_signing_secret() -> str:
    secret = os.getenv("NOPE_TOKEN_SECRET") or settings.github_webhook_secret
    if not secret:
        if settings.is_development:
            return "dev-insecure-token-signing-secret-nope-core"
        raise RuntimeError("NOPE_TOKEN_SECRET must be configured in production for signed tokens")
    return secret


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _base64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def issue_token(
    subject: str,
    role: Role | str,
    expires_in_seconds: int = 86400,
    organization: str = "default",
    secret: str | None = None,
) -> str:
    """Issue a cryptographically signed HMAC-SHA256 bearer token."""
    if isinstance(role, str):
        role = Role[role.upper()]
    signing_secret = secret or _get_signing_secret()
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject.strip(),
        "role": role.name.lower(),
        "org": organization.strip(),
        "iat": now,
        "exp": now + expires_in_seconds,
        "iss": "nope-core",
    }
    encoded_header = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(signing_secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded_sig = _base64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_sig}"


def verify_token(token: str, secret: str | None = None) -> AuthIdentity:
    """Verify an HMAC-SHA256 signed bearer token, checking signature and expiration."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Malformed token format; expected 3 dot-separated segments")
    encoded_header, encoded_payload, encoded_sig = parts
    signing_secret = secret or _get_signing_secret()
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    expected_sig = hmac.new(signing_secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual_sig = _base64url_decode(encoded_sig)
    except Exception as exc:
        raise ValueError(f"Invalid token signature encoding: {exc}") from exc
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid token signature")
    try:
        payload = json.loads(_base64url_decode(encoded_payload).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid token payload JSON: {exc}") from exc
    now = int(time.time())
    if "exp" in payload and payload["exp"] < now:
        raise ValueError("Token has expired")
    role_name = str(payload.get("role", "")).upper()
    try:
        role = Role[role_name]
    except KeyError:
        raise ValueError(f"Unknown role in token: {role_name}") from None
    subject = str(payload.get("sub", "")).strip()
    if not subject:
        raise ValueError("Missing subject claim in token payload")
    organization = str(payload.get("org", "default")).strip()
    return AuthIdentity(
        subject=subject,
        role=role,
        actor_id=f"user:{subject}",
        organization=organization,
        auth_type="bearer_token",
        is_user_identity=True,
    )


def parse_api_keys() -> dict[str, AuthIdentity]:
    """Parse NOPE_API_KEYS supporting:

    1. key:role (e.g. key:admin)
    2. key:role:subject (e.g. key:approver:alice@acme.com)
    3. key:role:subject:org (e.g. key:approver:alice@acme.com:acme-corp)
    """
    raw = os.getenv("NOPE_API_KEYS", "").strip()
    parsed: dict[str, AuthIdentity] = {}
    for entry in raw.split(","):
        if not entry.strip():
            continue
        parts = entry.split(":")
        if len(parts) < 2:
            raise RuntimeError("NOPE_API_KEYS must use 'key:role[:subject[:org]]' entries separated by commas")
        key = parts[0].strip()
        if not key or key in parsed:
            raise RuntimeError("NOPE_API_KEYS requires non-empty, unique keys")
        role_name = parts[1].strip().lower()
        try:
            role = Role[role_name.upper()]
        except KeyError as exc:
            raise RuntimeError(f"Unknown NOPE API role: {role_name!r}") from exc
        if len(parts) >= 3 and parts[2].strip():
            subject = parts[2].strip()
            org = parts[3].strip() if len(parts) >= 4 and parts[3].strip() else "default"
            parsed[key] = AuthIdentity(
                subject=subject,
                role=role,
                actor_id=f"user:{subject}",
                organization=org,
                auth_type="api_key",
                is_user_identity=True,
            )
        else:
            hashed_key = hashlib.sha256(key.encode()).hexdigest()[:16]
            parsed[key] = AuthIdentity(
                subject=role.name.lower(),
                role=role,
                actor_id=f"api-key:{role.name.lower()}:{hashed_key}",
                organization="default",
                auth_type="api_key",
                is_user_identity=False,
            )
    return parsed


API_KEYS = parse_api_keys()
ALLOW_ANONYMOUS = os.getenv("NOPE_ALLOW_ANONYMOUS", "false").lower() == "true"


def authorize(minimum: Role) -> Callable[[Annotated[str | None, Header()], Annotated[str | None, Header()]], Awaitable[AuthIdentity]]:
    async def dependency(
        x_nope_key: Annotated[str | None, Header()] = None,
        authorization: Annotated[str | None, Header()] = None,
    ) -> AuthIdentity:
        # 1. Bearer token support
        if authorization:
            auth_val = authorization.strip()
            if auth_val.lower().startswith("bearer "):
                raw_token = auth_val[7:].strip()
                try:
                    identity = verify_token(raw_token)
                except ValueError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Invalid or expired authorization token: {exc}",
                        headers={"WWW-Authenticate": "Bearer"},
                    ) from exc
                if identity.role < minimum:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Insufficient permissions; role '{identity.role.name.lower()}' is lower than required '{minimum.name.lower()}'",
                    )
                return identity

        # 2. X-NOPE-Key header support
        if x_nope_key:
            # Re-read API_KEYS if dynamically reconfigured in tests
            current_keys = API_KEYS or parse_api_keys()
            for expected_key, identity in current_keys.items():
                if hmac.compare_digest(expected_key.encode("utf-8"), x_nope_key.encode("utf-8")):
                    if identity.role < minimum:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Insufficient permissions; role '{identity.role.name.lower()}' is lower than required '{minimum.name.lower()}'",
                        )
                    return identity
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid X-NOPE-Key credentials",
            )

        # 3. Anonymous fallback if allowed
        if (
            ALLOW_ANONYMOUS
            and minimum <= Role.AGENT
            and os.getenv("NOPE_ENV", "production").lower() in {"dev", "development", "test"}
        ):
            return AuthIdentity(
                subject="local-anonymous",
                role=Role.ANONYMOUS,
                actor_id="local-anonymous",
                organization="default",
                auth_type="anonymous",
                is_user_identity=False,
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials (Authorization Bearer token or X-NOPE-Key)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return dependency


AdminRequired = Annotated[AuthIdentity, Depends(authorize(Role.ADMIN))]
ApproverRequired = Annotated[AuthIdentity, Depends(authorize(Role.APPROVER))]
AgentRequired = Annotated[AuthIdentity, Depends(authorize(Role.AGENT))]
CiRequired = Annotated[AuthIdentity, Depends(authorize(Role.CI))]

"""Small helpers shared by the modules (not part of the public API)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Mapping, Optional
from urllib.parse import quote


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def random_token(nbytes: int = 32) -> str:
    """A URL-safe random string from the OS CSPRNG."""
    return secrets.token_urlsafe(nbytes)


def pkce_verifier() -> str:
    """A PKCE code verifier: 48 random bytes -> 64 base64url characters (RFC 7636 allows 43-128)."""
    return secrets.token_urlsafe(48)


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def at_hash(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return b64url(digest[: len(digest) // 2])


def same(a: Optional[str], b: Optional[str]) -> bool:
    """Constant-time string comparison; False when either is missing."""
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def decode_jwt(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """The payload of a JWT WITHOUT verifying it (for display only); ``None`` when it is not a JWT."""
    if not token or not isinstance(token, str):
        return None
    try:
        payload = json.loads(b64url_decode(token.split(".")[1]).decode("utf-8"))
    except (IndexError, ValueError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def normalize_issuer(issuer: str) -> str:
    if not issuer or not isinstance(issuer, str):
        raise ValueError("issuer is required")
    issuer = issuer.strip().rstrip("/")
    if not (issuer.startswith("https://") or issuer.startswith("http://")):
        raise ValueError("issuer must be an http(s) URL")
    return issuer


def compact(data: Mapping[str, Any]) -> Dict[str, Any]:
    """The mapping without ``None`` values (like JSON.stringify dropping undefined)."""
    return {k: v for k, v in data.items() if v is not None}


def now_ms() -> int:
    return int(time.time() * 1000)


def basic_auth(client_id: str, client_secret: str) -> str:
    """``client_secret_basic``: both parts form-url-encoded first (RFC 6749 section 2.3.1)."""
    raw = f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")

"""A fake user pool behind ``httpx.MockTransport``: no network. Tokens are signed with an ES256 key generated here."""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

ISSUER = "https://api.example.com/gateway/shop/auth/main"
CLIENT_ID = "uapp_test123"

USER = {"id": "usr_1", "email": "ada@example.com", "email_verified": True, "display_name": "Ada", "photo_url": None,
        "locale": "en", "attributes": {"plan": "pro"}, "anonymous": False, "created_at": "2026-10-01T00:00:00Z",
        "last_login_at": None, "mfa": {"totp": False}}

Route = Union[httpx.Response, Callable[[httpx.Request], httpx.Response]]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def json_response(status: int, data: Any) -> httpx.Response:
    return httpx.Response(status, json=data)


def make_key() -> Any:
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(private_key: Any, kid: str) -> Dict[str, Any]:
    jwk = json.loads(ECAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return jwk


class FakePool:
    """Answers the pool's endpoints like users-service does (only what the tests need)."""

    def __init__(self, issuer: str = ISSUER, client_id: str = CLIENT_ID) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.keys: Dict[str, Any] = {"k1": make_key()}
        self.kid = "k1"
        self.calls: List[Tuple[str, str, httpx.Request]] = []
        self.routes: Dict[Tuple[str, str], Route] = {}
        self.valid_refresh: Dict[str, Optional[str]] = {}   # refresh token -> org id
        self.used_refresh: set = set()
        self.counter = 0
        self.access_ttl = 900
        self.refresh_delay = 0.0
        self.jwks_status = 200
        self.lock = threading.Lock()
        # OIDC
        self.code = "code_abc"
        self.code_challenge: Optional[str] = None
        self.nonce: Optional[str] = None
        self.id_token_nonce: Optional[str] = None   # override to break the nonce

    # --- helpers -------------------------------------------------------------------------------------------------

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def http(self) -> httpx.Client:
        return httpx.Client(transport=self.transport)

    def ahttp(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport)

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [public_jwk(k, kid) for kid, k in self.keys.items()]}

    def sign(self, claims: Dict[str, Any], *, typ: str = "at+jwt", kid: Optional[str] = None, key: Any = None,
             alg: str = "ES256") -> str:
        kid = kid or self.kid
        return jwt.encode(claims, key or self.keys[kid], algorithm=alg, headers={"kid": kid, "typ": typ})

    def access_claims(self, **extra: Any) -> Dict[str, Any]:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": "usr_1", "aud": self.client_id, "azp": self.client_id, "exp": now + self.access_ttl,
                  "iat": now, "jti": f"at_{now}", "sid": "sess_1", "pool": "upool_1", "sv": 1, "org_id": "org_1",
                  "roles": ["member"], "permissions": ["orders.read"], "email": "ada@example.com", "email_verified": True,
                  "amr": ["pwd"], "scope": "openid profile email"}
        claims.update(extra)
        return claims

    def access_token(self, **extra: Any) -> str:
        return self.sign(self.access_claims(**extra))

    def tokens(self, org: Optional[Dict[str, Any]] = None, *, with_id_token: bool = False) -> Dict[str, Any]:
        with self.lock:
            self.counter += 1
            refresh = f"obur_{self.counter}"
            self.valid_refresh[refresh] = (org or {}).get("id")
        access = self.access_token(jti=f"at_{self.counter}")
        out: Dict[str, Any] = {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl,
                               "scope": "openid profile email", "refresh_token": refresh, "refresh_expires_in": 86400}
        if org is not None:
            out["org"] = org
        if with_id_token:
            now = int(time.time())
            digest = hashlib.sha256(access.encode()).digest()
            id_claims = {"iss": self.issuer, "sub": "usr_1", "aud": self.client_id, "azp": self.client_id, "exp": now + 3600,
                         "iat": now, "auth_time": now, "sid": "sess_1", "pool": "upool_1", "email": "ada@example.com",
                         "email_verified": True, "name": "Ada", "org_id": "org_1", "roles": ["member"], "amr": ["pwd"],
                         "at_hash": b64url(digest[:16])}
            nonce = self.id_token_nonce or self.nonce
            if nonce:
                id_claims["nonce"] = nonce
            out["id_token"] = self.sign(id_claims, typ="JWT")
        return out

    def count(self, method: str, path: str) -> int:
        return sum(1 for m, p, _ in self.calls if m == method and p == path)

    def last(self, method: str, path: str) -> httpx.Request:
        return [r for m, p, r in self.calls if m == method and p == path][-1]

    # --- the server ----------------------------------------------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        prefix = httpx.URL(self.issuer).path
        rel = path[len(prefix):] if path.startswith(prefix) else path
        with self.lock:
            self.calls.append((request.method, rel, request))
        route = self.routes.get((request.method, rel))
        if route is not None:
            return route(request) if callable(route) else route
        if rel == "/.well-known/jwks.json":
            return json_response(self.jwks_status, self.jwks() if self.jwks_status == 200 else {"detail": "down"})
        if rel.startswith("/api/v1/"):
            return self.api(request, rel[len("/api/v1"):])
        if rel == "/token":
            return self.token(request)
        if rel == "/revoke":
            return httpx.Response(200)
        if rel == "/userinfo":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return json_response(401, {"error": "invalid_token"})
            return json_response(200, {"sub": "usr_1", "email": "ada@example.com", "email_verified": True,
                                       "org_id": "org_1", "roles": ["member"], "attributes": {}})
        return json_response(404, {"detail": "Not Found"})

    def _bearer_ok(self, request: httpx.Request) -> bool:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return False
        try:
            jwt.decode(auth[7:], self.keys[self.kid].public_key(), algorithms=["ES256"], audience=self.client_id)
        except jwt.InvalidTokenError:
            return False
        return True

    def api(self, request: httpx.Request, path: str) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        method = request.method
        if method == "POST" and path in ("/signin/password", "/signup", "/signin/anonymous", "/signin/email-code/verify",
                                         "/signin/mfa"):
            return json_response(200, {"status": "ok", **self.tokens(), "user": USER, "org": None})
        if method == "POST" and path == "/token/refresh":
            if self.refresh_delay:
                time.sleep(self.refresh_delay)
            return self._refresh(body.get("refresh_token"), body.get("org_id"))
        if method == "POST" and path == "/signout":
            return json_response(200, {"status": "signed_out"})
        if method == "POST" and path in ("/signin/email-code", "/password/forgot"):
            return json_response(200, {"status": "sent"})
        if method == "POST" and path == "/password/reset":
            return json_response(200, {"status": "password_changed"})
        if method == "GET" and path == "/config":
            return json_response(200, {"issuer": self.issuer, "mode": "b2c", "providers": []})
        # signed-in calls
        if not self._bearer_ok(request):
            return json_response(401, {"detail": {"code": "token_invalid", "message": "Sign-in required"}})
        if method == "GET" and path == "/me":
            return json_response(200, {**USER, "org_id": "org_1", "roles": ["member"], "providers": [], "has_password": True})
        if method == "PATCH" and path == "/me":
            return json_response(200, {**USER, **body})
        if method in ("DELETE",) and path == "/me":
            return json_response(200, {"status": "deleted"})
        if method == "POST" and path == "/me/password":
            return json_response(200, {"status": "password_changed", "signed_out": True})
        if method == "GET" and path == "/orgs":
            return json_response(200, {"orgs": [{"id": "org_1", "name": "Acme", "roles": ["owner"], "disabled": False}],
                                       "active": "org_1"})
        if method == "POST" and path == "/orgs/switch":
            return self._refresh(body.get("refresh_token"), body.get("org_id"))
        if method == "GET" and path.startswith("/orgs/") and path.endswith("/members"):
            return json_response(200, {"items": [{"user_id": "usr_2", "email": "bob@example.com", "display_name": "Bob",
                                                  "disabled": False, "roles": ["member"], "created_at": "2026-10-01"}],
                                       "total": 1, "roles": [{"key": "member", "label": "Member"}]})
        if method == "POST" and path.startswith("/orgs/") and path.endswith("/members"):
            return json_response(201, {"user_id": "usr_3", "email": body.get("email"), "roles": body.get("roles"),
                                       "created": True, "temporary_password": "Temp-Secret-123"})
        return json_response(404, {"detail": "Not Found"})

    def _refresh(self, value: Optional[str], org_id: Optional[str]) -> httpx.Response:
        with self.lock:
            if not value or value in self.used_refresh or value not in self.valid_refresh:
                return json_response(401, {"detail": {"code": "invalid_refresh_token", "message": "Session expired"}})
            self.used_refresh.add(value)
            del self.valid_refresh[value]
        org = {"id": org_id, "name": "Other", "roles": ["admin"], "choices": []} if org_id else None
        return json_response(200, self.tokens(org))

    def token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if form.get("grant_type") == "authorization_code":
            if form.get("code") != self.code:
                return json_response(400, {"error": "invalid_grant", "error_description": "invalid or expired code"})
            verifier = form.get("code_verifier") or ""
            if self.code_challenge and b64url(hashlib.sha256(verifier.encode()).digest()) != self.code_challenge:
                return json_response(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
            return json_response(200, self.tokens(with_id_token=True))
        if form.get("grant_type") == "refresh_token":
            response = self._refresh(form.get("refresh_token"), form.get("org_id"))
            if response.status_code == 401:
                return json_response(400, {"error": "invalid_grant", "error_description": "reused"})
            return response
        return json_response(400, {"error": "unsupported_grant_type"})


def query(url: str) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(httpx.URL(url).query.decode()).items()}


@pytest.fixture
def pool() -> FakePool:
    return FakePool()

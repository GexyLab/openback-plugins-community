"""Server-side verification of a pool's tokens, locally, with the pool's public keys (JWKS)."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Union

import httpx
import jwt
from jwt.algorithms import ECAlgorithm

from ._util import at_hash, normalize_issuer, same
from .errors import JwksUnavailableError, TokenVerificationError
from .models import AppUser

__all__ = ["TokenVerifier"]

ALGORITHM = "ES256"
_ACCESS_TYPES = ("at+jwt", "application/at+jwt")


class TokenVerifier:
    """Verify the pool's access tokens (and ID tokens) without calling OpenBack.

    Checks: signature with the pool's key named by ``kid`` (``ES256`` ONLY: ``none``, ``HS*``, ``RS*`` are refused),
    header ``typ`` ``at+jwt`` for access tokens, ``iss`` exactly the issuer, ``aud`` one of the configured client IDs,
    ``exp``, ``nbf`` and ``iat`` with ``leeway`` seconds of tolerance.

    The JWKS (``<issuer>/.well-known/jwks.json`` unless ``jwks_uri`` is given) is cached for ``cache_ttl`` seconds; a
    token naming an unknown ``kid`` triggers a refetch at most once every ``min_refetch_interval`` seconds (key
    rotation). When the JWKS cannot be fetched the cached keys keep working; without any key
    :class:`~openback_app_auth.JwksUnavailableError` (503) is raised.

    Access tokens cannot be revoked before they expire: keep their lifetime short in the pool's settings.

    Args:
        issuer: the pool's address.
        audience: the client ID (or IDs) of the apps whose tokens you accept.
        http_client / async_http_client: optional ``httpx`` clients for :meth:`verify` / :meth:`verify_async`.
    """

    def __init__(self, issuer: str, audience: Union[str, Iterable[str]], *, jwks_uri: Optional[str] = None,
                 leeway: float = 60, cache_ttl: float = 600, min_refetch_interval: float = 30,
                 http_client: Optional[httpx.Client] = None, async_http_client: Optional[httpx.AsyncClient] = None,
                 timeout: float = 10.0, clock: Callable[[], float] = time.time) -> None:
        self.issuer = normalize_issuer(issuer)
        self.audience: List[str] = [audience] if isinstance(audience, str) else [a for a in audience if a]
        if not self.audience:
            raise ValueError("audience (the accepted client IDs) is required")
        self.jwks_uri = jwks_uri or f"{self.issuer}/.well-known/jwks.json"
        self.leeway = float(leeway)
        self.cache_ttl = float(cache_ttl)
        self.min_refetch_interval = float(min_refetch_interval)
        self._http = http_client
        self._async_http = async_http_client
        self._timeout = timeout
        self._clock = clock
        self._keys: Dict[str, Any] = {}
        self._fetched_at: Optional[float] = None   # monotonic time of the last successful fetch
        self._attempted_at: Optional[float] = None  # monotonic time of the last attempt
        self._lock = threading.Lock()
        self._alock: Optional[asyncio.Lock] = None
        self._alock_loop: Optional[asyncio.AbstractEventLoop] = None

    # --- public API --------------------------------------------------------------------------------------------------

    def verify(self, token: Optional[str]) -> AppUser:
        """Verify an access token -> :class:`AppUser`. Raises :class:`TokenVerificationError` (401)."""
        header = self._header(token, access=True)
        key = self._key_sync(header["kid"])
        return AppUser.from_claims(self._decode(token, key, self.audience))  # type: ignore[arg-type]

    async def verify_async(self, token: Optional[str]) -> AppUser:
        """:meth:`verify` with the JWKS fetched asynchronously."""
        header = self._header(token, access=True)
        key = await self._key_async(header["kid"])
        return AppUser.from_claims(self._decode(token, key, self.audience))  # type: ignore[arg-type]

    def verify_id_token(self, token: Optional[str], *, nonce: Optional[str] = None, access_token: Optional[str] = None,
                        audience: Optional[Union[str, Iterable[str]]] = None) -> Dict[str, Any]:
        """Verify an ID token (``aud`` = the client ID, ``nonce`` and ``at_hash`` when given) -> its claims."""
        header = self._header(token, access=False)
        key = self._key_sync(header["kid"])
        return self._id_claims(token, key, nonce, access_token, audience)  # type: ignore[arg-type]

    async def verify_id_token_async(self, token: Optional[str], *, nonce: Optional[str] = None,
                                    access_token: Optional[str] = None,
                                    audience: Optional[Union[str, Iterable[str]]] = None) -> Dict[str, Any]:
        header = self._header(token, access=False)
        key = await self._key_async(header["kid"])
        return self._id_claims(token, key, nonce, access_token, audience)  # type: ignore[arg-type]

    # --- checks ------------------------------------------------------------------------------------------------------

    @staticmethod
    def _header(token: Optional[str], *, access: bool) -> Dict[str, Any]:
        if not token or not isinstance(token, str):
            raise TokenVerificationError("token_missing", "No token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise TokenVerificationError("token_invalid", "Malformed token") from None
        if header.get("alg") != ALGORITHM:
            raise TokenVerificationError("token_invalid", "Unexpected signing algorithm")
        typ = str(header.get("typ") or "").lower()
        if access and typ not in _ACCESS_TYPES:
            raise TokenVerificationError("token_invalid", "Not an access token")
        if not access and typ in _ACCESS_TYPES:
            raise TokenVerificationError("token_invalid", "An access token is not an ID token")
        if not isinstance(header.get("kid"), str) or not header.get("kid"):
            raise TokenVerificationError("token_invalid", "The token names no key")
        return header

    def _decode(self, token: str, key: Any, audience: List[str]) -> Dict[str, Any]:
        try:
            claims = jwt.decode(token, key, algorithms=[ALGORITHM], audience=audience, issuer=self.issuer,
                                leeway=self.leeway, options={"require": ["exp", "iss", "aud", "sub"]})
        except jwt.ExpiredSignatureError:
            raise TokenVerificationError("token_expired", "The token has expired") from None
        except jwt.InvalidTokenError as exc:
            raise TokenVerificationError("token_invalid", _reason(exc)) from None
        iat = claims.get("iat")
        if iat is not None and (not isinstance(iat, (int, float)) or iat > self._clock() + self.leeway):
            raise TokenVerificationError("token_invalid", "The token is issued in the future")
        if claims.get("exp", 0) <= self._clock() - self.leeway:  # also with an injected clock
            raise TokenVerificationError("token_expired", "The token has expired")
        return claims

    def _id_claims(self, token: str, key: Any, nonce: Optional[str], access_token: Optional[str],
                   audience: Optional[Union[str, Iterable[str]]]) -> Dict[str, Any]:
        wanted = self.audience if audience is None else ([audience] if isinstance(audience, str) else list(audience))
        claims = self._decode(token, key, wanted)
        if nonce is not None and not same(claims.get("nonce"), nonce):
            raise TokenVerificationError("token_invalid", "Nonce mismatch")
        if access_token and claims.get("at_hash") and not same(claims.get("at_hash"), at_hash(access_token)):
            raise TokenVerificationError("token_invalid", "at_hash mismatch")
        return claims

    # --- keys --------------------------------------------------------------------------------------------------------

    def _needs_fetch(self, kid: str) -> bool:
        """A fetch is due when the cache expired or the kid is unknown -- at most once per ``min_refetch_interval``
        (also after a failed attempt). An expired cache keeps serving while a new fetch is not allowed."""
        now = time.monotonic()
        fresh = self._fetched_at is not None and now - self._fetched_at < self.cache_ttl
        if kid in self._keys and fresh:
            return False
        return self._attempted_at is None or now - self._attempted_at >= self.min_refetch_interval

    def _found(self, kid: str) -> Any:
        key = self._keys.get(kid)
        if key is None:
            if self._fetched_at is None:
                raise JwksUnavailableError()
            raise TokenVerificationError("token_invalid", "Unknown signing key")
        return key

    def _key_sync(self, kid: str) -> Any:
        if self._needs_fetch(kid):
            with self._lock:
                if self._needs_fetch(kid):
                    self._attempted_at = time.monotonic()
                    try:
                        if self._http is not None:
                            response = self._http.get(self.jwks_uri, headers={"Accept": "application/json"})
                        else:
                            with httpx.Client(timeout=self._timeout) as client:
                                response = client.get(self.jwks_uri, headers={"Accept": "application/json"})
                        self._install(response)
                    except (httpx.HTTPError, ValueError):
                        pass  # keep the cached keys, if any
        return self._found(kid)

    async def _key_async(self, kid: str) -> Any:
        if self._needs_fetch(kid):
            loop = asyncio.get_running_loop()
            if self._alock is None or self._alock_loop is not loop:
                self._alock, self._alock_loop = asyncio.Lock(), loop
            async with self._alock:
                if self._needs_fetch(kid):
                    self._attempted_at = time.monotonic()
                    try:
                        if self._async_http is not None:
                            response = await self._async_http.get(self.jwks_uri, headers={"Accept": "application/json"})
                        else:
                            async with httpx.AsyncClient(timeout=self._timeout) as client:
                                response = await client.get(self.jwks_uri, headers={"Accept": "application/json"})
                        self._install(response)
                    except (httpx.HTTPError, ValueError):
                        pass
        return self._found(kid)

    def _install(self, response: httpx.Response) -> None:
        if response.status_code != 200:
            raise ValueError(f"JWKS answered {response.status_code}")
        keys = parse_jwks(response.json())
        self._keys = keys
        self._fetched_at = time.monotonic()


def parse_jwks(data: Any) -> Dict[str, Any]:
    """The usable keys of a JWKS: EC P-256 signing keys with a ``kid`` -> ``{kid: public key}``."""
    if not isinstance(data, Mapping) or not isinstance(data.get("keys"), list):
        raise ValueError("not a JWKS")
    keys: Dict[str, Any] = {}
    for jwk in data["keys"]:
        if not isinstance(jwk, Mapping):
            continue
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("kid"):
            continue
        if jwk.get("alg") not in (None, ALGORITHM) or jwk.get("use") not in (None, "sig"):
            continue
        try:
            keys[str(jwk["kid"])] = ECAlgorithm.from_jwk(json.dumps(dict(jwk)))
        except (jwt.InvalidKeyError, ValueError, TypeError):
            continue
    return keys


def _reason(exc: Exception) -> str:
    if isinstance(exc, jwt.InvalidAudienceError):
        return "The token is for another app"
    if isinstance(exc, jwt.InvalidIssuerError):
        return "The token is from another issuer"
    if isinstance(exc, jwt.InvalidSignatureError):
        return "Invalid signature"
    if isinstance(exc, jwt.ImmatureSignatureError):
        return "The token is not valid yet"
    if isinstance(exc, jwt.MissingRequiredClaimError):
        return "A required claim is missing"
    return "Invalid token"

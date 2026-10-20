// Local verification of a pool's tokens with its public keys (JWKS): no call to OpenBack per request.
//
// Only ES256 is accepted (none, HS*, RS*, ... are refused before any key lookup: no algorithm confusion). Access tokens
// must have typ "at+jwt" (or "application/at+jwt"), ID tokens "JWT". iss must match exactly, aud must be one of the
// configured client IDs, exp / nbf / iat are checked with a leeway. Keys are cached (10 minutes by default); an unknown
// kid triggers a refetch at most once every 30 seconds. Access tokens cannot be revoked before they expire.
import { jwtVerify, importJWK, decodeProtectedHeader } from "jose";
import { createHash } from "node:crypto";
import { normalizeIssuer, safeEqual } from "./util.js";

const ALG = "ES256";

/** Why a token was refused. status 401, except jwks_unavailable (503: the keys could not be fetched). */
export class TokenVerificationError extends Error {
  constructor(code, message, options) {
    super(message || code, options);
    this.name = "TokenVerificationError";
    this.code = code;
    this.status = code === "jwks_unavailable" ? 503 : 401;
  }
}

const asArray = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

/** The user of a verified access token. */
export class AppUser {
  constructor(claims, clientId) {
    this.id = claims.sub;
    this.poolId = claims.pool || null;
    this.clientId = clientId || (typeof claims.aud === "string" ? claims.aud : claims.azp || null);
    this.email = typeof claims.email === "string" ? claims.email : null;
    this.emailVerified = claims.email_verified === true;
    this.anonymous = claims.anon === true;
    this.orgId = claims.org_id || null;
    this.roles = asArray(claims.roles);
    this.permissions = asArray(claims.permissions);
    this.attributes = claims.attr && typeof claims.attr === "object" && !Array.isArray(claims.attr) ? claims.attr : {};
    this.sessionId = claims.sid || null;
    this.amr = asArray(claims.amr);
    this.scope = typeof claims.scope === "string" ? claims.scope : "";
    this.expiresAt = typeof claims.exp === "number" ? new Date(claims.exp * 1000) : null;
    this.claims = claims;
  }

  hasRole(role) {
    return this.roles.includes(role);
  }

  /** True when the token grants the permission, or all of them ("*"). */
  hasPermission(permission) {
    return this.permissions.includes(permission) || this.permissions.includes("*");
  }
}

function normalizeTyp(typ) {
  const t = String(typ || "").toLowerCase();
  return t.startsWith("application/") ? t.slice("application/".length) : t;
}

function joseError(e) {
  const code = e && e.code;
  if (code === "ERR_JWT_EXPIRED") return new TokenVerificationError("token_expired", "Token expired", { cause: e });
  if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
    if (e.claim === "iss") return new TokenVerificationError("invalid_issuer", "Token of another issuer", { cause: e });
    if (e.claim === "aud") return new TokenVerificationError("invalid_audience", "Token of another app", { cause: e });
    if (e.claim === "nbf") return new TokenVerificationError("token_not_yet_valid", "Token not valid yet", { cause: e });
    return new TokenVerificationError("invalid_claims", `Invalid claim ${e.claim || ""}`.trim(), { cause: e });
  }
  if (code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") return new TokenVerificationError("invalid_signature", "Invalid signature", { cause: e });
  if (code === "ERR_JOSE_ALG_NOT_ALLOWED") return new TokenVerificationError("alg_not_allowed", "Algorithm not allowed", { cause: e });
  return new TokenVerificationError("invalid_token", "Invalid token", { cause: e });
}

export class TokenVerifier {
  /**
   * @param {object} options
   * @param {string} options.issuer        the pool's address
   * @param {string|string[]} [options.clientIds]  accepted audiences (client IDs); `clientId`/`audience` are aliases
   * @param {string} [options.jwksUri]     default <issuer>/.well-known/jwks.json
   * @param {number} [options.leeway=60]   seconds of clock tolerance for exp / nbf / iat
   * @param {number} [options.jwksCacheTtl=600]        seconds the keys are kept
   * @param {number} [options.jwksRefetchInterval=30]  minimum seconds between two refetches for an unknown kid
   * @param {typeof fetch} [options.fetch]
   * @param {() => number} [options.now]  current time in ms (tests)
   */
  constructor(options = {}) {
    this.issuer = normalizeIssuer(options.issuer);
    const ids = options.clientIds ?? options.clientId ?? options.audience;
    this.clientIds = (Array.isArray(ids) ? ids : [ids]).filter((x) => typeof x === "string" && x);
    if (!this.clientIds.length) throw new TypeError("TokenVerifier: clientIds (one or more client IDs) is required");
    this.jwksUri = options.jwksUri || this.issuer + "/.well-known/jwks.json";
    this.leeway = options.leeway ?? 60;
    this.jwksCacheTtl = (options.jwksCacheTtl ?? 600) * 1000;
    this.jwksRefetchInterval = (options.jwksRefetchInterval ?? 30) * 1000;
    this._fetch = options.fetch || ((input, init) => globalThis.fetch(input, init));
    this._now = options.now || Date.now;
    this._keys = null;        // Map kid -> CryptoKey
    this._fetchedAt = 0;      // last successful fetch
    this._attemptAt = -Infinity; // last fetch attempt
    this._kidRefetchAt = -Infinity; // last refetch caused by an unknown kid
    this._inflight = null;
  }

  /** Verifies an access token and returns its AppUser. Throws TokenVerificationError. */
  async verify(token) {
    const { payload, clientId } = await this._verify(token, "at+jwt", this.clientIds);
    return new AppUser(payload, clientId);
  }

  /** Alias of verify(). */
  verifyAccessToken(token) {
    return this.verify(token);
  }

  /**
   * Verifies an ID token (typ JWT) and returns its claims: nonce (constant time) when given, azp when aud has several
   * values, at_hash when both it and the access token are present.
   */
  async verifyIdToken(token, { nonce, clientId, accessToken } = {}) {
    const audience = clientId ? [clientId] : this.clientIds;
    const { payload, clientId: aud } = await this._verify(token, "jwt", audience);
    if (nonce !== undefined && nonce !== null && !safeEqual(String(payload.nonce || ""), String(nonce))) {
      throw new TokenVerificationError("invalid_nonce", "Nonce mismatch");
    }
    if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== aud) {
      throw new TokenVerificationError("invalid_audience", "azp does not name this app");
    }
    if (accessToken && typeof payload.at_hash === "string") {
      const digest = createHash("sha256").update(accessToken).digest();
      const expected = digest.subarray(0, digest.length / 2).toString("base64url");
      if (!safeEqual(expected, payload.at_hash)) throw new TokenVerificationError("invalid_at_hash", "at_hash does not match the access token");
    }
    return payload;
  }

  async _verify(token, typ, audience) {
    if (typeof token !== "string" || token.split(".").length !== 3) throw new TokenVerificationError("invalid_token", "Malformed token");
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch (e) {
      throw new TokenVerificationError("invalid_token", "Malformed token header", { cause: e });
    }
    if (header.alg !== ALG) throw new TokenVerificationError("alg_not_allowed", "Only ES256 is accepted");
    if (normalizeTyp(header.typ) !== typ) throw new TokenVerificationError("invalid_typ", `Expected typ ${typ}`);
    if (typeof header.kid !== "string" || !header.kid) throw new TokenVerificationError("invalid_token", "Token without kid");
    const key = await this._key(header.kid);
    let result;
    try {
      result = await jwtVerify(token, key, {
        algorithms: [ALG],
        issuer: this.issuer,
        audience,
        clockTolerance: this.leeway,
        currentDate: new Date(this._now()),
        requiredClaims: ["iss", "sub", "aud", "exp"],
      });
    } catch (e) {
      throw joseError(e);
    }
    const payload = result.payload;
    const nowSec = this._now() / 1000;
    if (typeof payload.iat === "number" && payload.iat > nowSec + this.leeway) {
      throw new TokenVerificationError("token_not_yet_valid", "Token issued in the future");
    }
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    return { payload, clientId: auds.find((a) => audience.includes(a)) || null };
  }

  async _key(kid) {
    const now = this._now();
    const stale = !this._keys || now - this._fetchedAt >= this.jwksCacheTtl;
    let failure = null;
    if (this._inflight) {
      await this._inflight.catch((e) => { failure = e; });
    } else if (stale && now - this._attemptAt >= this.jwksRefetchInterval) {
      // A failed fetch is retried at most once per refetch interval; cached keys stay in use meanwhile.
      await this._load().catch((e) => { failure = e; });
    }
    if (!this._keys) throw new TokenVerificationError("jwks_unavailable", "The pool's keys could not be fetched", { cause: failure });
    let key = this._keys.get(kid);
    if (!key && this._now() - this._kidRefetchAt >= this.jwksRefetchInterval) {
      this._kidRefetchAt = this._now();
      try {
        await this._load();
      } catch (e) {
        throw new TokenVerificationError("jwks_unavailable", "The pool's keys could not be fetched", { cause: e });
      }
      key = this._keys.get(kid);
    }
    if (!key) throw new TokenVerificationError("unknown_kid", "Unknown signing key");
    return key;
  }

  _load() {
    if (this._inflight) return this._inflight;
    this._attemptAt = this._now();
    this._inflight = (async () => {
      const res = await this._fetch(this.jwksUri, { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error("JWKS answered HTTP " + res.status);
      const body = await res.json();
      const keys = new Map();
      for (const jwk of (body && Array.isArray(body.keys) ? body.keys : [])) {
        if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.kid !== "string") continue;
        if (jwk.use && jwk.use !== "sig") continue;
        if (jwk.alg && jwk.alg !== ALG) continue;
        try {
          keys.set(jwk.kid, await importJWK({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, ALG));
        } catch { /* skip an unusable key */ }
      }
      this._keys = keys;
      this._fetchedAt = this._now();
    })().finally(() => { this._inflight = null; });
    return this._inflight;
  }
}

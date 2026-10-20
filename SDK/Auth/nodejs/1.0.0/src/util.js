// Shared helpers: errors, encoding, randomness, HTTP answers of the pool.
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

export const VERSION = "1.0.0";

/** An error of the pool (JSON API or OIDC endpoints), of the network (status 0) or of a client-side check. */
export class AuthError extends Error {
  constructor(status, code, message, detail, options) {
    super(message || code || "HTTP " + status, options);
    this.name = "AuthError";
    this.status = status;
    this.code = code || "http_" + status;
    this.detail = detail === undefined ? null : detail;
  }
}

export function normalizeIssuer(issuer) {
  if (!issuer || typeof issuer !== "string") throw new TypeError("issuer is required");
  return issuer.replace(/\/+$/, "");
}

export function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

// base64url of n CSPRNG bytes (state, nonce, PKCE verifier).
export function randomString(nBytes) {
  return b64url(randomBytes(nBytes));
}

export function sha256b64url(text) {
  return createHash("sha256").update(text).digest("base64url");
}

// Constant-time comparison of two strings (compares their SHA-256 digests, so lengths do not leak either).
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = createHash("sha256").update(a).digest();
  const y = createHash("sha256").update(b).digest();
  return timingSafeEqual(x, y) && a.length === b.length;
}

export async function readJson(res) {
  let text = "";
  try { text = await res.text(); } catch { return null; }
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

export function errorFromResponse(res, data) {
  const status = res.status;
  const detail = data && typeof data === "object" && !Array.isArray(data) ? data.detail : undefined;
  let code = null;
  let message = null;
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    code = typeof detail.code === "string" ? detail.code : null;
    message = typeof detail.message === "string" ? detail.message : null;
  } else if (typeof detail === "string") {
    message = detail;
  } else if (Array.isArray(detail)) {
    message = detail.map((d) => (d && d.msg) || "").filter(Boolean).join("; ") || null;
  }
  if (!code && data && typeof data.error === "string") {
    code = data.error; // OAuth errors: {error, error_description}
    message = message || (typeof data.error_description === "string" ? data.error_description : null);
  }
  return new AuthError(status, code || "http_" + status, message || res.statusText || "HTTP " + status, detail !== undefined ? detail : data);
}

export function networkError(e) {
  return new AuthError(0, "network_error", "Network error: " + ((e && e.message) || "request failed"), null, { cause: e });
}

// Decodes a JWT's claims WITHOUT verifying it.
export function decodeJwt(token) {
  try {
    const claims = JSON.parse(Buffer.from(String(token).split(".")[1], "base64url").toString("utf8"));
    return claims && typeof claims === "object" && !Array.isArray(claims) ? claims : null;
  } catch {
    return null;
  }
}

// HTTP Basic credentials of an OAuth client (RFC 6749 2.3.1: each part form-url-encoded).
export function basicAuthorization(clientId, clientSecret) {
  return "Basic " + Buffer.from(encodeURIComponent(clientId) + ":" + encodeURIComponent(clientSecret)).toString("base64");
}

// Query parameters from a URL, a query string, URLSearchParams or a plain object (e.g. req.query).
export function paramsOf(input) {
  if (input instanceof URLSearchParams) return input;
  if (input instanceof URL) return input.searchParams;
  if (typeof input === "string") {
    if (/^[a-z][a-z0-9+.-]*:/i.test(input)) return new URL(input).searchParams;
    const i = input.indexOf("?");
    return new URLSearchParams(i >= 0 ? input.slice(i + 1) : input);
  }
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(input || {})) {
    if (v === undefined || v === null) continue;
    p.set(k, Array.isArray(v) ? String(v[0]) : String(v));
  }
  return p;
}

// Test support: an ES256 key pair, signed test tokens, and a fake pool behind a mocked fetch (JWKS, /token, JSON API).
import { generateKeyPair, exportJWK, SignJWT } from "jose";

export const ISSUER = "https://api.example.test/gateway/shop/auth/main";
export const CLIENT_ID = "uapp_test";
export const KEY = `openback.auth.${CLIENT_ID}`;

export async function makeKey(kid = "k1") {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  return { kid, publicKey, privateKey, jwk };
}

export function nowSec() {
  return Math.floor(Date.now() / 1000);
}

export function accessClaims(over = {}) {
  const t = nowSec();
  return { iss: ISSUER, sub: "usr_1", aud: CLIENT_ID, azp: CLIENT_ID, exp: t + 900, iat: t, jti: "jti_1", sid: "ses_1", pool: "upool_1",
    sv: 1, org_id: "org_1", roles: ["member"], permissions: ["orders.read"], email: "ada@example.test", email_verified: true,
    amr: ["pwd"], scope: "openid profile email", ...over };
}

export async function sign(key, claims, header = {}) {
  return new SignJWT(claims).setProtectedHeader({ alg: "ES256", typ: "at+jwt", kid: key.kid, ...header }).sign(key.privateKey);
}

export function jsonResponse(status, body) {
  return new Response(body === undefined ? "" : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

// A fake pool. routes: "METHOD /path" (relative to the issuer) -> handler(req) returning {status, body} or a Response.
export function mockPool({ keys = [] } = {}) {
  const base = new URL(ISSUER).pathname;
  const state = { keys: [...keys], jwksDown: false };
  const routes = new Map();
  const calls = [];
  async function fetch(input, init = {}) {
    const u = new URL(String(input));
    const path = u.pathname.startsWith(base) ? u.pathname.slice(base.length) : u.pathname;
    const headers = new Headers(init.headers || {});
    let body = init.body;
    if (body instanceof URLSearchParams) body = Object.fromEntries(body);
    else if (typeof body === "string") { try { body = JSON.parse(body); } catch { /* raw */ } }
    const req = { method: init.method || "GET", path, query: u.searchParams, headers, body, url: u.href };
    calls.push(req);
    if (req.method === "GET" && path === "/.well-known/jwks.json") {
      if (state.jwksDown) throw new TypeError("fetch failed");
      return jsonResponse(200, { keys: state.keys.map((k) => k.jwk) });
    }
    const handler = routes.get(`${req.method} ${path}`);
    if (!handler) return jsonResponse(404, { detail: "Not Found" });
    const out = await handler(req);
    if (out instanceof Response) return out;
    return jsonResponse(out.status || 200, out.body);
  }
  return {
    fetch,
    calls,
    state,
    on(method, path, handler) { routes.set(`${method} ${path}`, handler); return this; },
    callsTo(method, path) { return calls.filter((c) => c.method === method && c.path === path); },
    jwksFetches() { return calls.filter((c) => c.path === "/.well-known/jwks.json").length; },
  };
}

export function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
}

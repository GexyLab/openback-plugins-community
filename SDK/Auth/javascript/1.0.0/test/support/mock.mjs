// Test support: a fake user pool behind a mocked fetch, a recording storage, unsigned JWTs.

export const ISSUER = "https://api.example.test/gateway/shop/auth/main";
export const CLIENT_ID = "uapp_test";
export const KEY = `openback.auth.${CLIENT_ID}`;

export function jsonResponse(status, body) {
  return new Response(body === undefined ? "" : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

// An unsigned token with the given claims (the browser SDK only decodes them).
export function fakeJwt(claims, header = { alg: "ES256", typ: "at+jwt", kid: "k1" }) {
  return `${b64url(header)}.${b64url(claims)}.c2lnbmF0dXJl`;
}

export function mockPool() {
  const base = new URL(ISSUER).pathname;
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
    const handler = routes.get(`${req.method} ${path}`);
    if (!handler) return jsonResponse(404, { detail: "Not Found" });
    const out = await handler(req);
    if (out instanceof Response) return out;
    return jsonResponse(out.status || 200, out.body);
  }
  return {
    fetch,
    calls,
    on(method, path, handler) { routes.set(`${method} ${path}`, handler); return this; },
    callsTo(method, path) { return calls.filter((c) => c.method === method && c.path === path); },
  };
}

export function recordingStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  const writes = [];
  return {
    data,
    writes,
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => { writes.push([k, v]); data.set(k, String(v)); },
    removeItem: (k) => { writes.push([k, null]); data.delete(k); },
  };
}

export const USER = { id: "usr_1", email: "ada@example.test", email_verified: true, display_name: "Ada", photo_url: "", locale: "en",
  attributes: {}, anonymous: false, created_at: "2026-01-01T00:00:00Z", last_login_at: null, mfa: { totp: false } };

let counter = 0;
export function tokens(extra = {}) {
  counter += 1;
  return { access_token: fakeJwt({ sub: "usr_1", n: counter, aud: CLIENT_ID, iss: ISSUER }), token_type: "Bearer", expires_in: 900,
    scope: "openid profile email", refresh_token: `obur_${counter}`, refresh_expires_in: 86400, ...extra };
}

export function okOutcome(extra = {}) {
  return { status: "ok", ...tokens(), user: USER, org: null, ...extra };
}

export function storedSession(over = {}) {
  return JSON.stringify({ accessToken: fakeJwt({ sub: "usr_1" }), refreshToken: "obur_stored", idToken: null,
    expiresAt: Date.now() + 10 * 60_000, user: USER, org: null, ...over });
}

export function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
}

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createAuth, createClient, AuthError } from "../src/index.js";
import { ISSUER, CLIENT_ID, KEY, mockPool, deferred, jsonResponse } from "./support/pool.mjs";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = (claims, header = { alg: "ES256", typ: "at+jwt", kid: "k1" }) => `${b64(header)}.${b64(claims)}.c2ln`;
const USER = { id: "usr_1", email: "ada@example.test", email_verified: true, display_name: "Ada", photo_url: "", locale: "en", attributes: {},
  anonymous: false, created_at: "2026-01-01T00:00:00Z", last_login_at: null, mfa: { totp: false } };
let n = 0;
const tokens = (extra = {}) => { n += 1; return { access_token: fakeJwt({ sub: "usr_1", n }), token_type: "Bearer", expires_in: 900, scope: "openid", refresh_token: `obur_${n}`, refresh_expires_in: 3600, ...extra }; };
const stored = (over = {}) => JSON.stringify({ accessToken: fakeJwt({ sub: "usr_1" }), refreshToken: "obur_stored", idToken: null, expiresAt: Date.now() + 600_000, user: USER, org: null, ...over });

function setup({ session, storage, clientSecret } = {}) {
  const pool = mockPool();
  const data = new Map(session ? [[KEY, session]] : []);
  const store = storage || { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => { data.set(k, v); }, removeItem: (k) => { data.delete(k); } };
  const auth = createAuth({ issuer: ISSUER, clientId: CLIENT_ID, storage: store, fetch: pool.fetch, redirectUri: "http://127.0.0.1:8765/callback", clientSecret });
  const events = [];
  auth.onAuthStateChanged((user, org) => events.push({ user, org }));
  return { pool, data, auth, events };
}

test("defaults to an in-memory storage; no Origin header is sent", async () => {
  const pool = mockPool();
  pool.on("POST", "/api/v1/signin/password", (req) => {
    assert.equal(req.headers.get("origin"), null);
    assert.equal(req.headers.get("x-client-id"), CLIENT_ID);
    return { body: { status: "ok", ...tokens(), user: USER, org: null } };
  });
  const auth = createClient(ISSUER, CLIENT_ID, { fetch: pool.fetch });
  await auth.signInWithPassword({ email: "a", password: "b" });
  assert.equal(auth.isSignedIn, true);
  assert.equal(auth.currentUser.id, "usr_1");
});

test("outcomes: only ok keeps a session", async () => {
  const { pool, auth, data } = setup();
  pool.on("POST", "/api/v1/signin/password", () => ({ body: { status: "mfa_required", mfa_token: "m1" } }));
  pool.on("POST", "/api/v1/signin/mfa", () => ({ body: { status: "ok", ...tokens(), user: USER, org: null } }));
  const r = await auth.signInWithPassword({ email: "a", password: "b" });
  assert.equal(r.status, "mfa_required");
  assert.equal(data.has(KEY), false);
  await auth.verifyMfa({ mfaToken: r.mfa_token, code: "000000" });
  assert.deepEqual(Object.keys(JSON.parse(data.get(KEY))).sort(), ["accessToken", "expiresAt", "idToken", "org", "refreshToken", "user"]);
});

test("single-flight refresh, rotated token stored, next refresh presents it", async () => {
  const { pool, auth, data } = setup({ session: stored({ expiresAt: 0 }) });
  const gate = deferred();
  const seen = [];
  pool.on("POST", "/api/v1/token/refresh", async (req) => {
    await gate.promise;
    const t = tokens();
    seen.push([req.body.refresh_token, t.refresh_token]);
    return { body: t };
  });
  const p = Promise.all([auth.getAccessToken(), auth.getAccessToken(), auth.refresh()]);
  setTimeout(() => gate.resolve(), 5);
  const [a, b, c] = await p;
  assert.equal(seen.length, 1);
  assert.ok(a === b && b === c);
  assert.equal(JSON.parse(data.get(KEY)).refreshToken, seen[0][1]);
  await auth.refresh();
  assert.equal(seen[1][0], seen[0][1]);
});

test("invalid_refresh_token and token_* 401 clear the session and notify", async () => {
  {
    const { pool, auth, events, data } = setup({ session: stored({ expiresAt: 0 }) });
    pool.on("POST", "/api/v1/token/refresh", () => ({ status: 401, body: { detail: { code: "invalid_refresh_token", message: "x" } } }));
    await assert.rejects(auth.getAccessToken(), (e) => e instanceof AuthError && e.code === "invalid_refresh_token");
    assert.equal(auth.isSignedIn, false);
    assert.equal(data.has(KEY), false);
    assert.equal(events.at(-1).user, null);
  }
  {
    const { pool, auth, events } = setup({ session: stored() });
    pool.on("GET", "/api/v1/orgs", () => ({ status: 401, body: { detail: { code: "token_revoked", message: "x" } } }));
    await assert.rejects(auth.organizations(), (e) => e.code === "token_revoked");
    assert.equal(auth.isSignedIn, false);
    assert.equal(events.at(-1).user, null);
  }
});

test("a network error during refresh is not retried and keeps the session", async () => {
  const { pool, auth } = setup({ session: stored({ expiresAt: 0 }) });
  pool.on("POST", "/api/v1/token/refresh", () => { throw new TypeError("fetch failed"); });
  await assert.rejects(auth.getAccessToken(), (e) => e.code === "network_error");
  assert.equal(pool.callsTo("POST", "/api/v1/token/refresh").length, 1);
  assert.equal(auth.isSignedIn, true);
});

test("an async storage (file/DB) is supported; a failed write keeps the newest token in memory", async () => {
  const data = new Map([[KEY, stored({ expiresAt: 0 })]]);
  let failWrites = false;
  const storage = {
    getItem: async (k) => data.get(k) ?? null,
    setItem: async (k, v) => { if (failWrites) throw new Error("disk full"); data.set(k, v); },
    removeItem: async (k) => { data.delete(k); },
  };
  const { pool, auth } = setup({ storage });
  await auth.ready;
  assert.equal(auth.isSignedIn, true);
  const sent = [];
  pool.on("POST", "/api/v1/token/refresh", (req) => { sent.push(req.body.refresh_token); return { body: tokens({ expires_in: 1 }) }; });
  failWrites = true;
  await assert.rejects(auth.refresh(), /disk full/);
  failWrites = false;
  await auth.refresh();
  assert.equal(sent[0], "obur_stored");
  assert.notEqual(sent[1], "obur_stored", "the rotated token kept in memory is presented, not the stale stored one");
});

test("OIDC with a loopback redirect: PKCE, state, iss, nonce; client secret sent with Basic auth", async () => {
  const { pool, auth } = setup({ clientSecret: "sec" });
  const req = await auth.buildAuthorizationRequest();
  const q = new URL(req.url).searchParams;
  assert.equal(q.get("code_challenge"), createHash("sha256").update(req.codeVerifier).digest("base64url"));
  assert.equal(q.get("redirect_uri"), "http://127.0.0.1:8765/callback");
  await assert.rejects(auth.handleRedirectCallback(`http://127.0.0.1:8765/callback?code=c&state=wrong`), (e) => e.code === "invalid_state");
  await assert.rejects(auth.handleRedirectCallback(`http://127.0.0.1:8765/callback?code=c&state=${req.state}&iss=https%3A%2F%2Fevil.test`), (e) => e.code === "invalid_issuer");
  assert.equal(await auth.handleRedirectCallback("http://127.0.0.1:8765/callback"), null);
  const idToken = fakeJwt({ iss: ISSUER, aud: CLIENT_ID, sub: "usr_1", nonce: req.nonce }, { alg: "ES256", typ: "JWT", kid: "k1" });
  pool.on("POST", "/token", (r) => {
    assert.equal(r.headers.get("authorization"), "Basic " + Buffer.from(`${CLIENT_ID}:sec`).toString("base64"));
    assert.equal(r.body.code_verifier, req.codeVerifier);
    return { body: tokens({ id_token: idToken }) };
  });
  pool.on("GET", "/api/v1/me", () => ({ body: USER }));
  const user = await auth.handleRedirectCallback(`http://127.0.0.1:8765/callback?code=c&state=${req.state}&iss=${encodeURIComponent(ISSUER)}`, req);
  assert.equal(user.id, "usr_1");
  assert.equal(auth.idToken, idToken);
  const req2 = await auth.buildAuthorizationRequest();
  pool.on("POST", "/token", () => ({ body: tokens({ id_token: fakeJwt({ iss: ISSUER, aud: CLIENT_ID, nonce: "x" }, { alg: "ES256", typ: "JWT" }) }) }));
  await assert.rejects(auth.handleRedirectCallback(`?code=c&state=${req2.state}`), (e) => e.code === "invalid_nonce");
});

test("signOut is best effort and always clears; buildLogoutUrl", async () => {
  const { pool, auth } = setup({ session: stored({ idToken: "id.tok.en" }) });
  const url = new URL(auth.buildLogoutUrl({ postLogoutRedirectUri: "https://app.example.test/", state: "s" }));
  assert.equal(url.searchParams.get("id_token_hint"), "id.tok.en");
  pool.on("POST", "/api/v1/signout", () => jsonResponse(503, {}));
  await auth.signOut({ everywhere: true });
  assert.equal(auth.isSignedIn, false);
  assert.equal(pool.callsTo("POST", "/api/v1/signout")[0].body.everywhere, true);
});

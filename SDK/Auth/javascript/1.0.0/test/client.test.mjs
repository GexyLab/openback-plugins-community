import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createAuth, createClient, AuthError, decodeJwt } from "../src/index.js";
import { ISSUER, CLIENT_ID, KEY, mockPool, recordingStorage, okOutcome, tokens, storedSession, USER, fakeJwt, jsonResponse, deferred } from "./support/mock.mjs";

function setup({ stored, locks = false, transactionStorage } = {}) {
  const pool = mockPool();
  const storage = recordingStorage(stored ? { [KEY]: stored } : {});
  const tx = transactionStorage || recordingStorage();
  const auth = createAuth({ issuer: ISSUER + "/", clientId: CLIENT_ID, storage, transactionStorage: tx, fetch: pool.fetch, locks,
    redirectUri: "https://app.example.test/callback" });
  const events = [];
  auth.onAuthStateChanged((user, org) => events.push({ user, org }));
  return { pool, storage, tx, auth, events };
}

test("issuer trailing slash is removed and calls send X-Client-Id + Accept", async () => {
  const { pool, auth } = setup();
  pool.on("GET", "/api/v1/config", () => ({ body: { issuer: ISSUER, mode: "b2c" } }));
  assert.equal(auth.issuer, ISSUER);
  await auth.config();
  const [c] = pool.calls;
  assert.equal(c.url, ISSUER + "/api/v1/config");
  assert.equal(c.headers.get("x-client-id"), CLIENT_ID);
  assert.equal(c.headers.get("accept"), "application/json");
  assert.equal(c.headers.get("authorization"), null);
});

test("createClient(issuer, clientId, options) is the spec-shaped constructor", () => {
  const auth = createClient(ISSUER, CLIENT_ID, { storage: recordingStorage(), fetch: async () => jsonResponse(200, {}) , locks: false});
  assert.equal(auth.clientId, CLIENT_ID);
  assert.equal(auth.isSignedIn, false);
});

test("password sign-in ok: the session is stored as one JSON and listeners hear it", async () => {
  const { pool, storage, auth, events } = setup();
  const out = okOutcome();
  pool.on("POST", "/api/v1/signin/password", (req) => {
    assert.deepEqual(req.body, { email: "ada@example.test", password: "pw" });
    assert.equal(req.headers.get("content-type"), "application/json");
    return { body: out };
  });
  const res = await auth.signInWithPassword({ email: "ada@example.test", password: "pw" });
  assert.equal(res.status, "ok");
  assert.equal(auth.isSignedIn, true);
  assert.deepEqual(auth.currentUser, USER);
  assert.equal(events.length, 2); // immediate (signed out) + signed in
  assert.equal(events[0].user, null);
  assert.deepEqual(events[1].user, USER);
  const saved = JSON.parse(storage.data.get(KEY));
  assert.deepEqual(Object.keys(saved).sort(), ["accessToken", "expiresAt", "idToken", "org", "refreshToken", "user"]);
  assert.equal(saved.refreshToken, out.refresh_token);
  assert.ok(Math.abs(saved.expiresAt - (Date.now() + 900_000)) < 5_000);
  assert.equal(auth.accessTokenClaims.sub, "usr_1");
});

test("outcomes other than ok are returned and keep no session (MFA branch)", async () => {
  const { pool, storage, auth } = setup();
  pool.on("POST", "/api/v1/signin/password", () => ({ body: { status: "mfa_required", mfa_token: "mfa_1" } }));
  pool.on("POST", "/api/v1/signin/mfa", (req) => {
    assert.deepEqual(req.body, { mfa_token: "mfa_1", code: "123456" });
    return { body: okOutcome() };
  });
  const first = await auth.signInWithPassword({ email: "a@b.c", password: "pw" });
  assert.equal(first.status, "mfa_required");
  assert.equal(auth.isSignedIn, false);
  assert.equal(storage.data.has(KEY), false);
  const second = await auth.verifyMfa({ mfaToken: first.mfa_token, code: "123456" });
  assert.equal(second.status, "ok");
  assert.equal(auth.isSignedIn, true);

  for (const status of ["verification_required", "password_change_required", "mfa_enroll_required"]) {
    const s = setup();
    s.pool.on("POST", "/api/v1/signup", () => ({ body: { status, change_token: "c", mfa_token: "m" } }));
    const r = await s.auth.signUp({ email: "a@b.c", password: "pw" });
    assert.equal(r.status, status);
    assert.equal(s.auth.isSignedIn, false);
  }
});

test("errors map detail.code / string detail / validation list / fallback http_<status>", async () => {
  const { pool, auth } = setup();
  pool.on("POST", "/api/v1/signin/password", () => ({ status: 401, body: { detail: { code: "invalid_credentials", message: "Wrong" } } }));
  pool.on("POST", "/api/v1/signup", () => ({ status: 422, body: { detail: [{ msg: "field required" }, { msg: "too short" }] } }));
  pool.on("POST", "/api/v1/password/forgot", () => ({ status: 400, body: { detail: "bad email" } }));
  pool.on("GET", "/api/v1/config", () => new Response("oops", { status: 502, statusText: "Bad Gateway" }));
  await assert.rejects(auth.signInWithPassword({ email: "a", password: "b" }), (e) => e instanceof AuthError && e.status === 401 && e.code === "invalid_credentials" && e.message === "Wrong");
  await assert.rejects(auth.signUp({ email: "a", password: "b" }), (e) => e.status === 422 && e.code === "http_422" && e.message === "field required; too short" && Array.isArray(e.detail));
  await assert.rejects(auth.sendPasswordReset("x"), (e) => e.code === "http_400" && e.message === "bad email");
  await assert.rejects(auth.config(), (e) => e.code === "http_502" && e.message === "Bad Gateway");
});

test("invalid_credentials 401 on a sign-in does not clear an existing session", async () => {
  const { pool, auth } = setup({ stored: storedSession() });
  pool.on("POST", "/api/v1/signin/password", () => ({ status: 401, body: { detail: { code: "invalid_credentials", message: "x" } } }));
  await assert.rejects(auth.signInWithPassword({ email: "a", password: "b" }));
  assert.equal(auth.isSignedIn, true);
});

test("getAccessToken returns the stored token while it is fresh, refreshes within 60 s of expiry", async () => {
  const { pool, auth, storage } = setup({ stored: storedSession() });
  const before = JSON.parse(storage.data.get(KEY)).accessToken;
  assert.equal(await auth.getAccessToken(), before);
  assert.equal(pool.calls.length, 0);

  const s2 = setup({ stored: storedSession({ expiresAt: Date.now() + 30_000 }) });
  const fresh = tokens();
  s2.pool.on("POST", "/api/v1/token/refresh", (req) => {
    assert.deepEqual(req.body, { refresh_token: "obur_stored" });
    return { body: fresh };
  });
  assert.equal(await s2.auth.getAccessToken(), fresh.access_token);
  assert.equal(JSON.parse(s2.storage.data.get(KEY)).refreshToken, fresh.refresh_token);
});

test("refresh is single-flight and the rotated refresh token is stored at once", async () => {
  const { pool, auth, storage, events } = setup({ stored: storedSession({ expiresAt: 0 }) });
  const gate = deferred();
  const issued = [];
  pool.on("POST", "/api/v1/token/refresh", async (req) => {
    await gate.promise;
    const t = tokens();
    issued.push({ sent: req.body.refresh_token, got: t.refresh_token });
    return { body: t };
  });
  const all = Promise.all([auth.getAccessToken(), auth.getAccessToken(), auth.refresh()]);
  await new Promise((r) => setTimeout(r, 10));
  gate.resolve();
  const [a, b, c] = await all;
  assert.equal(pool.callsTo("POST", "/api/v1/token/refresh").length, 1);
  assert.equal(a, b);
  assert.equal(b, c);
  assert.equal(issued[0].sent, "obur_stored");
  assert.equal(JSON.parse(storage.data.get(KEY)).refreshToken, issued[0].got);
  assert.equal(events.length, 1, "a renewal does not notify listeners");

  // The next refresh presents the rotated token, never the used one.
  await auth.refresh();
  assert.equal(issued[1].sent, issued[0].got);
});

test("refresh(orgId) waits for the refresh in flight and sends org_id", async () => {
  const { pool, auth } = setup({ stored: storedSession({ expiresAt: 0 }) });
  const sent = [];
  const issued = [];
  let inFlight = 0;
  pool.on("POST", "/api/v1/token/refresh", async (req) => {
    inFlight += 1;
    assert.equal(inFlight, 1, "never two refreshes at once");
    sent.push(req.body);
    await new Promise((r) => setTimeout(r, 5));
    inFlight -= 1;
    const t = tokens({ org: req.body.org_id ? { id: req.body.org_id, name: "Org", roles: ["admin"], choices: 2 } : null });
    issued.push(t.refresh_token);
    return { body: t };
  });
  await Promise.all([auth.refresh(), auth.refresh("org_2"), auth.getAccessToken()]);
  assert.equal(sent.length, 2);
  assert.equal(sent[0].refresh_token, "obur_stored");
  assert.equal(sent[1].org_id, "org_2");
  assert.equal(sent[1].refresh_token, issued[0], "the second request presents the rotated token");
  assert.equal(auth.currentOrg.id, "org_2");
});

test("the refresh runs inside the cross-tab lock named <key>.refresh", async () => {
  const names = [];
  const locks = { async request(name, cb) { names.push(name); return cb(); } };
  const { pool, auth } = setup({ stored: storedSession({ expiresAt: 0 }), locks });
  pool.on("POST", "/api/v1/token/refresh", () => ({ body: tokens() }));
  await auth.getAccessToken();
  assert.deepEqual(names, [`${KEY}.refresh`]);
});

test("a refresh done by another tab while waiting for the lock is adopted without a request", async () => {
  let release;
  const held = new Promise((r) => { release = r; });
  const locks = { async request(_name, cb) { await held; return cb(); } };
  const { pool, auth, storage } = setup({ stored: storedSession({ expiresAt: 0 }), locks });
  pool.on("POST", "/api/v1/token/refresh", () => ({ body: tokens() }));
  const p = auth.getAccessToken();
  // The other tab rotates and writes the new session while this one waits for the lock.
  const other = storedSession({ refreshToken: "obur_other_tab", accessToken: fakeJwt({ sub: "usr_1", other: true }) });
  storage.data.set(KEY, other);
  release();
  assert.equal(await p, JSON.parse(other).accessToken);
  assert.equal(pool.callsTo("POST", "/api/v1/token/refresh").length, 0);
});

test("invalid_refresh_token clears the session and notifies the listeners", async () => {
  const { pool, auth, storage, events } = setup({ stored: storedSession({ expiresAt: 0 }) });
  pool.on("POST", "/api/v1/token/refresh", () => ({ status: 401, body: { detail: { code: "invalid_refresh_token", message: "expired" } } }));
  await assert.rejects(auth.getAccessToken(), (e) => e.code === "invalid_refresh_token" && e.status === 401);
  assert.equal(auth.isSignedIn, false);
  assert.equal(storage.data.has(KEY), false);
  assert.equal(events.at(-1).user, null);
  await assert.rejects(auth.getAccessToken(), (e) => e.code === "not_signed_in");
});

test("a token_* 401 on a signed-in call clears the session", async () => {
  for (const code of ["token_expired", "token_revoked", "token_invalid", "token_other_app"]) {
    const { pool, auth, events } = setup({ stored: storedSession() });
    pool.on("GET", "/api/v1/me", () => ({ status: 401, body: { detail: { code, message: "x" } } }));
    await assert.rejects(auth.me(), (e) => e.code === code);
    assert.equal(auth.isSignedIn, false, code);
    assert.equal(events.at(-1).user, null);
  }
});

test("a network error during refresh is surfaced, not retried, and keeps the session", async () => {
  const { pool, auth } = setup({ stored: storedSession({ expiresAt: 0 }) });
  pool.on("POST", "/api/v1/token/refresh", () => { throw new TypeError("Failed to fetch"); });
  await assert.rejects(auth.getAccessToken(), (e) => e instanceof AuthError && e.code === "network_error" && e.status === 0);
  assert.equal(pool.callsTo("POST", "/api/v1/token/refresh").length, 1);
  assert.equal(auth.isSignedIn, true);
});

test("authorized fetch adds the Bearer token", async () => {
  const { pool, auth, storage } = setup({ stored: storedSession() });
  pool.on("GET", "/orders", (req) => ({ body: { auth: req.headers.get("authorization"), x: req.headers.get("x-extra") } }));
  const res = await auth.fetch(ISSUER + "/orders", { headers: { "X-Extra": "1" } });
  const body = await res.json();
  assert.equal(body.auth, "Bearer " + JSON.parse(storage.data.get(KEY)).accessToken);
  assert.equal(body.x, "1");
});

test("switchOrganization goes through the rotation queue and stores the new org", async () => {
  const { pool, auth, events } = setup({ stored: storedSession() });
  pool.on("POST", "/api/v1/orgs/switch", (req) => {
    assert.equal(req.body.refresh_token, "obur_stored");
    assert.equal(req.body.org_id, "org_9");
    assert.ok(req.headers.get("authorization").startsWith("Bearer "));
    return { body: tokens({ org: { id: "org_9", name: "Nine", roles: ["owner"], choices: 2 } }) };
  });
  const org = await auth.switchOrganization("org_9");
  assert.equal(org.id, "org_9");
  assert.equal(events.at(-1).org.id, "org_9");
});

test("signOut calls the server with the refresh token and always clears locally", async () => {
  const { pool, auth, storage } = setup({ stored: storedSession() });
  pool.on("POST", "/api/v1/signout", (req) => {
    assert.deepEqual(req.body, { refresh_token: "obur_stored", everywhere: false });
    return { status: 500, body: { detail: "boom" } };
  });
  await auth.signOut();
  assert.equal(auth.isSignedIn, false);
  assert.equal(storage.data.has(KEY), false);
  assert.equal(pool.callsTo("POST", "/api/v1/signout").length, 1);
});

test("changePassword and deleteAccount clear the session", async () => {
  for (const [method, path, run] of [["POST", "/api/v1/me/password", (a) => a.changePassword({ currentPassword: "a", newPassword: "b" })],
    ["DELETE", "/api/v1/me", (a) => a.deleteAccount("pw")]]) {
    const { pool, auth } = setup({ stored: storedSession() });
    pool.on(method, path, () => ({ body: { status: "ok" } }));
    await run(auth);
    assert.equal(auth.isSignedIn, false);
  }
});

test("me() updates the stored user without notifying when nothing changed", async () => {
  const { pool, auth, events } = setup({ stored: storedSession() });
  pool.on("GET", "/api/v1/me", () => ({ body: USER }));
  await auth.me();
  assert.equal(events.length, 1);
  pool.on("GET", "/api/v1/me", () => ({ body: { ...USER, display_name: "Ada L." } }));
  await auth.me();
  assert.equal(events.length, 2);
  assert.equal(auth.currentUser.display_name, "Ada L.");
});

test("an asynchronous storage is supported (ready)", async () => {
  const data = new Map([[KEY, storedSession()]]);
  const storage = { getItem: async (k) => data.get(k) ?? null, setItem: async (k, v) => { data.set(k, v); }, removeItem: async (k) => { data.delete(k); } };
  const auth = createAuth({ issuer: ISSUER, clientId: CLIENT_ID, storage, fetch: async () => jsonResponse(404, {}), locks: false, transactionStorage: recordingStorage() });
  assert.equal(auth.isSignedIn, false);
  await auth.ready;
  assert.equal(auth.isSignedIn, true);
  assert.deepEqual(auth.currentUser, USER);
});

test("a storage that throws falls back to memory and keeps the rotated token", async () => {
  const broken = { getItem: () => null, setItem: () => { throw new Error("QuotaExceeded"); }, removeItem: () => {} };
  const pool = mockPool();
  pool.on("POST", "/api/v1/signin/password", () => ({ body: okOutcome() }));
  pool.on("POST", "/api/v1/token/refresh", () => ({ body: tokens() }));
  const auth = createAuth({ issuer: ISSUER, clientId: CLIENT_ID, storage: broken, fetch: pool.fetch, locks: false, transactionStorage: recordingStorage() });
  const out = await auth.signInWithPassword({ email: "a", password: "b" });
  assert.equal(auth.isSignedIn, true);
  await auth.refresh();
  assert.equal(pool.callsTo("POST", "/api/v1/token/refresh")[0].body.refresh_token, out.refresh_token);
});

test("storage events of other tabs are followed", async () => {
  const listeners = {};
  globalThis.window = { addEventListener: (type, fn) => { listeners[type] = fn; } };
  try {
    const { auth, events } = setup();
    assert.equal(auth.isSignedIn, false);
    listeners.storage({ key: KEY, newValue: storedSession() });
    assert.equal(auth.isSignedIn, true);
    assert.deepEqual(events.at(-1).user, USER);
    listeners.storage({ key: KEY, newValue: null });
    assert.equal(auth.isSignedIn, false);
    assert.equal(events.at(-1).user, null);
  } finally {
    delete globalThis.window;
  }
});

test("decodeJwt decodes UTF-8 claims and returns null on garbage", () => {
  const t = fakeJwt({ name: "Zoë 東京" });
  assert.equal(decodeJwt(t).name, "Zoë 東京");
  assert.equal(decodeJwt("nope"), null);
  assert.equal(decodeJwt(null), null);
});

// --- OpenID Connect ---------------------------------------------------------------------------------------------------

async function startRedirect(s, opts) {
  const req = await s.auth.buildAuthorizationRequest(opts);
  return req;
}

function idToken(claims) {
  return fakeJwt({ iss: ISSUER, aud: CLIENT_ID, sub: "usr_1", exp: Math.floor(Date.now() / 1000) + 300, ...claims }, { alg: "ES256", typ: "JWT", kid: "k1" });
}

test("buildAuthorizationRequest: PKCE S256, state, nonce, extras, persisted transaction", async () => {
  const s = setup();
  const req = await startRedirect(s, { provider: "uprov_g", orgId: "org_1", prompt: "login", screenHint: "signup", loginHint: "a@b.c", maxAge: 0, uiLocales: "it" });
  const u = new URL(req.url);
  assert.equal(u.origin + u.pathname, ISSUER + "/authorize");
  const q = Object.fromEntries(u.searchParams);
  assert.equal(q.response_type, "code");
  assert.equal(q.client_id, CLIENT_ID);
  assert.equal(q.redirect_uri, "https://app.example.test/callback");
  assert.equal(q.scope, "openid profile email");
  assert.equal(q.code_challenge_method, "S256");
  assert.equal(q.code_challenge, createHash("sha256").update(req.codeVerifier).digest("base64url"));
  assert.ok(req.codeVerifier.length >= 43 && req.codeVerifier.length <= 128);
  assert.match(req.codeVerifier, /^[A-Za-z0-9_-]+$/);
  assert.equal(q.state, req.state);
  assert.equal(q.nonce, req.nonce);
  assert.deepEqual([q.provider, q.org_id, q.prompt, q.screen_hint, q.login_hint, q.max_age, q.ui_locales], ["uprov_g", "org_1", "login", "signup", "a@b.c", "0", "it"]);
  const tx = JSON.parse(s.tx.data.get(`${KEY}.transaction`));
  assert.equal(tx.state, req.state);
  assert.equal(tx.codeVerifier, req.codeVerifier);
  const again = await s.auth.buildAuthorizationRequest();
  assert.notEqual(again.state, req.state);
});

test("handleRedirectCallback returns null on a URL without code and without a pending transaction", async () => {
  const s = setup();
  assert.equal(await s.auth.handleRedirectCallback("https://app.example.test/callback"), null);
  assert.equal(await s.auth.handleRedirectCallback("https://app.example.test/callback?foo=1"), null);
});

test("handleRedirectCallback: happy path exchanges the code and loads the user", async () => {
  const s = setup();
  const req = await startRedirect(s);
  const data = tokens({ id_token: idToken({ nonce: req.nonce }) });
  s.pool.on("POST", "/token", (r) => {
    assert.equal(r.headers.get("content-type"), "application/x-www-form-urlencoded");
    assert.deepEqual(r.body, { grant_type: "authorization_code", code: "c0de", redirect_uri: req.redirectUri, client_id: CLIENT_ID, code_verifier: req.codeVerifier });
    return { body: data };
  });
  s.pool.on("GET", "/api/v1/me", (r) => {
    assert.equal(r.headers.get("authorization"), "Bearer " + data.access_token);
    return { body: { ...USER, roles: [], org_id: null, providers: [], has_password: true } };
  });
  const user = await s.auth.handleRedirectCallback(`https://app.example.test/callback?code=c0de&state=${req.state}&iss=${encodeURIComponent(ISSUER)}`);
  assert.equal(user.id, "usr_1");
  assert.equal(s.auth.isSignedIn, true);
  assert.equal(s.auth.idToken, data.id_token);
  assert.equal(s.tx.data.has(`${KEY}.transaction`), false, "the transaction is used once");
  assert.equal(s.events.length, 2);
  // Replaying the same callback fails: no transaction any more.
  await assert.rejects(s.auth.handleRedirectCallback(`https://app.example.test/callback?code=c0de&state=${req.state}`), (e) => e.code === "missing_transaction");
});

test("handleRedirectCallback rejects a wrong state, a wrong iss, a wrong nonce, an ID token of another app", async () => {
  {
    const s = setup();
    await startRedirect(s);
    await assert.rejects(s.auth.handleRedirectCallback("https://app.example.test/callback?code=c&state=forged"), (e) => e.code === "invalid_state");
    assert.equal(s.pool.calls.length, 0);
  }
  {
    const s = setup();
    const req = await startRedirect(s);
    await assert.rejects(s.auth.handleRedirectCallback(`https://app.example.test/callback?code=c&state=${req.state}&iss=https%3A%2F%2Fevil.test`), (e) => e.code === "invalid_issuer");
    assert.equal(s.pool.calls.length, 0);
  }
  {
    const s = setup();
    const req = await startRedirect(s);
    s.pool.on("POST", "/token", () => ({ body: tokens({ id_token: idToken({ nonce: "other" }) }) }));
    await assert.rejects(s.auth.handleRedirectCallback(`https://app.example.test/callback?code=c&state=${req.state}`), (e) => e.code === "invalid_nonce");
    assert.equal(s.auth.isSignedIn, false);
  }
  {
    const s = setup();
    const req = await startRedirect(s);
    s.pool.on("POST", "/token", () => ({ body: tokens({ id_token: idToken({ nonce: req.nonce, aud: "uapp_other" }) }) }));
    await assert.rejects(s.auth.handleRedirectCallback(`https://app.example.test/callback?code=c&state=${req.state}`), (e) => e.code === "invalid_id_token");
  }
});

test("handleRedirectCallback surfaces the redirect's error and OAuth token errors", async () => {
  const s = setup();
  const req = await startRedirect(s);
  await assert.rejects(s.auth.handleRedirectCallback(`https://app.example.test/callback?error=login_required&error_description=no%20session&state=${req.state}`),
    (e) => e.code === "login_required" && e.message === "no session");
  assert.equal(s.tx.data.has(`${KEY}.transaction`), false);
  const req2 = await startRedirect(s);
  s.pool.on("POST", "/token", () => ({ status: 400, body: { error: "invalid_grant", error_description: "invalid or expired code" } }));
  await assert.rejects(s.auth.handleRedirectCallback(`https://app.example.test/callback?code=c&state=${req2.state}`),
    (e) => e.status === 400 && e.code === "invalid_grant" && e.message === "invalid or expired code");
});

test("buildLogoutUrl carries client_id, id_token_hint, post-logout redirect and state", async () => {
  const s = setup({ stored: storedSession({ idToken: "id.tok.en" }) });
  const u = new URL(s.auth.buildLogoutUrl("https://app.example.test/bye", "st1"));
  assert.equal(u.origin + u.pathname, ISSUER + "/logout");
  assert.deepEqual(Object.fromEntries(u.searchParams), { client_id: CLIENT_ID, id_token_hint: "id.tok.en", post_logout_redirect_uri: "https://app.example.test/bye", state: "st1" });
  const u2 = new URL(s.auth.buildLogoutUrl({ postLogoutRedirectUri: "https://app.example.test/x" }));
  assert.equal(u2.searchParams.get("post_logout_redirect_uri"), "https://app.example.test/x");
  assert.equal(u2.searchParams.get("state"), null);
});

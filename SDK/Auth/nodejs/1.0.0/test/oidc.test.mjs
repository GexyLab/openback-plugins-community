import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { OidcWebClient, AuthError, TokenVerificationError } from "../src/index.js";
import { ISSUER, CLIENT_ID, makeKey, sign, mockPool, nowSec } from "./support/pool.mjs";

const SECRET = "s3cr:et/with+chars";
const REDIRECT = "https://app.example.test/auth/callback";

async function setup(opts = {}) {
  const key = await makeKey("k1");
  const pool = mockPool({ keys: [key] });
  const client = new OidcWebClient({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: SECRET, redirectUri: REDIRECT, fetch: pool.fetch, ...opts });
  return { key, pool, client };
}

function idClaims(over = {}) {
  return { iss: ISSUER, sub: "usr_1", aud: CLIENT_ID, azp: CLIENT_ID, exp: nowSec() + 300, iat: nowSec(), auth_time: nowSec(), sid: "ses_1",
    email: "ada@example.test", email_verified: true, roles: [], amr: ["pwd"], ...over };
}

function tokenAnswer(over = {}) {
  return { access_token: "at_1", token_type: "Bearer", expires_in: 900, scope: "openid profile email", refresh_token: "obur_1",
    refresh_expires_in: 86400, ...over };
}

test("authorizationUrl: PKCE S256, state, nonce, extras; the transaction carries what the callback needs", async () => {
  const { client } = await setup();
  const { url, transaction } = await client.authorizationUrl({ provider: "uprov_g", orgId: "org_1", prompt: "none", maxAge: 300, uiLocales: "en", loginHint: "a@b.c", screenHint: "signup" });
  const u = new URL(url);
  assert.equal(u.origin + u.pathname, ISSUER + "/authorize");
  const q = Object.fromEntries(u.searchParams);
  assert.equal(q.client_id, CLIENT_ID);
  assert.equal(q.redirect_uri, REDIRECT);
  assert.equal(q.response_type, "code");
  assert.equal(q.scope, "openid profile email");
  assert.equal(q.state, transaction.state);
  assert.equal(q.nonce, transaction.nonce);
  assert.equal(q.code_challenge_method, "S256");
  assert.equal(q.code_challenge, createHash("sha256").update(transaction.codeVerifier).digest("base64url"));
  assert.ok(transaction.codeVerifier.length >= 43 && transaction.codeVerifier.length <= 128);
  assert.deepEqual([q.provider, q.org_id, q.prompt, q.max_age, q.ui_locales, q.login_hint, q.screen_hint], ["uprov_g", "org_1", "none", "300", "en", "a@b.c", "signup"]);
  assert.equal(transaction.redirectUri, REDIRECT);
});

test("handleCallback: code exchange with client_secret_basic, verified ID token", async () => {
  const { key, pool, client } = await setup();
  const { transaction } = await client.authorizationUrl();
  const idToken = await sign(key, idClaims({ nonce: transaction.nonce }), { typ: "JWT" });
  pool.on("POST", "/token", (req) => {
    const auth = req.headers.get("authorization");
    assert.ok(auth.startsWith("Basic "));
    const [id, secret] = Buffer.from(auth.slice(6), "base64").toString().split(":").map(decodeURIComponent);
    assert.equal(id, CLIENT_ID);
    assert.equal(secret, SECRET);
    assert.equal(req.headers.get("content-type"), "application/x-www-form-urlencoded");
    assert.deepEqual(req.body, { grant_type: "authorization_code", code: "c0de", redirect_uri: REDIRECT, client_id: CLIENT_ID, code_verifier: transaction.codeVerifier });
    return { body: tokenAnswer({ id_token: idToken }) };
  });
  const out = await client.handleCallback({ code: "c0de", state: transaction.state, iss: ISSUER }, transaction);
  assert.equal(out.accessToken, "at_1");
  assert.equal(out.refreshToken, "obur_1");
  assert.equal(out.idToken, idToken);
  assert.equal(out.idTokenClaims.sub, "usr_1");
  assert.equal(out.expiresIn, 900);
  // An openid request answered without an ID token is refused (callback given as the full URL)
  const t2 = (await client.authorizationUrl()).transaction;
  pool.on("POST", "/token", () => ({ body: tokenAnswer({ id_token: null, scope: "profile" }) }));
  await assert.rejects(client.handleCallback(`${REDIRECT}?code=x&state=${t2.state}`, t2), (e) => e instanceof TokenVerificationError);
});

test("handleCallback: client_secret_post sends the secret in the form and no Authorization header", async () => {
  const { key, pool, client } = await setup({ tokenEndpointAuthMethod: "client_secret_post" });
  const { transaction } = await client.authorizationUrl();
  pool.on("POST", "/token", async (req) => {
    assert.equal(req.headers.get("authorization"), null);
    assert.equal(req.body.client_secret, SECRET);
    assert.equal(req.body.client_id, CLIENT_ID);
    return { body: tokenAnswer({ id_token: await sign(key, idClaims({ nonce: transaction.nonce }), { typ: "JWT" }) }) };
  });
  const out = await client.handleCallback(new URLSearchParams({ code: "c", state: transaction.state }), transaction);
  assert.equal(out.accessToken, "at_1");
});

test("handleCallback refuses wrong state, wrong iss, a redirect error, no transaction — before any request", async () => {
  const { pool, client } = await setup();
  const { transaction } = await client.authorizationUrl();
  await assert.rejects(client.handleCallback({ code: "c", state: "forged" }, transaction), (e) => e instanceof AuthError && e.code === "invalid_state");
  await assert.rejects(client.handleCallback({ code: "c", state: transaction.state, iss: "https://evil.test" }, transaction), (e) => e.code === "invalid_issuer");
  await assert.rejects(client.handleCallback({ error: "access_denied", error_description: "not a member", state: transaction.state }, transaction),
    (e) => e.code === "access_denied" && e.message === "not a member");
  await assert.rejects(client.handleCallback({ code: "c", state: transaction.state }, null), (e) => e.code === "missing_transaction");
  await assert.rejects(client.handleCallback({ state: transaction.state }, transaction), (e) => e.code === "invalid_request");
  assert.equal(pool.calls.length, 0);
});

test("handleCallback refuses an ID token with a wrong nonce, issuer or signature", async () => {
  const { key, pool, client } = await setup();
  const { transaction } = await client.authorizationUrl();
  const cases = [
    [await sign(key, idClaims({ nonce: "other" }), { typ: "JWT" }), "invalid_nonce"],
    [await sign(key, idClaims({ nonce: transaction.nonce, iss: "https://evil.test" }), { typ: "JWT" }), "invalid_issuer"],
    [await sign(await makeKey("k1"), idClaims({ nonce: transaction.nonce }), { typ: "JWT" }), "invalid_signature"],
    [await sign(key, idClaims({ nonce: transaction.nonce, aud: "uapp_other" }), { typ: "JWT" }), "invalid_audience"],
  ];
  for (const [idToken, code] of cases) {
    pool.on("POST", "/token", () => ({ body: tokenAnswer({ id_token: idToken }) }));
    await assert.rejects(client.handleCallback({ code: "c", state: transaction.state }, transaction), (e) => e.code === code);
  }
});

test("token endpoint errors become AuthError with the OAuth code", async () => {
  const { pool, client } = await setup();
  const { transaction } = await client.authorizationUrl();
  pool.on("POST", "/token", () => ({ status: 400, body: { error: "invalid_grant", error_description: "code already used" } }));
  await assert.rejects(client.handleCallback({ code: "c", state: transaction.state }, transaction),
    (e) => e instanceof AuthError && e.status === 400 && e.code === "invalid_grant" && e.message === "code already used");
  pool.on("POST", "/token", () => ({ status: 401, body: { error: "invalid_client" } }));
  await assert.rejects(client.refresh("obur_1"), (e) => e.status === 401 && e.code === "invalid_client");
});

test("refresh, revoke, userinfo, logoutUrl", async () => {
  const { pool, client } = await setup();
  pool.on("POST", "/token", (req) => {
    assert.deepEqual(req.body, { grant_type: "refresh_token", refresh_token: "obur_1", client_id: CLIENT_ID, org_id: "org_2" });
    assert.ok(req.headers.get("authorization").startsWith("Basic "));
    return { body: tokenAnswer({ refresh_token: "obur_2", org: { id: "org_2", name: "Two", roles: ["admin"], choices: 2 } }) };
  });
  const r = await client.refresh("obur_1", { orgId: "org_2" });
  assert.equal(r.refreshToken, "obur_2");
  assert.equal(r.org.id, "org_2");
  assert.equal(r.idToken, null);

  pool.on("POST", "/revoke", (req) => {
    assert.equal(req.body.token, "obur_2");
    assert.equal(req.body.token_type_hint, "refresh_token");
    assert.ok(req.headers.get("authorization").startsWith("Basic "));
    return new Response(null, { status: 200 });
  });
  await client.revoke("obur_2");

  pool.on("GET", "/userinfo", (req) => {
    if (req.headers.get("authorization") !== "Bearer at_1") return { status: 401, body: { error: "invalid_token" } };
    return { body: { sub: "usr_1", email: "ada@example.test", email_verified: true, org_id: null, roles: [], attributes: {} } };
  });
  assert.equal((await client.userinfo("at_1")).sub, "usr_1");
  await assert.rejects(client.userinfo("bad"), (e) => e.status === 401 && e.code === "invalid_token");

  const u = new URL(client.logoutUrl({ idTokenHint: "id.tok", postLogoutRedirectUri: "https://app.example.test/", state: "s1" }));
  assert.equal(u.origin + u.pathname, ISSUER + "/logout");
  assert.deepEqual(Object.fromEntries(u.searchParams), { client_id: CLIENT_ID, id_token_hint: "id.tok", post_logout_redirect_uri: "https://app.example.test/", state: "s1" });
});

test("a network error is surfaced as network_error and not retried", async () => {
  const { pool, client } = await setup();
  pool.on("POST", "/token", () => { throw new TypeError("fetch failed"); });
  await assert.rejects(client.refresh("obur_1"), (e) => e.code === "network_error" && e.status === 0);
  assert.equal(pool.callsTo("POST", "/token").length, 1);
});

test("constructor validation", () => {
  assert.throws(() => new OidcWebClient({ issuer: ISSUER }), TypeError);
  assert.throws(() => new OidcWebClient({ issuer: ISSUER, clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" }), TypeError);
  assert.throws(() => new OidcWebClient({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: "x", tokenEndpointAuthMethod: "private_key_jwt" }), TypeError);
  assert.equal(new OidcWebClient({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: "x" }).authMethod, "client_secret_basic");
});

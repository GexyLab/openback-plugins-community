import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { SignJWT, exportSPKI } from "jose";
import { TokenVerifier, TokenVerificationError, AppUser } from "../src/index.js";
import { ISSUER, CLIENT_ID, makeKey, accessClaims, sign, mockPool, nowSec } from "./support/pool.mjs";

async function setup(opts = {}) {
  const key = await makeKey("k1");
  const pool = mockPool({ keys: [key] });
  let now = Date.now();
  const verifier = new TokenVerifier({ issuer: ISSUER + "/", clientIds: [CLIENT_ID, "uapp_second"], fetch: pool.fetch, now: () => now, ...opts });
  return { key, pool, verifier, advance: (ms) => { now += ms; }, now: () => now };
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (e) => {
    assert.ok(e instanceof TokenVerificationError, `expected TokenVerificationError, got ${e && e.name}: ${e && e.message}`);
    assert.equal(e.code, code);
    return true;
  });
}

test("a valid access token gives an AppUser", async () => {
  const { key, verifier } = await setup();
  const token = await sign(key, accessClaims({ attr: { plan: "pro" }, permissions: ["*"] }));
  const user = await verifier.verify(token);
  assert.ok(user instanceof AppUser);
  assert.equal(user.id, "usr_1");
  assert.equal(user.poolId, "upool_1");
  assert.equal(user.clientId, CLIENT_ID);
  assert.equal(user.email, "ada@example.test");
  assert.equal(user.emailVerified, true);
  assert.equal(user.anonymous, false);
  assert.equal(user.orgId, "org_1");
  assert.deepEqual(user.roles, ["member"]);
  assert.deepEqual(user.attributes, { plan: "pro" });
  assert.equal(user.sessionId, "ses_1");
  assert.deepEqual(user.amr, ["pwd"]);
  assert.equal(user.claims.jti, "jti_1");
  assert.equal(user.hasRole("member"), true);
  assert.equal(user.hasRole("admin"), false);
  assert.equal(user.hasPermission("anything.at.all"), true, "* grants every permission");
  const second = await verifier.verify(await sign(key, accessClaims({ aud: "uapp_second", permissions: ["a"] })));
  assert.equal(second.clientId, "uapp_second");
  assert.equal(second.hasPermission("a"), true);
  assert.equal(second.hasPermission("b"), false);
});

test("alg none is refused before any key lookup", async () => {
  const { pool, verifier } = await setup();
  const token = `${b64({ alg: "none", typ: "at+jwt", kid: "k1" })}.${b64(accessClaims())}.`;
  await rejectsWith(verifier.verify(token), "alg_not_allowed");
  const token2 = `${b64({ alg: "none", typ: "at+jwt", kid: "k1" })}.${b64(accessClaims())}.c2ln`;
  await rejectsWith(verifier.verify(token2), "alg_not_allowed");
  assert.equal(pool.jwksFetches(), 0);
});

test("HS256 is refused, also when signed with the pool's public key (algorithm confusion)", async () => {
  const { key, verifier } = await setup();
  const secret = new TextEncoder().encode("a-very-long-shared-secret-of-32-bytes!");
  const hs = await new SignJWT(accessClaims()).setProtectedHeader({ alg: "HS256", typ: "at+jwt", kid: "k1" }).sign(secret);
  await rejectsWith(verifier.verify(hs), "alg_not_allowed");
  const pem = new TextEncoder().encode(await exportSPKI(key.publicKey));
  const confused = await new SignJWT(accessClaims()).setProtectedHeader({ alg: "HS256", typ: "at+jwt", kid: "k1" }).sign(pem);
  await rejectsWith(verifier.verify(confused), "alg_not_allowed");
});

test("RS256 and ES384 are refused", async () => {
  const { verifier } = await setup();
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rs = await new SignJWT(accessClaims()).setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "k1" }).sign(privateKey);
  await rejectsWith(verifier.verify(rs), "alg_not_allowed");
  const forged = `${b64({ alg: "ES384", typ: "at+jwt", kid: "k1" })}.${b64(accessClaims())}.c2ln`;
  await rejectsWith(verifier.verify(forged), "alg_not_allowed");
});

test("typ must be at+jwt for access tokens (case-insensitive, application/ prefix accepted)", async () => {
  const { key, verifier } = await setup();
  await rejectsWith(verifier.verify(await sign(key, accessClaims(), { typ: "JWT" })), "invalid_typ");
  const noTyp = await new SignJWT(accessClaims()).setProtectedHeader({ alg: "ES256", kid: "k1" }).sign(key.privateKey);
  await rejectsWith(verifier.verify(noTyp), "invalid_typ");
  assert.equal((await verifier.verify(await sign(key, accessClaims(), { typ: "application/at+jwt" }))).id, "usr_1");
  assert.equal((await verifier.verify(await sign(key, accessClaims(), { typ: "AT+JWT" }))).id, "usr_1");
});

test("iss must match exactly and aud must be a configured client ID", async () => {
  const { key, verifier } = await setup();
  await rejectsWith(verifier.verify(await sign(key, accessClaims({ iss: ISSUER + "/" }))), "invalid_issuer");
  await rejectsWith(verifier.verify(await sign(key, accessClaims({ iss: "https://evil.test/auth/main" }))), "invalid_issuer");
  await rejectsWith(verifier.verify(await sign(key, accessClaims({ aud: "uapp_other" }))), "invalid_audience");
});

test("exp is checked with a 60 s leeway by default; nbf and iat in the future are refused", async () => {
  const { key, verifier } = await setup();
  const t = nowSec();
  assert.equal((await verifier.verify(await sign(key, accessClaims({ exp: t - 30 })))).id, "usr_1");
  await rejectsWith(verifier.verify(await sign(key, accessClaims({ exp: t - 120 }))), "token_expired");
  await rejectsWith(verifier.verify(await sign(key, accessClaims({ nbf: t + 300 }))), "token_not_yet_valid");
  await rejectsWith(verifier.verify(await sign(key, accessClaims({ iat: t + 300 }))), "token_not_yet_valid");
  const { exp, ...noExp } = accessClaims();
  await rejectsWith(verifier.verify(await sign(key, noExp)), "invalid_claims");
  const strict = (await setup({ leeway: 0 }));
  await rejectsWith(strict.verifier.verify(await sign(strict.key, accessClaims({ exp: nowSec() - 5 }))), "token_expired");
});

test("a tampered token or one signed by another key fails the signature", async () => {
  const { key, verifier } = await setup();
  const token = await sign(key, accessClaims());
  const [h, , s] = token.split(".");
  await rejectsWith(verifier.verify(`${h}.${b64(accessClaims({ roles: ["admin"] }))}.${s}`), "invalid_signature");
  const other = await makeKey("k1");
  await rejectsWith(verifier.verify(await sign(other, accessClaims())), "invalid_signature");
  await rejectsWith(verifier.verify("not.a.jwt"), "invalid_token");
  await rejectsWith(verifier.verify("garbage"), "invalid_token");
});

test("an unknown kid refetches the JWKS at most once per 30 s; a rotated key is then accepted", async () => {
  const { key, pool, verifier, advance } = await setup();
  await verifier.verify(await sign(key, accessClaims()));
  assert.equal(pool.jwksFetches(), 1);
  const k2 = await makeKey("k2");
  const t2 = await sign(k2, accessClaims());
  await rejectsWith(verifier.verify(t2), "unknown_kid");
  assert.equal(pool.jwksFetches(), 2, "one refetch for the unknown kid");
  pool.state.keys.push(k2); // the pool rotates its key
  await rejectsWith(verifier.verify(t2), "unknown_kid");
  await rejectsWith(verifier.verify(await sign(await makeKey("k3"), accessClaims())), "unknown_kid");
  assert.equal(pool.jwksFetches(), 2, "no refetch within 30 s");
  advance(31_000);
  assert.equal((await verifier.verify(t2)).id, "usr_1");
  assert.equal(pool.jwksFetches(), 3);
  assert.equal((await verifier.verify(t2)).id, "usr_1");
  assert.equal(pool.jwksFetches(), 3, "known kid: cached");
});

test("concurrent first verifications share one JWKS fetch; the cache expires after 10 minutes", async () => {
  const { key, pool, verifier, advance } = await setup();
  const token = await sign(key, accessClaims({ exp: nowSec() + 3600 }));
  await Promise.all([verifier.verify(token), verifier.verify(token), verifier.verify(token)]);
  assert.equal(pool.jwksFetches(), 1);
  advance(9 * 60_000);
  await verifier.verify(token);
  assert.equal(pool.jwksFetches(), 1);
  advance(2 * 60_000);
  await verifier.verify(token);
  assert.equal(pool.jwksFetches(), 2);
});

test("JWKS unreachable: 503-type error without keys, cached keys keep working", async () => {
  const { key, pool, verifier, advance } = await setup();
  pool.state.jwksDown = true;
  const token = await sign(key, accessClaims({ exp: nowSec() + 3600 }));
  await assert.rejects(verifier.verify(token), (e) => e.code === "jwks_unavailable" && e.status === 503);
  await assert.rejects(verifier.verify(token), (e) => e.code === "jwks_unavailable");
  assert.equal(pool.jwksFetches(), 1, "a failed fetch is not retried within 30 s");
  advance(31_000);
  pool.state.jwksDown = false;
  await verifier.verify(token);
  pool.state.jwksDown = true;
  advance(11 * 60_000);
  assert.equal((await verifier.verify(token)).id, "usr_1", "stale keys are used while the pool is unreachable");
});

test("verifyIdToken: typ JWT, nonce, aud, at_hash", async () => {
  const { key, verifier } = await setup();
  const accessToken = "at.example.token";
  const digest = createHash("sha256").update(accessToken).digest();
  const atHash = digest.subarray(0, 16).toString("base64url");
  const claims = { iss: ISSUER, sub: "usr_1", aud: CLIENT_ID, azp: CLIENT_ID, exp: nowSec() + 300, iat: nowSec(), nonce: "n-1", at_hash: atHash };
  const idToken = await sign(key, claims, { typ: "JWT" });
  const out = await verifier.verifyIdToken(idToken, { nonce: "n-1", clientId: CLIENT_ID, accessToken });
  assert.equal(out.sub, "usr_1");
  await rejectsWith(verifier.verifyIdToken(idToken, { nonce: "n-2" }), "invalid_nonce");
  await rejectsWith(verifier.verifyIdToken(idToken, { nonce: "n-1", accessToken: "other" }), "invalid_at_hash");
  await rejectsWith(verifier.verifyIdToken(await sign(key, claims, { typ: "at+jwt" }), { nonce: "n-1" }), "invalid_typ");
  await rejectsWith(verifier.verifyIdToken(idToken, { nonce: "n-1", clientId: "uapp_second" }), "invalid_audience");
  await rejectsWith(verifier.verify(idToken), "invalid_typ");
});

test("the constructor requires an issuer and a client ID", () => {
  assert.throws(() => new TokenVerifier({ clientIds: [CLIENT_ID] }), TypeError);
  assert.throws(() => new TokenVerifier({ issuer: ISSUER }), TypeError);
  assert.equal(new TokenVerifier({ issuer: ISSUER + "/", clientId: CLIENT_ID }).jwksUri, ISSUER + "/.well-known/jwks.json");
});

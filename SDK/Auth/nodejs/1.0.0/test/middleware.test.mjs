import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { TokenVerifier, requireAppUser, requireAppUserHttp, fastifyRequireAppUser, fastifyAppUser, createAppUserAuthenticator } from "../src/index.js";
import { ISSUER, CLIENT_ID, makeKey, accessClaims, sign, mockPool } from "./support/pool.mjs";

async function setup() {
  const key = await makeKey("k1");
  const pool = mockPool({ keys: [key] });
  const verifier = new TokenVerifier({ issuer: ISSUER, clientIds: CLIENT_ID, fetch: pool.fetch });
  return { key, pool, verifier, token: (over, header) => sign(key, accessClaims(over), header) };
}

function mockRes() {
  return {
    statusCode: 200, headers: {}, body: null, headersSent: false,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    end(b) { this.body = b === undefined ? null : JSON.parse(b); this.headersSent = true; },
  };
}

// Runs an Express-style middleware and resolves when it answers or calls next().
function runExpress(mw, headers) {
  return new Promise((resolve) => {
    const req = { headers };
    const res = mockRes();
    const origEnd = res.end.bind(res);
    res.end = (b) => { origEnd(b); resolve({ req, res, nextCalled: false }); };
    mw(req, res, (err) => resolve({ req, res, nextCalled: true, err }));
  });
}

test("express: a valid token sets req.appUser and calls next()", async () => {
  const s = await setup();
  const mw = requireAppUser({ verifier: s.verifier });
  const { req, nextCalled, err } = await runExpress(mw, { authorization: `Bearer ${await s.token()}` });
  assert.equal(nextCalled, true);
  assert.equal(err, undefined);
  assert.equal(req.appUser.id, "usr_1");
});

test("express: missing, malformed or invalid tokens answer 401 invalid_token with WWW-Authenticate", async () => {
  const s = await setup();
  const mw = requireAppUser({ verifier: s.verifier });
  for (const headers of [{}, { authorization: "Basic abc" }, { authorization: "Bearer" }, { authorization: "Bearer not.a.token" },
    { authorization: `Bearer ${await s.token({ exp: 1 })}` }, { authorization: `Bearer ${await s.token({ aud: "uapp_other" })}` }]) {
    const { res, nextCalled } = await runExpress(mw, headers);
    assert.equal(nextCalled, false, JSON.stringify(headers));
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers["www-authenticate"], 'Bearer error="invalid_token"');
    assert.match(res.headers["content-type"], /application\/json/);
    assert.deepEqual(res.body, { error: "invalid_token" });
  }
});

test("express: options failing answer 403 insufficient_scope", async () => {
  const s = await setup();
  const cases = [
    [{}, { anon: true }],
    [{ requireVerifiedEmail: true }, { email_verified: false }],
    [{ requireRoles: ["admin", "owner"] }, { roles: ["member"] }],
    [{ requirePermissions: ["orders.read", "orders.write"] }, { permissions: ["orders.read"] }],
  ];
  for (const [opts, claims] of cases) {
    const { res, nextCalled } = await runExpress(requireAppUser({ verifier: s.verifier, ...opts }), { authorization: `Bearer ${await s.token(claims)}` });
    assert.equal(nextCalled, false, JSON.stringify(opts));
    assert.equal(res.statusCode, 403);
    assert.deepEqual(res.body, { error: "insufficient_scope" });
    assert.equal(res.headers["www-authenticate"], 'Bearer error="insufficient_scope"');
  }
});

test("express: options met pass (any role, all permissions, * permission, allowAnonymous)", async () => {
  const s = await setup();
  const cases = [
    [{ allowAnonymous: true }, { anon: true }],
    [{ requireVerifiedEmail: true }, {}],
    [{ requireRoles: ["admin", "member"] }, {}],
    [{ requirePermissions: ["orders.read"] }, {}],
    [{ requirePermissions: ["x.y", "z"] }, { permissions: ["*"] }],
  ];
  for (const [opts, claims] of cases) {
    const { nextCalled } = await runExpress(requireAppUser({ verifier: s.verifier, ...opts }), { authorization: `Bearer ${await s.token(claims)}` });
    assert.equal(nextCalled, true, JSON.stringify(opts));
  }
});

test("express: the middleware builds its own verifier from issuer + clientIds; JWKS down answers 503", async () => {
  const s = await setup();
  s.pool.state.jwksDown = true;
  const mw = requireAppUser({ issuer: ISSUER, clientIds: [CLIENT_ID], fetch: s.pool.fetch });
  const { res } = await runExpress(mw, { authorization: `Bearer ${await s.token()}` });
  assert.equal(res.statusCode, 503);
  assert.deepEqual(res.body, { error: "temporarily_unavailable" });
});

test("node:http guard on a real server", async () => {
  const s = await setup();
  const guard = requireAppUserHttp({ verifier: s.verifier, requireRoles: ["member"] });
  const server = createServer(async (req, res) => {
    const user = await guard(req, res);
    if (!user) return;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ id: user.id, same: req.appUser === user }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    const ok = await fetch(url, { headers: { Authorization: `Bearer ${await s.token()}` } });
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { id: "usr_1", same: true });
    const no = await fetch(url);
    assert.equal(no.status, 401);
    assert.equal(no.headers.get("www-authenticate"), 'Bearer error="invalid_token"');
    assert.deepEqual(await no.json(), { error: "invalid_token" });
  } finally {
    await new Promise((r) => server.close(r));
  }
});

function mockReply() {
  return {
    statusCode: 200, headers: {}, payload: undefined, sent: false,
    code(c) { this.statusCode = c; return this; },
    header(k, v) { this.headers[k.toLowerCase()] = v; return this; },
    send(p) { this.payload = p; this.sent = true; return this; },
  };
}

test("fastify preHandler: sets request.appUser or answers 401/403", async () => {
  const s = await setup();
  const pre = fastifyRequireAppUser({ verifier: s.verifier, requireRoles: ["admin"] });
  {
    const request = { headers: { authorization: `Bearer ${await s.token({ roles: ["admin"] })}` } };
    const reply = mockReply();
    assert.equal(await pre(request, reply), undefined);
    assert.equal(reply.sent, false);
    assert.equal(request.appUser.id, "usr_1");
  }
  {
    const reply = mockReply();
    const ret = await pre({ headers: {} }, reply);
    assert.equal(ret, reply);
    assert.equal(reply.statusCode, 401);
    assert.equal(reply.headers["www-authenticate"], 'Bearer error="invalid_token"');
    assert.deepEqual(reply.payload, { error: "invalid_token" });
  }
  {
    const reply = mockReply();
    await pre({ headers: { authorization: `Bearer ${await s.token()}` } }, reply);
    assert.equal(reply.statusCode, 403);
    assert.deepEqual(reply.payload, { error: "insufficient_scope" });
  }
});

test("fastify plugin decorates the instance and shares one verifier", async () => {
  const s = await setup();
  const decorated = {};
  const hooks = [];
  const fastify = {
    decorateRequest(name, value) { decorated.request = [name, value]; },
    decorate(name, fn) { this[name] = fn; },
    addHook(name, fn) { hooks.push([name, fn]); },
  };
  let doneCalled = false;
  fastifyAppUser(fastify, { verifier: s.verifier, global: true }, () => { doneCalled = true; });
  assert.equal(doneCalled, true);
  assert.deepEqual(decorated.request, ["appUser", null]);
  assert.equal(hooks[0][0], "preHandler");
  assert.equal(fastifyAppUser[Symbol.for("skip-override")], true);
  const pre = fastify.requireAppUser({ requirePermissions: ["orders.read"] });
  const request = { headers: { authorization: `Bearer ${await s.token()}` } };
  await pre(request, mockReply());
  assert.equal(request.appUser.id, "usr_1");
});

test("createAppUserAuthenticator accepts Fetch Headers", async () => {
  const s = await setup();
  const authenticate = createAppUserAuthenticator({ verifier: s.verifier });
  const r = await authenticate(new Headers({ Authorization: `Bearer ${await s.token()}` }));
  assert.equal(r.ok, true);
  assert.equal(r.user.id, "usr_1");
});

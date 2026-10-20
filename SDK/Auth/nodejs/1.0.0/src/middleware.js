// Guards for HTTP servers: read "Authorization: Bearer <access token>", verify it locally, attach the AppUser.
// No dependency on any framework: the Express/Connect middleware also works with plain node:http, and the Fastify
// helpers only use the request/reply methods every Fastify version has.
//
//   401  WWW-Authenticate: Bearer error="invalid_token"        {"error":"invalid_token"}       missing / invalid token
//   403  WWW-Authenticate: Bearer error="insufficient_scope"   {"error":"insufficient_scope"}  the options are not met
//   503  {"error":"temporarily_unavailable"}                                                   the pool's keys are unreachable
//
// Options: verifier (a TokenVerifier) or the TokenVerifier options (issuer, clientIds, ...); requireRoles (any of them),
// requirePermissions (all of them; "*" grants all), requireVerifiedEmail (false), allowAnonymous (false: guest tokens
// are refused), property ("appUser": where the user is attached).
import { TokenVerifier } from "./verifier.js";

const BEARER = /^Bearer[ \t]+([A-Za-z0-9\-._~+/]+=*)[ \t]*$/i;

function resolveVerifier(options) {
  if (options.verifier) return options.verifier;
  if (options.issuer) return new TokenVerifier(options);
  throw new TypeError("requireAppUser: pass a verifier or the TokenVerifier options (issuer, clientIds)");
}

const asList = (v) => (Array.isArray(v) ? v : v ? [v] : []).filter(Boolean);

function headerOf(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  const v = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

const unauthorized = { ok: false, status: 401, headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' }, body: { error: "invalid_token" } };
const forbidden = { ok: false, status: 403, headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope"' }, body: { error: "insufficient_scope" } };
const unavailable = { ok: false, status: 503, headers: { "Retry-After": "30" }, body: { error: "temporarily_unavailable" } };

/**
 * The framework-free core: `await authenticate(headers)` -> `{ok: true, user}` or `{ok: false, status, headers, body, error?}`.
 * `headers`: a Node IncomingHttpHeaders object, a Fetch Headers, or anything with an `authorization` entry.
 */
export function createAppUserAuthenticator(options = {}) {
  const verifier = resolveVerifier(options);
  const requireRoles = asList(options.requireRoles);
  const requirePermissions = asList(options.requirePermissions);
  const requireVerifiedEmail = options.requireVerifiedEmail === true;
  const allowAnonymous = options.allowAnonymous === true;
  return async function authenticate(headers) {
    const m = BEARER.exec(headerOf(headers, "authorization") || "");
    if (!m) return { ...unauthorized, error: null };
    let user;
    try {
      user = await verifier.verify(m[1]);
    } catch (e) {
      if (e && e.code === "jwks_unavailable") return { ...unavailable, error: e };
      if (e && e.name === "TokenVerificationError") return { ...unauthorized, error: e };
      throw e;
    }
    if (user.anonymous && !allowAnonymous) return { ...forbidden, error: null };
    if (requireVerifiedEmail && !user.emailVerified) return { ...forbidden, error: null };
    if (requireRoles.length && !requireRoles.some((r) => user.hasRole(r))) return { ...forbidden, error: null };
    if (requirePermissions.some((p) => !user.hasPermission(p))) return { ...forbidden, error: null };
    return { ok: true, user };
  };
}

function sendNode(res, r) {
  if (res.headersSent) return;
  res.statusCode = r.status;
  for (const [k, v] of Object.entries(r.headers)) res.setHeader(k, v);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(r.body));
}

/**
 * Express / Connect middleware (also plain node:http: `guard(req, res, () => handle(req, res))`).
 * On success sets req.appUser (or options.property) and calls next(); otherwise answers 401 / 403 / 503.
 */
export function requireAppUser(options = {}) {
  const authenticate = createAppUserAuthenticator(options);
  const property = options.property || "appUser";
  return function openbackRequireAppUser(req, res, next) {
    authenticate(req.headers).then((r) => {
      if (r.ok) {
        req[property] = r.user;
        if (typeof next === "function") next();
        return;
      }
      sendNode(res, r);
    }, (e) => {
      if (typeof next === "function") next(e);
      else sendNode(res, { status: 500, headers: {}, body: { error: "server_error" } });
    });
  };
}

/**
 * Plain node:http: `const user = await guard(req, res); if (!user) return;` — answers 401 / 403 / 503 itself and
 * resolves to null, or resolves to the AppUser (also set on req.appUser).
 */
export function requireAppUserHttp(options = {}) {
  const authenticate = createAppUserAuthenticator(options);
  const property = options.property || "appUser";
  return async function openbackGuard(req, res) {
    const r = await authenticate(req.headers);
    if (r.ok) {
      req[property] = r.user;
      return r.user;
    }
    sendNode(res, r);
    return null;
  };
}

/** A Fastify preHandler: `fastify.get("/x", { preHandler: fastifyRequireAppUser(opts) }, handler)`; sets request.appUser. */
export function fastifyRequireAppUser(options = {}) {
  const authenticate = createAppUserAuthenticator(options);
  const property = options.property || "appUser";
  return async function openbackPreHandler(request, reply) {
    const r = await authenticate(request.headers);
    if (r.ok) {
      request[property] = r.user;
      return;
    }
    reply.code(r.status);
    for (const [k, v] of Object.entries(r.headers)) reply.header(k, v);
    reply.header("Cache-Control", "no-store");
    reply.header("Content-Type", "application/json; charset=utf-8");
    reply.send(r.body);
    return reply;
  };
}

/**
 * A Fastify plugin: `fastify.register(fastifyAppUser, { issuer, clientIds })`, then
 * `{ preHandler: fastify.requireAppUser({ requireRoles: ["admin"] }) }` on the routes (one shared TokenVerifier), or
 * `global: true` to guard every route of the instance. Not encapsulated (like fastify-plugin).
 */
export function fastifyAppUser(fastify, options, done) {
  const base = { ...(options || {}) };
  const verifier = resolveVerifier(base);
  const property = base.property || "appUser";
  if (typeof fastify.decorateRequest === "function" && !(fastify.hasRequestDecorator && fastify.hasRequestDecorator(property))) {
    fastify.decorateRequest(property, null);
  }
  if (typeof fastify.decorate === "function") {
    fastify.decorate("requireAppUser", (opts = {}) => fastifyRequireAppUser({ ...base, ...opts, verifier }));
  }
  if (base.global) fastify.addHook("preHandler", fastifyRequireAppUser({ ...base, verifier }));
  if (typeof done === "function") done();
}
fastifyAppUser[Symbol.for("skip-override")] = true;
fastifyAppUser[Symbol.for("fastify.display-name")] = "openback-app-auth";

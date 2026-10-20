// The client of a user pool for Node.js: the same API as openback-app-auth-javascript (browser), without window, Web
// Locks or sessionStorage. Use it for CLIs, desktop apps, scripts, tests, and "backend" apps calling the JSON API.
//
// The session is kept in a storage: in memory by default; pass your own (sync or async getItem/setItem/removeItem) to
// keep it in a file, a database or the user's server-side session. One refresh at a time per client (a promise queue):
// share one client per session, and if several processes share one stored session, put a lock around your storage.
import { AuthError, normalizeIssuer, randomString, sha256b64url, safeEqual, readJson, errorFromResponse, networkError, decodeJwt, basicAuthorization, paramsOf } from "./util.js";

const API = "/api/v1";
const SKEW_MS = 60_000;
const DEFAULT_SCOPE = "openid profile email";
const DEFAULT_EXPIRES_IN = 900;

export function memoryStorage() {
  const data = new Map();
  return {
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => { data.set(k, String(v)); },
    removeItem: (k) => { data.delete(k); },
  };
}

function isThenable(v) {
  return v !== null && (typeof v === "object" || typeof v === "function") && typeof v.then === "function";
}

function normalize(s) {
  s = s && typeof s === "object" ? s : {};
  return {
    accessToken: s.accessToken || null,
    refreshToken: s.refreshToken || null,
    idToken: s.idToken || null,
    expiresAt: typeof s.expiresAt === "number" ? s.expiresAt : 0,
    user: s.user || null,
    org: s.org || null,
  };
}

function parseSession(raw) {
  let s = null;
  try { s = typeof raw === "string" ? JSON.parse(raw) : null; } catch { s = null; }
  return normalize(s);
}

function isFresh(s) {
  return Boolean(s.accessToken && s.expiresAt && s.expiresAt - Date.now() > SKEW_MS);
}

function expiresAtOf(expiresIn) {
  const n = Number(expiresIn);
  return Date.now() + (Number.isFinite(n) && n > 0 ? n : DEFAULT_EXPIRES_IN) * 1000;
}

export function createAuth(options = {}) {
  const clientId = options.clientId;
  if (!options.issuer || !clientId) throw new TypeError("createAuth: issuer and clientId are required");
  const issuer = normalizeIssuer(options.issuer);
  const clientSecret = options.clientSecret || null;
  const key = options.storageKey || "openback.auth." + clientId;
  const txKey = key + ".transaction";
  const store = options.storage || memoryStorage();
  const txStore = options.transactionStorage || store;
  const doFetch = options.fetch || ((input, init) => globalThis.fetch(input, init));
  const listeners = new Set();
  let state = normalize(null);
  let lastSignature = signature(state);
  let queue = null;

  const ready = (() => {
    let raw = null;
    try { raw = store.getItem(key); } catch { raw = null; }
    if (isThenable(raw)) {
      return Promise.resolve(raw).then((v) => { state = parseSession(v); notify(); }, () => {});
    }
    state = parseSession(raw);
    lastSignature = signature(state);
    return Promise.resolve();
  })();

  function signature(s) {
    return JSON.stringify([Boolean(s.refreshToken || s.accessToken), s.user || null, s.org || null]);
  }

  function notify() {
    const sig = signature(state);
    if (sig === lastSignature) return;
    lastSignature = sig;
    for (const fn of [...listeners]) {
      try { fn(state.user, state.org); } catch { /* a listener's error is its own */ }
    }
  }

  // While the last write failed, the session in memory is the newest one (never present an older, used refresh token).
  let unsaved = false;

  async function readState() {
    if (unsaved) return normalize(state);
    try { return parseSession(await store.getItem(key)); } catch { return normalize(state); }
  }

  // One write per session change. A storage error is thrown after the session is kept in memory.
  async function save(next) {
    state = normalize(next);
    try {
      if (state.refreshToken || state.accessToken) await store.setItem(key, JSON.stringify(state));
      else await store.removeItem(key);
      unsaved = false;
    } catch (e) {
      unsaved = true;
      notify();
      throw e;
    }
    notify();
    return state;
  }

  function adopt(s) {
    state = normalize(s);
    notify();
    return state;
  }

  async function sessionRejected(code, sentAccess, sentRefresh) {
    if (code === "invalid_refresh_token" && sentRefresh) {
      const cur = await readState();
      if (cur.refreshToken && cur.refreshToken !== sentRefresh) adopt(cur);
      else await save(null);
    } else if (/^token_/.test(code) && sentAccess) {
      const cur = await readState();
      if (cur.accessToken && cur.accessToken !== sentAccess) adopt(cur);
      else if (state.accessToken === sentAccess || cur.accessToken === sentAccess) await save(null);
    }
  }

  async function call(method, path, body, opts = {}) {
    await ready;
    const headers = { "X-Client-Id": clientId, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let sent = opts.token || null;
    if (opts.auth && !sent) sent = await getAccessToken();
    if (sent) headers.Authorization = "Bearer " + sent;
    let res;
    try {
      res = await doFetch(issuer + API + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) {
      throw networkError(e);
    }
    const data = await readJson(res);
    if (!res.ok) {
      const err = errorFromResponse(res, data);
      if (res.status === 401) await sessionRejected(err.code, opts.auth || opts.token ? sent : null, opts.refreshToken || null);
      throw err;
    }
    return data;
  }

  async function outcome(data) {
    if (data && data.status === "ok" && data.access_token) {
      await save({ accessToken: data.access_token, refreshToken: data.refresh_token || null, idToken: data.id_token || null,
        expiresAt: expiresAtOf(data.expires_in), user: data.user || null, org: data.org || null });
    }
    return data;
  }

  async function storeTokens(data, base) {
    return save({ accessToken: data.access_token, refreshToken: data.refresh_token || base.refreshToken, idToken: base.idToken,
      expiresAt: expiresAtOf(data.expires_in), user: base.user,
      org: data && Object.prototype.hasOwnProperty.call(data, "org") ? data.org || null : base.org });
  }

  async function exchangeRefresh(cur, orgId) {
    const data = await call("POST", "/token/refresh", { refresh_token: cur.refreshToken, org_id: orgId || undefined },
      { refreshToken: cur.refreshToken });
    return storeTokens(data, cur);
  }

  // Everything that uses (and so rotates) the refresh token runs here, one at a time. A network error is surfaced,
  // never retried: the request may have reached the server.
  async function runRotation(op, startRefresh) {
    const cur = await readState();
    if (!cur.refreshToken) {
      if (state.refreshToken || state.accessToken) adopt(cur);
      throw new AuthError(401, "not_signed_in", "Not signed in");
    }
    if (op.kind === "refresh" && !op.orgId && cur.refreshToken !== startRefresh && isFresh(cur)) {
      adopt(cur);
      return cur.accessToken;
    }
    if (op.kind === "switch") {
      const s = isFresh(cur) ? cur : await exchangeRefresh(cur, null);
      const data = await call("POST", "/orgs/switch", { org_id: op.orgId, refresh_token: s.refreshToken },
        { token: s.accessToken, refreshToken: s.refreshToken });
      return (await storeTokens(data, s)).org;
    }
    return (await exchangeRefresh(cur, op.orgId)).accessToken;
  }

  function rotate(op) {
    if (op.kind === "refresh" && !op.orgId && queue && queue.kind === "refresh" && !queue.orgId) return queue.promise;
    const startRefresh = state.refreshToken;
    const prev = queue ? queue.promise.catch(() => {}) : ready;
    const entry = { kind: op.kind, orgId: op.orgId || null, promise: null };
    entry.promise = prev.then(() => runRotation(op, startRefresh));
    queue = entry;
    const done = () => { if (queue === entry) queue = null; };
    entry.promise.then(done, done);
    return entry.promise;
  }

  async function settleRotation() {
    while (queue) await queue.promise.catch(() => {});
  }

  function refresh(orgId) {
    return rotate({ kind: "refresh", orgId: orgId || null });
  }

  async function getAccessToken() {
    await ready;
    if (isFresh(state)) return state.accessToken;
    return refresh();
  }

  // --- OpenID Connect (hosted page; e.g. a CLI with a loopback redirect) ---

  async function txGet() {
    try {
      const raw = await txStore.getItem(txKey);
      const tx = raw ? JSON.parse(raw) : null;
      return tx && typeof tx === "object" ? tx : null;
    } catch {
      return null;
    }
  }

  async function buildAuthorizationRequest(p = {}) {
    const redirect = p.redirectUri || options.redirectUri;
    if (!redirect) throw new TypeError("buildAuthorizationRequest: redirectUri is required");
    const codeVerifier = randomString(48);
    const st = randomString(32);
    const nonce = randomString(32);
    const params = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirect,
      scope: p.scope || DEFAULT_SCOPE, state: st, nonce, code_challenge: sha256b64url(codeVerifier), code_challenge_method: "S256" });
    if (p.provider) params.set("provider", p.provider);
    if (p.orgId) params.set("org_id", p.orgId);
    if (p.prompt) params.set("prompt", p.prompt);
    if (p.screenHint) params.set("screen_hint", p.screenHint);
    if (p.loginHint) params.set("login_hint", p.loginHint);
    if (p.maxAge !== undefined && p.maxAge !== null) params.set("max_age", String(p.maxAge));
    if (p.uiLocales) params.set("ui_locales", p.uiLocales);
    await txStore.setItem(txKey, JSON.stringify({ state: st, nonce, codeVerifier, redirectUri: redirect, createdAt: Date.now() }));
    return { url: issuer + "/authorize?" + params, state: st, nonce, codeVerifier, redirectUri: redirect };
  }

  async function tokenEndpoint(form) {
    const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    if (clientSecret) headers.Authorization = basicAuthorization(clientId, clientSecret);
    let res;
    try {
      res = await doFetch(issuer + "/token", { method: "POST", headers, body: new URLSearchParams(form) });
    } catch (e) {
      throw networkError(e);
    }
    const data = await readJson(res);
    if (!res.ok) throw errorFromResponse(res, data);
    if (!data || !data.access_token) throw new AuthError(res.status, "invalid_response", "The token endpoint answered without a token");
    return data;
  }

  // url: the callback address (or its query); transaction: the one buildAuthorizationRequest() returned, when you kept it
  // yourself (default: the one in transactionStorage).
  async function handleRedirectCallback(url, transaction) {
    const q = paramsOf(url);
    const error = q.get("error");
    const code = q.get("code");
    if (!error && !code) return null;
    const fromStore = !transaction;
    const pending = transaction || (await txGet());
    const stateOk = Boolean(pending && safeEqual(String(pending.state || ""), q.get("state") || ""));
    if (stateOk && fromStore) { try { await txStore.removeItem(txKey); } catch { /* nothing to remove */ } }
    if (error) throw new AuthError(400, error, q.get("error_description") || error);
    if (!pending) throw new AuthError(400, "missing_transaction", "No sign-in in progress for this callback");
    if (!stateOk) throw new AuthError(400, "invalid_state", "Sign-in state mismatch");
    const iss = q.get("iss");
    if (iss !== null && iss !== issuer) throw new AuthError(400, "invalid_issuer", "Unexpected issuer in the callback");
    const data = await tokenEndpoint({ grant_type: "authorization_code", code, redirect_uri: pending.redirectUri,
      client_id: clientId, code_verifier: pending.codeVerifier });
    if (data.id_token) {
      // Straight from the token endpoint over TLS: claims checked here; verify the signature with TokenVerifier if needed.
      const claims = decodeJwt(data.id_token);
      if (!claims) throw new AuthError(400, "invalid_id_token", "Malformed ID token");
      if (claims.iss !== issuer) throw new AuthError(400, "invalid_id_token", "ID token of another issuer");
      const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!aud.includes(clientId)) throw new AuthError(400, "invalid_id_token", "ID token of another app");
      if (!safeEqual(String(claims.nonce || ""), String(pending.nonce || ""))) throw new AuthError(400, "invalid_nonce", "Nonce mismatch");
    }
    let user = null;
    try { user = await call("GET", "/me", undefined, { token: data.access_token }); } catch { user = null; }
    await save({ accessToken: data.access_token, refreshToken: data.refresh_token || null, idToken: data.id_token || null,
      expiresAt: expiresAtOf(data.expires_in), user, org: data.org || null });
    return user;
  }

  function buildLogoutUrl(arg, st) {
    const o = arg && typeof arg === "object" ? arg : { postLogoutRedirectUri: arg || undefined, state: st };
    const params = new URLSearchParams({ client_id: clientId });
    if (state.idToken) params.set("id_token_hint", state.idToken);
    if (o.postLogoutRedirectUri) params.set("post_logout_redirect_uri", o.postLogoutRedirectUri);
    if (o.state) params.set("state", o.state);
    return issuer + "/logout?" + params;
  }

  async function signOut(p = {}) {
    await ready;
    await settleRotation();
    const cur = state;
    if (cur.refreshToken || cur.accessToken) {
      try {
        let token = isFresh(cur) ? cur.accessToken : null;
        if (p.everywhere && !token) token = await getAccessToken();
        await call("POST", "/signout", { refresh_token: state.refreshToken || undefined, everywhere: Boolean(p.everywhere) },
          { token: token || undefined });
      } catch { /* signed out locally anyway */ }
    }
    await save(null);
  }

  async function me() {
    const user = await call("GET", "/me", undefined, { auth: true });
    if (user && (state.refreshToken || state.accessToken)) await save({ ...state, user });
    return user;
  }

  async function endSession(out) {
    await settleRotation();
    await save(null);
    return out;
  }

  const enc = encodeURIComponent;

  return {
    get currentUser() { return state.user; },
    get currentOrg() { return state.org; },
    get accessTokenClaims() { return state.accessToken ? decodeJwt(state.accessToken) : null; },
    get isSignedIn() { return Boolean(state.refreshToken || isFresh(state)); },
    get idToken() { return state.idToken; },
    issuer,
    clientId,
    ready,
    config: () => call("GET", "/config"),
    onAuthStateChanged(fn) {
      listeners.add(fn);
      try { fn(state.user, state.org); } catch { /* ignore */ }
      return () => { listeners.delete(fn); };
    },
    getAccessToken,
    refresh,
    async fetch(input, init = {}) {
      const token = await getAccessToken();
      const base = init.headers || (typeof Request !== "undefined" && input instanceof Request ? input.headers : undefined);
      const headers = new Headers(base || {});
      headers.set("Authorization", "Bearer " + token);
      return doFetch(input, { ...init, headers });
    },
    signUp: ({ email, password, displayName, locale, orgId }) =>
      call("POST", "/signup", { email, password, display_name: displayName || undefined, locale, org_id: orgId }).then(outcome),
    signInWithPassword: ({ email, password, orgId }) => call("POST", "/signin/password", { email, password, org_id: orgId }).then(outcome),
    sendEmailCode: (email) => call("POST", "/signin/email-code", { email }),
    signInWithEmailCode: ({ email, code, token, orgId }) =>
      call("POST", "/signin/email-code/verify", { email, code, token, org_id: orgId }).then(outcome),
    signInAnonymously: () => call("POST", "/signin/anonymous", {}).then(outcome),
    verifyMfa: ({ mfaToken, code }) => call("POST", "/signin/mfa", { mfa_token: mfaToken, code }).then(outcome),
    enrollMfa: (mfaToken) => (mfaToken ? call("POST", "/mfa/enroll", { mfa_token: mfaToken }) : call("POST", "/mfa/enroll", {}, { auth: true })),
    confirmMfa: (code, mfaToken) => (mfaToken
      ? call("POST", "/mfa/enroll/confirm", { mfa_token: mfaToken, code }).then(outcome)
      : call("POST", "/mfa/enroll/confirm", { code }, { auth: true })),
    disableMfa: (code) => call("POST", "/mfa/disable", { code }, { auth: true }),
    buildAuthorizationRequest,
    handleRedirectCallback,
    buildLogoutUrl,
    sendPasswordReset: (email) => call("POST", "/password/forgot", { email }),
    resetPassword: ({ token, email, code, newPassword }) => call("POST", "/password/reset", { token, email, code, new_password: newPassword }),
    changeForcedPassword: ({ changeToken, newPassword }) => call("POST", "/password/reset", { change_token: changeToken, new_password: newPassword }),
    verifyEmail: ({ token, email, code }) => call("POST", "/email/verify", { token, email, code }),
    resendVerification: () => call("POST", "/email/verify/send", {}, { auth: true }),
    me,
    async updateProfile(fields = {}) {
      const body = {
        display_name: fields.displayName !== undefined ? fields.displayName : fields.display_name,
        photo_url: fields.photoUrl !== undefined ? fields.photoUrl : fields.photo_url,
        locale: fields.locale,
      };
      const user = await call("PATCH", "/me", body, { auth: true });
      if (user && (state.refreshToken || state.accessToken)) await save({ ...state, user });
      return user;
    },
    changePassword: ({ currentPassword, newPassword }) =>
      call("POST", "/me/password", { current_password: currentPassword, new_password: newPassword }, { auth: true }).then(endSession),
    changeEmail: (newEmail) => call("POST", "/me/email", { new_email: newEmail }, { auth: true }),
    async confirmEmailChange({ code, token }) {
      const out = await call("POST", "/me/email/confirm", { code, token }, { auth: true });
      if (out && out.user && (state.refreshToken || state.accessToken)) await save({ ...state, user: out.user });
      return out;
    },
    async upgradeAnonymous({ email, password }) {
      const out = await call("POST", "/me/upgrade", { email, password }, { auth: true });
      if (out && out.user && (state.refreshToken || state.accessToken)) await save({ ...state, user: out.user });
      return out;
    },
    deleteAccount: (password) => call("DELETE", "/me", { password }, { auth: true }).then(endSession),
    signOut,
    organizations: () => call("GET", "/orgs", undefined, { auth: true }),
    createOrganization: (name) => call("POST", "/orgs", { name }, { auth: true }),
    switchOrganization: (orgId) => rotate({ kind: "switch", orgId }),
    members: (orgId, { q = "", skip = 0, limit = 50 } = {}) =>
      call("GET", "/orgs/" + enc(orgId) + "/members?" + new URLSearchParams({ q, skip: String(skip), limit: String(limit) }), undefined, { auth: true }),
    addMember: (orgId, { email, displayName, password, roles }) =>
      call("POST", "/orgs/" + enc(orgId) + "/members", { email, display_name: displayName || undefined, password, roles: roles || [] }, { auth: true }),
    setMemberRoles: (orgId, userId, roles) => call("PATCH", "/orgs/" + enc(orgId) + "/members/" + enc(userId), { roles }, { auth: true }),
    removeMember: (orgId, userId) => call("DELETE", "/orgs/" + enc(orgId) + "/members/" + enc(userId), undefined, { auth: true }),
  };
}

export function createClient(issuer, clientId, options = {}) {
  return createAuth({ ...options, issuer, clientId });
}

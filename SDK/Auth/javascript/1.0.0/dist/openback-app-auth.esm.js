/*! openback-app-auth-javascript v1.0.0 | MIT License | https://github.com/GexyLab/openback-plugins-community/tree/production/SDK/Auth/javascript/1.0.0#readme */
// openback-app-auth-javascript 1.0.0 -- browser client of an OpenBack user pool (App authenticator, users-service).
//
// Two ways to sign users in, freely mixed:
//   - your own forms: signUp(), signInWithPassword(), signInWithEmailCode(), signInAnonymously(), verifyMfa() call the
//     pool's JSON API (<issuer>/api/v1);
//   - the pool's hosted sign-in page: signInWithRedirect() / handleRedirectCallback() (OpenID Connect, code + PKCE S256).
// The session is kept in a storage (localStorage by default, memory when it is blocked). The access token is renewed one
// minute before it expires, one refresh at a time (also across the browser's tabs, with Web Locks), the rotated refresh
// token is stored at once, and onAuthStateChanged() tells the app when the user changes.
//
//   import { createAuth } from "openback-app-auth-javascript";
//   const auth = createAuth({ issuer: "https://api.example.com/gateway/shop/auth/main", clientId: "uapp_..." });
//   const res = await auth.signInWithPassword({ email, password });   // res.status: "ok" | "mfa_required" | ...
//   const token = await auth.getAccessToken();                         // for your API calls
//
// Plain ES module, no dependencies. The build (scripts/build.mjs) turns this file into the dist/ bundles: keep template
// literals on one line and exports as "export const|class|function NAME" (no export lists).

export const VERSION = "1.0.0";

const API = "/api/v1";
const SKEW_MS = 60_000;
const DEFAULT_SCOPE = "openid profile email";
const DEFAULT_EXPIRES_IN = 900;

export class AuthError extends Error {
  constructor(status, code, message, detail, options) {
    super(message || code || "HTTP " + status, options);
    this.name = "AuthError";
    this.status = status;
    this.code = code || "http_" + status;
    this.detail = detail === undefined ? null : detail;
  }
}

// --- storage ---------------------------------------------------------------------------------------------------------

export function memoryStorage() {
  const data = new Map();
  return {
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => { data.set(k, String(v)); },
    removeItem: (k) => { data.delete(k); },
  };
}

function probe(getStorage) {
  try {
    const s = getStorage();
    if (!s) return null;
    s.setItem("__openback_auth_probe", "1");
    s.removeItem("__openback_auth_probe");
    return s;
  } catch {
    return null; // private mode, blocked storage, no window
  }
}

function defaultStorage() {
  return probe(() => (typeof localStorage !== "undefined" ? localStorage : null)) || memoryStorage();
}

function defaultTransactionStorage() {
  return probe(() => (typeof sessionStorage !== "undefined" ? sessionStorage : null)) || memoryStorage();
}

function isThenable(v) {
  return v !== null && (typeof v === "object" || typeof v === "function") && typeof v.then === "function";
}

function parseSession(raw) {
  let s = null;
  try { s = typeof raw === "string" ? JSON.parse(raw) : null; } catch { s = null; }
  return normalize(s);
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

function isFresh(s) {
  return Boolean(s.accessToken && s.expiresAt && s.expiresAt - Date.now() > SKEW_MS);
}

function expiresAtOf(expiresIn) {
  const n = Number(expiresIn);
  return Date.now() + (Number.isFinite(n) && n > 0 ? n : DEFAULT_EXPIRES_IN) * 1000;
}

// --- encoding and crypto ---------------------------------------------------------------------------------------------

function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString(nBytes) {
  const bytes = new Uint8Array(nBytes);
  globalThis.crypto.getRandomValues(bytes);
  return b64url(bytes);
}

async function sha256(text) {
  return b64url(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

// Constant-time comparison of two strings (the time depends only on the longer length).
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const n = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) | 0) ^ (b.charCodeAt(i) | 0);
  return diff === 0;
}

// Decodes a JWT's claims WITHOUT verifying it (display only; servers verify tokens with the pool's keys).
export function decodeJwt(token) {
  try {
    let b64 = String(token).split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const claims = JSON.parse(new TextDecoder().decode(bytes));
    return claims && typeof claims === "object" && !Array.isArray(claims) ? claims : null;
  } catch {
    return null;
  }
}

// --- HTTP ------------------------------------------------------------------------------------------------------------

async function readJson(res) {
  let text = "";
  try { text = await res.text(); } catch { return null; }
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function errorFromResponse(res, data) {
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
    code = data.error; // OAuth errors of /token: {error, error_description}
    message = message || (typeof data.error_description === "string" ? data.error_description : null);
  }
  return new AuthError(status, code || "http_" + status, message || res.statusText || "HTTP " + status, detail !== undefined ? detail : data);
}

function networkError(e) {
  return new AuthError(0, "network_error", "Network error: " + ((e && e.message) || "request failed"), null, { cause: e });
}

// --- the client ------------------------------------------------------------------------------------------------------

export function createAuth(options = {}) {
  const clientId = options.clientId;
  let issuer = options.issuer;
  if (!issuer || !clientId) throw new TypeError("createAuth: issuer and clientId are required");
  issuer = String(issuer).replace(/\/+$/, "");
  const key = options.storageKey || "openback.auth." + clientId;
  const txKey = key + ".transaction";
  let store = options.storage || defaultStorage();
  let txStore = options.transactionStorage || defaultTransactionStorage();
  const doFetch = options.fetch || ((input, init) => globalThis.fetch(input, init));
  const locks = options.locks === undefined
    ? (typeof navigator !== "undefined" && navigator.locks && typeof navigator.locks.request === "function" ? navigator.locks : null)
    : options.locks || null;
  const listeners = new Set();
  let state = normalize(null);
  let lastSignature = signature(state);
  let queue = null; // the token rotation in flight: {kind, orgId, promise}

  // The stored session: read synchronously when the storage is synchronous (localStorage), else when `ready` settles.
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

  // Listeners hear about changes of the user, the organization or the signed-in state (not about every renewal).
  function notify() {
    const sig = signature(state);
    if (sig === lastSignature) return;
    lastSignature = sig;
    for (const fn of [...listeners]) {
      try { fn(state.user, state.org); } catch { /* a listener's error is its own */ }
    }
  }

  async function readState() {
    try { return parseSession(await store.getItem(key)); } catch { return normalize(state); }
  }

  async function persist(next) {
    const signedIn = Boolean(next.refreshToken || next.accessToken);
    try {
      if (signedIn) await store.setItem(key, JSON.stringify(next));
      else await store.removeItem(key);
    } catch {
      // Storage full or blocked: keep the session in memory, so a rotated refresh token is never lost.
      store = memoryStorage();
      if (signedIn) store.setItem(key, JSON.stringify(next));
    }
  }

  // Stores a whole session at once (one write) and notifies the listeners.
  async function save(next) {
    state = normalize(next);
    await persist(state);
    notify();
    return state;
  }

  // Follows a session another tab (or the storage's owner) wrote, without writing it again.
  function adopt(s) {
    state = normalize(s);
    notify();
    return state;
  }

  // Another tab signed in, renewed or signed out: follow it.
  if (typeof window !== "undefined" && window && typeof window.addEventListener === "function") {
    window.addEventListener("storage", (e) => {
      if (e.key === key) adopt(parseSession(e.newValue));
      else if (e.key === null && e.storageArea === store) adopt(null);
    });
  }

  // The session is dead on the server: clear it, unless another tab already replaced it with a newer one.
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

  // An outcome of a sign-in: the session is kept on "ok"; the other statuses are returned for the app to continue.
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

  function withLock(fn) {
    if (locks) return locks.request(key + ".refresh", () => fn());
    return fn();
  }

  // Everything that uses (and so rotates) the refresh token goes through here: one at a time in this tab (a queue)
  // and across tabs (Web Locks). A network error is surfaced, never retried: the request may have reached the server.
  async function runRotation(op, startRefresh) {
    const cur = await readState(); // another tab may have rotated it already
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
    entry.promise = prev.then(() => withLock(() => runRotation(op, startRefresh)));
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

  // --- OpenID Connect (hosted page) ---

  async function txSet(tx) {
    try { await txStore.setItem(txKey, JSON.stringify(tx)); } catch { txStore = memoryStorage(); txStore.setItem(txKey, JSON.stringify(tx)); }
  }

  async function txGet() {
    try {
      const raw = await txStore.getItem(txKey);
      const tx = raw ? JSON.parse(raw) : null;
      return tx && typeof tx === "object" ? tx : null;
    } catch {
      return null;
    }
  }

  async function txRemove() {
    try { await txStore.removeItem(txKey); } catch { /* nothing to remove */ }
  }

  function defaultRedirectUri() {
    if (options.redirectUri) return options.redirectUri;
    if (typeof window !== "undefined" && window.location) return window.location.origin + window.location.pathname;
    return null;
  }

  async function buildAuthorizationRequest(p = {}) {
    const redirect = p.redirectUri || defaultRedirectUri();
    if (!redirect) throw new TypeError("buildAuthorizationRequest: redirectUri is required");
    const codeVerifier = randomString(48);
    const st = randomString(32);
    const nonce = randomString(32);
    const params = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirect,
      scope: p.scope || DEFAULT_SCOPE, state: st, nonce, code_challenge: await sha256(codeVerifier), code_challenge_method: "S256" });
    if (p.provider) params.set("provider", p.provider);
    if (p.orgId) params.set("org_id", p.orgId);
    if (p.prompt) params.set("prompt", p.prompt);
    if (p.screenHint) params.set("screen_hint", p.screenHint);
    if (p.loginHint) params.set("login_hint", p.loginHint);
    if (p.maxAge !== undefined && p.maxAge !== null) params.set("max_age", String(p.maxAge));
    if (p.uiLocales) params.set("ui_locales", p.uiLocales);
    await txSet({ state: st, nonce, codeVerifier, redirectUri: redirect, createdAt: Date.now() });
    return { url: issuer + "/authorize?" + params, state: st, nonce, codeVerifier, redirectUri: redirect };
  }

  async function tokenEndpoint(form) {
    let res;
    try {
      res = await doFetch(issuer + "/token", { method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body: new URLSearchParams(form) });
    } catch (e) {
      throw networkError(e);
    }
    const data = await readJson(res);
    if (!res.ok) throw errorFromResponse(res, data);
    if (!data || !data.access_token) throw new AuthError(res.status, "invalid_response", "The token endpoint answered without a token");
    return data;
  }

  async function handleRedirectCallback(url) {
    const href = url || (typeof window !== "undefined" && window.location ? window.location.href : "");
    const q = new URL(href).searchParams;
    const error = q.get("error");
    const code = q.get("code");
    if (!error && !code) return null; // not a sign-in callback
    const pending = await txGet();
    const stateOk = Boolean(pending && safeEqual(String(pending.state || ""), q.get("state") || ""));
    if (stateOk) await txRemove(); // a transaction is used once
    if (error) throw new AuthError(400, error, q.get("error_description") || error);
    if (!pending) throw new AuthError(400, "missing_transaction", "No sign-in in progress for this callback");
    if (!stateOk) throw new AuthError(400, "invalid_state", "Sign-in state mismatch");
    const iss = q.get("iss");
    if (iss !== null && iss !== issuer) throw new AuthError(400, "invalid_issuer", "Unexpected issuer in the callback");
    const data = await tokenEndpoint({ grant_type: "authorization_code", code, redirect_uri: pending.redirectUri,
      client_id: clientId, code_verifier: pending.codeVerifier });
    if (data.id_token) {
      // The ID token comes straight from the token endpoint over TLS: its claims are checked, its signature is not.
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

  async function signInWithRedirect(p = {}) {
    if (typeof window === "undefined" || !window.location) throw new Error("signInWithRedirect needs a browser window");
    const req = await buildAuthorizationRequest(p);
    window.location.assign(req.url);
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
    // --- sign-up and sign-in ---
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
    // --- OpenID Connect ---
    buildAuthorizationRequest,
    signInWithRedirect,
    handleRedirectCallback,
    buildLogoutUrl,
    async signOutRedirect(p = {}) {
      if (typeof window === "undefined" || !window.location) throw new Error("signOutRedirect needs a browser window");
      const url = buildLogoutUrl(p);
      await signOut({ everywhere: p.everywhere });
      window.location.assign(url);
    },
    // --- passwords and emails ---
    sendPasswordReset: (email) => call("POST", "/password/forgot", { email }),
    resetPassword: ({ token, email, code, newPassword }) => call("POST", "/password/reset", { token, email, code, new_password: newPassword }),
    changeForcedPassword: ({ changeToken, newPassword }) => call("POST", "/password/reset", { change_token: changeToken, new_password: newPassword }),
    verifyEmail: ({ token, email, code }) => call("POST", "/email/verify", { token, email, code }),
    resendVerification: () => call("POST", "/email/verify/send", {}, { auth: true }),
    // --- the signed-in user ---
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
    // Every session of the user ends on the server: the local one is cleared, sign in again.
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
    // --- organizations (B2B pools) ---
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

// The spec's shape: createClient(issuer, clientId, options).
export function createClient(issuer, clientId, options = {}) {
  return createAuth({ ...options, issuer, clientId });
}

export default createAuth;

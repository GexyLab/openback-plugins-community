// Checks an OpenBack user pool against what Shopify needs from a third-party identity provider of the new customer
// accounts (Shopify Plus). Read-only: it loads the pool's discovery document and public keys (and, with a client ID,
// the pool's public configuration). Nothing secret is sent or needed.

// ID token algorithms Shopify lists as supported (Help Center, "Requirements for connecting your own identity provider").
export const SHOPIFY_ID_TOKEN_ALGS = Object.freeze([
  "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES256K", "PS256", "PS384", "PS512", "Ed25519", "EdDSA",
]);
// Shopify needs the token, discovery and userinfo endpoints to answer within 1 second.
export const SHOPIFY_MAX_LATENCY_MS = 1000;

const DEFAULT_TIMEOUT_MS = 10000;
const PRIVATE_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|0\.0\.0\.0|\[.*\])$/i;

/**
 * The pool's issuer without a trailing "/".
 * @param {string} issuer
 * @returns {string}
 */
export function normalizeIssuer(issuer) {
  if (typeof issuer !== "string" || !issuer.trim()) throw new TypeError("issuer is required");
  let url;
  try {
    url = new URL(issuer.trim());
  } catch {
    throw new TypeError("issuer must be an absolute URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new TypeError("issuer must be an http(s) URL");
  if (url.search || url.hash) throw new TypeError("issuer must not have a query or a fragment");
  return url.toString().replace(/\/+$/, "");
}

/**
 * The value of Shopify's "Discovery URL" field for a pool.
 * @param {string} issuer
 * @returns {string}
 */
export function discoveryUrl(issuer) {
  return `${normalizeIssuer(issuer)}/.well-known/openid-configuration`;
}

function list(value) {
  return Array.isArray(value) ? value.map(String) : null;
}

async function getJson(fetchImpl, url, timeoutMs, headers = {}) {
  const started = Date.now();
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { Accept: "application/json", ...headers },
    redirect: "error",
    signal: typeof AbortSignal !== "undefined" && AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined,
  });
  const elapsed = Date.now() - started;
  if (!response.ok) {
    const error = new Error(`HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error("the answer is not JSON");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("the answer is not a JSON object");
  return { body, elapsed };
}

/**
 * @typedef {"pass"|"warn"|"fail"} CheckStatus
 * @typedef {{ id: string, status: CheckStatus, message: string }} CheckResult
 */

/**
 * Loads the pool's discovery document and reports, check by check, whether Shopify can use the pool as the third-party
 * identity provider of the new customer accounts.
 * @param {{ issuer: string, clientId?: string, fetch?: typeof fetch, timeoutMs?: number }} options
 * @returns {Promise<{ issuer: string, discoveryUrl: string, ok: boolean, counts: {pass: number, warn: number, fail: number},
 *   checks: CheckResult[], discovery: object|null }>}
 */
export async function checkPool({ issuer, clientId, fetch: fetchImpl, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const iss = normalizeIssuer(issuer);
  const doFetch = fetchImpl || globalThis.fetch;
  if (typeof doFetch !== "function") throw new TypeError("no fetch implementation: pass options.fetch (Node.js >= 18 has one)");
  const checks = [];
  const add = (id, status, message) => checks.push({ id, status, message });
  const url = new URL(iss);

  // Where Shopify's servers have to reach the pool from.
  if (url.protocol !== "https:") {
    add("https", "fail", "the issuer is not https: Shopify only talks to identity providers over https");
  } else if (PRIVATE_HOST.test(url.hostname)) {
    add("https", "fail", `the issuer's host ${url.hostname} is not reachable from the internet: set the gateway's public address (GATEWAY_PUBLIC_URL)`);
  } else {
    add("https", "pass", "the issuer is a public https address");
  }

  let discovery = null;
  const discovery_url = `${iss}/.well-known/openid-configuration`;
  try {
    const { body, elapsed } = await getJson(doFetch, discovery_url, timeoutMs);
    discovery = body;
    add("discovery", "pass", `discovery document loaded from ${discovery_url}`);
    if (elapsed > SHOPIFY_MAX_LATENCY_MS) {
      add("latency", "warn", `the discovery document took ${elapsed} ms: Shopify needs discovery, token and userinfo to answer within ${SHOPIFY_MAX_LATENCY_MS} ms`);
    } else {
      add("latency", "pass", `the discovery document answered in ${elapsed} ms (Shopify's limit: ${SHOPIFY_MAX_LATENCY_MS} ms)`);
    }
  } catch (error) {
    add("discovery", "fail", `cannot load ${discovery_url}: ${error.message}`);
  }

  if (discovery) {
    checkDiscovery(discovery, iss, add);
    await checkJwks(doFetch, discovery, timeoutMs, add);
    if (clientId) await checkConfig(doFetch, discovery, iss, clientId, timeoutMs, add);
    else add("pool-settings", "warn", "pass the client ID (--client-id) to also check hosted sign-in and email verification");
  }

  const counts = { pass: 0, warn: 0, fail: 0 };
  for (const c of checks) counts[c.status] += 1;
  return { issuer: iss, discoveryUrl: discovery_url, ok: counts.fail === 0, counts, checks, discovery };
}

function checkDiscovery(d, iss, add) {
  if (typeof d.issuer === "string" && d.issuer.replace(/\/+$/, "") === iss) {
    add("issuer", "pass", "the discovery document's issuer matches");
  } else {
    add("issuer", "fail", `the discovery document's issuer (${JSON.stringify(d.issuer)}) differs from ${iss}: ID tokens would be refused`);
  }

  for (const [field, label] of [["authorization_endpoint", "authorization"], ["token_endpoint", "token"], ["jwks_uri", "JWKS"]]) {
    if (typeof d[field] === "string" && d[field].startsWith("https://")) add(`endpoint:${field}`, "pass", `${label} endpoint ${d[field]}`);
    else add(`endpoint:${field}`, "fail", `${field} is missing or not https`);
  }
  if (typeof d.userinfo_endpoint === "string") add("endpoint:userinfo_endpoint", "pass", "userinfo endpoint present (used by Sync customer data)");
  else add("endpoint:userinfo_endpoint", "warn", "no userinfo_endpoint: Shopify's Sync customer data cannot backfill claims");

  const responseTypes = list(d.response_types_supported);
  if (responseTypes && responseTypes.includes("code")) add("response_type", "pass", "response_type code supported");
  else add("response_type", "fail", "response_type code (authorization code flow) is not supported");

  // RFC 8414 default when absent: ["authorization_code", "implicit"].
  const grants = list(d.grant_types_supported) || ["authorization_code", "implicit"];
  if (grants.includes("authorization_code")) add("grant:authorization_code", "pass", "authorization_code grant supported");
  else add("grant:authorization_code", "fail", "the authorization_code grant is not supported");
  if (grants.includes("refresh_token")) add("grant:refresh_token", "pass", "refresh tokens supported (Shopify sessions can last beyond the access token)");
  else add("grant:refresh_token", "warn", "no refresh_token grant: Shopify sessions end when the access token expires");

  // Default when absent: client_secret_basic. Shopify's Help Center names client_secret_basic as the default method while
  // its Okta guide says client_secret_basic "isn't supported for this flow" and asks for client_secret_post.
  const methods = list(d.token_endpoint_auth_methods_supported) || ["client_secret_basic"];
  const post = methods.includes("client_secret_post");
  const basic = methods.includes("client_secret_basic");
  if (post && basic) add("token_auth", "pass", "client_secret_post and client_secret_basic both accepted at the token endpoint");
  else if (post) add("token_auth", "pass", "client_secret_post accepted at the token endpoint (client_secret_basic is not)");
  else if (basic) add("token_auth", "warn", "only client_secret_basic is accepted: Shopify's provider guides ask for client_secret_post");
  else add("token_auth", "fail", "neither client_secret_post nor client_secret_basic is accepted at the token endpoint");

  const prompts = list(d.prompt_values_supported);
  if (prompts && prompts.includes("none")) add("prompt_none", "pass", "prompt=none supported (silent single sign-on)");
  else if (prompts) add("prompt_none", "warn", "prompt=none is not supported: SSO links always show the sign-in page");
  else add("prompt_none", "warn", "prompt_values_supported is not published: cannot confirm silent single sign-on (prompt=none)");

  const claims = list(d.claims_supported);
  if (claims) {
    const missing = ["sub", "email", "email_verified"].filter((c) => !claims.includes(c));
    if (missing.length) add("claims", "fail", `claims_supported lacks ${missing.join(", ")}: Shopify needs sub, email and email_verified=true`);
    else add("claims", "pass", "sub, email and email_verified are supported claims");
    const importable = ["given_name", "family_name", "phone_number", "address"].filter((c) => claims.includes(c));
    if (importable.length) add("claim_import", "pass", `claims Shopify can import: ${importable.join(", ")}`);
    else add("claim_import", "warn", "no given_name, family_name, phone_number or address claims: Shopify's claim import has nothing to import (the email still works)");
  } else {
    add("claims", "warn", "claims_supported is not published: cannot confirm sub, email and email_verified");
  }

  const scopes = list(d.scopes_supported);
  if (scopes) {
    const missing = ["openid", "email"].filter((s) => !scopes.includes(s));
    if (missing.length) add("scopes", "fail", `scopes_supported lacks ${missing.join(", ")} (Shopify always asks for openid email)`);
    else add("scopes", "pass", "openid and email scopes supported");
    const extra = ["offline_access", "profile", "phone", "address"].filter((s) => scopes.includes(s));
    add("additional_scopes", "pass", `scopes usable in Shopify's "Additional scopes": ${extra.length ? extra.join(" ") : "(none)"}`);
  } else {
    add("scopes", "warn", "scopes_supported is not published: cannot confirm the openid and email scopes");
  }

  if (typeof d.end_session_endpoint === "string" && d.end_session_endpoint) {
    add("logout", "pass", `RP-initiated logout at ${d.end_session_endpoint}`);
  } else {
    add("logout", "fail", "no end_session_endpoint: Shopify needs OpenID Connect RP-Initiated Logout");
  }

  const pkce = list(d.code_challenge_methods_supported);
  if (pkce && pkce.includes("S256")) add("pkce", "pass", "PKCE S256 supported (needed by Shopify's mobile apps)");
  else add("pkce", "warn", "PKCE S256 not advertised: Shopify's mobile requirements need code_challenge_method=S256");

  const algs = list(d.id_token_signing_alg_values_supported) || [];
  const usable = algs.filter((a) => SHOPIFY_ID_TOKEN_ALGS.includes(a));
  if (!algs.length) {
    add("id_token_alg", "fail", "id_token_signing_alg_values_supported is missing");
  } else if (!usable.length) {
    add("id_token_alg", "fail", `ID token algorithms ${algs.join(", ")} are not among those Shopify supports (HS256 is refused)`);
  } else if (usable.includes("RS256")) {
    add("id_token_alg", "pass", `ID tokens signed with ${usable.join(", ")}`);
  } else {
    add("id_token_alg", "warn", `ID tokens signed with ${usable.join(", ")} only: listed as supported by Shopify's requirements, but not yet verified on a Plus store (RS256 is the common default)`);
  }
}

async function checkJwks(doFetch, d, timeoutMs, add) {
  if (typeof d.jwks_uri !== "string") return;
  try {
    const { body } = await getJson(doFetch, d.jwks_uri, timeoutMs);
    const keys = Array.isArray(body.keys) ? body.keys : [];
    const signing = keys.filter((k) => k && typeof k === "object" && (!k.use || k.use === "sig"));
    if (!signing.length) {
      add("jwks", "fail", "the JWKS has no signing key");
    } else if (signing.some((k) => k.d || k.p || k.q || k.k)) {
      add("jwks", "fail", "the JWKS publishes private or symmetric key material");
    } else if (!signing.every((k) => typeof k.kid === "string" && k.kid)) {
      add("jwks", "warn", `the JWKS has ${signing.length} signing key(s), some without kid`);
    } else {
      add("jwks", "pass", `the JWKS has ${signing.length} signing key(s) (${[...new Set(signing.map((k) => k.alg || k.kty))].join(", ")})`);
    }
  } catch (error) {
    add("jwks", "fail", `cannot load the JWKS ${d.jwks_uri}: ${error.message}`);
  }
}

async function checkConfig(doFetch, d, iss, clientId, timeoutMs, add) {
  const api = (d.x_openback && typeof d.x_openback.api === "string" && d.x_openback.api) || `${iss}/api/v1`;
  let config;
  try {
    ({ body: config } = await getJson(doFetch, `${api.replace(/\/+$/, "")}/config`, timeoutMs, { "X-Client-Id": clientId }));
  } catch (error) {
    add("pool-settings", "warn", `cannot read the pool's configuration with client ID ${clientId}: ${error.message}`);
    return;
  }
  if (config.hosted_login === false) {
    add("hosted_login", "fail", "hosted sign-in is off: Shopify signs customers in on the pool's hosted page, and silent SSO needs its browser session");
  } else {
    add("hosted_login", "pass", "hosted sign-in is on");
  }
  const signup = config.signup || {};
  if (signup.require_email_verification === false) {
    add("email_verification", "warn", "sign-up does not require email verification: customers with an unverified email are refused by Shopify (email_verified must be true)");
  } else {
    add("email_verification", "pass", "sign-up requires email verification (email_verified is true after sign-up)");
  }
  const methods = config.methods || {};
  if (methods.anonymous) {
    add("anonymous", "warn", "guest (anonymous) accounts are on: they have no email and cannot sign in to Shopify until upgraded and verified");
  }
  if (config.mode === "b2b") {
    add("mode", "warn", "B2B pool: customers in several organizations are asked to choose one during sign-in, also on silent SSO");
  }
  if (config.mfa === "required") {
    add("mfa", "warn", "two-step verification is required: customers complete it on the pool's page during the Shopify sign-in");
  }
}

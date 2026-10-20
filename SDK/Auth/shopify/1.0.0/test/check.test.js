import assert from "node:assert/strict";
import { test } from "node:test";

import { checkPool, discoveryUrl, normalizeIssuer } from "../src/index.js";
import { CLIENT_ID, ISSUER, es256Jwk, mockFetch, poolConfig, poolDiscovery, poolRoutes } from "./helpers.js";

const status = (report, id) => report.checks.find((c) => c.id === id)?.status;

test("normalizeIssuer and discoveryUrl", () => {
  assert.equal(normalizeIssuer(`${ISSUER}/`), ISSUER);
  assert.equal(discoveryUrl(`${ISSUER}//`), `${ISSUER}/.well-known/openid-configuration`);
  assert.throws(() => normalizeIssuer("not a url"), TypeError);
  assert.throws(() => normalizeIssuer("ftp://x.example/y"), TypeError);
  assert.throws(() => normalizeIssuer(`${ISSUER}?x=1`), TypeError);
  assert.throws(() => normalizeIssuer(""), TypeError);
});

test("an OpenBack pool passes every hard requirement (ES256 is a warning only)", async () => {
  const fetch = mockFetch(poolRoutes());
  const report = await checkPool({ issuer: `${ISSUER}/`, clientId: CLIENT_ID, fetch });
  assert.equal(report.ok, true, JSON.stringify(report.checks, null, 2));
  assert.equal(report.issuer, ISSUER);
  assert.equal(report.discoveryUrl, `${ISSUER}/.well-known/openid-configuration`);
  assert.equal(report.counts.fail, 0);
  for (const id of ["https", "discovery", "issuer", "endpoint:token_endpoint", "response_type", "grant:authorization_code",
    "grant:refresh_token", "token_auth", "prompt_none", "claims", "scopes", "logout", "pkce", "jwks", "hosted_login", "email_verification"]) {
    assert.equal(status(report, id), "pass", id);
  }
  assert.equal(status(report, "id_token_alg"), "warn");
  assert.match(report.checks.find((c) => c.id === "id_token_alg").message, /ES256/);
  // The pool has no given_name / family_name / phone_number / address claims: nothing for Shopify's claim import.
  assert.equal(status(report, "claim_import"), "warn");
  // The config call carries the client ID, never a secret.
  const configCall = fetch.calls.find((c) => c.url.endsWith("/api/v1/config"));
  assert.equal(configCall.init.headers["X-Client-Id"], CLIENT_ID);
  assert.ok(!fetch.calls.some((c) => JSON.stringify(c.init).includes("secret")));
});

test("without a client ID the pool settings are not checked (warning)", async () => {
  const fetch = mockFetch(poolRoutes());
  const report = await checkPool({ issuer: ISSUER, fetch });
  assert.equal(report.ok, true);
  assert.equal(status(report, "pool-settings"), "warn");
  assert.equal(status(report, "hosted_login"), undefined);
  assert.ok(!fetch.calls.some((c) => c.url.endsWith("/config")));
});

test("token endpoint auth: post only passes, basic only warns, none fails", async () => {
  const cases = [
    [["client_secret_post"], "pass"],
    [["client_secret_basic"], "warn"],
    [["none"], "fail"],
    [undefined, "warn"], // RFC 8414 default: client_secret_basic
  ];
  for (const [methods, expected] of cases) {
    const discovery = { ...poolDiscovery(), token_endpoint_auth_methods_supported: methods };
    const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(poolRoutes({ discovery })) });
    assert.equal(status(report, "token_auth"), expected, JSON.stringify(methods));
  }
});

test("missing email / email_verified claims, end_session_endpoint or authorization_code fail", async () => {
  const d = poolDiscovery();
  const broken = {
    ...d,
    claims_supported: ["sub", "email"],
    end_session_endpoint: undefined,
    grant_types_supported: ["client_credentials"],
    scopes_supported: ["openid"],
    response_types_supported: ["token"],
  };
  const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(poolRoutes({ discovery: broken })) });
  assert.equal(report.ok, false);
  for (const id of ["claims", "logout", "grant:authorization_code", "scopes", "response_type"]) assert.equal(status(report, id), "fail", id);
  assert.equal(status(report, "grant:refresh_token"), "warn");
});

test("prompt=none: absent list warns, list without none warns", async () => {
  for (const prompts of [undefined, ["login"]]) {
    const discovery = { ...poolDiscovery(), prompt_values_supported: prompts };
    const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(poolRoutes({ discovery })) });
    assert.equal(status(report, "prompt_none"), "warn");
  }
});

test("ID token algorithms: RS256 passes, HS256 fails, missing fails", async () => {
  for (const [algs, expected] of [[["RS256", "ES256"], "pass"], [["HS256"], "fail"], [undefined, "fail"], [["ES256"], "warn"]]) {
    const discovery = { ...poolDiscovery(), id_token_signing_alg_values_supported: algs };
    const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(poolRoutes({ discovery })) });
    assert.equal(status(report, "id_token_alg"), expected, JSON.stringify(algs));
  }
});

test("issuer mismatch fails (GATEWAY_PUBLIC_URL not set)", async () => {
  const discovery = poolDiscovery("http://users-service:8016/gateway/shop/auth/main");
  const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(poolRoutes({ discovery })) });
  assert.equal(status(report, "issuer"), "fail");
  assert.equal(report.ok, false);
});

test("http, localhost and private issuers fail the reachability check", async () => {
  for (const issuer of ["http://api.example.com/gateway/shop/auth/main", "https://localhost/gateway/shop/auth/main",
    "https://192.168.1.10/gateway/shop/auth/main", "https://10.0.0.5/x"]) {
    const report = await checkPool({ issuer, fetch: mockFetch(poolRoutes({ issuer })) });
    assert.equal(status(report, "https"), "fail", issuer);
  }
});

test("discovery not reachable, not JSON or HTTP error fails and stops", async () => {
  const url = `${ISSUER}/.well-known/openid-configuration`;
  for (const route of [new TypeError("fetch failed"), () => new Response("<html>", { status: 200 }), () => new Response("{}", { status: 503 })]) {
    const report = await checkPool({ issuer: ISSUER, fetch: mockFetch({ [url]: route }) });
    assert.equal(status(report, "discovery"), "fail");
    assert.equal(report.ok, false);
    assert.equal(report.discovery, null);
    assert.equal(report.checks.length, 2); // https + discovery
  }
});

test("slow discovery warns about Shopify's 1 second limit", async () => {
  const routes = poolRoutes();
  const url = `${ISSUER}/.well-known/openid-configuration`;
  const body = routes[url];
  routes[url] = async () => {
    await new Promise((resolve) => setTimeout(resolve, 1100));
    return new Response(JSON.stringify(body), { status: 200 });
  };
  const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(routes) });
  assert.equal(status(report, "latency"), "warn");
});

test("JWKS problems: no keys, private material, unreachable", async () => {
  const leaked = { ...es256Jwk(), d: "secret-part" };
  for (const jwks of [{ keys: [] }, { keys: [leaked] }, () => new Response("nope", { status: 500 })]) {
    const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(poolRoutes({ jwks })) });
    assert.equal(status(report, "jwks"), "fail");
  }
  const noKid = { ...es256Jwk() };
  delete noKid.kid;
  const report = await checkPool({ issuer: ISSUER, fetch: mockFetch(poolRoutes({ jwks: { keys: [noKid] } })) });
  assert.equal(status(report, "jwks"), "warn");
});

test("pool settings: hosted sign-in off fails; no verification, guests, B2B and required MFA warn", async () => {
  const config = poolConfig({
    hosted_login: false,
    signup: { enabled: true, require_email_verification: false },
    methods: { password: true, anonymous: true },
    mode: "b2b",
    mfa: "required",
  });
  const report = await checkPool({ issuer: ISSUER, clientId: CLIENT_ID, fetch: mockFetch(poolRoutes({ config })) });
  assert.equal(status(report, "hosted_login"), "fail");
  assert.equal(report.ok, false);
  for (const id of ["email_verification", "anonymous", "mode", "mfa"]) assert.equal(status(report, id), "warn", id);
});

test("an unknown client ID only warns", async () => {
  const routes = poolRoutes();
  routes[`${ISSUER}/api/v1/config`] = () => new Response(JSON.stringify({ detail: { code: "unknown_client" } }), { status: 401 });
  const report = await checkPool({ issuer: ISSUER, clientId: "uapp_wrong", fetch: mockFetch(routes) });
  assert.equal(status(report, "pool-settings"), "warn");
  assert.equal(report.ok, true);
});

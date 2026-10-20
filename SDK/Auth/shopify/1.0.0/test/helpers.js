// Test helpers: a fake OpenBack pool served through a mocked fetch (no network).
import { generateKeyPairSync, randomBytes } from "node:crypto";

export const ISSUER = "https://api.example.com/gateway/shop/auth/main";
export const CLIENT_ID = "uapp_test0000000000000000";

/** A real ES256 (P-256) public JWK, generated per test run, as the pool publishes it. */
export function es256Jwk() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  return { ...jwk, kid: randomBytes(8).toString("hex"), alg: "ES256", use: "sig" };
}

/** The discovery document of users-service (routes/oidc_routes.py). */
export function poolDiscovery(issuer = ISSUER) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    revocation_endpoint: `${issuer}/revoke`,
    end_session_endpoint: `${issuer}/logout`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    prompt_values_supported: ["none", "login"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name", "picture",
      "org_id", "roles", "amr", "sid"],
    authorization_response_iss_parameter_supported: true,
    ui_locales_supported: ["it", "en"],
    x_openback: { pool: "upool_test", mode: "b2c", api: `${issuer}/api/v1` },
  };
}

export function poolConfig(overrides = {}) {
  return {
    issuer: ISSUER,
    mode: "b2c",
    methods: { password: true, email_code: false, anonymous: false },
    signup: { enabled: true, require_email_verification: true },
    hosted_login: true,
    password_policy: { min_length: 10 },
    mfa: "optional",
    orgs: { self_service: false },
    providers: [],
    branding: {},
    ...overrides,
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/**
 * A mocked fetch serving routes { url: body | (request) => Response | body }; records the calls.
 * Unknown URLs answer 404. A route value of Error rejects (network error).
 */
export function mockFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const route = routes[String(url)];
    if (route === undefined) return jsonResponse({ detail: "not found" }, 404);
    if (route instanceof Error) throw route;
    const value = typeof route === "function" ? await route(String(url), init) : route;
    return value instanceof Response ? value : jsonResponse(value);
  };
  fn.calls = calls;
  return fn;
}

export function poolRoutes({ issuer = ISSUER, discovery, jwks, config } = {}) {
  return {
    [`${issuer}/.well-known/openid-configuration`]: discovery ?? poolDiscovery(issuer),
    [`${issuer}/.well-known/jwks.json`]: jwks ?? { keys: [es256Jwk()] },
    [`${issuer}/api/v1/config`]: config ?? poolConfig(),
  };
}

/** A writable stream stand-in that collects the text. */
export function sink() {
  const out = { text: "", write(chunk) { out.text += chunk; return true; } };
  return out;
}

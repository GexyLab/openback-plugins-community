// OpenID Connect for confidential "web" apps (a server with a client secret): authorization code + PKCE S256.
//
//   const oidc = new OidcWebClient({ issuer, clientId, clientSecret, redirectUri });
//   const { url, transaction } = await oidc.authorizationUrl();   // keep `transaction` in the user's server session
//   // ... redirect to url; on the redirect URI:
//   const tokens = await oidc.handleCallback(req.query, transaction);   // tokens.idTokenClaims: verified
import { AuthError, normalizeIssuer, randomString, sha256b64url, safeEqual, readJson, errorFromResponse, networkError, basicAuthorization, paramsOf } from "./util.js";
import { TokenVerifier, TokenVerificationError } from "./verifier.js";

const DEFAULT_SCOPE = "openid profile email";

function tokenResult(data, idTokenClaims, now) {
  const expiresIn = Number(data.expires_in) || 0;
  return {
    accessToken: data.access_token,
    tokenType: data.token_type || "Bearer",
    expiresIn,
    expiresAt: now + expiresIn * 1000,
    scope: data.scope || "",
    refreshToken: data.refresh_token || null,
    refreshExpiresIn: data.refresh_expires_in ?? null,
    idToken: data.id_token || null,
    idTokenClaims: idTokenClaims || null,
    org: data.org || null,
    raw: data,
  };
}

export class OidcWebClient {
  /**
   * @param {object} options
   * @param {string} options.issuer
   * @param {string} options.clientId
   * @param {string} [options.clientSecret]   required for client_secret_basic / client_secret_post
   * @param {string} [options.redirectUri]    default redirect URI (registered in the pool)
   * @param {string} [options.postLogoutRedirectUri]
   * @param {string} [options.scope="openid profile email"]  add "offline_access" if you like; refresh tokens are always issued
   * @param {"client_secret_basic"|"client_secret_post"|"none"} [options.tokenEndpointAuthMethod="client_secret_basic"]
   * @param {TokenVerifier} [options.verifier]  verifies ID tokens (default: one for this issuer and client ID)
   * @param {typeof fetch} [options.fetch]
   */
  constructor(options = {}) {
    this.issuer = normalizeIssuer(options.issuer);
    this.clientId = options.clientId;
    if (!this.clientId) throw new TypeError("OidcWebClient: clientId is required");
    this.clientSecret = options.clientSecret || null;
    this.redirectUri = options.redirectUri || null;
    this.postLogoutRedirectUri = options.postLogoutRedirectUri || null;
    this.scope = options.scope || DEFAULT_SCOPE;
    this.authMethod = options.tokenEndpointAuthMethod || (this.clientSecret ? "client_secret_basic" : "none");
    if (!["client_secret_basic", "client_secret_post", "none"].includes(this.authMethod)) {
      throw new TypeError("OidcWebClient: tokenEndpointAuthMethod must be client_secret_basic, client_secret_post or none");
    }
    if (this.authMethod !== "none" && !this.clientSecret) throw new TypeError(`OidcWebClient: ${this.authMethod} needs clientSecret`);
    this._fetch = options.fetch || ((input, init) => globalThis.fetch(input, init));
    this._now = options.now || Date.now;
    this.verifier = options.verifier || new TokenVerifier({ issuer: this.issuer, clientIds: [this.clientId], fetch: options.fetch,
      leeway: options.leeway, now: options.now });
  }

  /**
   * The address of the hosted sign-in page and the transaction to keep (server-side session) until the callback.
   * Options: redirectUri, scope, provider, orgId, prompt ("none"|"login"), screenHint ("signup"), loginHint, maxAge, uiLocales.
   */
  async authorizationUrl(p = {}) {
    const redirectUri = p.redirectUri || this.redirectUri;
    if (!redirectUri) throw new TypeError("authorizationUrl: redirectUri is required");
    const scope = p.scope || this.scope;
    const transaction = { state: randomString(32), nonce: randomString(32), codeVerifier: randomString(48), redirectUri, scope,
      createdAt: this._now() };
    const params = new URLSearchParams({ response_type: "code", client_id: this.clientId, redirect_uri: redirectUri, scope,
      state: transaction.state, nonce: transaction.nonce, code_challenge: sha256b64url(transaction.codeVerifier), code_challenge_method: "S256" });
    if (p.provider) params.set("provider", p.provider);
    if (p.orgId) params.set("org_id", p.orgId);
    if (p.prompt) params.set("prompt", p.prompt);
    if (p.screenHint) params.set("screen_hint", p.screenHint);
    if (p.loginHint) params.set("login_hint", p.loginHint);
    if (p.maxAge !== undefined && p.maxAge !== null) params.set("max_age", String(p.maxAge));
    if (p.uiLocales) params.set("ui_locales", p.uiLocales);
    return { url: this.issuer + "/authorize?" + params, transaction };
  }

  /**
   * The redirect back from the hosted page. `params`: req.query, URLSearchParams, the full callback URL or its query.
   * Checks error, state (constant time), iss (RFC 9207); exchanges the code (PKCE); verifies the ID token (signature,
   * iss, aud, exp, nonce, at_hash). Resolves to the tokens; throws AuthError (or TokenVerificationError for the ID token).
   */
  async handleCallback(params, transaction) {
    const q = paramsOf(params);
    const error = q.get("error");
    if (error) throw new AuthError(400, error, q.get("error_description") || error);
    if (!transaction || typeof transaction !== "object" || !transaction.state) {
      throw new AuthError(400, "missing_transaction", "No sign-in in progress for this callback");
    }
    if (!safeEqual(String(transaction.state), q.get("state") || "")) throw new AuthError(400, "invalid_state", "Sign-in state mismatch");
    const iss = q.get("iss");
    if (iss !== null && iss !== this.issuer) throw new AuthError(400, "invalid_issuer", "Unexpected issuer in the callback");
    const code = q.get("code");
    if (!code) throw new AuthError(400, "invalid_request", "The callback has no code");
    const data = await this._token({ grant_type: "authorization_code", code, redirect_uri: transaction.redirectUri,
      client_id: this.clientId, code_verifier: transaction.codeVerifier });
    const wantsIdToken = String(transaction.scope || this.scope).split(/\s+/).includes("openid");
    let claims = null;
    if (data.id_token) {
      claims = await this.verifier.verifyIdToken(data.id_token, { nonce: transaction.nonce, clientId: this.clientId, accessToken: data.access_token });
    } else if (wantsIdToken) {
      throw new TokenVerificationError("invalid_token", "The token endpoint answered without an ID token");
    }
    return tokenResult(data, claims, this._now());
  }

  /** New tokens from a refresh token (rotated: store the new refresh token, the old one is now invalid). No ID token. */
  async refresh(refreshToken, { orgId } = {}) {
    if (!refreshToken) throw new TypeError("refresh: refreshToken is required");
    const form = { grant_type: "refresh_token", refresh_token: refreshToken, client_id: this.clientId };
    if (orgId) form.org_id = orgId;
    return tokenResult(await this._token(form), null, this._now());
  }

  /** Revokes a refresh token (RFC 7009) and so the session it belongs to. */
  async revoke(refreshToken) {
    if (!refreshToken) return;
    const res = await this._post("/revoke", { token: refreshToken, token_type_hint: "refresh_token", client_id: this.clientId });
    if (!res.ok) throw errorFromResponse(res, await readJson(res));
  }

  /** The OIDC userinfo of an access token. */
  async userinfo(accessToken) {
    let res;
    try {
      res = await this._fetch(this.issuer + "/userinfo", { headers: { Authorization: "Bearer " + accessToken, Accept: "application/json" } });
    } catch (e) {
      throw networkError(e);
    }
    const data = await readJson(res);
    if (!res.ok) throw errorFromResponse(res, data);
    return data;
  }

  /** The hosted logout address: ends the hosted page's session and redirects to a registered post-logout URI. */
  logoutUrl({ idTokenHint, postLogoutRedirectUri, state } = {}) {
    const params = new URLSearchParams({ client_id: this.clientId });
    if (idTokenHint) params.set("id_token_hint", idTokenHint);
    const target = postLogoutRedirectUri || this.postLogoutRedirectUri;
    if (target) params.set("post_logout_redirect_uri", target);
    if (state) params.set("state", state);
    return this.issuer + "/logout?" + params;
  }

  async _post(path, form) {
    const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    const body = new URLSearchParams(form);
    if (this.authMethod === "client_secret_basic") headers.Authorization = basicAuthorization(this.clientId, this.clientSecret);
    else if (this.authMethod === "client_secret_post") body.set("client_secret", this.clientSecret);
    try {
      return await this._fetch(this.issuer + path, { method: "POST", headers, body });
    } catch (e) {
      throw networkError(e);
    }
  }

  async _token(form) {
    const res = await this._post("/token", form);
    const data = await readJson(res);
    if (!res.ok) throw errorFromResponse(res, data);
    if (!data || !data.access_token) throw new AuthError(res.status, "invalid_response", "The token endpoint answered without a token");
    return data;
  }
}

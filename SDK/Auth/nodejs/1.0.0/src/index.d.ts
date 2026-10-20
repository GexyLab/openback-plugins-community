// Types of openback-app-auth-nodejs 1.0.0.
import type { IncomingMessage, ServerResponse, IncomingHttpHeaders } from "node:http";

export declare const VERSION: string;

// --- data of the pool --------------------------------------------------------------------------------------------------

export interface PoolUser {
  id: string;
  email: string | null;
  email_verified: boolean;
  display_name: string;
  photo_url: string;
  locale: "it" | "en" | null;
  attributes: Record<string, unknown>;
  anonymous: boolean;
  created_at: string;
  last_login_at: string | null;
  mfa: { totp: boolean };
}

export interface MeUser extends PoolUser {
  org_id: string | null;
  roles: string[];
  providers: { provider_id: string; kind: string }[];
  has_password: boolean;
}

export interface ActiveOrg {
  id: string;
  name: string;
  roles: string[];
  choices: number;
}

export interface OkOutcome {
  status: "ok";
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user: PoolUser;
  org: ActiveOrg | null;
  id_token?: string;
  [extra: string]: unknown;
}

export type Outcome =
  | OkOutcome
  | { status: "verification_required"; [extra: string]: unknown }
  | { status: "mfa_required"; mfa_token: string; [extra: string]: unknown }
  | { status: "mfa_enroll_required"; mfa_token: string; [extra: string]: unknown }
  | { status: "password_change_required"; change_token: string; [extra: string]: unknown };

/** Access token claims (JWT, ES256, typ at+jwt). */
export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  azp?: string;
  exp: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  sid?: string;
  pool?: string;
  sv?: number;
  org_id?: string | null;
  roles?: string[];
  permissions?: string[];
  email?: string | null;
  email_verified?: boolean;
  amr?: string[];
  scope?: string;
  anon?: boolean;
  attr?: Record<string, unknown>;
  [claim: string]: unknown;
}

/** ID token claims (JWT, ES256, typ JWT). */
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  azp?: string;
  exp: number;
  iat?: number;
  auth_time?: number;
  sid?: string;
  pool?: string;
  email?: string | null;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  org_id?: string | null;
  roles?: string[];
  amr?: string[];
  at_hash?: string;
  nonce?: string;
  [claim: string]: unknown;
}

// --- errors ------------------------------------------------------------------------------------------------------------

/** An error of the pool (status + code; `network_error` with status 0) or of a client-side check. */
export declare class AuthError extends Error {
  constructor(status: number, code: string, message?: string, detail?: unknown, options?: { cause?: unknown });
  readonly name: "AuthError";
  status: number;
  code: string;
  detail: unknown;
}

export type TokenVerificationCode =
  | "invalid_token" | "alg_not_allowed" | "invalid_typ" | "unknown_kid" | "invalid_signature" | "invalid_issuer"
  | "invalid_audience" | "token_expired" | "token_not_yet_valid" | "invalid_claims" | "invalid_nonce" | "invalid_at_hash"
  | "jwks_unavailable";

/** Why a token was refused: status 401, or 503 for jwks_unavailable. */
export declare class TokenVerificationError extends Error {
  constructor(code: TokenVerificationCode, message?: string, options?: { cause?: unknown });
  readonly name: "TokenVerificationError";
  code: TokenVerificationCode;
  status: 401 | 503;
}

// --- token verification ------------------------------------------------------------------------------------------------

export declare class AppUser {
  constructor(claims: AccessTokenClaims, clientId?: string | null);
  /** sub (usr_...). */
  id: string;
  poolId: string | null;
  /** The aud the token was issued for. */
  clientId: string | null;
  email: string | null;
  emailVerified: boolean;
  /** Guest account (anon claim). */
  anonymous: boolean;
  orgId: string | null;
  roles: string[];
  permissions: string[];
  attributes: Record<string, unknown>;
  sessionId: string | null;
  amr: string[];
  scope: string;
  expiresAt: Date | null;
  /** The raw verified claims. */
  claims: AccessTokenClaims;
  hasRole(role: string): boolean;
  /** True when permissions contains it or "*". */
  hasPermission(permission: string): boolean;
}

export interface TokenVerifierOptions {
  /** The pool's address (a trailing slash is removed); tokens' iss must match it exactly. */
  issuer: string;
  /** Accepted audiences (client IDs). `clientId` and `audience` are aliases. */
  clientIds?: string | string[];
  clientId?: string;
  audience?: string | string[];
  /** Default <issuer>/.well-known/jwks.json. */
  jwksUri?: string;
  /** Clock tolerance in seconds for exp / nbf / iat (default 60). */
  leeway?: number;
  /** Seconds the keys are cached (default 600). */
  jwksCacheTtl?: number;
  /** Minimum seconds between two refetches for an unknown kid, and between retries of a failed fetch (default 30). */
  jwksRefetchInterval?: number;
  fetch?: typeof fetch;
  /** Current time in milliseconds (tests). */
  now?: () => number;
}

export declare class TokenVerifier {
  constructor(options: TokenVerifierOptions);
  readonly issuer: string;
  readonly clientIds: string[];
  readonly jwksUri: string;
  /** Verifies an access token locally (no call to OpenBack). */
  verify(token: string): Promise<AppUser>;
  verifyAccessToken(token: string): Promise<AppUser>;
  /** Verifies an ID token: typ JWT, nonce (constant time), azp, at_hash when accessToken is given. */
  verifyIdToken(token: string, options?: { nonce?: string; clientId?: string; accessToken?: string }): Promise<IdTokenClaims>;
}

// --- middleware --------------------------------------------------------------------------------------------------------

export interface RequireAppUserOptions extends Partial<TokenVerifierOptions> {
  /** A shared verifier; otherwise one is built from issuer + clientIds. */
  verifier?: TokenVerifier;
  /** The user needs at least one of these roles. */
  requireRoles?: string[];
  /** The user needs all of these permissions ("*" grants all). */
  requirePermissions?: string[];
  /** Default false. */
  requireVerifiedEmail?: boolean;
  /** Default false: guest tokens (anon: true) are refused with 403. */
  allowAnonymous?: boolean;
  /** Request property the user is attached to (default "appUser"). */
  property?: string;
}

export type AuthenticateResult =
  | { ok: true; user: AppUser }
  | { ok: false; status: 401 | 403 | 503; headers: Record<string, string>; body: { error: "invalid_token" | "insufficient_scope" | "temporarily_unavailable" }; error: Error | null };

export declare function createAppUserAuthenticator(options: RequireAppUserOptions):
  (headers: IncomingHttpHeaders | Headers | Record<string, string | string[] | undefined>) => Promise<AuthenticateResult>;

/** Express / Connect middleware (also node:http with a next callback). Sets req.appUser. */
export declare function requireAppUser(options: RequireAppUserOptions):
  (req: IncomingMessage & { [key: string]: any }, res: ServerResponse, next?: (err?: unknown) => void) => void;

/** node:http guard: resolves to the AppUser, or null after answering 401/403/503. */
export declare function requireAppUserHttp(options: RequireAppUserOptions):
  (req: IncomingMessage & { [key: string]: any }, res: ServerResponse) => Promise<AppUser | null>;

/** Fastify preHandler. Sets request.appUser. */
export declare function fastifyRequireAppUser(options: RequireAppUserOptions):
  (request: { headers: IncomingHttpHeaders; [key: string]: any }, reply: any) => Promise<unknown>;

/** Fastify plugin: decorates `fastify.requireAppUser(opts)` and `request.appUser`; `global: true` guards every route. */
export declare function fastifyAppUser(fastify: any, options: RequireAppUserOptions & { global?: boolean }, done: (err?: Error) => void): void;

// --- OIDC for web apps -------------------------------------------------------------------------------------------------

export interface OidcWebClientOptions {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  postLogoutRedirectUri?: string;
  /** Default "openid profile email". */
  scope?: string;
  /** Default client_secret_basic (none when there is no secret). */
  tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post" | "none";
  /** Verifies the ID tokens (default: one for this issuer and client ID). */
  verifier?: TokenVerifier;
  leeway?: number;
  fetch?: typeof fetch;
  now?: () => number;
}

export interface AuthorizationOptions {
  redirectUri?: string;
  scope?: string;
  provider?: string;
  orgId?: string;
  prompt?: "none" | "login";
  screenHint?: "signup";
  loginHint?: string;
  maxAge?: number;
  uiLocales?: string;
}

/** Keep it in the user's server-side session between authorizationUrl() and handleCallback(). */
export interface OidcTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  scope: string;
  createdAt: number;
}

export interface TokenResult {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  /** Epoch milliseconds. */
  expiresAt: number;
  scope: string;
  /** Rotated at every use: always store the new one. */
  refreshToken: string | null;
  refreshExpiresIn: number | null;
  idToken: string | null;
  /** Verified claims of the ID token (callback only). */
  idTokenClaims: IdTokenClaims | null;
  org: ActiveOrg | null;
  raw: Record<string, unknown>;
}

export type CallbackParams = URLSearchParams | URL | string | Record<string, string | string[] | undefined>;

export declare class OidcWebClient {
  constructor(options: OidcWebClientOptions);
  readonly issuer: string;
  readonly clientId: string;
  readonly verifier: TokenVerifier;
  authorizationUrl(options?: AuthorizationOptions): Promise<{ url: string; transaction: OidcTransaction }>;
  handleCallback(params: CallbackParams, transaction: OidcTransaction): Promise<TokenResult>;
  refresh(refreshToken: string, options?: { orgId?: string }): Promise<TokenResult>;
  revoke(refreshToken: string): Promise<void>;
  userinfo(accessToken: string): Promise<{ sub: string; email?: string | null; email_verified?: boolean; name?: string; picture?: string; locale?: string; org_id: string | null; roles: string[]; attributes: Record<string, unknown> }>;
  logoutUrl(options?: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string }): string;
}

// --- the pool's client -------------------------------------------------------------------------------------------------

/** A storage of strings by key; synchronous or asynchronous (file, database, server-side session). */
export interface AuthStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export interface AuthOptions {
  issuer: string;
  clientId: string;
  /** Sent with HTTP Basic to <issuer>/token by handleRedirectCallback (web/backend apps only). */
  clientSecret?: string;
  redirectUri?: string;
  /** Default: in memory. */
  storage?: AuthStorage;
  /** Default `openback.auth.<clientId>`. */
  storageKey?: string;
  /** Default: `storage` (key `<storageKey>.transaction`). */
  transactionStorage?: AuthStorage;
  fetch?: typeof fetch;
}

export interface AuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
}

export interface Auth {
  readonly currentUser: PoolUser | MeUser | null;
  readonly currentOrg: ActiveOrg | null;
  readonly accessTokenClaims: Record<string, any> | null;
  readonly isSignedIn: boolean;
  readonly idToken: string | null;
  readonly issuer: string;
  readonly clientId: string;
  readonly ready: Promise<void>;
  config(): Promise<Record<string, any>>;
  onAuthStateChanged(listener: (user: PoolUser | MeUser | null, org: ActiveOrg | null) => void): () => void;
  getAccessToken(): Promise<string>;
  refresh(orgId?: string): Promise<string>;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  signUp(p: { email: string; password: string; displayName?: string; locale?: "it" | "en"; orgId?: string }): Promise<Outcome>;
  signInWithPassword(p: { email: string; password: string; orgId?: string }): Promise<Outcome>;
  sendEmailCode(email: string): Promise<{ status: "sent" }>;
  signInWithEmailCode(p: { email?: string; code?: string; token?: string; orgId?: string }): Promise<Outcome>;
  signInAnonymously(): Promise<Outcome>;
  verifyMfa(p: { mfaToken: string; code: string }): Promise<Outcome>;
  enrollMfa(mfaToken?: string): Promise<{ secret: string; otpauth_uri: string }>;
  confirmMfa(code: string, mfaToken?: string): Promise<{ recovery_codes: string[] } & Partial<Outcome>>;
  disableMfa(code: string): Promise<{ status: "disabled" }>;
  buildAuthorizationRequest(p?: AuthorizationOptions): Promise<AuthorizationRequest>;
  /** url: the callback URL (or its query). Resolves to null when it is not a callback. */
  handleRedirectCallback(url: string | URL | URLSearchParams, transaction?: AuthorizationRequest): Promise<MeUser | null>;
  buildLogoutUrl(options?: { postLogoutRedirectUri?: string; state?: string }): string;
  buildLogoutUrl(postLogoutRedirectUri?: string, state?: string): string;
  sendPasswordReset(email: string): Promise<{ status: "sent" }>;
  resetPassword(p: { token?: string; email?: string; code?: string; newPassword: string }): Promise<{ status: "password_changed" }>;
  changeForcedPassword(p: { changeToken: string; newPassword: string }): Promise<{ status: "password_changed" }>;
  verifyEmail(p: { token?: string; email?: string; code?: string }): Promise<{ status: "verified"; user: PoolUser }>;
  resendVerification(): Promise<{ status: "sent" }>;
  me(): Promise<MeUser>;
  updateProfile(fields: { displayName?: string; photoUrl?: string; locale?: "it" | "en"; display_name?: string; photo_url?: string }): Promise<PoolUser>;
  changePassword(p: { currentPassword?: string; newPassword: string }): Promise<unknown>;
  changeEmail(newEmail: string): Promise<{ status: "verification_sent" }>;
  confirmEmailChange(p: { code?: string; token?: string }): Promise<{ status: "email_changed"; user: PoolUser }>;
  upgradeAnonymous(p: { email: string; password: string }): Promise<{ status: "upgraded"; user: PoolUser }>;
  deleteAccount(password?: string): Promise<{ status: "deleted" }>;
  signOut(p?: { everywhere?: boolean }): Promise<void>;
  organizations(): Promise<{ orgs: { id: string; name: string; roles: string[]; disabled: boolean }[]; active: string | null }>;
  createOrganization(name: string): Promise<{ id: string; name: string; roles: string[] }>;
  switchOrganization(orgId: string): Promise<ActiveOrg | null>;
  members(orgId: string, p?: { q?: string; skip?: number; limit?: number }): Promise<{
    items: { user_id: string; email: string | null; display_name: string; disabled: boolean; roles: string[]; created_at: string }[];
    total?: number;
    roles: { key: string; label: string }[];
  }>;
  addMember(orgId: string, p: { email: string; displayName?: string; password?: string; roles?: string[] }): Promise<any>;
  setMemberRoles(orgId: string, userId: string, roles: string[]): Promise<any>;
  removeMember(orgId: string, userId: string): Promise<any>;
}

export declare function createAuth(options: AuthOptions): Auth;
export declare function createClient(issuer: string, clientId: string, options?: Omit<AuthOptions, "issuer" | "clientId">): Auth;
export declare function memoryStorage(): AuthStorage;
/** Decodes a JWT's claims without verifying it. */
export declare function decodeJwt(token: string): Record<string, any> | null;
export default createAuth;

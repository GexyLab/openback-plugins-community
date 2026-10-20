// Types of openback-app-auth-javascript 1.0.0 (src/index.js).

export declare const VERSION: string;

/** A user of the pool, as the JSON API returns it. */
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

/** GET /me: the user plus the active organization, roles and linked providers. */
export interface MeUser extends PoolUser {
  org_id: string | null;
  roles: string[];
  providers: { provider_id: string; kind: string }[];
  has_password: boolean;
}

/** The organization the tokens are issued for (B2B pools; null in B2C). */
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

/** The answer of every sign-up / sign-in call. The session is kept only on "ok". */
export type Outcome =
  | OkOutcome
  | { status: "verification_required"; [extra: string]: unknown }
  | { status: "mfa_required"; mfa_token: string; [extra: string]: unknown }
  | { status: "mfa_enroll_required"; mfa_token: string; [extra: string]: unknown }
  | { status: "password_change_required"; change_token: string; [extra: string]: unknown };

/** Tokens answered by POST /token/refresh and POST /orgs/switch. */
export interface TokenSet {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  refresh_token: string;
  refresh_expires_in: number;
  org?: ActiveOrg | null;
}

/** GET /config: what the pool offers. */
export interface PoolConfig {
  issuer: string;
  mode: "b2c" | "b2b";
  methods: Record<string, unknown>;
  signup: unknown;
  hosted_login: unknown;
  password_policy: Record<string, unknown>;
  mfa: unknown;
  orgs: { self_service: boolean };
  providers: { id: string; kind: string; label: string; start_url: string }[];
  branding: {
    display_name: string;
    logo_url: string;
    primary_color: string;
    default_language: string;
    terms_url: string;
    privacy_url: string;
  };
  [extra: string]: unknown;
}

/**
 * Every failure: an HTTP error of the pool (status, code from `detail.code` or the OAuth `error`, fallback
 * `http_<status>`), `network_error` (status 0), `not_signed_in` (401), or a callback check (`invalid_state`,
 * `invalid_issuer`, `invalid_nonce`, `invalid_id_token`, `missing_transaction`, or the `error` of the redirect).
 */
export declare class AuthError extends Error {
  constructor(status: number, code: string, message?: string, detail?: unknown, options?: { cause?: unknown });
  readonly name: "AuthError";
  status: number;
  code: string;
  detail: unknown;
}

/** A storage of strings by key. Synchronous (localStorage) or asynchronous (returning promises). */
export interface AuthStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

/** What createAuth() keeps under `openback.auth.<clientId>` (JSON). */
export interface StoredSession {
  accessToken: string | null;
  refreshToken: string | null;
  idToken: string | null;
  /** Epoch milliseconds. */
  expiresAt: number;
  user: PoolUser | MeUser | null;
  org: ActiveOrg | null;
}

export interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T> | T): Promise<T>;
}

export interface AuthOptions {
  /** The pool's address, e.g. https://api.example.com/gateway/shop/auth/main (a trailing slash is removed). */
  issuer: string;
  /** The app's client ID (uapp_...). */
  clientId: string;
  /** Default redirect address of the hosted page (default: the current page without query and hash). */
  redirectUri?: string;
  /** Where the session is kept (default: localStorage, memory when blocked). */
  storage?: AuthStorage;
  /** Storage key of the session (default `openback.auth.<clientId>`). */
  storageKey?: string;
  /** Where the pending OIDC transaction is kept between redirect and callback (default: sessionStorage). */
  transactionStorage?: AuthStorage;
  /** The fetch to use (default: the global fetch). */
  fetch?: typeof fetch;
  /** Cross-tab lock for the refresh (default: navigator.locks when present); false disables it. */
  locks?: LockManagerLike | false | null;
}

export interface AuthorizationOptions {
  /** Go straight to a provider of the pool (its id, e.g. uprov_...). */
  provider?: string;
  /** B2B: the organization to sign in to. */
  orgId?: string;
  prompt?: "none" | "login";
  screenHint?: "signup";
  loginHint?: string;
  /** Seconds. */
  maxAge?: number;
  /** Default "openid profile email". */
  scope?: string;
  uiLocales?: string;
  /** Overrides the client's redirectUri. */
  redirectUri?: string;
}

export interface AuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
}

export interface LogoutOptions {
  postLogoutRedirectUri?: string;
  state?: string;
}

export interface Auth {
  readonly currentUser: PoolUser | MeUser | null;
  readonly currentOrg: ActiveOrg | null;
  /** The access token's claims, decoded and NOT verified. */
  readonly accessTokenClaims: Record<string, any> | null;
  readonly isSignedIn: boolean;
  readonly idToken: string | null;
  readonly issuer: string;
  readonly clientId: string;
  /** Settles when the stored session has been read (immediately with a synchronous storage). */
  readonly ready: Promise<void>;

  config(): Promise<PoolConfig>;
  /** Called at once with the current state, then on every change of user, organization or signed-in state. */
  onAuthStateChanged(listener: (user: PoolUser | MeUser | null, org: ActiveOrg | null) => void): () => void;
  /** The access token, renewed when it expires within 60 s. Throws AuthError `not_signed_in` when signed out. */
  getAccessToken(): Promise<string>;
  /** Renews the tokens now (single-flight); with orgId, for that organization. Resolves to the new access token. */
  refresh(orgId?: string): Promise<string>;
  /** fetch() with `Authorization: Bearer <access token>`. */
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
  signInWithRedirect(p?: AuthorizationOptions): Promise<void>;
  /** Resolves to null when the URL is not a callback (no code, no error). */
  handleRedirectCallback(url?: string): Promise<MeUser | null>;
  buildLogoutUrl(options?: LogoutOptions): string;
  buildLogoutUrl(postLogoutRedirectUri?: string, state?: string): string;
  signOutRedirect(p?: LogoutOptions & { everywhere?: boolean }): Promise<void>;

  sendPasswordReset(email: string): Promise<{ status: "sent" }>;
  resetPassword(p: { token?: string; email?: string; code?: string; newPassword: string }): Promise<{ status: "password_changed" }>;
  changeForcedPassword(p: { changeToken: string; newPassword: string }): Promise<{ status: "password_changed" }>;
  verifyEmail(p: { token?: string; email?: string; code?: string }): Promise<{ status: "verified"; user: PoolUser }>;
  resendVerification(): Promise<{ status: "sent" }>;

  me(): Promise<MeUser>;
  updateProfile(fields: { displayName?: string; photoUrl?: string; locale?: "it" | "en"; display_name?: string; photo_url?: string }): Promise<PoolUser>;
  /** Ends every session of the user: the local session is cleared. */
  changePassword(p: { currentPassword?: string; newPassword: string }): Promise<unknown>;
  changeEmail(newEmail: string): Promise<{ status: "verification_sent" }>;
  confirmEmailChange(p: { code?: string; token?: string }): Promise<{ status: "email_changed"; user: PoolUser }>;
  upgradeAnonymous(p: { email: string; password: string }): Promise<{ status: "upgraded"; user: PoolUser }>;
  /** Clears the local session. */
  deleteAccount(password?: string): Promise<{ status: "deleted" }>;
  /** Best-effort server sign-out; the local session is always cleared. */
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
export declare function decodeJwt(token: string): Record<string, any> | null;
export declare function memoryStorage(): AuthStorage;
export default createAuth;

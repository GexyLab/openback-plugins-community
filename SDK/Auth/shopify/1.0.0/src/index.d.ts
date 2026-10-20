// Types of openback-app-auth-shopify 1.0.0.

export declare const VERSION: string;

/** An invalid argument of the SSO helpers. */
export declare class ShopifySsoError extends Error {
  readonly name: "ShopifySsoError";
  readonly code: "invalid_shop_domain" | "invalid_email" | "invalid_return_to";
  constructor(code: string, message: string);
}

export interface SsoLoginUrlOptions {
  /** The store's host name ("my-store.myshopify.com" or a custom domain) or its https:// origin. */
  shopDomain: string;
  /** The customer's email: sent as Shopify's login_hint, which Shopify forwards to the pool. */
  email: string;
  /** A relative path on the shop opened after sign-in ("/", "/cart", "/products/handle"...). Default "/". */
  returnTo?: string;
}

/** https://{shop}/customer_authentication/login?login_hint=...&return_to=... */
export declare function ssoLoginUrl(options: SsoLoginUrlOptions): string;

/** The store's lower-case host name; throws ShopifySsoError when it is not a plain https host. */
export declare function normalizeShopDomain(shopDomain: string): string;

/** Whether a value is a relative path on the same shop (starts with "/", not "//", no backslash or control chars). */
export declare function isSafeReturnTo(returnTo: unknown): boolean;

export type CheckStatus = "pass" | "warn" | "fail";

export interface CheckResult {
  /** Stable identifier, e.g. "discovery", "token_auth", "prompt_none", "claims", "id_token_alg", "hosted_login". */
  id: string;
  status: CheckStatus;
  message: string;
}

export interface CheckPoolOptions {
  /** The pool's issuer, e.g. https://api.example.com/gateway/shop/auth/main (a trailing "/" is ignored). */
  issuer: string;
  /** Optional client ID (uapp_...): also checks hosted sign-in, email verification, guests, B2B and MFA settings. */
  clientId?: string;
  /** fetch implementation (default: globalThis.fetch). */
  fetch?: typeof fetch;
  /** Timeout of each request in ms (default 10000). */
  timeoutMs?: number;
}

export interface CheckPoolReport {
  issuer: string;
  /** The value for Shopify's "Discovery URL" field. */
  discoveryUrl: string;
  /** true when no check failed (warnings allowed). */
  ok: boolean;
  counts: { pass: number; warn: number; fail: number };
  checks: CheckResult[];
  /** The discovery document, or null when it could not be loaded. */
  discovery: Record<string, unknown> | null;
}

/** Loads the pool's discovery document (and JWKS, and with a client ID its public configuration) and reports pass/warn/fail for Shopify. */
export declare function checkPool(options: CheckPoolOptions): Promise<CheckPoolReport>;

/** `<issuer>/.well-known/openid-configuration` */
export declare function discoveryUrl(issuer: string): string;

/** The issuer without a trailing "/"; throws TypeError when it is not an absolute http(s) URL. */
export declare function normalizeIssuer(issuer: string): string;

/** ID token signing algorithms listed as supported by Shopify. */
export declare const SHOPIFY_ID_TOKEN_ALGS: readonly string[];

/** Shopify's response-time limit for the discovery, token and userinfo endpoints (ms). */
export declare const SHOPIFY_MAX_LATENCY_MS: number;

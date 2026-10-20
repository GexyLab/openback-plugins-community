// Single sign-on links into a Shopify Plus store whose new customer accounts use an OpenBack user pool as the
// third-party identity provider.
//
// Shopify's SSO entry point: https://{shop}/customer_authentication/login?login_hint=<email>&return_to=<relative path>
// Shopify then starts an OIDC request to the pool with prompt=none and the same login_hint: a customer who already has
// a browser session on the pool's hosted pages is signed in silently; otherwise Shopify shows the pool's sign-in page.

const HOST_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
// Control characters, whitespace and the backslash (browsers read "/\evil.example" like "//evil.example").
const UNSAFE_PATH_CHARS = /[\u0000- \u007f-\u009f\\]/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** An error raised for an invalid argument (bad shop domain, email or return path). */
export class ShopifySsoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ShopifySsoError";
    this.code = code;
  }
}

/**
 * The store's host name, lower-case: "my-store.myshopify.com" or a custom domain ("shop.example.com").
 * Accepts a bare host name or an https:// origin (a trailing "/" is ignored); refuses paths, queries, ports, user
 * information, http:// and IP addresses.
 * @param {string} shopDomain
 * @returns {string}
 */
export function normalizeShopDomain(shopDomain) {
  if (typeof shopDomain !== "string" || !shopDomain.trim()) {
    throw new ShopifySsoError("invalid_shop_domain", "shopDomain is required");
  }
  let host = shopDomain.trim();
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(host);
  if (scheme) {
    if (scheme[1].toLowerCase() !== "https") {
      throw new ShopifySsoError("invalid_shop_domain", "the shop domain must be served over https");
    }
    host = host.slice(scheme[0].length);
    if (host.endsWith("/")) host = host.slice(0, -1);
  }
  host = host.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host || host.length > 253 || /[/?#@:\\\s]/.test(host)) {
    throw new ShopifySsoError("invalid_shop_domain", "the shop domain must be a host name such as my-store.myshopify.com");
  }
  const labels = host.split(".");
  if (labels.length < 2 || !labels.every((label) => HOST_LABEL.test(label)) || !TLD.test(labels[labels.length - 1])) {
    throw new ShopifySsoError("invalid_shop_domain", "the shop domain must be a host name such as my-store.myshopify.com");
  }
  return host;
}

/**
 * Whether a value is a safe Shopify return_to: a relative path on the same shop. It starts with "/" but not "//" or
 * "/\", has no scheme, no backslash, no control characters or whitespace, and stays so once percent-decoded.
 * @param {unknown} returnTo
 * @returns {boolean}
 */
export function isSafeReturnTo(returnTo) {
  if (typeof returnTo !== "string" || returnTo.length === 0 || returnTo.length > 2048) return false;
  if (!returnTo.startsWith("/") || returnTo.startsWith("//") || UNSAFE_PATH_CHARS.test(returnTo)) return false;
  let decoded;
  try {
    decoded = decodeURIComponent(returnTo);
  } catch {
    return false; // malformed percent-encoding
  }
  if (decoded.startsWith("//") || decoded.startsWith("/\\") || /[\u0000-\u001f\u007f]/.test(decoded)) return false;
  // The path part (before any query or fragment) must not carry a scheme-like segment such as "/https:/...".
  const path = decoded.split(/[?#]/, 1)[0];
  if (/^\/[a-z][a-z0-9+.-]*:/i.test(path)) return false;
  return true;
}

function checkEmail(email) {
  if (typeof email !== "string") throw new ShopifySsoError("invalid_email", "email is required");
  const value = email.trim();
  if (!value || value.length > 254 || !EMAIL.test(value) || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ShopifySsoError("invalid_email", "email is not a valid address");
  }
  return value;
}

/**
 * The Shopify SSO address that signs the customer in to the store (silently when they have a session on the pool's
 * hosted pages) and then opens `returnTo`.
 * @param {{ shopDomain: string, email: string, returnTo?: string }} options
 * @returns {string}
 */
export function ssoLoginUrl({ shopDomain, email, returnTo = "/" } = {}) {
  const host = normalizeShopDomain(shopDomain);
  const loginHint = checkEmail(email);
  if (!isSafeReturnTo(returnTo)) {
    throw new ShopifySsoError("invalid_return_to", 'returnTo must be a relative path on the shop, starting with "/" (not "//")');
  }
  const query = new URLSearchParams({ login_hint: loginHint, return_to: returnTo });
  return `https://${host}/customer_authentication/login?${query.toString()}`;
}

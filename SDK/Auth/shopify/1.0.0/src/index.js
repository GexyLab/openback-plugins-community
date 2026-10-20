// openback-app-auth-shopify: helpers for using an OpenBack user pool as the third-party identity provider of a
// Shopify Plus store's new customer accounts.
export { ssoLoginUrl, normalizeShopDomain, isSafeReturnTo, ShopifySsoError } from "./sso.js";
export { checkPool, discoveryUrl, normalizeIssuer, SHOPIFY_ID_TOKEN_ALGS, SHOPIFY_MAX_LATENCY_MS } from "./check.js";
export const VERSION = "1.0.0";

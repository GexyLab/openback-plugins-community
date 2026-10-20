import assert from "node:assert/strict";
import { test } from "node:test";

import { isSafeReturnTo, normalizeShopDomain, ShopifySsoError, ssoLoginUrl } from "../src/index.js";

test("ssoLoginUrl builds Shopify's customer_authentication/login address", () => {
  const url = new URL(ssoLoginUrl({ shopDomain: "my-store.myshopify.com", email: "jane@example.com", returnTo: "/cart/44321456:1" }));
  assert.equal(url.origin, "https://my-store.myshopify.com");
  assert.equal(url.pathname, "/customer_authentication/login");
  assert.equal(url.searchParams.get("login_hint"), "jane@example.com");
  assert.equal(url.searchParams.get("return_to"), "/cart/44321456:1");
  assert.deepEqual([...url.searchParams.keys()], ["login_hint", "return_to"]);
});

test("returnTo defaults to / and the email is trimmed and encoded", () => {
  const url = ssoLoginUrl({ shopDomain: "shop.example.com", email: "  jane+vip@example.com " });
  assert.equal(url, "https://shop.example.com/customer_authentication/login?login_hint=jane%2Bvip%40example.com&return_to=%2F");
});

test("returnTo keeps its query string", () => {
  const url = new URL(ssoLoginUrl({ shopDomain: "shop.example.com", email: "a@b.co", returnTo: "/collections/all?sort_by=price&page=2" }));
  assert.equal(url.searchParams.get("return_to"), "/collections/all?sort_by=price&page=2");
});

test("normalizeShopDomain accepts host names and https origins", () => {
  assert.equal(normalizeShopDomain("My-Store.MyShopify.com"), "my-store.myshopify.com");
  assert.equal(normalizeShopDomain("https://shop.example.com/"), "shop.example.com");
  assert.equal(normalizeShopDomain(" shop.example.co.uk. "), "shop.example.co.uk");
});

test("normalizeShopDomain refuses anything that is not a plain https host", () => {
  for (const bad of ["", "   ", "localhost", "http://shop.example.com", "https://shop.example.com/path", "shop.example.com:8443",
    "user@shop.example.com", "shop.example.com?x=1", "shop.example.com#x", "-shop.example.com", "shop..example.com", "127.0.0.1",
    "javascript://shop.example.com", "shop.example.com\\evil.com", "shop example.com", null, undefined, 42]) {
    assert.throws(() => normalizeShopDomain(bad), (error) => error instanceof ShopifySsoError && error.code === "invalid_shop_domain", String(bad));
  }
});

test("isSafeReturnTo accepts relative same-shop paths", () => {
  for (const ok of ["/", "/cart", "/checkout", "/products/red-shirt", "/cart/44321456:1", "/account?tab=orders", "/pages/a%20b", "/search?q=a/b"]) {
    assert.equal(isSafeReturnTo(ok), true, ok);
  }
});

test("isSafeReturnTo refuses absolute, protocol-relative and tricky paths", () => {
  for (const bad of ["", "cart", "https://evil.example/", "//evil.example", "/\\evil.example", "/\\/evil.example", "\\\\evil.example",
    "/%2F%2Fevil.example", "/%2f/evil.example", "/%5Cevil.example", "/a\\b", "/a b", "/a\tb", "/a\nb", "/%0d%0aSet-Cookie:x",
    "/%E0%A4%A", "/javascript:alert(1)", "/https://evil.example", "/" + "a".repeat(2048), null, undefined, 1, {}]) {
    assert.equal(isSafeReturnTo(bad), false, String(bad));
  }
});

test("ssoLoginUrl reports invalid arguments with ShopifySsoError codes", () => {
  assert.throws(() => ssoLoginUrl({ shopDomain: "shop.example.com", email: "not-an-email" }), { code: "invalid_email" });
  assert.throws(() => ssoLoginUrl({ shopDomain: "shop.example.com" }), { code: "invalid_email" });
  assert.throws(() => ssoLoginUrl({ shopDomain: "shop.example.com", email: "a@b.co", returnTo: "//evil.example" }), { code: "invalid_return_to" });
  assert.throws(() => ssoLoginUrl({ shopDomain: "shop.example.com", email: "a@b.co", returnTo: "https://evil.example" }), { code: "invalid_return_to" });
  assert.throws(() => ssoLoginUrl({ email: "a@b.co" }), { code: "invalid_shop_domain" });
  assert.throws(() => ssoLoginUrl(), { code: "invalid_shop_domain" });
});

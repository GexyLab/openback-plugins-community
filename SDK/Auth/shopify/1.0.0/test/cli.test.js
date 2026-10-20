import assert from "node:assert/strict";
import { test } from "node:test";

import { main } from "../bin/openback-app-auth-shopify.mjs";
import { CLIENT_ID, ISSUER, mockFetch, poolDiscovery, poolRoutes, sink } from "./helpers.js";

async function run(argv, fetch) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(argv, { stdout, stderr, fetch });
  return { code, out: stdout.text, err: stderr.text };
}

test("check prints the Discovery URL and the checks, exit 0 on a good pool", async () => {
  const { code, out } = await run(["check", ISSUER, "--client-id", CLIENT_ID], mockFetch(poolRoutes()));
  assert.equal(code, 0);
  assert.match(out, new RegExp(`Discovery URL \\(Shopify admin\\): ${ISSUER.replace(/[.]/g, "\\.")}/\\.well-known/openid-configuration`));
  assert.match(out, /\[PASS\] token_auth:/);
  assert.match(out, /\[WARN\] id_token_alg:/);
  assert.match(out, /usable by Shopify/);
});

test("check --json prints a machine-readable report, exit 1 when a check fails", async () => {
  const discovery = { ...poolDiscovery(), end_session_endpoint: null };
  const { code, out } = await run(["check", ISSUER, "--json"], mockFetch(poolRoutes({ discovery })));
  assert.equal(code, 1);
  const report = JSON.parse(out);
  assert.equal(report.ok, false);
  assert.equal(report.discovery, undefined);
  assert.equal(report.checks.find((c) => c.id === "logout").status, "fail");
});

test("sso-url prints the address; --return-to=... form works", async () => {
  const a = await run(["sso-url", "--shop", "my-store.myshopify.com", "--email", "jane@example.com", "--return-to", "/cart"]);
  assert.equal(a.code, 0);
  assert.equal(a.out.trim(), "https://my-store.myshopify.com/customer_authentication/login?login_hint=jane%40example.com&return_to=%2Fcart");
  const b = await run(["sso-url", "--shop=my-store.myshopify.com", "--email=jane@example.com"]);
  assert.match(b.out, /return_to=%2F$/m);
});

test("sso-url refuses an unsafe return path (exit 1)", async () => {
  const { code, err } = await run(["sso-url", "--shop", "my-store.myshopify.com", "--email", "jane@example.com", "--return-to", "//evil.example"]);
  assert.equal(code, 1);
  assert.match(err, /relative path/);
});

test("usage errors exit 2; --help and --version exit 0", async () => {
  assert.equal((await run([])).code, 2);
  assert.equal((await run(["nope"])).code, 2);
  assert.equal((await run(["check"])).code, 2);
  assert.equal((await run(["sso-url", "--shop", "x.example.com"])).code, 2);
  assert.equal((await run(["sso-url", "--email"])).code, 2);
  assert.equal((await run(["check", "not a url"])).code, 2);
  const help = await run(["--help"]);
  assert.equal(help.code, 0);
  assert.match(help.out, /Usage:/);
  const version = await run(["--version"]);
  assert.equal(version.out.trim(), "1.0.0");
});

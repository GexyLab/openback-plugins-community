import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { build } from "../scripts/build.mjs";

const dist = (f) => readFileSync(new URL(`../dist/${f}`, import.meta.url), "utf8").replace(/\r\n/g, "\n");

test("the committed dist/ bundles match the build of src/index.js", () => {
  const files = build();
  for (const [name, code] of Object.entries(files)) assert.equal(dist(name), code, `dist/${name} is stale: run node scripts/build.mjs`);
});

test("the UMD bundles define the global OpenBackAppAuth (plain <script> tag)", () => {
  for (const f of ["openback-app-auth.umd.js", "openback-app-auth.umd.min.js"]) {
    const sandbox = { window: undefined };
    sandbox.self = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(dist(f), sandbox);
    const lib = sandbox.OpenBackAppAuth;
    assert.equal(typeof lib.createAuth, "function", f);
    assert.equal(typeof lib.createClient, "function", f);
    assert.equal(typeof lib.AuthError, "function", f);
    assert.equal(typeof lib.decodeJwt, "function", f);
    assert.equal(lib.default, lib.createAuth);
  }
});

test("the UMD bundle works with CommonJS", () => {
  const module = { exports: {} };
  const sandbox = { module, exports: module.exports };
  vm.createContext(sandbox);
  vm.runInContext(dist("openback-app-auth.umd.js"), sandbox);
  assert.equal(typeof module.exports.createAuth, "function");
});

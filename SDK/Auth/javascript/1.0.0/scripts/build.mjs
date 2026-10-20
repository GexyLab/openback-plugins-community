// Builds the browser bundles from src/index.js, with no dependencies:
//   dist/openback-app-auth.esm.js      the ES module (bundlers, <script type="module">)
//   dist/openback-app-auth.umd.js      UMD: global OpenBackAppAuth for a plain <script> tag, AMD, CommonJS
//   dist/openback-app-auth.umd.min.js  the same, without comments, indentation and blank lines (a light minification)
//
//   node scripts/build.mjs           write dist/
//   node scripts/build.mjs --check   fail when dist/ differs from what the build would write
//
// src/index.js is one file without imports, with exports written as "export const|class|function NAME" and
// "export default NAME;". The build checks that and loads the UMD bundle in a sandbox before writing anything.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

export function build() {
  const src = readFileSync(join(root, "src", "index.js"), "utf8").replace(/\r\n/g, "\n");
  const banner = `/*! ${pkg.name} v${pkg.version} | MIT License | ${pkg.homepage} */\n`;

  if (/^\s*import\s/m.test(src) || /^export\s*\{/m.test(src) || /^export\s+\*/m.test(src)) {
    throw new Error("src/index.js must have no imports and no export lists");
  }
  const names = [];
  let defaultName = null;
  const body = src
    .replace(/^export default (\w+);\s*$/m, (_, name) => { defaultName = name; return ""; })
    .replace(/^export (const|let|class|function|async function) (\w+)/gm, (_, kind, name) => { names.push(name); return `${kind} ${name}`; });
  if (/^export\s/m.test(body)) throw new Error("src/index.js has an export the build does not understand");
  if (!defaultName) throw new Error("src/index.js has no default export");

  const exportsObject = `{ ${names.map((n) => `${n}: ${n}`).join(", ")}, default: ${defaultName} }`;
  const umd = banner +
    "(function (root, factory) {\n" +
    "  if (typeof define === \"function\" && define.amd) define([], factory);\n" +
    "  else if (typeof module === \"object\" && module.exports) module.exports = factory();\n" +
    "  else root.OpenBackAppAuth = factory();\n" +
    "})(typeof globalThis !== \"undefined\" ? globalThis : typeof self !== \"undefined\" ? self : this, function () {\n" +
    "\"use strict\";\n" +
    body.trimEnd() + "\n\n" +
    `return ${exportsObject};\n` +
    "});\n";

  const esm = banner + src;
  const min = banner + minify(umd.slice(banner.length));

  for (const [file, code] of [["umd", umd], ["umd.min", min]]) {
    const sandbox = { console };
    vm.createContext(sandbox);
    vm.runInContext(code, sandbox, { filename: `openback-app-auth.${file}.js` });
    const lib = sandbox.OpenBackAppAuth;
    if (!lib || typeof lib.createAuth !== "function" || lib.VERSION !== pkg.version) {
      throw new Error(`the ${file} bundle does not expose OpenBackAppAuth.createAuth v${pkg.version}`);
    }
  }
  if (!src.includes(`export const VERSION = "${pkg.version}";`)) throw new Error("VERSION in src/index.js differs from package.json");
  return {
    "openback-app-auth.esm.js": esm,
    "openback-app-auth.umd.js": umd,
    "openback-app-auth.umd.min.js": min,
  };
}

// Drops comment-only lines, blank lines and indentation. Lines are kept (no ASI hazard); safe because the source keeps
// every template literal on one line.
function minify(code) {
  const out = [];
  let inBlock = false;
  for (const line of code.split("\n")) {
    const t = line.trim();
    if (inBlock) { if (t.includes("*/")) inBlock = false; continue; }
    if (t === "" || t.startsWith("//")) continue;
    if (t.startsWith("/*") && !t.startsWith("/*!")) { if (!t.includes("*/")) inBlock = true; continue; }
    out.push(t);
  }
  return out.join("\n") + "\n";
}

if (process.argv[1] && fileURLToPath(import.meta.url) === join(process.argv[1])) {
  const files = build();
  const dist = join(root, "dist");
  if (process.argv.includes("--check")) {
    const stale = Object.entries(files).filter(([f, code]) => !existsSync(join(dist, f)) || readFileSync(join(dist, f), "utf8").replace(/\r\n/g, "\n") !== code);
    if (stale.length) {
      console.error(`dist/ is out of date: ${stale.map(([f]) => f).join(", ")} (run: node scripts/build.mjs)`);
      process.exit(1);
    }
    console.log("dist/ is up to date");
  } else {
    mkdirSync(dist, { recursive: true });
    for (const [f, code] of Object.entries(files)) {
      writeFileSync(join(dist, f), code);
      console.log(`dist/${f}  ${code.length} bytes`);
    }
  }
}

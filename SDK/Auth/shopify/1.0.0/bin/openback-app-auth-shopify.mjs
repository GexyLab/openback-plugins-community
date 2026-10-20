#!/usr/bin/env node
// openback-app-auth-shopify — command line.
//
//   openback-app-auth-shopify check <issuer> [--client-id uapp_...] [--json]
//   openback-app-auth-shopify sso-url --shop <domain> --email <email> [--return-to /path]
//
// Exit codes: 0 ok, 1 a check failed / invalid argument, 2 usage error.

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { checkPool, ssoLoginUrl, VERSION } from "../src/index.js";

const USAGE = `openback-app-auth-shopify ${VERSION}

Usage:
  openback-app-auth-shopify check <issuer> [--client-id <uapp_...>] [--json]
      Checks that an OpenBack user pool can be the third-party identity provider of a
      Shopify Plus store's new customer accounts, and prints the Discovery URL to paste.

  openback-app-auth-shopify sso-url --shop <domain> --email <email> [--return-to </path>]
      Prints the Shopify single sign-on address for a customer.

  openback-app-auth-shopify --help | --version
`;

function parse(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const name = eq > 0 ? arg.slice(2, eq) : arg.slice(2);
      if (["json", "help", "version"].includes(name)) {
        flags[name] = true;
      } else if (eq > 0) {
        flags[name] = arg.slice(eq + 1);
      } else {
        if (i + 1 >= argv.length) throw new Error(`--${name} needs a value`);
        flags[name] = argv[++i];
      }
    } else if (arg === "-h") {
      flags.help = true;
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

const MARK = { pass: "PASS", warn: "WARN", fail: "FAIL" };

export async function main(argv, { stdout = process.stdout, stderr = process.stderr, fetch: fetchImpl } = {}) {
  let parsed;
  try {
    parsed = parse(argv);
  } catch (error) {
    stderr.write(`${error.message}\n\n${USAGE}`);
    return 2;
  }
  const { positional, flags } = parsed;
  if (flags.version) {
    stdout.write(`${VERSION}\n`);
    return 0;
  }
  const [command, ...rest] = positional;
  if (flags.help || !command) {
    (flags.help ? stdout : stderr).write(USAGE);
    return flags.help ? 0 : 2;
  }

  if (command === "check") {
    const issuer = rest[0] || flags.issuer;
    if (!issuer) {
      stderr.write(`check needs the pool's issuer\n\n${USAGE}`);
      return 2;
    }
    let report;
    try {
      report = await checkPool({ issuer, clientId: flags["client-id"], fetch: fetchImpl });
    } catch (error) {
      stderr.write(`${error.message}\n`);
      return 2;
    }
    if (flags.json) {
      const { discovery, ...out } = report;
      stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    } else {
      stdout.write(`Pool: ${report.issuer}\n`);
      stdout.write(`Discovery URL (Shopify admin): ${report.discoveryUrl}\n\n`);
      for (const c of report.checks) stdout.write(`[${MARK[c.status]}] ${c.id}: ${c.message}\n`);
      const { pass, warn, fail } = report.counts;
      stdout.write(`\n${pass} passed, ${warn} warning(s), ${fail} failed — ${report.ok ? "usable by Shopify" : "NOT usable by Shopify yet"}\n`);
    }
    return report.ok ? 0 : 1;
  }

  if (command === "sso-url") {
    const shop = flags.shop || flags["shop-domain"];
    if (!shop || !flags.email) {
      stderr.write(`sso-url needs --shop and --email\n\n${USAGE}`);
      return 2;
    }
    try {
      stdout.write(`${ssoLoginUrl({ shopDomain: shop, email: flags.email, returnTo: flags["return-to"] ?? "/" })}\n`);
      return 0;
    } catch (error) {
      stderr.write(`${error.message}\n`);
      return 1;
    }
  }

  stderr.write(`unknown command: ${command}\n\n${USAGE}`);
  return 2;
}

// Run when executed directly (not when imported by the tests).
function isMain() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}

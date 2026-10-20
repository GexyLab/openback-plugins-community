// Example: an external site (blog, community, loyalty portal...) that signs people in with the SAME OpenBack user pool
// the Shopify Plus store uses as its third-party identity provider, and sends them to the store already signed in.
//
// How it works
//   1. "Sign in" runs the OIDC authorization code flow (+ PKCE) against the pool's HOSTED page. Signing in there also
//      leaves the pool's browser session cookie (obu_session) in the visitor's browser.
//   2. "Shop now" redirects to Shopify's SSO address  https://{shop}/customer_authentication/login?login_hint=<email>
//      &return_to=<path>  built with ssoLoginUrl() from the email of the VERIFIED ID token (never from user input).
//   3. Shopify asks the pool with prompt=none: the pool sees its session cookie and answers at once, so the customer
//      lands on the store signed in, without typing anything. Without a pool session, Shopify shows the pool's sign-in.
//
// Register in the pool's Apps tab an app of kind "web" (a separate one from the Shopify app is fine; same pool):
//   redirect URI              http://localhost:3000/callback        (http:// is accepted for localhost only)
//   post-logout redirect URI  http://localhost:3000/
//
// Run (Node.js >= 18, no dependencies):
//   OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main OPENBACK_CLIENT_ID=uapp_... \
//   OPENBACK_CLIENT_SECRET=obus_sec_... SHOP_DOMAIN=my-store.myshopify.com node examples/external-site/server.mjs
//
// This is a teaching example: sessions live in memory, there is no CSRF protection beyond the OIDC state, and it serves
// plain http. Use your framework's session store and https in production.

import { createPublicKey, createHash, randomBytes, timingSafeEqual, verify } from "node:crypto";
import { createServer } from "node:http";

// Once published: import { ssoLoginUrl } from "openback-app-auth-shopify";
import { ssoLoginUrl, isSafeReturnTo } from "../../src/index.js";

const ISSUER = (process.env.OPENBACK_ISSUER || "").replace(/\/+$/, "");
const CLIENT_ID = process.env.OPENBACK_CLIENT_ID || "";
const CLIENT_SECRET = process.env.OPENBACK_CLIENT_SECRET || "";
const SHOP_DOMAIN = process.env.SHOP_DOMAIN || "";
const SITE_URL = (process.env.SITE_URL || "http://localhost:3000").replace(/\/+$/, "");
const PORT = Number(process.env.PORT || new URL(SITE_URL).port || 3000);
const REDIRECT_URI = `${SITE_URL}/callback`;

if (!ISSUER || !CLIENT_ID || !CLIENT_SECRET || !SHOP_DOMAIN) {
  console.error("Set OPENBACK_ISSUER, OPENBACK_CLIENT_ID, OPENBACK_CLIENT_SECRET and SHOP_DOMAIN.");
  process.exit(2);
}

// --- tiny helpers --------------------------------------------------------------------------------------------------

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const random = (n = 32) => b64url(randomBytes(n));
const sessions = new Map(); // cookie value -> { user?, tx?, idToken? }
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function sessionOf(req, res) {
  const cookie = /(?:^|;\s*)site_session=([A-Za-z0-9_-]{20,})/.exec(req.headers.cookie || "")?.[1];
  if (cookie && sessions.has(cookie)) return sessions.get(cookie);
  const id = random();
  const session = {};
  sessions.set(id, session);
  res.setHeader("Set-Cookie", `site_session=${id}; Path=/; HttpOnly; SameSite=Lax${SITE_URL.startsWith("https:") ? "; Secure" : ""}`);
  return session;
}

function sameText(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
}

function page(res, body, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(`<!doctype html><meta charset="utf-8"><title>Example site</title><body style="font-family:sans-serif;max-width:40rem;margin:2rem auto">${body}</body>`);
}

let discoveryCache;
async function discovery() {
  discoveryCache ||= fetch(`${ISSUER}/.well-known/openid-configuration`).then((r) => {
    if (!r.ok) throw new Error(`discovery: HTTP ${r.status}`);
    return r.json();
  });
  return discoveryCache;
}

// --- ID token verification (ES256, the pool's only algorithm) -------------------------------------------------------

let jwksCache = { at: 0, keys: [] };
async function publicKey(kid) {
  const fresh = Date.now() - jwksCache.at < 10 * 60 * 1000;
  if (!fresh || !jwksCache.keys.some((k) => k.kid === kid)) {
    const r = await fetch((await discovery()).jwks_uri);
    if (!r.ok) throw new Error(`jwks: HTTP ${r.status}`);
    jwksCache = { at: Date.now(), keys: (await r.json()).keys || [] };
  }
  const jwk = jwksCache.keys.find((k) => k.kid === kid);
  if (!jwk) throw new Error("unknown signing key");
  return createPublicKey({ key: jwk, format: "jwk" });
}

async function verifyIdToken(idToken, nonce) {
  const [h, p, s] = String(idToken).split(".");
  if (!h || !p || !s) throw new Error("malformed ID token");
  const header = JSON.parse(Buffer.from(h, "base64url").toString());
  if (header.alg !== "ES256") throw new Error("unexpected algorithm"); // never accept "none", HS*, RS*
  const ok = verify("sha256", Buffer.from(`${h}.${p}`), { key: await publicKey(header.kid), dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  if (!ok) throw new Error("bad signature");
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== ISSUER) throw new Error("wrong issuer");
  if (claims.aud !== CLIENT_ID) throw new Error("wrong audience");
  if (typeof claims.exp !== "number" || claims.exp + 60 < now) throw new Error("expired");
  if (!claims.nonce || !sameText(claims.nonce, nonce)) throw new Error("wrong nonce");
  return claims;
}

// --- routes ----------------------------------------------------------------------------------------------------------

async function handle(req, res) {
  const url = new URL(req.url, SITE_URL);
  const session = sessionOf(req, res);

  if (url.pathname === "/") {
    if (!session.user) return page(res, `<h1>Example site</h1><p><a href="/login">Sign in</a></p>`);
    const u = session.user;
    const warn = u.email_verified ? "" : "<p><strong>Your email is not verified: the store will refuse the sign-in.</strong></p>";
    return page(res, `<h1>Hello ${escapeHtml(u.name || u.email)}</h1>${warn}
      <p><a href="/shop?to=/">Shop now</a> · <a href="/shop?to=/cart">Go to my cart</a> · <a href="/logout">Sign out</a></p>`);
  }

  if (url.pathname === "/login") {
    const d = await discovery();
    const verifier = random(32);
    session.tx = { state: random(), nonce: random(), verifier, returnTo: isSafeReturnTo(url.searchParams.get("to")) ? url.searchParams.get("to") : null };
    const q = new URLSearchParams({
      response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: "openid email profile",
      state: session.tx.state, nonce: session.tx.nonce,
      code_challenge: b64url(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256",
    });
    return redirect(res, `${d.authorization_endpoint}?${q}`);
  }

  if (url.pathname === "/callback") {
    const tx = session.tx;
    session.tx = undefined;
    const p = url.searchParams;
    if (!tx || !p.get("state") || !sameText(p.get("state"), tx.state)) return page(res, "<p>Invalid or expired sign-in. <a href='/login'>Retry</a></p>", 400);
    if (p.get("iss") && p.get("iss") !== ISSUER) return page(res, "<p>Wrong issuer.</p>", 400);
    if (p.get("error")) return page(res, `<p>Sign-in refused: ${escapeHtml(p.get("error"))}</p>`, 400);
    const d = await discovery();
    // client_secret_post: the same method Shopify uses with the pool.
    const r = await fetch(d.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: p.get("code") || "", redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: tx.verifier }),
    });
    const tokens = await r.json().catch(() => ({}));
    if (!r.ok || !tokens.id_token) return page(res, `<p>Token exchange failed: ${escapeHtml(tokens.error || r.status)}</p>`, 502);
    const claims = await verifyIdToken(tokens.id_token, tx.nonce);
    session.user = { sub: claims.sub, email: claims.email, email_verified: claims.email_verified === true, name: claims.name };
    session.idToken = tokens.id_token; // for the logout hint; never logged
    if (tx.returnTo) return redirect(res, `/shop?to=${encodeURIComponent(tx.returnTo)}`);
    return redirect(res, "/");
  }

  if (url.pathname === "/shop") {
    const to = url.searchParams.get("to") || "/";
    if (!isSafeReturnTo(to)) return page(res, "<p>Invalid store path.</p>", 400);
    if (!session.user) return redirect(res, `/login?to=${encodeURIComponent(to)}`);
    // The email comes from the verified ID token; Shopify forwards it to the pool as login_hint.
    return redirect(res, ssoLoginUrl({ shopDomain: SHOP_DOMAIN, email: session.user.email, returnTo: to }));
  }

  if (url.pathname === "/logout") {
    const d = await discovery();
    const q = new URLSearchParams({ client_id: CLIENT_ID, post_logout_redirect_uri: `${SITE_URL}/` });
    if (session.idToken) q.set("id_token_hint", session.idToken);
    session.user = undefined;
    session.idToken = undefined;
    // Ends the pool's browser session too: the next "Shop now" asks for the password again. The Shopify session itself
    // is not ended by this (Shopify has no front-/back-channel logout).
    return redirect(res, `${d.end_session_endpoint}?${q}`);
  }

  page(res, "<p>Not found</p>", 404);
}

createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error("request failed:", error.message); // no tokens or codes in the message
    if (!res.headersSent) page(res, "<p>Something went wrong.</p>", 500);
  });
}).listen(PORT, () => console.log(`Example site on ${SITE_URL}`));

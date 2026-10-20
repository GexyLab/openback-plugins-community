// "Sign in with the pool" for a web app with its own server (app kind "web": client secret + redirect URI).
// No framework: node:http and an in-memory session store, to show the flow. Use your framework's session in production.
//   OPENBACK_ISSUER=... OPENBACK_CLIENT_ID=uapp_... OPENBACK_CLIENT_SECRET=... node oidc-web-login.mjs
// Register http://localhost:3000/callback as a redirect URI and http://localhost:3000/ as a post-logout redirect URI.
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { OidcWebClient } from "openback-app-auth-nodejs";

const oidc = new OidcWebClient({
  issuer: process.env.OPENBACK_ISSUER,
  clientId: process.env.OPENBACK_CLIENT_ID,
  clientSecret: process.env.OPENBACK_CLIENT_SECRET,
  redirectUri: "http://localhost:3000/callback",
  postLogoutRedirectUri: "http://localhost:3000/",
});

const sessions = new Map(); // session id -> { transaction?, tokens?, claims? }

function session(req, res) {
  const sid = /(?:^|;\s*)sid=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || "")?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid);
  const id = randomBytes(24).toString("base64url");
  const s = {};
  sessions.set(id, s);
  res.setHeader("Set-Cookie", `sid=${id}; HttpOnly; SameSite=Lax; Path=/`); // add Secure on https
  return s;
}

const html = (res, body) => { res.setHeader("Content-Type", "text/html; charset=utf-8"); res.end(body); };
const redirect = (res, url) => { res.statusCode = 302; res.setHeader("Location", url); res.end(); };
const escape = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost:3000");
  const s = session(req, res);
  try {
    if (url.pathname === "/login") {
      const { url: target, transaction } = await oidc.authorizationUrl({ uiLocales: "en" });
      s.transaction = transaction; // kept server-side until the callback
      return redirect(res, target);
    }
    if (url.pathname === "/callback") {
      const transaction = s.transaction;
      delete s.transaction; // one use
      const tokens = await oidc.handleCallback(url.searchParams, transaction);
      s.tokens = tokens;
      return redirect(res, "/");
    }
    if (url.pathname === "/logout") {
      const idTokenHint = s.tokens?.idToken;
      if (s.tokens?.refreshToken) await oidc.revoke(s.tokens.refreshToken).catch(() => {});
      delete s.tokens;
      return redirect(res, oidc.logoutUrl({ idTokenHint }));
    }
    if (s.tokens) {
      if (s.tokens.expiresAt - Date.now() < 60_000) {
        // Rotated: keep the new refresh token (never reuse the old one). One request per session at a time in a real app.
        const fresh = await oidc.refresh(s.tokens.refreshToken);
        s.tokens = { ...fresh, idToken: s.tokens.idToken, idTokenClaims: s.tokens.idTokenClaims };
      }
      const c = s.tokens.idTokenClaims;
      return html(res, `<p>Signed in as ${escape(c.email || c.sub)}</p><p><a href="/logout">Sign out</a></p>`);
    }
    return html(res, `<p><a href="/login">Sign in</a></p>`);
  } catch (e) {
    res.statusCode = 400;
    return html(res, `<p>Sign-in failed: ${escape(e.code || "error")}</p><p><a href="/">Back</a></p>`);
  }
}).listen(3000, () => console.log("Open http://localhost:3000"));

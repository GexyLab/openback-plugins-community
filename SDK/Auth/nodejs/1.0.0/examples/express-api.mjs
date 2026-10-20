// An Express API protected by the pool's access tokens.
//   npm install express openback-app-auth-nodejs
//   OPENBACK_ISSUER=https://api.example.com/gateway/shop/auth/main OPENBACK_CLIENT_ID=uapp_... node express-api.mjs
import express from "express";
import { TokenVerifier, requireAppUser } from "openback-app-auth-nodejs";

const verifier = new TokenVerifier({
  issuer: process.env.OPENBACK_ISSUER,
  clientIds: (process.env.OPENBACK_CLIENT_ID || "").split(","), // the apps whose tokens this API accepts
});

const app = express();

// Any signed-in user (guests refused).
app.get("/api/profile", requireAppUser({ verifier }), (req, res) => {
  const u = req.appUser;
  res.json({ id: u.id, email: u.email, org: u.orgId, roles: u.roles });
});

// Organization admins with a permission, verified email only.
app.delete("/api/orders/:id", requireAppUser({ verifier, requireRoles: ["admin", "owner"], requirePermissions: ["orders.delete"], requireVerifiedEmail: true }),
  (req, res) => res.status(204).end());

app.listen(3000, () => console.log("API on http://localhost:3000"));

// A plain node:http API (no framework) protected by the pool's access tokens.
//   OPENBACK_ISSUER=... OPENBACK_CLIENT_ID=uapp_... node http-api.mjs
//   curl -H "Authorization: Bearer <access token>" http://localhost:3000/
import { createServer } from "node:http";
import { requireAppUserHttp } from "openback-app-auth-nodejs";

const guard = requireAppUserHttp({ issuer: process.env.OPENBACK_ISSUER, clientIds: [process.env.OPENBACK_CLIENT_ID] });

createServer(async (req, res) => {
  const user = await guard(req, res); // answers 401 / 403 / 503 itself
  if (!user) return;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ hello: user.email || user.id, permissions: user.permissions }));
}).listen(3000, () => console.log("API on http://localhost:3000"));

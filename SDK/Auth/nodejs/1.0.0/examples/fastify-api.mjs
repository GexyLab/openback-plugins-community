// A Fastify API protected by the pool's access tokens.
//   npm install fastify openback-app-auth-nodejs
//   OPENBACK_ISSUER=... OPENBACK_CLIENT_ID=uapp_... node fastify-api.mjs
import Fastify from "fastify";
import { fastifyAppUser } from "openback-app-auth-nodejs";

const fastify = Fastify();
await fastify.register(fastifyAppUser, { issuer: process.env.OPENBACK_ISSUER, clientIds: [process.env.OPENBACK_CLIENT_ID] });

fastify.get("/api/profile", { preHandler: fastify.requireAppUser() }, async (request) => ({
  id: request.appUser.id,
  email: request.appUser.email,
}));

fastify.get("/api/admin", { preHandler: fastify.requireAppUser({ requireRoles: ["admin"] }) }, async () => ({ ok: true }));

await fastify.listen({ port: 3000 });
console.log("API on http://localhost:3000");

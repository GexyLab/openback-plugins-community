// openback-app-auth-nodejs 1.0.0 -- OpenBack App authenticator (user pools) for Node.js servers and apps.
//   createAuth / createClient   the pool's client (JSON API + OIDC), the same API as the browser SDK, in-memory storage
//   TokenVerifier / AppUser     local verification of access and ID tokens (ES256, JWKS cached)
//   OidcWebClient               OpenID Connect for confidential "web" apps (client secret + PKCE)
//   requireAppUser, ...         Express / Connect / node:http / Fastify guards
import "./webcrypto.js";

export { VERSION, AuthError, decodeJwt } from "./util.js";
export { createAuth, createClient, memoryStorage } from "./client.js";
export { TokenVerifier, TokenVerificationError, AppUser } from "./verifier.js";
export { OidcWebClient } from "./oidc.js";
export { createAppUserAuthenticator, requireAppUser, requireAppUserHttp, fastifyRequireAppUser, fastifyAppUser } from "./middleware.js";
export { createAuth as default } from "./client.js";

// A script / CLI signing a user in through the JSON API (app kind "native" or "backend": no Origin is sent),
// with the two-step verification branch, then calling an API with the access token.
//   OPENBACK_ISSUER=... OPENBACK_CLIENT_ID=uapp_... node backend-signin.mjs
import { createInterface } from "node:readline/promises";
import { createAuth } from "openback-app-auth-nodejs";

const rl = createInterface({ input: process.stdin, output: process.stdout });
const auth = createAuth({ issuer: process.env.OPENBACK_ISSUER, clientId: process.env.OPENBACK_CLIENT_ID });

auth.onAuthStateChanged((user) => console.log(user ? `signed in: ${user.email}` : "signed out"));

try {
  let res = await auth.signInWithPassword({ email: await rl.question("Email: "), password: await rl.question("Password: ") });
  if (res.status === "mfa_required") res = await auth.verifyMfa({ mfaToken: res.mfa_token, code: await rl.question("Code: ") });
  if (res.status !== "ok") {
    console.log(`Not signed in: ${res.status}`);
  } else {
    console.log("Access token claims:", auth.accessTokenClaims);
    if (process.env.API_URL) {
      const r = await auth.fetch(process.env.API_URL); // Authorization: Bearer <access token>, renewed when needed
      console.log(r.status, await r.text());
    }
    await auth.signOut();
  }
} catch (e) {
  console.error(`${e.code}: ${e.message}`);
} finally {
  rl.close();
}

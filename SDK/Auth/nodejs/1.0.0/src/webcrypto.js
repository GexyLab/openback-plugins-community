// jose 6 uses the Web Crypto global. Node.js 18 exposes it only as require("node:crypto").webcrypto: install it as the
// global when it is missing (Node.js 19+ already has it). Imported first by src/index.js.
import { webcrypto } from "node:crypto";

if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true, enumerable: false, writable: true });
}

const assert = require("assert");
const handshakeToken = require("./index.js");

const secret = "test-secret-key-123";
const WINDOW = 300;
const BUFFER = 30;

// 1. Token generation returns 64-char hex string
const token = handshakeToken(secret, null, WINDOW, BUFFER);
assert.strictEqual(typeof token, "string");
assert.strictEqual(token.length, 64);
assert.match(token, /^[0-9a-f]{64}$/);
console.log(" Token generation test passed");

// 2. Token verification returns true for valid token
const isValid = handshakeToken(secret, token, WINDOW, BUFFER);
assert.strictEqual(isValid, true);
console.log(" Token verification test passed");

// 3. Token verification fails for invalid token or wrong secret
assert.strictEqual(handshakeToken("wrong-secret", token, WINDOW, BUFFER), false);
assert.strictEqual(handshakeToken(secret, "bad" + token.slice(3), WINDOW, BUFFER), false);
assert.strictEqual(handshakeToken(secret, "short-token", WINDOW, BUFFER), false);
console.log(" Negative verification test passed");

// 4. Custom window and buffer settings work
const customToken = handshakeToken(secret, undefined, 60, 5);
assert.strictEqual(handshakeToken(secret, customToken, 60, 5), true);
assert.strictEqual(handshakeToken(secret, customToken, 120, 5), false);
console.log(" Custom window/buffer test passed");

// 5. Validation errors when mandatory params are missing
assert.throws(() => handshakeToken(), /secret must be a non-empty string/);
assert.throws(() => handshakeToken(secret, null), /windowSeconds is required/);
assert.throws(() => handshakeToken(secret, null, -10, 5), /windowSeconds is required/);
assert.throws(() => handshakeToken(secret, null, 60), /bufferSeconds is required/);
assert.throws(() => handshakeToken(secret, null, 60, -5), /bufferSeconds is required/);
console.log(" Mandatory parameter validation test passed");

console.log("\nAll tests passed successfully!");


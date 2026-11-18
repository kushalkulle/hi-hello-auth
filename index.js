/**
 * Self-contained plain JS HMAC-SHA256 generator & verifier with mandatory window & buffer.
 * Works synchronously in all browsers (including HTTP local testing) and Node.js.
 *
 * @param {string} secret - Shared secret key
 * @param {string|null|undefined} [tokenToVerify] - Optional token to validate (returns boolean if provided, null/undefined to generate)
 * @param {number} windowSeconds - Time window in seconds (required, positive number)
 * @param {number} bufferSeconds - Clock buffer in seconds (required, non-negative number)
 * @returns {string|boolean} 64-char hex token when generating, or true/false when verifying
 */
function handshakeToken(secret, tokenToVerify, windowSeconds, bufferSeconds) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new TypeError("secret must be a non-empty string");
  }
  if (typeof windowSeconds !== "number" || isNaN(windowSeconds) || windowSeconds <= 0) {
    throw new TypeError("windowSeconds is required and must be a positive number");
  }
  if (typeof bufferSeconds !== "number" || isNaN(bufferSeconds) || bufferSeconds < 0) {
    throw new TypeError("bufferSeconds is required and must be a non-negative number");
  }

  var WINDOW_SECONDS = windowSeconds;
  var BUFFER_SECONDS = bufferSeconds;

  function toUtf8Bytes(str) {
    var utf8 = unescape(encodeURIComponent(str));
    var bytes = new Array(utf8.length);
    for (var i = 0; i < utf8.length; i++) {
      bytes[i] = utf8.charCodeAt(i);
    }
    return bytes;
  }

  function sha256Bytes(msgBytes) {
    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    var H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    var bytes = msgBytes.slice();
    var bitLen = bytes.length * 8;
    bytes.push(0x80);
    while ((bytes.length % 64) !== 56) {
      bytes.push(0x00);
    }

    var highBits = Math.floor(bitLen / 0x100000000);
    var lowBits = bitLen >>> 0;
    bytes.push((highBits >>> 24) & 0xff, (highBits >>> 16) & 0xff, (highBits >>> 8) & 0xff, highBits & 0xff);
    bytes.push((lowBits >>> 24) & 0xff, (lowBits >>> 16) & 0xff, (lowBits >>> 8) & 0xff, lowBits & 0xff);

    var w = new Array(64);
    for (var offset = 0; offset < bytes.length; offset += 64) {
      for (var i = 0; i < 16; i++) {
        var j = offset + i * 4;
        w[i] = ((bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3]) >>> 0;
      }
      for (var i = 16; i < 64; i++) {
        var s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
        var s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }

      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (var i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ ((~e) & g);
        var temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;

        h = g; g = f; f = e;
        e = (d + temp1) >>> 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) >>> 0;
      }

      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    var out = [];
    for (var i = 0; i < 8; i++) {
      out.push((H[i] >>> 24) & 0xff, (H[i] >>> 16) & 0xff, (H[i] >>> 8) & 0xff, H[i] & 0xff);
    }
    return out;
  }

  function hmacSha256Hex(keyStr, msgStr) {
    var keyBytes = toUtf8Bytes(keyStr);
    if (keyBytes.length > 64) {
      keyBytes = sha256Bytes(keyBytes);
    }
    while (keyBytes.length < 64) {
      keyBytes.push(0x00);
    }

    var oKeyPad = new Array(64);
    var iKeyPad = new Array(64);
    for (var i = 0; i < 64; i++) {
      oKeyPad[i] = keyBytes[i] ^ 0x5c;
      iKeyPad[i] = keyBytes[i] ^ 0x36;
    }

    var innerHash = sha256Bytes(iKeyPad.concat(toUtf8Bytes(msgStr)));
    var outerHash = sha256Bytes(oKeyPad.concat(innerHash));

    var hex = "";
    for (var i = 0; i < outerHash.length; i++) {
      hex += ("0" + outerHash[i].toString(16)).slice(-2);
    }
    return hex;
  }

  var nowSeconds = Math.floor(Date.now() / 1000);
  var currentStep = Math.floor(nowSeconds / WINDOW_SECONDS);

    // Mode 1: Generate token (no tokenToVerify passed or passed as null/undefined)
    if (tokenToVerify === undefined || tokenToVerify === null) {
      return hmacSha256Hex(secret, String(currentStep));
    }

    // Mode 2: Verify token with boundary buffer
    if (typeof tokenToVerify !== "string" || tokenToVerify.length !== 64) {
      return false;
    }

    var offset = nowSeconds % WINDOW_SECONDS;
    var validSteps = [currentStep];
    if (offset < BUFFER_SECONDS) validSteps.push(currentStep - 1);
    if (offset >= WINDOW_SECONDS - BUFFER_SECONDS) validSteps.push(currentStep + 1);

    for (var s = 0; s < validSteps.length; s++) {
      var expected = hmacSha256Hex(secret, String(validSteps[s]));
      var diff = 0;
      for (var c = 0; c < 64; c++) {
        diff |= expected.charCodeAt(c) ^ tokenToVerify.charCodeAt(c);
      }
      if (diff === 0) return true;
    }
    return false;
  }

  // CommonJS export
  if (typeof module !== "undefined" && module.exports) {
    module.exports = handshakeToken;
    module.exports.handshakeToken = handshakeToken;
    module.exports.default = handshakeToken;
  }

  // Global browser fallback
  if (typeof window !== "undefined") {
    window.handshakeToken = handshakeToken;
  }


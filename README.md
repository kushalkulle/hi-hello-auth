# hi-hello-auth

Zero-dependency, synchronous, cross-platform HMAC-SHA256 handshake token generator and validator with clock drift tolerance. Works in Node.js and all modern/legacy browsers.

## Features

- **Zero dependencies**: Pure ES5 vanilla JavaScript implementation.
- **Synchronous & Portable**: Runs anywhere without `crypto.subtle` async headaches or Node-only `crypto` modules. Works over unsecure `http://` in local development too.
- **Configurable Time Windows**: Default 5-minute time window (`300s`) or custom duration.
- **Clock Drift Buffer**: Built-in 30-second buffer to handle boundary clock sync differences between client and server.
- **Timing Attack Safe**: Validates tokens with constant-time XOR comparison.
- **Dual Support**: CommonJS (`require`), ES Modules (`import`), and direct browser script tags. TypeScript definitions included.

---

## Installation

```bash
npm install hi-hello-auth
```

---

## Usage

### 1. Generating a Token (Client / Sender)

Pass `null` or `undefined` as the 2nd parameter when generating:

```javascript
// CommonJS
const handshakeToken = require("hi-hello-auth");

// or ES Modules
import handshakeToken from "hi-hello-auth";

const SHARED_SECRET = "your-shared-secret-key";
const WINDOW_SECONDS = 300; // 5-minute window
const BUFFER_SECONDS = 30;  // 30-second buffer

// Generate token
const token = handshakeToken(SHARED_SECRET, null, WINDOW_SECONDS, BUFFER_SECONDS);
console.log(token);
// Output: 64-character hex string
```

### 2. Verifying a Token (Server / Receiver)

```javascript
const handshakeToken = require("hi-hello-auth");

const SHARED_SECRET = "your-shared-secret-key";
const WINDOW_SECONDS = 300;
const BUFFER_SECONDS = 30;

const clientToken = req.headers["x-handshake-token"];

const isValid = handshakeToken(SHARED_SECRET, clientToken, WINDOW_SECONDS, BUFFER_SECONDS);

if (!isValid) {
  return res.status(401).json({ error: "Invalid or expired handshake token" });
}

// Proceed with request...
```

---

## API

### `handshakeToken(secret, tokenToVerify, windowSeconds, bufferSeconds)`

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `secret` | `string` | **Yes** | Shared secret key between client and server (non-empty string). |
| `tokenToVerify` | `string \| null \| undefined` | **Yes** | The token string to validate, or `null`/`undefined` to generate a new token. |
| `windowSeconds` | `number` | **Yes** | Validity window duration in seconds (must be a positive number). |
| `bufferSeconds` | `number` | **Yes** | Boundary buffer in seconds to tolerate clock skew (must be >= 0). |

**Returns:**
- `string`: 64-character hex token when generating.
- `boolean`: `true` if valid, `false` otherwise when verifying.

**Throws:**
- `TypeError`: If any mandatory parameter is missing or invalid.

---

## License

[MIT](LICENSE)


"""
Section 9 ground-truth test bundle: CASE-0044
(Aarondoran/servify-express, CVE-2025-67731, CWE-400 uncontrolled resource
consumption).

Core vulnerable mechanism: `StartServer.listen(port)` starts an Express app
with no rate limiting anywhere -- every route (including the default "/")
accepts unlimited requests per client, allowing a trivial denial-of-service
via request flooding. The fix adds an OPTIONAL `options.rateLimit` config
that, when supplied, applies `express-rate-limit` middleware.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0044"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''    static listen(port) {
        const app = express();

        // Middleware (optional)
        app.use(express.json());

        // Default route (optional)
        app.get("/", (req, res) => {
            res.send("Server is running!");
        });

        // Start the server and log the default message
        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename listen -> start, port -> serverPort, app -> server. Same exact
# absence of any rate-limiting mechanism.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    static start(serverPort) {
        const server = express();

        // Middleware (optional)
        server.use(express.json());

        // Default route (optional)
        server.get("/", (req, res) => {
            res.send("Server is running!");
        });

        // Start the server and log the default message
        server.listen(serverPort, () => {
            console.log(`Server is running on port ${serverPort}`);
        });
    }''',
)
assert "static start(serverPort)" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact vulnerability (no rate limiting reachable at all), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    static listen(port) {
        const app = express();
        const jsonMiddleware = express.json();
        app.use(jsonMiddleware);

        const defaultHandler = (req, res) => {
            res.send("Server is running!");
        };
        app.get("/", defaultHandler);

        const onReady = () => {
            console.log(`Server is running on port ${port}`);
        };
        app.listen(port, onReady);
    }''',
)
assert structural_source != original
assert "const jsonMiddleware = express.json();" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (bound the rate of incoming requests) but a
# materially different implementation: a small hand-rolled fixed-window
# counter middleware instead of the real fix's express-rate-limit
# dependency, and rate limiting is always ON (not opt-in via an options
# flag) -- genuinely mitigates unbounded request flooding, different code
# shape/dependency from the real patched_source.js.
SAFE_SOURCE = '''const express = require("express");

class StartServer {
    static listen(port) {
        const app = express();

        const requestCounts = new Map();
        const WINDOW_MS = 60000;
        const MAX_REQUESTS = 100;

        app.use((req, res, next) => {
            const now = Date.now();
            const clientKey = req.ip;
            const entry = requestCounts.get(clientKey) || { count: 0, windowStart: now };
            if (now - entry.windowStart > WINDOW_MS) {
                entry.count = 0;
                entry.windowStart = now;
            }
            entry.count += 1;
            requestCounts.set(clientKey, entry);
            if (entry.count > MAX_REQUESTS) {
                return res.status(429).send("Too many requests");
            }
            next();
        });

        app.use(express.json());

        app.get("/", (req, res) => {
            res.send("Server is running!");
        });

        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }
}

module.exports = StartServer;
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "MAX_REQUESTS" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (an Express app with no explicit rate-limiting
# middleware, a default "/" route, app.listen(port, cb)) but this sibling
# is a LOCAL-ONLY development helper that binds explicitly to 127.0.0.1
# and is only ever invoked from a CLI dev script, never reachable from an
# untrusted network -- no request-flooding attack surface exists despite
# looking structurally identical to StartServer.listen().
BENIGN_SOURCE = '''const express = require("express");

class DevPreviewServer {
    // Only ever started from `npm run dev:preview`, bound to loopback --
    // never exposed to any untrusted client, so the absence of explicit
    // rate limiting here carries no real risk, unlike the production
    // listener this class superficially resembles.
    static listen(port) {
        const app = express();

        app.use(express.json());

        app.get("/", (req, res) => {
            res.send("Dev preview server running!");
        });

        app.listen(port, "127.0.0.1", () => {
            console.log(`Dev preview server running on 127.0.0.1:${port}`);
        });
    }
}

module.exports = DevPreviewServer;
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "127.0.0.1" in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0044.")

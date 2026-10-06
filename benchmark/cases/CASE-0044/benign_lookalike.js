const express = require("express");

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

const express = require("express");

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

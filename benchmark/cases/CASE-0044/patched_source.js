const express = require("express");
const rateLimit = require("express-rate-limit");

class StartServer {
    static listen(port, options = {}) {
        const app = express();

        if (options.rateLimit) {
            const limiter = rateLimit({
                windowMs: options.rateLimit.windowMs || 60000,
                max: options.rateLimit.max || 100
            });
            app.use(limiter);
        }

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

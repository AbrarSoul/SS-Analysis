const express = require("express");

class StartServer {
    static listen(port) {
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
    }
}

module.exports = StartServer;

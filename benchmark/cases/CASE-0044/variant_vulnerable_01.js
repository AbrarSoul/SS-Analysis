const express = require("express");

class StartServer {
    static start(serverPort) {
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
    }
}

module.exports = StartServer;

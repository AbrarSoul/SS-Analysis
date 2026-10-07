const express = require("express");

class StartServer {
    static listen(port) {
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
    }
}

module.exports = StartServer;

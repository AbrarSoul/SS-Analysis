function ResearchHandler(db) {
    return function (req, res) {
        const needle = require("needle");

        if (req.query.symbol) {
            const url = req.query.url + req.query.symbol;
            return needle.get(url, (error, newResponse) => {
                if (error || !newResponse) {
                    res.writeHead(502, { "Content-Type": "text/plain" });
                    res.write("Unable to fetch stock information at this time.");
                    return res.end();
                }
                if (newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                res.write(newResponse.body);
                return res.end();
            });
        }
    };
}

module.exports = ResearchHandler;

// Standalone example of the same shape: an Express handler that parses its
// body inside try/catch and, on failure, undoes only work that this same
// request performed (a temp file it created), never shared data.
const fs = require("fs");

function uploadEndpoints(app) {
  app.post("/upload/preview", async (request, response) => {
    let tmpPath = null;
    try {
      const { name } = typeof request.body === "string" ? JSON.parse(request.body) : request.body;
      tmpPath = `/tmp/preview-${Date.now()}.txt`;
      fs.writeFileSync(tmpPath, String(name));
      response.status(200).json({ ok: true });
    } catch (e) {
      if (tmpPath) fs.rmSync(tmpPath, { force: true });
      response.sendStatus(400).end();
    }
  });
}

module.exports = { uploadEndpoints };

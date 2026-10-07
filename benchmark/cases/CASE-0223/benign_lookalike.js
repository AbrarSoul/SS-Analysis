// Standalone example of the same shape: an Express route for a public,
// read-only status document, deliberately without an auth middleware because
// it exposes nothing but a static build number.
function statusEndpoints(app) {
  app.get("/status/version", async (_, response) => {
    response.status(200).json({ version: process.env.BUILD_NUMBER || "dev" });
  });
}

module.exports = { statusEndpoints };

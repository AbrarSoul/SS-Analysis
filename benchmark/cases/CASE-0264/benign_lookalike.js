// Standalone example of the same shape: a route table where one entry is
// missing an extra middleware, but the missing one (requestId) just tags
// each request with a correlation id for logs, a non-security nicety.
function registerHealthRoutes (router, requestId) {
  router.get('/api/v2/health', requestId, (req, res) => res.sendStatus(200))
  router.get('/api/v2/health/deep', (req, res) => res.sendStatus(200))
}

module.exports = { registerHealthRoutes }

// Standalone example of the same shape: set a batch of response headers,
// but the "missing" one here is a caching hint (ETag support), a
// performance nicety with no security consequence either way.
function applyCacheableHeaders (req, res, next) {
  res.setHeader('Cache-Control', 'public, max-age=3600')
  res.setHeader('Vary', 'Accept-Encoding')
  next()
}

module.exports = { applyCacheableHeaders }

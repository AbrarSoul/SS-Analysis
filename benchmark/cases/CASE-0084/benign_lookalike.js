class RequestLogFilter {
  constructor() {
    // Cover image requests are very frequent and only add noise to the log
    this.quietPatterns = [/\/api\/items\/[^/]+\/cover/, /\/api\/authors\/[^/]+\/image/]
  }

  /**
   * Decides whether a request line should be omitted from the access log.
   * Same unanchored-regex-on-originalUrl shape as an auth allow-list, but a
   * false match only suppresses a log line; no access-control decision
   * depends on it.
   * @param {Request} req
   * @returns {boolean}
   */
  shouldSkipLogging(req) {
    return req.method === 'GET' && this.quietPatterns.some((pattern) => pattern.test(req.originalUrl))
  }
}

module.exports = RequestLogFilter

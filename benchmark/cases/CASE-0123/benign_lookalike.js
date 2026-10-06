"use strict";

/**
 * Same "reflect the request's Origin with credentials" shape as a CORS
 * handler, but only for origins that are OWN keys of an explicit allow-list
 * object (exact string match), never for arbitrary or inherited names, so a
 * foreign page never receives a credentialed cross-origin grant.
 */
function applyCors(req, res, allowedOrigins) {
  var origin = req.headers.origin;
  if (typeof origin === "string" && Object.prototype.hasOwnProperty.call(allowedOrigins, origin)) {
    res.setHeader("access-control-allow-origin", origin);
    res.setHeader("access-control-allow-credentials", true);
    return true;
  }
  return false;
}

module.exports = { applyCors: applyCors };

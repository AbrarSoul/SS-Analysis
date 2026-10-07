"use strict";

/**
 * Same "write into req.session" shape as logIn, but it records a harmless
 * UI value (last-seen time) and grants no authentication or privilege, so
 * keeping the current session id is correct and no fixation is possible.
 */
function recordLastSeen(req, now) {
  if (!req.session) {
    req.session = {};
  }
  req.session.lastSeen = now;
}

module.exports = recordLastSeen;

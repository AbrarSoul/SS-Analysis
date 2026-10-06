"use strict";

/**
 * Same "persist the session object" shape as SessionStore.set, but only a
 * whitelist of non-sensitive fields is ever copied into the stored record, so
 * a password (or any other secret) on the live session can never be written.
 */
function persistableSession(sess) {
  return {
    cookie: sess.cookie,
    language: sess.language,
    lastSeen: sess.lastSeen
  };
}

module.exports = { persistableSession: persistableSession };

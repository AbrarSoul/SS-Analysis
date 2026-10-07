"""
Section 9 ground-truth test bundle: CASE-0157
(ether/etherpad-lite, src/node/db/SessionStore.js SessionStore.prototype.set,
CVE-2020-22781, CWE-312 cleartext storage of sensitive information).

Core vulnerable mechanism: express-session hands `set(sid, sess, fn)` the
whole session object, and when a user authenticated with a password the
session contains `sess.user.password` in clear text. `set` writes that object
to the database as is (`db.set("sessionstorage:" + sid, sess)`), so plaintext
passwords sit in the session records. The upstream fix overwrites
`sess.user.password` with "PASSWORD_HIDDEN" before storing.

Measured caveat, kept in the manifest notes: upstream redacts by MUTATING the
live session object, so after set() the in-memory `req.session.user.password`
is also "PASSWORD_HIDDEN"; the safe variant stores a redacted COPY and leaves
the live session intact.

Sibling sites: none (set is the only writer of session records).

Every variant is the FULL real file. `set` is the express-session Store
interface method (an override of Store.prototype.set), so the renamed variant
renames parameters and locals, not the method.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0157"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

SET = '''SessionStore.prototype.set = function(sid, sess, fn) {
  messageLogger.debug('SET ' + sid);

  db.set("sessionstorage:" + sid, sess);
  if (fn) {
    process.nextTick(fn);
  }
};
'''
assert original.count(SET) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, SET, '''SessionStore.prototype.set = function(sessionId, data, callback) {
  messageLogger.debug('SET ' + sessionId);

  db.set("sessionstorage:" + sessionId, data);
  if (callback) {
    process.nextTick(callback);
  }
};
''')
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, SET, '''SessionStore.prototype.set = function(sid, sess, fn) {
  messageLogger.debug('SET ' + sid);

  const key = "sessionstorage:" + sid;
  db.set(key, sess);
  if (typeof fn === 'function') {
    setImmediate(fn);
  }
};
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The stored record is a redacted COPY (user.password replaced) and the live
# session object is left untouched; upstream overwrites the password on the
# live object.
v3 = swap(original, SET, '''SessionStore.prototype.set = function(sid, sess, fn) {
  messageLogger.debug('SET ' + sid);

  let stored = sess;
  if (sess && sess.user && sess.user.password) {
    stored = Object.assign({}, sess, {user: Object.assign({}, sess.user, {password: "PASSWORD_HIDDEN"})});
  }
  db.set("sessionstorage:" + sid, stored);
  if (fn) {
    process.nextTick(fn);
  }
};
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

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
'''
assert "whitelist" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0157.")

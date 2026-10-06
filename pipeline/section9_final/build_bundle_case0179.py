"""
Section 9 ground-truth test bundle: CASE-0179
(jaredhanson/passport, lib/sessionmanager.js SessionManager.logIn,
CVE-2022-25896, CWE-384 session fixation).

Located target: `this._serializeUser(user, req, function(err, obj) {`.

Core vulnerable mechanism: `logIn` stores the authenticated user in the EXISTING
session (`req.session[key].user = obj`) without issuing a new session id.
An attacker who can plant a known session id in the victim's browser
(session fixation) keeps a valid session after the victim logs in. The
upstream fix calls `req.session.regenerate` first and serialises the user
into the fresh session.

Measured caveat, kept in the manifest notes: upstream's `logIn` throws a
TypeError when `req.session` is undefined (the code below it still contains a
"create req.session" fallback that is now unreachable), and it adds two
debug `console.log` lines.

Sibling sites: `logOut` only deletes the user entry (no id rotation); it is not
part of the login fixation and is unchanged in every variant.

Every variant is the FULL real file. logIn is a prototype method called by
passport by name, so the renamed variant keeps the name and renames its
parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0179"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

LOGIN = original[original.index("SessionManager.prototype.logIn"):original.index("SessionManager.prototype.logOut")]
assert original.count(LOGIN) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
b = LOGIN
for old, new in (("req", "request"), ("user", "account"), ("cb", "done"), ("self", "manager"), ("obj", "serialized"), ("err", "error")):
    b = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, b)
b = b.replace("manager._key].account = serialized", "manager._key].user = serialized")
assert "function(request, account, done)" in b and "request.session[manager._key].user = serialized;" in b
assert "this._serializeUser(account, request, function(error, serialized)" in b
(CASE_DIR / "variant_vulnerable_01.js").write_text(swap(original, LOGIN, b))

# --- Variant 2: structurally changed vulnerable variant ---
b = LOGIN.replace('''    if (!req.session) {
      req.session = {};
    }
    if (!req.session[self._key]) {
      req.session[self._key] = {};
    }
    req.session[self._key].user = obj;
    cb();''', '''    storeUser(req, self._key, obj);
    cb();''')
assert b != LOGIN
v2 = swap(original, LOGIN, b)
v2 = swap(v2, "SessionManager.prototype.logOut", '''function storeUser(req, key, obj) {
  if (!req.session) {
    req.session = {};
  }
  if (!req.session[key]) {
    req.session[key] = {};
  }
  req.session[key].user = obj;
}

SessionManager.prototype.logOut''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The session id is rotated when the session supports it (and login still
# works on a bare req.session-less object, unlike upstream, which throws);
# serialisation happens first, then the fresh session receives the user.
b = '''SessionManager.prototype.logIn = function(req, user, cb) {
  var self = this;
  this._serializeUser(user, req, function(err, obj) {
    if (err) {
      return cb(err);
    }
    var rotate = req.session && typeof req.session.regenerate === 'function'
      ? function(next) { req.session.regenerate(next); }
      : function(next) { next(); };
    rotate(function(err) {
      if (err) {
        return cb(err);
      }
      if (!req.session) {
        req.session = {};
      }
      if (!req.session[self._key]) {
        req.session[self._key] = {};
      }
      req.session[self._key].user = obj;
      cb();
    });
  });
}

'''
(CASE_DIR / "variant_safe_01.js").write_text(swap(original, LOGIN, b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

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
'''
assert "grants no authentication" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0179.")

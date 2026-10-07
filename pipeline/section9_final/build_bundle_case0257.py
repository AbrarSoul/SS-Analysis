"""
Section 9 ground-truth test bundle: CASE-0257
(pgadmin-org/pgadmin4, web/pgadmin/utils/session.py
FileBackedSessionManager, CVE-2024-2044, CWE-31 path traversal in a
file-backed session store).

Core vulnerable mechanism: pgAdmin's Flask session cookie is `sid!digest`.
`ManagedSessionInterface.open_session` splits the cookie on `!` with NO
validation and hands the raw `sid` to `self.manager.exists(sid)` and
`self.manager.get(sid, digest)`, both of which build the session file's path
with plain `os.path.join(self.path, sid)`. A cookie value such as
`../../../../etc/passwd!x` makes `exists` test (and `get` open and
`pickle.load`) a file outside the session directory; if `exists` returns
True, the resulting `ManagedSession`'s `sid` is exactly that same traversal
string, and a later `put()` (also `os.path.join(self.path, session.sid)`)
writes the pickled session back through the SAME escaped path -- an
authenticated (or even pre-authentication, since sessions are created for
anonymous requests too) local file read and overwrite anywhere the pgAdmin
process can access. The upstream fix replaces every `os.path.join(self.path,
sid)` with `werkzeug.security.safe_join(self.path, sid)`, which returns
`None` for any name that would leave `self.path`, and treats `None` as "does
not exist" (or raises `InternalServerError` where a session must be written).

Sibling sites: the same `os.path.join(self.path, sid_or_session.sid)` pattern
appears in `exists`, `remove`, `new_session` (twice; there `sid` is the
manager's own `uuid4()`, not attacker input, but the upstream patch still
guards it), `get`, and `put`. The auto-located target is `new_session` only;
the safe variant fixes all five call sites and the vulnerable variants leave
all five unchanged.

Verification: each full file is used as the real, unmodified module
(`FileBackedSessionManager` calls `os.path.exists`/`open`/`pickle.load` for
real; for the safe variant, `from werkzeug.security import safe_join`
resolves to the REAL werkzeug function) with `config`, `flask`/`flask_login`
stand-ins for `request`/`current_app`. A real temporary directory holds the
session store plus a validly `pickle`-dumped session file one level above it
(standing in for another user's real session file, or any file the pgAdmin
process can read). `exists(traversal_sid)` and `get(traversal_sid, digest)`
are called with `../secret.session`, and a normal in-store session is created
and read back as a control.

Every variant is the FULL real file. `FileBackedSessionManager`'s methods
implement the `SessionManager` interface used by `ManagedSessionInterface`, so
their names and signatures are kept; the renamed variant renames locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0257"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


JOINS = [
    "        fname = os.path.join(self.path, sid)\n        return os.path.exists(fname)\n",
    "        fname = os.path.join(self.path, sid)\n        if os.path.exists(fname):\n            os.unlink(fname)\n",
    "        fname = os.path.join(self.path, sid)\n\n        while os.path.exists(fname):\n            sid = str(uuid4())\n            fname = os.path.join(self.path, sid)\n",
    "        fname = os.path.join(self.path, sid)\n        data = None\n",
    "        fname = os.path.join(self.path, session.sid)\n        with open(fname, 'wb') as f:\n",
]
for j in JOINS:
    assert original.count(j) == 1

# --- Variant 1: renamed vulnerable variant ---
# fname is purely local everywhere in this class (never an attribute name or a
# keyword argument name), so it can be renamed with a blanket word-boundary
# substitution. hmac_digest/randval are ALSO used as ManagedSession attribute
# names (session.hmac_digest, session.randval) and as the ManagedSession(...)
# constructor's keyword argument names two lines below, so only their LOCAL
# bindings inside get() are renamed, by exact text, leaving the attribute
# accesses and keyword argument names untouched.
s = original.index("class FileBackedSessionManager(SessionManager):")
e = original.index("\n\nclass ManagedSessionInterface(SessionInterface):")
seg = original[s:e]
seg = re.sub(r"\bfname\b", "target_path", seg)
seg = swap(seg, "        hmac_digest = None\n        randval = None\n",
                 "        digest_value = None\n        rand_value = None\n")
seg = swap(seg, "                    randval, hmac_digest, data = load(f)\n",
                 "                    rand_value, digest_value, data = load(f)\n")
seg = swap(seg, "        if hmac_digest != digest:\n", "        if digest_value != digest:\n")
seg = swap(seg, "            data, sid=sid, randval=randval, hmac_digest=hmac_digest\n",
                 "            data, sid=sid, randval=rand_value, hmac_digest=digest_value\n")
assert "target_path" in seg and "digest_value" in seg and "rand_value" in seg
assert "session.hmac_digest" in seg and "session.randval" in seg  # untouched attribute accesses
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
seg2 = original[s:e]
for j in JOINS:
    seg2 = seg2.replace(j, j.replace("os.path.join(self.path, sid)", "self._session_file(sid)")
                           .replace("os.path.join(self.path, session.sid)", "self._session_file(session.sid)"), 1)
assert seg2.count("class FileBackedSessionManager(SessionManager):\n") == 1
seg2 = seg2.replace(
    "class FileBackedSessionManager(SessionManager):\n",
    "class FileBackedSessionManager(SessionManager):\n\n"
    "    def _session_file(self, sid):\n"
    "        return os.path.join(self.path, sid)\n",
    1,
)
v2 = original[:s] + seg2 + original[e:]
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "from werkzeug.datastructures import CallbackDict\n",
          "from werkzeug.datastructures import CallbackDict\nfrom werkzeug.security import safe_join\n")
v3 = swap(v3, JOINS[0], "        fname = safe_join(self.path, sid)\n        return fname is not None and os.path.exists(fname)\n")
v3 = swap(v3, JOINS[1], "        fname = safe_join(self.path, sid)\n        if fname is not None and os.path.exists(fname):\n            os.unlink(fname)\n")
v3 = swap(v3, JOINS[2], "        fname = safe_join(self.path, sid)\n\n        while fname is not None and os.path.exists(fname):\n            sid = str(uuid4())\n            fname = safe_join(self.path, sid)\n")
v3 = swap(v3, JOINS[3], "        fname = safe_join(self.path, sid)\n        data = None\n")
v3 = swap(v3, "        if os.path.exists(fname):\n            try:\n                with open(fname, 'rb') as f:",
          "        if fname is not None and os.path.exists(fname):\n            try:\n                with open(fname, 'rb') as f:")
v3 = swap(v3, JOINS[4], "        fname = safe_join(self.path, session.sid)\n        if fname is None:\n            return\n        with open(fname, 'wb') as f:\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: join a cache directory with a key,
but the key is always a UUID this process just generated, never a value that
came back from a client."""
import os
from uuid import uuid4


def new_cache_entry(cache_dir):
    key = str(uuid4())
    path = os.path.join(cache_dir, key)
    with open(path, "wb"):
        pass
    return key
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)

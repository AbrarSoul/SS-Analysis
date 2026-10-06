r"""
Section 9 ground-truth test bundle: CASE-0319
(usmannasir/cyberpanel, databases/views.py restartMySQL,
CVE-2024-54679, CWE-862 missing authorization).

Core vulnerable mechanism: the `restartMySQL` view authenticates (reads
`request.session['userID']`) and loads the caller's ACL, but it calls
`mysqlUtilities.restartMySQL()` BEFORE checking `currentACL['admin'] == 1`.
A logged-in NON-admin user (for example a reseller or website user) gets the
"FilemanagerAdmin" error response, but the MySQL server has already been
restarted: an authorization check performed after the privileged action
(availability impact, any authenticated user can restart the database).
The fix moves the restart call after the admin check.

Sibling sites: `upgrademysqlstatus` in the same file had no check at all
(CASE-0318); this view's check exists but is ordered wrong.

Verification: the view function (plus any helper a variant adds) is sliced
from each full file and exec'd with a stub `mysqlUtilities.restartMySQL`
that counts calls, an `ACLManager` stub (user 1 is admin), a real `json`,
and stub `HttpResponse`/`redirect`. Callers: unauthenticated (empty session),
non-admin session, admin session. The number of restarts triggered is the
measurement: vulnerable variants restart the database for the non-admin
caller; patched/safe do not; the unauthenticated caller never restarts in
any file (KeyError before the call) and the admin caller restarts in all.

Every variant is the FULL real file; `restartMySQL` is a URL-routed view and
keeps its name and signature.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0319"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


START = "def restartMySQL(request):\n"
assert original.count(START) == 1 and patched.count(START) == 1


def slice_func(text):
    a = text.index(START)
    nxt = text.find("\ndef ", a + 5)
    return text[a:nxt + 1] if nxt != -1 else text[a:]


func = slice_func(original)
pfunc = slice_func(patched)

# --- Variant 1: renamed vulnerable variant (locals renamed inside restartMySQL) ---
f1 = func
for old, new in [("userID", "callerId"), ("finalData", "restartResult"), ("currentACL", "callerAcl"),
                 ("json_data", "encoded"), ("data", "reply")]:
    f1 = re.sub(r"(?<![\w.'\"])%s(?![\w'\"])" % old, new, f1)
assert "reply['status']" in f1 and "mysqlUtilities.restartMySQL()" in f1
v1 = original.replace(func, f1)
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (the restart moves into a helper, still called first) ---
f2 = swap(func, "        finalData = mysqlUtilities.restartMySQL()\n", "        finalData = _restartDatabase()\n")
v2 = original.replace(func, "def _restartDatabase():\n    return mysqlUtilities.restartMySQL()\n\n\n" + f2)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the restart is wrapped in a helper, called after the check) ---
pf3 = swap(pfunc, "        finalData = mysqlUtilities.restartMySQL()\n", "        finalData = _restartDatabase()\n")
v3 = patched.replace(pfunc, "def _restartDatabase():\n    return mysqlUtilities.restartMySQL()\n\n\n" + pf3)
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""Maintenance action: the privileged operation runs only after the caller has been authorised."""
import json


def restart_cache(session, acl_loader, restart):
    """Restart the cache, but only for admins; the check happens BEFORE the action."""
    acl = acl_loader(session['userID'])
    if acl['admin'] != 1:
        return json.dumps({'status': 0, 'error_message': 'not allowed'})
    result = restart()
    return json.dumps({'status': result[0], 'error_message': result[1]})
''')

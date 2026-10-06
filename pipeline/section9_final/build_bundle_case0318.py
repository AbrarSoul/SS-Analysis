r"""
Section 9 ground-truth test bundle: CASE-0318
(usmannasir/cyberpanel, databases/views.py upgrademysqlstatus,
CVE-2024-51567, CWE-306 missing authentication for a critical function).

Core vulnerable mechanism: `upgrademysqlstatus` is a Django view that polls
the progress of a MySQL upgrade. It reads `statusfile` from the JSON request
body and runs `sudo cat <statusfile>` and, on completion markers, `sudo rm -f
<statusfile>` through `ProcessUtilities`, all as root, with NO session or
admin check: an unauthenticated remote client can read any file as root and
delete files, and because `statusfile` is concatenated into a shell command
it is also command injection (pre-auth RCE, exploited in the wild against
CyberPanel). The fix adds `userID = request.session['userID']` and an
`ACLManager` admin check at the top of the view.

Sibling sites: the neighbouring views in the same file (`upgrademysqlnow`,
`restartMySQL`) already do the session/ACL check (restartMySQL is CASE-0319,
which has a check-ordering defect).

Verification: the view function (plus any helper a variant adds) is sliced
from each full file and exec'd with stubbed `ProcessUtilities` (records every
command), `ACLManager`, `HttpResponse`, `redirect` and `json` (real).
Requests: unauthenticated (empty session), non-admin session, admin session.
Vulnerable variants run the `sudo cat` and `sudo rm -f` commands for ALL
three callers (including the injected `; id` statusfile); patched/safe run
commands only for the admin caller and answer the others with a login
redirect / ACL error.

Every variant is the FULL real file; `upgrademysqlstatus` is a URL-routed
view and keeps its name and signature.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0318"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


START = "def upgrademysqlstatus(request):\n"
assert original.count(START) == 1
a = original.index(START)
b = original.index("\ndef ", a + 5) + 1 if "\ndef " in original[a + 5:] else len(original)
func = original[a:b]

# --- Variant 1: renamed vulnerable variant (locals renamed; the JSON keys stay) ---
f1 = func
for old, new in [("statusfile", "progressFile"), ("installStatus", "progressText"), ("command", "cleanupCommand"),
                 ("final_json", "responseBody"), ("data", "payload")]:
    f1 = re.sub(r"(?<![\w.'\"])%s(?![\w'\"])" % old, new, f1)
assert "data['statusfile']" not in f1 and "payload['statusfile']" in f1
v1 = original.replace(func, f1)
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (status-file read/remove moved into helpers) ---
RM = "            command = 'sudo rm -f ' + statusfile\n            ProcessUtilities.executioner(command)\n"
assert func.count(RM) == 2
f2 = func.replace(RM, "            _removeStatusFile(statusfile)\n")
f2 = swap(f2, '        installStatus = ProcessUtilities.outputExecutioner("sudo cat " + statusfile)\n',
          "        installStatus = _readStatusFile(statusfile)\n")
helpers = '''def _readStatusFile(statusfile):
    return ProcessUtilities.outputExecutioner("sudo cat " + statusfile)


def _removeStatusFile(statusfile):
    ProcessUtilities.executioner('sudo rm -f ' + statusfile)


'''
v2 = original.replace(func, helpers + f2)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the session/ACL check moves into a helper) ---
ACL = '''
        userID = request.session['userID']

        currentACL = ACLManager.loadedACL(userID)

        if currentACL['admin'] == 1:
            pass
        else:
            return ACLManager.loadErrorJson('FilemanagerAdmin', 0)
'''
pa = patched.index(START)
pfunc = patched[pa:patched.index("\ndef ", pa + 5) + 1] if "\ndef " in patched[pa + 5:] else patched[pa:]
assert pfunc.count(ACL) == 1
pf3 = pfunc.replace(ACL, "\n        denied = _adminGate(request)\n        if denied is not None:\n            return denied\n")
gate = '''def _adminGate(request):
    currentACL = ACLManager.loadedACL(request.session['userID'])
    if currentACL['admin'] == 1:
        return None
    return ACLManager.loadErrorJson('FilemanagerAdmin', 0)


'''
v3 = patched.replace(pfunc, gate + pf3)
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""Public health endpoint: reports a fixed, server-chosen status file; no request-controlled path and no shell."""
import json

STATUS_FILE = '/var/run/app/upgrade.status'


def upgrade_status_view(read_file=open):
    """Return the progress text of the fixed status file as JSON.

    The path is a module constant, the read is a plain file read (no
    subprocess, no root), so publishing it without a login is intentional.
    """
    try:
        with read_file(STATUS_FILE) as handle:
            text = handle.read()
    except OSError:
        text = ''
    return json.dumps({'abort': 1 if '[200]' in text else 0, 'requestStatus': text})
''')

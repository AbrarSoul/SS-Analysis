r"""
Section 9 ground-truth test bundle: CASE-0333
(xwiki/xwiki-platform, xwiki-platform-oldcore com/xpn/xwiki/api/User.java
setDisabledStatus, CVE-2022-41929, CWE-862 missing authorization).

Core vulnerable mechanism: `com.xpn.xwiki.api.User` is the scripting API
wrapper (`$xwiki.getUser(...)` in Velocity/Groovy wiki pages). Its public
`setDisabledStatus(boolean)` calls `this.user.setDisabled(status, context)`
with NO permission check, so any wiki user allowed to run a script (or anyone able
to inject one) can disable or re-enable ANY account, including administrators
(denial of service / account manipulation). The upstream fix wraps the call in
`if (hasAdminRights())`.

Sibling sites: `getUser()` in the same class is protected with
`@Programming` and `hasProgrammingRights()`; the disabled-status setter was
the unguarded mutator.

Verification: the `setDisabledStatus` method (plus any helper a variant adds)
is sliced from each full file into a javac harness class that extends a
stand-in `Api` base (`hasAdminRights()` returns a test-controlled value,
`getXWikiContext()` a dummy) and has a `user` field of a stand-in
`XWikiUser` that records `setDisabled(status, context)` calls.
Vulnerable variants record the change for a non-admin caller; patched/safe
record nothing for a non-admin caller; an admin caller always succeeds.

Every variant is the FULL real file; `setDisabledStatus` is a public
scripting API and keeps its name and signature.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0333"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


M = '''    public void setDisabledStatus(boolean disabledStatus)
    {
        this.user.setDisabled(disabledStatus, getXWikiContext());
    }
'''
assert original.count(M) == 1

# --- Variant 1: renamed vulnerable variant (parameter renamed) ---
v1 = swap(original, M, '''    public void setDisabledStatus(boolean newStatus)
    {
        this.user.setDisabled(newStatus, getXWikiContext());
    }
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (mutation delegated to a helper; still unguarded) ---
v2 = swap(original, M, '''    public void setDisabledStatus(boolean disabledStatus)
    {
        applyDisabledStatus(disabledStatus);
    }

    private void applyDisabledStatus(boolean status)
    {
        this.user.setDisabled(status, getXWikiContext());
    }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; guard kept, mutation moved into a helper) ---
PM = '''    public void setDisabledStatus(boolean disabledStatus)
    {
        if (hasAdminRights()) {
            this.user.setDisabled(disabledStatus, getXWikiContext());
        }
    }
'''
v3 = swap(patched, PM, '''    public void setDisabledStatus(boolean disabledStatus)
    {
        if (hasAdminRights()) {
            applyDisabledStatus(disabledStatus);
        }
    }

    private void applyDisabledStatus(boolean status)
    {
        this.user.setDisabled(status, getXWikiContext());
    }
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package com.xpn.xwiki.api;

/**
 * Standalone example of the same shape: a setter that changes state on the wrapped user object with no
 * permission check, because the wrapped object is the CALLER'S OWN preferences record (a user editing
 * their own display theme), not another account.
 */
class OwnPreferences {

    interface PreferenceStore {
        void setTheme(String theme);
    }

    private final PreferenceStore ownStore;

    OwnPreferences(PreferenceStore ownStore) {
        this.ownStore = ownStore;
    }

    public void setTheme(String theme) {
        this.ownStore.setTheme(theme);
    }
}
''')
